use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
use tokio::sync::Notify;

use quion_proto::{
    VarInt,
    config::TransportConfig as ProtoTransportConfig,
    connection::{ConnectionEvent, Effects, StreamSchedulerConfig},
    ecn::EcnCodepoint,
    streams::{StreamId, StreamInitiator, StreamLimitKind},
    transport_error::TransportErrorCode,
    transport_parameters::{TransportParameters, ids as transport_parameter_ids},
};
use tracing::{debug, trace, trace_span};

use crate::{
    diagnostics::{ConnectionDiagnostics, PathDiagnostics, PathValidationStatus},
    error::ConnectionError,
    qlog::{DEFAULT_MAX_BUFFERED_QLOG_EVENTS, SharedQlogState},
    recv_stream::RecvStream,
    send_stream::SendStream,
    stats::ConnectionStats,
};

const MAX_ROUTED_DATAGRAM_QUEUE_LEN: usize = 2048;
const MAX_ROUTED_DATAGRAM_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const BTREE_ENTRY_BOOKKEEPING_BYTES: usize = 3 * std::mem::size_of::<usize>();
const TRANSPORT_CLOSE_METADATA_RESERVATION_BYTES: usize = 256;

fn stateless_reset_candidate(packet: &[u8]) -> Option<[u8; 16]> {
    if packet.len() < 21 || packet[0] & 0xc0 != 0x40 {
        return None;
    }
    packet[packet.len() - 16..].try_into().ok()
}

/// Bidirectional stream send and receive handles.
pub type BiStream = (SendStream, RecvStream);

/// Outcome of the TLS 0-RTT attempt associated with a connection.
#[cfg(feature = "zero-rtt")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ZeroRttStatus {
    /// No usable resumption state was available, so 0-RTT was not attempted.
    #[default]
    NotAttempted,
    /// 0-RTT keys were available, but the TLS handshake has not resolved the
    /// server's decision yet.
    Attempted,
    /// The server accepted 0-RTT.
    Accepted,
    /// The server rejected 0-RTT. Reliable early STREAM and control data is
    /// re-queued automatically for 1-RTT transmission; unreliable DATAGRAM
    /// data is not replayed.
    Rejected,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct OneRttReceiveState {
    pub(crate) largest_received: Option<u64>,
    pub(crate) largest_acked: Option<u64>,
    pub(crate) key_retirement_duration: std::time::Duration,
}

/// Established or handshaking QUIC connection handle.
#[derive(Debug, Clone)]
pub struct Connection {
    inner: Arc<ConnectionInner>,
}

/// Shared connection state exposed only as the target of the handle's
/// dereference implementation. Its fields and representation are not stable
/// public API.
#[doc(hidden)]
#[derive(Debug)]
#[allow(unnameable_types)]
pub struct ConnectionInner {
    local: SocketAddr,
    remote: SocketAddr,
    path_state: Mutex<ConnectionPathState>,
    created_at: web_time::Instant,
    proto: Arc<Mutex<quion_proto::connection::Connection>>,
    local_transport_config: ProtoTransportConfig,
    peer_transport_parameters: Mutex<Option<TransportParameters>>,
    initial_peer_stateless_reset_token: Mutex<Option<[u8; 16]>>,
    peer_stateless_reset_token: Mutex<Option<[u8; 16]>>,
    initial_peer_connection_id: Mutex<Option<quion_proto::cid::ConnectionId>>,
    peer_connection_ids: Mutex<BTreeMap<u64, PeerConnectionId>>,
    active_peer_connection_id: Mutex<Option<u64>>,
    peer_connection_id_update_pending: AtomicBool,
    largest_peer_retire_prior_to: Mutex<u64>,
    local_connection_ids: Mutex<BTreeMap<u64, quion_proto::cid::ConnectionId>>,
    retired_local_connection_ids_by_sequence: Mutex<BTreeMap<u64, quion_proto::cid::ConnectionId>>,
    retired_local_connection_ids: Mutex<VecDeque<quion_proto::cid::ConnectionId>>,
    retired_local_connection_id_pending: AtomicBool,
    peer_certificates: Mutex<Option<Vec<Vec<u8>>>>,
    alpn_protocol: Mutex<Option<Vec<u8>>>,
    negotiated_transport: Arc<Mutex<Option<NegotiatedTransport>>>,
    established: Mutex<bool>,
    #[cfg(feature = "zero-rtt")]
    zero_rtt_status: Mutex<ZeroRttStatus>,
    closed_state: Arc<Mutex<ClosedState>>,
    timeout_state: Mutex<TimeoutState>,
    protocol_memory: Arc<ProtocolMemoryTracker>,
    connection_id_memory: ProtocolMemoryTracker,
    connection_id_memory_update: Mutex<()>,
    routed_datagrams: Mutex<VecDeque<RoutedDatagram>>,
    datagram_state: Arc<Mutex<DatagramState>>,
    qlog: SharedQlogState,
    stream_wakers: Arc<Mutex<StreamWakers>>,
    stream_write_state: Arc<Mutex<StreamWriteState>>,
    stream_stop_state: Arc<Mutex<StreamStopState>>,
    stream_reset_state: Arc<Mutex<StreamResetState>>,
    accept_wakers: Arc<Mutex<AcceptWakers>>,
    next_bidi_stream: Mutex<u64>,
    next_uni_stream: Mutex<u64>,
    peer_stream_limits: Mutex<PeerStreamLimits>,
    open_stream_wakers: Mutex<OpenStreamWakers>,
    local_initiator: StreamInitiator,
    runtime_driven: Mutex<bool>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    runtime_notify: Arc<Notify>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    endpoint_runtime_notify: Arc<Mutex<Option<EndpointRuntimeNotify>>>,
}

impl std::ops::Deref for Connection {
    type Target = ConnectionInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
pub(crate) trait EndpointDriverWakeup: Send + Sync {
    fn wake_driver(&self, driver_id: u64);
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
#[derive(Clone)]
pub(crate) struct EndpointRuntimeNotify {
    notify: Arc<Notify>,
    driver: Option<(Arc<dyn EndpointDriverWakeup>, u64)>,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl std::fmt::Debug for EndpointRuntimeNotify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointRuntimeNotify")
            .field("driver_id", &self.driver.as_ref().map(|(_, id)| id))
            .finish_non_exhaustive()
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl EndpointRuntimeNotify {
    fn endpoint_only(notify: Arc<Notify>) -> Self {
        Self {
            notify,
            driver: None,
        }
    }

    pub(crate) fn notify(&self) {
        if let Some((wakeup, driver_id)) = &self.driver {
            wakeup.wake_driver(*driver_id);
        }
        self.notify.notify_one();
    }
}

#[derive(Debug, Clone)]
struct PeerConnectionId {
    connection_id: quion_proto::cid::ConnectionId,
    reset_token: [u8; 16],
}

#[derive(Debug, Clone, Copy, Default)]
struct PathCounters {
    packets_sent: u64,
    bytes_sent: u64,
    packets_received: u64,
    bytes_received: u64,
    smoothed_rtt: Option<Duration>,
    congestion_window: Option<u64>,
    ecn_disabled: bool,
    amplification_limited: bool,
}

#[derive(Debug)]
struct ConnectionPathState {
    active_remote: SocketAddr,
    active: PathCounters,
    candidate: Option<(SocketAddr, PathCounters)>,
    previous: VecDeque<(SocketAddr, PathCounters)>,
    responses: std::collections::BTreeMap<[u8; 8], SocketAddr>,
    peer_address_changes: u64,
}

impl ConnectionPathState {
    fn new(active_remote: SocketAddr) -> Self {
        Self {
            active_remote,
            active: PathCounters::default(),
            candidate: None,
            previous: VecDeque::new(),
            responses: std::collections::BTreeMap::new(),
            peer_address_changes: 0,
        }
    }
}

#[derive(Debug, Default)]
struct PeerStreamLimits {
    bidi: u64,
    uni: u64,
}

impl Connection {
    pub(crate) fn is_same_connection(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.proto, &other.proto)
    }

    #[cfg(test)]
    pub(crate) fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self::new_with_transport(local, remote, ProtoTransportConfig::default())
    }

    #[cfg(test)]
    pub(crate) fn server(local: SocketAddr, remote: SocketAddr) -> Self {
        Self::server_with_transport(local, remote, ProtoTransportConfig::default())
    }

    #[allow(dead_code)]
    pub(crate) fn new_with_transport(
        local: SocketAddr,
        remote: SocketAddr,
        transport_config: ProtoTransportConfig,
    ) -> Self {
        Self::with_initiator(
            local,
            remote,
            StreamInitiator::Client,
            transport_config,
            None,
            DEFAULT_MAX_BUFFERED_QLOG_EVENTS,
        )
    }

    pub(crate) fn new_with_qlog(
        local: SocketAddr,
        remote: SocketAddr,
        transport_config: ProtoTransportConfig,
        qlog_handler: Option<crate::QlogHandler>,
        max_buffered_qlog_events: usize,
    ) -> Self {
        Self::with_initiator(
            local,
            remote,
            StreamInitiator::Client,
            transport_config,
            qlog_handler,
            max_buffered_qlog_events,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn server_with_transport(
        local: SocketAddr,
        remote: SocketAddr,
        transport_config: ProtoTransportConfig,
    ) -> Self {
        Self::with_initiator(
            local,
            remote,
            StreamInitiator::Server,
            transport_config,
            None,
            DEFAULT_MAX_BUFFERED_QLOG_EVENTS,
        )
    }

    pub(crate) fn server_with_qlog(
        local: SocketAddr,
        remote: SocketAddr,
        transport_config: ProtoTransportConfig,
        qlog_handler: Option<crate::QlogHandler>,
        max_buffered_qlog_events: usize,
    ) -> Self {
        Self::with_initiator(
            local,
            remote,
            StreamInitiator::Server,
            transport_config,
            qlog_handler,
            max_buffered_qlog_events,
        )
    }

    pub(crate) fn install_server_proto(&self, mut proto: quion_proto::connection::Connection) {
        self.configure_proto_for_runtime(&mut proto);
        *self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = proto;
    }

    pub(crate) fn finish_client_handshake(&self, reservation: EndpointMemoryReservation) -> bool {
        let payload_bytes = self.with_proto(|proto| proto.memory_stats().payload_bytes());
        if !self
            .protocol_memory
            .reconcile_with_reservation(reservation, payload_bytes)
        {
            return false;
        }
        true
    }

    pub(crate) fn with_proto<R>(
        &self,
        operation: impl FnOnce(&quion_proto::connection::Connection) -> R,
    ) -> R {
        let proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        operation(&proto)
    }

    pub(crate) fn with_proto_mut<R>(
        &self,
        operation: impl FnOnce(&mut quion_proto::connection::Connection) -> R,
    ) -> R {
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        operation(&mut proto)
    }

    pub(crate) fn reset_proto_for_handshake(&self) {
        self.with_proto_mut(|proto| {
            *proto = quion_proto::connection::Connection::new();
            self.configure_proto_for_runtime(proto);
        });
    }

    fn configure_proto_for_runtime(&self, proto: &mut quion_proto::connection::Connection) {
        Self::configure_proto_for_transport(
            proto,
            self.local_initiator,
            &self.local_transport_config,
        );
    }

    pub(crate) fn configure_proto_for_transport(
        proto: &mut quion_proto::connection::Connection,
        local_initiator: StreamInitiator,
        transport_config: &ProtoTransportConfig,
    ) {
        proto.set_congestion_algorithm(transport_config.congestion_algorithm);
        proto.configure_mtu_discovery(
            transport_config.initial_mtu,
            transport_config.mtu_discovery.clone(),
        );
        Self::configure_inbound_stream_limits(proto, local_initiator, transport_config);
        proto.set_max_stream_metadata_entries(transport_config.max_stream_metadata_entries);
        proto.set_max_send_buffered_stream_data(transport_config.max_send_buffered_stream_data);
        proto.set_max_recv_buffered_stream_data(transport_config.max_recv_buffered_stream_data);
        proto.set_max_recv_buffered_stream_data_per_connection(
            transport_config.max_recv_buffered_stream_data_per_connection,
        );
        proto.configure_receive_flow_control(
            transport_config.initial_max_data.into_inner(),
            transport_config
                .initial_max_stream_data_bidi_local
                .into_inner(),
            transport_config
                .initial_max_stream_data_bidi_remote
                .into_inner(),
            transport_config.initial_max_stream_data_uni.into_inner(),
        );
        proto.set_receive_datagram_frame_size(transport_config.max_datagram_frame_size);
        proto.set_datagram_queue_limits(
            transport_config.max_queued_datagrams,
            transport_config.max_queued_datagram_bytes,
        );
        proto.set_max_queued_control_frames(transport_config.max_queued_control_frames);
        proto.set_max_ack_ranges_per_space(transport_config.max_ack_ranges_per_space);
        proto.set_max_crypto_buffered_data(transport_config.max_crypto_buffered_data);
        proto.set_local_ack_delay_config(
            Duration::from_millis(25),
            3,
            transport_config
                .min_ack_delay
                .map(|value| Duration::from_micros(value.into_inner())),
        );
        proto.set_ack_frequency_config(transport_config.ack_frequency_config.clone());
    }

    fn with_initiator(
        local: SocketAddr,
        remote: SocketAddr,
        local_initiator: StreamInitiator,
        transport_config: ProtoTransportConfig,
        qlog_handler: Option<crate::QlogHandler>,
        max_buffered_qlog_events: usize,
    ) -> Self {
        let has_qlog_handler = qlog_handler.is_some();
        let qlog =
            SharedQlogState::with_max_buffered_events(qlog_handler, max_buffered_qlog_events);
        let mut proto = quion_proto::connection::Connection::new();
        proto.set_max_buffered_qlog_events(if has_qlog_handler {
            max_buffered_qlog_events.max(4096)
        } else {
            max_buffered_qlog_events
        });
        proto.set_congestion_algorithm(transport_config.congestion_algorithm);
        proto.configure_mtu_discovery(
            transport_config.initial_mtu,
            transport_config.mtu_discovery.clone(),
        );
        Self::configure_inbound_stream_limits(&mut proto, local_initiator, &transport_config);
        proto.set_max_stream_metadata_entries(transport_config.max_stream_metadata_entries);
        proto.set_max_send_buffered_stream_data(transport_config.max_send_buffered_stream_data);
        proto.set_max_recv_buffered_stream_data(transport_config.max_recv_buffered_stream_data);
        proto.set_max_recv_buffered_stream_data_per_connection(
            transport_config.max_recv_buffered_stream_data_per_connection,
        );
        proto.configure_receive_flow_control(
            transport_config.initial_max_data.into_inner(),
            transport_config
                .initial_max_stream_data_bidi_local
                .into_inner(),
            transport_config
                .initial_max_stream_data_bidi_remote
                .into_inner(),
            transport_config.initial_max_stream_data_uni.into_inner(),
        );
        proto.set_receive_datagram_frame_size(transport_config.max_datagram_frame_size);
        proto.set_datagram_queue_limits(
            transport_config.max_queued_datagrams,
            transport_config.max_queued_datagram_bytes,
        );
        proto.set_max_queued_control_frames(transport_config.max_queued_control_frames);
        proto.set_max_ack_ranges_per_space(transport_config.max_ack_ranges_per_space);
        proto.set_max_crypto_buffered_data(transport_config.max_crypto_buffered_data);
        proto.set_local_ack_delay_config(
            Duration::from_millis(25),
            3,
            transport_config
                .min_ack_delay
                .map(|value| Duration::from_micros(value.into_inner())),
        );
        proto.set_ack_frequency_config(transport_config.ack_frequency_config.clone());
        proto.set_reset_stream_at_enabled(false);
        Self {
            inner: Arc::new(ConnectionInner {
                local,
                remote,
                path_state: Mutex::new(ConnectionPathState::new(remote)),
                created_at: web_time::Instant::now(),
                proto: Arc::new(Mutex::new(proto)),
                local_transport_config: transport_config,
                peer_transport_parameters: Mutex::new(None),
                initial_peer_stateless_reset_token: Mutex::new(None),
                peer_stateless_reset_token: Mutex::new(None),
                initial_peer_connection_id: Mutex::new(None),
                peer_connection_ids: Mutex::new(BTreeMap::new()),
                active_peer_connection_id: Mutex::new(None),
                peer_connection_id_update_pending: AtomicBool::new(false),
                largest_peer_retire_prior_to: Mutex::new(0),
                local_connection_ids: Mutex::new(BTreeMap::new()),
                retired_local_connection_ids_by_sequence: Mutex::new(BTreeMap::new()),
                retired_local_connection_ids: Mutex::new(VecDeque::new()),
                retired_local_connection_id_pending: AtomicBool::new(false),
                peer_certificates: Mutex::new(None),
                alpn_protocol: Mutex::new(None),
                negotiated_transport: Arc::new(Mutex::new(None)),
                established: Mutex::new(false),
                #[cfg(feature = "zero-rtt")]
                zero_rtt_status: Mutex::new(ZeroRttStatus::NotAttempted),
                closed_state: Arc::new(Mutex::new(ClosedState::default())),
                timeout_state: Mutex::new(TimeoutState::default()),
                protocol_memory: Arc::new(ProtocolMemoryTracker::default()),
                connection_id_memory: ProtocolMemoryTracker::default(),
                connection_id_memory_update: Mutex::new(()),
                routed_datagrams: Mutex::new(VecDeque::new()),
                datagram_state: Arc::new(Mutex::new(DatagramState::default())),
                qlog,
                stream_wakers: Arc::new(Mutex::new(StreamWakers::default())),
                stream_write_state: Arc::new(Mutex::new(StreamWriteState::default())),
                stream_stop_state: Arc::new(Mutex::new(StreamStopState::default())),
                stream_reset_state: Arc::new(Mutex::new(StreamResetState::default())),
                accept_wakers: Arc::new(Mutex::new(AcceptWakers::default())),
                next_bidi_stream: Mutex::new(match local_initiator {
                    StreamInitiator::Client => 0,
                    StreamInitiator::Server => 1,
                }),
                next_uni_stream: Mutex::new(match local_initiator {
                    StreamInitiator::Client => 2,
                    StreamInitiator::Server => 3,
                }),
                peer_stream_limits: Mutex::new(PeerStreamLimits::default()),
                open_stream_wakers: Mutex::new(OpenStreamWakers::default()),
                local_initiator,
                runtime_driven: Mutex::new(false),
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                runtime_notify: Arc::new(Notify::new()),
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                endpoint_runtime_notify: Arc::new(Mutex::new(None)),
            }),
        }
    }

    pub(crate) fn attach_endpoint_memory_budget(&self, budget: Arc<EndpointMemoryBudget>) -> bool {
        let payload_bytes = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .memory_stats()
            .payload_bytes();
        if !self.protocol_memory.attach(budget.clone(), payload_bytes) {
            return false;
        }
        if !self
            .connection_id_memory
            .attach(budget.clone(), self.connection_id_memory_bytes())
        {
            return false;
        }
        self.qlog.attach_endpoint_memory_budget(budget);
        true
    }

    pub(crate) fn reserve_endpoint_memory_budget(
        &self,
        budget: Arc<EndpointMemoryBudget>,
        payload_bytes: usize,
    ) -> bool {
        if !self.protocol_memory.attach(budget.clone(), payload_bytes) {
            return false;
        }
        if !self
            .connection_id_memory
            .attach(budget.clone(), self.connection_id_memory_bytes())
        {
            return false;
        }
        self.qlog.attach_endpoint_memory_budget(budget);
        true
    }

    pub(crate) fn adopt_endpoint_memory_reservation(
        &self,
        reservation: EndpointMemoryReservation,
        payload_bytes: usize,
    ) -> bool {
        let budget = reservation.budget.clone();
        if !self
            .protocol_memory
            .attach_reservation(reservation, payload_bytes)
        {
            return false;
        }
        if !self
            .connection_id_memory
            .attach(budget.clone(), self.connection_id_memory_bytes())
        {
            return false;
        }
        self.qlog.attach_endpoint_memory_budget(budget);
        true
    }

    /// Waits for peer credit and opens a unidirectional stream.
    pub fn open_uni(&self) -> OpenUni {
        let _span = trace_span!(
            "quion.connection",
            action = "open_uni",
            local = %self.local,
            remote = %self.remote
        )
        .entered();
        OpenUni {
            connection: self.clone(),
        }
    }

    /// Waits for peer credit and opens a bidirectional stream.
    pub fn open_bi(&self) -> OpenBi {
        let _span = trace_span!(
            "quion.connection",
            action = "open_bi",
            local = %self.local,
            remote = %self.remote
        )
        .entered();
        OpenBi {
            connection: self.clone(),
        }
    }

    /// Waits for the next peer-initiated unidirectional stream.
    pub fn accept_uni(&self) -> AcceptUni {
        AcceptUni {
            proto: self.proto.clone(),
            accept_wakers: self.accept_wakers.clone(),
            closed_state: self.closed_state.clone(),
            qlog: self.qlog.clone(),
            stream_wakers: self.stream_wakers.clone(),
            stream_reset_state: self.stream_reset_state.clone(),
            protocol_memory: self.protocol_memory.clone(),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            runtime_notify: self.runtime_notify.clone(),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            endpoint_runtime_notify: self.endpoint_runtime_notify.clone(),
        }
    }

    /// Waits for the next peer-initiated bidirectional stream.
    pub fn accept_bi(&self) -> AcceptBi {
        AcceptBi {
            proto: self.proto.clone(),
            accept_wakers: self.accept_wakers.clone(),
            closed_state: self.closed_state.clone(),
            qlog: self.qlog.clone(),
            stream_wakers: self.stream_wakers.clone(),
            stream_write_state: self.stream_write_state.clone(),
            stream_stop_state: self.stream_stop_state.clone(),
            stream_reset_state: self.stream_reset_state.clone(),
            negotiated_transport: self.negotiated_transport.clone(),
            protocol_memory: self.protocol_memory.clone(),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            runtime_notify: self.runtime_notify.clone(),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            endpoint_runtime_notify: self.endpoint_runtime_notify.clone(),
        }
    }

    /// Conservative limit for a sendable DATAGRAM payload, accounting for the peer's
    /// frame limit and path MTU. Returns `None` until support is negotiated.
    /// The value can shrink after path changes; queued datagrams may be dropped.
    pub fn max_datagram_size(&self) -> Option<usize> {
        let peer = self
            .negotiated_transport()?
            .max_datagram_frame_size?
            .into_inner();
        if peer < 2 {
            return None;
        }
        let mtu = self
            .proto
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .current_mtu() as usize;
        let overhead = if self.is_established() { 64 } else { 128 };
        let budget = peer.min(mtu.saturating_sub(overhead) as u64) as usize;
        let mut payload = budget.saturating_sub(2);
        while 1 + VarInt::new(payload as u64).ok()?.encoded_len() + payload > budget {
            payload = payload.checked_sub(1)?;
        }
        Some(payload)
    }

    /// Queues an unreliable DATAGRAM payload.
    pub fn send_datagram(&self, data: impl Into<Vec<u8>>) -> Result<(), crate::SendDatagramError> {
        self.send_datagram_bytes(data.into().into())
    }

    /// Queues an unreliable DATAGRAM payload backed by shared immutable
    /// storage.
    ///
    /// Cloning [`bytes::Bytes`] is constant-time, allowing applications to
    /// reuse one payload allocation across many DATAGRAM sends.
    pub fn send_datagram_bytes(&self, data: bytes::Bytes) -> Result<(), crate::SendDatagramError> {
        let _span = trace_span!(
            "quion.connection",
            action = "send_datagram",
            local = %self.local,
            remote = %self.remote
        )
        .entered();
        if let Some(error) = self.closed_error() {
            return Err(crate::SendDatagramError::ConnectionLost(error));
        }
        trace!(len = data.len(), "queueing datagram");
        let maximum = self
            .max_datagram_size()
            .ok_or(crate::SendDatagramError::Unsupported)?;
        if data.len() > maximum {
            return Err(crate::SendDatagramError::TooLarge {
                maximum: maximum as u64,
            });
        }
        let data_len = data.len();
        let Some(memory_growth) = self.protocol_memory.try_reserve_growth(data_len) else {
            return Err(crate::SendDatagramError::EndpointMemoryLimitReached);
        };
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proto
            .send_datagram_bytes(data)
            .map(|_| ())
            .map_err(|error| match error {
                quion_proto::error::CodecError::BufferLimitExceeded
                | quion_proto::error::CodecError::Transport(
                    quion_proto::transport_error::TransportErrorCode::FlowControlError,
                ) => crate::SendDatagramError::Blocked,
                other => crate::SendDatagramError::ConnectionLost(ConnectionError::TransportError(
                    other.transport_code(),
                )),
            })?;
        if !memory_growth.commit(proto.memory_stats().payload_bytes()) {
            return Err(crate::SendDatagramError::EndpointMemoryLimitReached);
        }
        drop(proto);
        self.pump_qlog_events();
        self.notify_runtime_activity();
        Ok(())
    }

    /// Waits for the next received DATAGRAM payload.
    pub fn read_datagram(&self) -> ReadDatagram {
        ReadDatagram {
            proto: self.proto.clone(),
            datagram_state: self.datagram_state.clone(),
            closed_state: self.closed_state.clone(),
            protocol_memory: self.protocol_memory.clone(),
        }
    }

    /// Waits for the next received DATAGRAM payload without copying its
    /// immutable storage.
    pub fn read_datagram_bytes(&self) -> ReadDatagramBytes {
        ReadDatagramBytes {
            proto: self.proto.clone(),
            datagram_state: self.datagram_state.clone(),
            closed_state: self.closed_state.clone(),
            protocol_memory: self.protocol_memory.clone(),
        }
    }

    /// Starts an application close with the supplied code and reason.
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let _span = trace_span!(
            "quion.connection",
            action = "close",
            local = %self.local,
            remote = %self.remote,
            error_code = error_code.into_inner()
        )
        .entered();
        debug!(
            reason_len = reason.len(),
            "closing connection with application error"
        );
        let memory_growth = self.protocol_memory.try_reserve_growth(reason.len());
        let retained_reason = if memory_growth.is_some() { reason } else { &[] };
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = proto.close_application(error_code, retained_reason);
        if let Some(memory_growth) = memory_growth {
            let _ = memory_growth.commit(proto.memory_stats().payload_bytes());
        } else {
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
        }
        let close_drain_duration = proto.close_drain_duration();
        drop(proto);
        self.arm_shutdown_deadline(close_drain_duration);
        self.pump_qlog_events();
        self.set_closed(ConnectionError::LocallyClosed);
    }

    /// Starts a transport close for protocol-layer integrations.
    pub fn close_transport(
        &self,
        error_code: TransportErrorCode,
        frame_type: VarInt,
        reason: &[u8],
    ) -> Result<(), ConnectionError> {
        let _span = trace_span!(
            "quion.connection",
            action = "close_transport",
            local = %self.local,
            remote = %self.remote,
            frame_type = frame_type.into_inner()
        )
        .entered();
        debug!(
            reason_len = reason.len(),
            ?error_code,
            "closing connection with transport error"
        );
        let Some(memory_growth) = self.protocol_memory.try_reserve_growth(
            reason
                .len()
                .saturating_add(TRANSPORT_CLOSE_METADATA_RESERVATION_BYTES),
        ) else {
            self.abort_with_error(ConnectionError::TransportError(error_code));
            return Ok(());
        };
        let effects = {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let close_drain_duration = proto.close_drain_duration();
            let effects = proto
                .close_transport(error_code, frame_type, reason)
                .map_err(map_proto_error)?;
            if !memory_growth.commit(proto.memory_stats().payload_bytes()) {
                drop(proto);
                self.abort_with_error(ConnectionError::TransportError(error_code));
                return Ok(());
            }
            (effects, close_drain_duration)
        };
        self.arm_shutdown_deadline(effects.1);
        self.set_closed(ConnectionError::TransportError(error_code));
        self.handle_effects(&effects.0);
        self.pump_qlog_events();
        Ok(())
    }

    fn abort_with_error(&self, error: ConnectionError) {
        let (effects, payload_bytes) = {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let effects = proto.abort();
            (effects, proto.memory_stats().payload_bytes())
        };
        let _ = self.protocol_memory.reconcile(payload_bytes);
        self.set_closed(error);
        self.handle_effects(&effects);
        self.pump_qlog_events();
    }

    pub(crate) fn abort_with_runtime_error(&self, error: ConnectionError) {
        self.abort_with_error(error);
        self.routed_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.timeout_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .shutdown_deadline = None;
    }

    /// Immediately aborts local protocol processing and wakes all waiters.
    pub fn abort(&self) {
        let _span = trace_span!(
            "quion.connection",
            action = "abort",
            local = %self.local,
            remote = %self.remote
        )
        .entered();
        {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _effects = proto.abort();
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
        }
        self.routed_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.timeout_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .shutdown_deadline = None;
        self.pump_qlog_events();
        self.set_closed(ConnectionError::LocallyClosed);
    }

    /// Returns a future that resolves with the terminal connection reason.
    pub fn closed(&self) -> Closed {
        Closed {
            closed_state: self.closed_state.clone(),
        }
    }

    /// Returns whether the connection has entered a terminal state.
    pub fn is_closed(&self) -> bool {
        self.closed_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .error
            .is_some()
    }

    pub(crate) fn runtime_shutdown_ready(&self) -> bool {
        if !self.is_closed() {
            return false;
        }
        let now = web_time::Instant::now();
        if self.shutdown_deadline_reached(now) {
            return true;
        }
        if self.shutdown_deadline().is_some() {
            return false;
        }
        if self
            .routed_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .front()
            .is_some()
        {
            return false;
        }
        let proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !proto.has_pending_transmit() && proto.timeout().is_none()
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[allow(dead_code)]
    pub(crate) fn runtime_has_pending_work(&self) -> bool {
        if !self
            .routed_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
        {
            return true;
        }
        self.proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .has_pending_transmit()
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub(crate) fn runtime_has_immediate_work(&self) -> bool {
        if !self
            .routed_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
        {
            return true;
        }
        self.proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .has_immediate_transmit()
    }

    /// Returns aggregate connection counters.
    pub fn stats(&self) -> ConnectionStats {
        let mut stats = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stats()
            .clone();
        stats.migrations = self
            .path_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .peer_address_changes;
        stats
    }

    /// Returns congestion and recovery counters.
    pub fn congestion_stats(&self) -> crate::CongestionStats {
        crate::CongestionStats::from(&self.stats())
    }

    /// Returns stable snapshots for active, candidate, and previous paths.
    pub fn path_stats(&self) -> Vec<crate::PathStats> {
        let stats = self.stats();
        self.path_diagnostics(&stats).0
    }

    /// Returns a stable diagnostics snapshot without draining events or
    /// exposing protocol-internal state.
    pub fn diagnostics(&self) -> ConnectionDiagnostics {
        self.pump_qlog_events();
        let (
            stats,
            flow_control,
            recv_stream_bytes_buffered,
            send_stream_bytes_buffered,
            send_datagrams_queued,
            send_datagram_bytes,
            recv_datagrams_queued,
            recv_datagram_bytes,
            protocol_memory,
        ) = {
            let proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                proto.stats().clone(),
                proto.flow_control_stats(),
                proto.recv_buffered_stream_data(),
                proto.send_buffered_stream_data(),
                proto.queued_send_datagrams(),
                proto.queued_send_datagram_bytes(),
                proto.queued_recv_datagrams(),
                proto.queued_recv_datagram_bytes(),
                proto.memory_stats(),
            )
        };
        let (routed_datagrams_queued, routed_datagram_bytes) = {
            let datagrams = self
                .routed_datagrams
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                datagrams.len(),
                datagrams
                    .iter()
                    .map(|datagram| datagram.contents.len())
                    .sum(),
            )
        };
        let (paths, peer_address_changes) = self.path_diagnostics(&stats);
        let connection_id_bytes = self.connection_id_memory_bytes();
        let qlog_events_buffered = self.qlog.buffered_len();
        let qlog_bytes = self.qlog.buffered_bytes();
        let mut stats = stats;
        stats.migrations = peer_address_changes;
        ConnectionDiagnostics {
            stats,
            flow_control,
            paths,
            peer_address_changes,
            is_established: *self
                .established
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            is_closed: self.is_closed(),
            routed_datagrams_queued,
            routed_datagram_bytes,
            recv_stream_bytes_buffered,
            send_stream_bytes_buffered,
            send_datagrams_queued,
            send_datagram_bytes,
            recv_datagrams_queued,
            recv_datagram_bytes,
            qlog_events_buffered,
            memory: crate::ConnectionMemoryDiagnostics {
                protocol: protocol_memory,
                routed_datagram_bytes,
                connection_id_bytes,
                qlog_events: qlog_events_buffered,
                qlog_bytes,
            },
        }
    }

    fn path_diagnostics(&self, stats: &ConnectionStats) -> (Vec<PathDiagnostics>, u64) {
        let state = self
            .path_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut paths = state
            .previous
            .iter()
            .map(|(remote, counters)| PathDiagnostics {
                local_address: self.local,
                remote_address: *remote,
                validation: PathValidationStatus::Validated,
                packets_sent: counters.packets_sent,
                bytes_sent: counters.bytes_sent,
                packets_received: counters.packets_received,
                bytes_received: counters.bytes_received,
                smoothed_rtt: counters.smoothed_rtt,
                congestion_window: counters.congestion_window,
                current_mtu: None,
                ecn_disabled: counters.ecn_disabled,
                amplification_limited: counters.amplification_limited,
            })
            .collect::<Vec<_>>();
        paths.push(PathDiagnostics {
            local_address: self.local,
            remote_address: state.active_remote,
            validation: PathValidationStatus::Validated,
            packets_sent: state.active.packets_sent,
            bytes_sent: state.active.bytes_sent,
            packets_received: state.active.packets_received,
            bytes_received: state.active.bytes_received,
            smoothed_rtt: stats.smoothed_rtt,
            congestion_window: Some(stats.congestion_window),
            current_mtu: Some(stats.current_mtu),
            ecn_disabled: stats.ecn_disabled,
            amplification_limited: false,
        });
        if let Some((remote, counters)) = state.candidate {
            paths.push(PathDiagnostics {
                local_address: self.local,
                remote_address: remote,
                validation: PathValidationStatus::Validating,
                packets_sent: counters.packets_sent,
                bytes_sent: counters.bytes_sent,
                packets_received: counters.packets_received,
                bytes_received: counters.bytes_received,
                smoothed_rtt: counters.smoothed_rtt,
                congestion_window: counters.congestion_window,
                current_mtu: None,
                ecn_disabled: counters.ecn_disabled,
                amplification_limited: counters.amplification_limited,
            });
        }
        (paths, state.peer_address_changes)
    }

    /// Returns flow-control diagnostics for one QUIC stream.
    pub fn stream_flow_control(&self, stream_id: VarInt) -> crate::StreamFlowControlStats {
        self.proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stream_flow_control_stats(StreamId(stream_id))
    }

    /// Returns stable flow-control counters for one stream.
    pub fn stream_stats(&self, stream_id: StreamId) -> crate::StreamStats {
        self.stream_flow_control(stream_id.0)
    }

    /// Drains structured qlog events retained by this connection.
    pub fn drain_qlog_events(&self) -> Vec<quion_proto::qlog::QlogEvent> {
        self.pump_qlog_events();
        self.qlog.drain()
    }

    /// Returns the peer leaf certificate in DER form when the peer presented
    /// a certificate chain during the TLS handshake.
    pub fn peer_identity(&self) -> Option<Vec<u8>> {
        self.peer_certificates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(|certs| certs.first().cloned())
    }

    /// Returns the full peer certificate chain in DER form when the peer
    /// authenticated with certificates.
    pub fn peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
        self.peer_certificates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Returns the negotiated ALPN protocol bytes, if any.
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.alpn_protocol
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Returns the active peer UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.path_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_remote
    }

    /// Returns the local UDP address.
    pub fn local_address(&self) -> SocketAddr {
        self.local
    }

    fn candidate_remote_address(&self) -> Option<SocketAddr> {
        self.path_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .candidate
            .map(|(remote, _)| remote)
    }

    fn transmit_destination(&self, path_probe: bool) -> SocketAddr {
        if path_probe {
            self.candidate_remote_address()
                .unwrap_or_else(|| self.remote_address())
        } else {
            self.remote_address()
        }
    }

    fn transmit_path_destination(&self, probe: bool, response: Option<[u8; 8]>) -> SocketAddr {
        if let Some(token) = response {
            let mut path = self.path_state.lock().unwrap_or_else(|p| p.into_inner());
            return path.responses.remove(&token).unwrap_or(path.active_remote);
        }
        self.transmit_destination(probe)
    }

    pub(crate) fn record_path_sent_batch(&self, remote: SocketAddr, packets: u64, bytes: usize) {
        let mut state = self
            .path_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let counters = if state.active_remote == remote {
            Some(&mut state.active)
        } else {
            state
                .candidate
                .as_mut()
                .filter(|(candidate, _)| *candidate == remote)
                .map(|(_, counters)| counters)
        };
        if let Some(counters) = counters {
            counters.packets_sent = counters.packets_sent.saturating_add(packets);
            counters.bytes_sent = counters.bytes_sent.saturating_add(bytes as u64);
        }
    }

    /// Returns whether TLS and QUIC handshake processing completed.
    pub fn is_established(&self) -> bool {
        *self
            .established
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns the current 0-RTT attempt outcome.
    #[cfg(feature = "zero-rtt")]
    pub fn zero_rtt_status(&self) -> ZeroRttStatus {
        *self
            .zero_rtt_status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(feature = "zero-rtt")]
    pub(crate) fn set_zero_rtt_status(&self, status: ZeroRttStatus) {
        *self
            .zero_rtt_status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = status;
    }

    /// Returns the validated peer transport parameters, when available.
    pub fn peer_transport_parameters(&self) -> Option<TransportParameters> {
        self.peer_transport_parameters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Returns the applied negotiated transport snapshot.
    pub fn negotiated_transport(&self) -> Option<NegotiatedTransport> {
        *self
            .negotiated_transport
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set_peer_stream_limits(&self, transport: NegotiatedTransport) {
        let mut limits = self
            .peer_stream_limits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limits.bidi = transport
            .initial_max_streams_bidi
            .unwrap_or(VarInt::ZERO)
            .into_inner();
        limits.uni = transport
            .initial_max_streams_uni
            .unwrap_or(VarInt::ZERO)
            .into_inner();
    }

    fn increase_peer_stream_limit(&self, kind: StreamKind, maximum: VarInt) {
        let mut limits = self
            .peer_stream_limits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let limit = match kind {
            StreamKind::Bi => &mut limits.bidi,
            StreamKind::Uni => &mut limits.uni,
        };
        let previous = *limit;
        *limit = (*limit).max(maximum.into_inner());
        let increased = *limit > previous;
        drop(limits);
        if increased {
            self.open_stream_wakers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .wake(kind);
        }
    }

    fn peer_stream_limit(&self, kind: StreamKind) -> u64 {
        let limits = self
            .peer_stream_limits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match kind {
            StreamKind::Bi => limits.bidi,
            StreamKind::Uni => limits.uni,
        }
    }

    pub(crate) fn mark_established(&self, peer_transport_parameters: TransportParameters) {
        let _span = trace_span!(
            "quion.connection",
            action = "mark_established",
            local = %self.local,
            remote = %self.remote
        )
        .entered();
        let negotiated_transport =
            NegotiatedTransport::from_peer_parameters(&peer_transport_parameters)
                .unwrap_or_default();
        {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.reset_idle_send_time();
            Self::configure_inbound_stream_limits(
                &mut proto,
                self.local_initiator,
                &self.local_transport_config,
            );
            proto.set_peer_max_udp_payload_size(peer_max_udp_payload_size(
                negotiated_transport.max_udp_payload_size,
            ));
            proto.configure_stream_scheduler(StreamSchedulerConfig {
                max_frame_data: max_stream_frame_data(
                    negotiated_transport.max_udp_payload_size,
                    self.local_transport_config.initial_mtu,
                ),
            });
            proto.configure_outbound_stream_limits(
                negotiated_transport
                    .initial_max_streams_bidi
                    .map_or(0, VarInt::into_inner),
                negotiated_transport
                    .initial_max_streams_uni
                    .map_or(0, VarInt::into_inner),
            );
            self.set_peer_stream_limits(negotiated_transport);
            if let Some(initial_max_data) = negotiated_transport.initial_max_data {
                proto.increase_connection_send_limit(initial_max_data.into_inner());
            }
            if self.local_initiator == StreamInitiator::Server {
                proto.confirm_handshake();
                let _ = proto.send_handshake_done();
            }
            proto.discard_packet_space(quion_proto::crypto::EncryptionLevel::Initial);
            #[cfg(feature = "zero-rtt")]
            let retain_zero_rtt_recovery = self.zero_rtt_status() == ZeroRttStatus::Accepted;
            #[cfg(not(feature = "zero-rtt"))]
            let retain_zero_rtt_recovery = false;
            if !retain_zero_rtt_recovery {
                proto.discard_packet_space(quion_proto::crypto::EncryptionLevel::ZeroRtt);
            }
            if self.local_initiator == StreamInitiator::Server {
                proto.discard_packet_space(quion_proto::crypto::EncryptionLevel::Handshake);
            }
            proto.set_peer_ack_delay_config(
                Duration::from_millis(negotiated_transport.max_ack_delay.into_inner()),
                negotiated_transport
                    .ack_delay_exponent
                    .into_inner()
                    .min(u64::from(u8::MAX)) as u8,
            );
            proto.set_peer_min_ack_delay(
                negotiated_transport
                    .min_ack_delay
                    .map(|value| Duration::from_micros(value.into_inner())),
            );
            proto.set_reset_stream_at_enabled(
                self.local_transport_config.reset_stream_at && negotiated_transport.reset_stream_at,
            );
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
        }
        {
            let mut timeout_state = self
                .timeout_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            timeout_state.idle_timeout =
                idle_timeout_from_transport(&self.local_transport_config, &negotiated_transport);
            timeout_state.last_activity = Some(web_time::Instant::now());
        }
        *self
            .peer_transport_parameters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(peer_transport_parameters.clone());
        let peer_stateless_reset_token =
            stateless_reset_token_from_transport_parameters(&peer_transport_parameters);
        *self
            .initial_peer_stateless_reset_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = peer_stateless_reset_token;
        *self
            .peer_stateless_reset_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = peer_stateless_reset_token;
        *self
            .negotiated_transport
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(negotiated_transport);
        *self
            .established
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.record_handshake_duration(
                web_time::Instant::now().duration_since(self.created_at),
            );
        }
        self.qlog.publish(vec![
            transport_parameters_qlog_event("peer", &peer_transport_parameters),
            quion_proto::qlog::QlogEvent::PathStateUpdated { state: "validated" },
        ]);
        debug!("connection marked established");
        self.pump_qlog_events();
    }

    pub(crate) fn prepare_proto_for_establishment(
        &self,
        proto: &mut quion_proto::connection::Connection,
        peer_transport_parameters: &TransportParameters,
        zero_rtt_accepted: bool,
    ) {
        self.configure_proto_for_runtime(proto);
        let negotiated_transport =
            NegotiatedTransport::from_peer_parameters(peer_transport_parameters)
                .unwrap_or_default();
        Self::configure_inbound_stream_limits(
            proto,
            self.local_initiator,
            &self.local_transport_config,
        );
        proto.set_peer_max_udp_payload_size(peer_max_udp_payload_size(
            negotiated_transport.max_udp_payload_size,
        ));
        proto.configure_stream_scheduler(StreamSchedulerConfig {
            max_frame_data: max_stream_frame_data(
                negotiated_transport.max_udp_payload_size,
                self.local_transport_config.initial_mtu,
            ),
        });
        proto.configure_outbound_stream_limits(
            negotiated_transport
                .initial_max_streams_bidi
                .map_or(0, VarInt::into_inner),
            negotiated_transport
                .initial_max_streams_uni
                .map_or(0, VarInt::into_inner),
        );
        proto.discard_packet_space(quion_proto::crypto::EncryptionLevel::Initial);
        #[cfg(feature = "zero-rtt")]
        let zero_rtt_status = self.zero_rtt_status();
        #[cfg(feature = "zero-rtt")]
        let zero_rtt_rejected = !zero_rtt_accepted
            && matches!(
                zero_rtt_status,
                ZeroRttStatus::Attempted | ZeroRttStatus::Rejected
            );
        #[cfg(not(feature = "zero-rtt"))]
        let zero_rtt_rejected = false;
        if !zero_rtt_accepted {
            #[cfg(feature = "zero-rtt")]
            if zero_rtt_status == ZeroRttStatus::Attempted {
                proto.reject_zero_rtt();
            } else {
                proto.discard_packet_space(quion_proto::crypto::EncryptionLevel::ZeroRtt);
            }
            #[cfg(not(feature = "zero-rtt"))]
            proto.discard_packet_space(quion_proto::crypto::EncryptionLevel::ZeroRtt);
        }
        if zero_rtt_rejected {
            proto.reset_zero_rtt_send_limits(
                negotiated_transport
                    .initial_max_data
                    .map_or(0, VarInt::into_inner),
                negotiated_transport
                    .initial_max_stream_data_bidi_remote
                    .map_or(0, VarInt::into_inner),
                negotiated_transport
                    .initial_max_stream_data_uni
                    .map_or(0, VarInt::into_inner),
                negotiated_transport
                    .initial_max_streams_bidi
                    .map_or(0, VarInt::into_inner),
                negotiated_transport
                    .initial_max_streams_uni
                    .map_or(0, VarInt::into_inner),
            );
        } else if let Some(initial_max_data) = negotiated_transport.initial_max_data {
            proto.increase_connection_send_limit(initial_max_data.into_inner());
        }
        proto.set_peer_ack_delay_config(
            Duration::from_millis(negotiated_transport.max_ack_delay.into_inner()),
            negotiated_transport
                .ack_delay_exponent
                .into_inner()
                .min(u64::from(u8::MAX)) as u8,
        );
        proto.set_peer_min_ack_delay(
            negotiated_transport
                .min_ack_delay
                .map(|value| Duration::from_micros(value.into_inner())),
        );
        proto.set_reset_stream_at_enabled(
            self.local_transport_config.reset_stream_at && negotiated_transport.reset_stream_at,
        );
    }

    #[cfg(feature = "zero-rtt")]
    pub(crate) fn prepare_for_zero_rtt(
        &self,
        cached_peer_transport_parameters: &TransportParameters,
    ) {
        let negotiated_transport =
            NegotiatedTransport::from_peer_parameters(cached_peer_transport_parameters)
                .unwrap_or_default();
        self.with_proto_mut(|proto| {
            proto.set_peer_max_udp_payload_size(peer_max_udp_payload_size(
                negotiated_transport.max_udp_payload_size,
            ));
            proto.configure_stream_scheduler(StreamSchedulerConfig {
                max_frame_data: max_stream_frame_data(
                    negotiated_transport.max_udp_payload_size,
                    self.local_transport_config.initial_mtu,
                ),
            });
            proto.configure_outbound_stream_limits(
                negotiated_transport
                    .initial_max_streams_bidi
                    .map_or(0, VarInt::into_inner),
                negotiated_transport
                    .initial_max_streams_uni
                    .map_or(0, VarInt::into_inner),
            );
            if let Some(initial_max_data) = negotiated_transport.initial_max_data {
                proto.increase_connection_send_limit(initial_max_data.into_inner());
            }
        });
        self.set_peer_stream_limits(negotiated_transport);
        *self
            .negotiated_transport
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(negotiated_transport);
    }

    pub(crate) fn set_peer_security_context(
        &self,
        peer_certificates: Option<Vec<Vec<u8>>>,
        alpn_protocol: Option<Vec<u8>>,
    ) {
        *self
            .peer_certificates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = peer_certificates;
        *self
            .alpn_protocol
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = alpn_protocol;
    }

    fn connection_id_memory_bytes(&self) -> usize {
        let _update = self
            .connection_id_memory_update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.connection_id_memory_bytes_unlocked()
    }

    fn connection_id_memory_bytes_unlocked(&self) -> usize {
        let initial_peer_bytes = self
            .initial_peer_connection_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map_or(0, |connection_id| {
                std::mem::size_of::<quion_proto::cid::ConnectionId>()
                    .saturating_add(connection_id.len())
            });
        let peer_bytes = self
            .peer_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|entry| {
                std::mem::size_of::<u64>()
                    .saturating_add(std::mem::size_of::<PeerConnectionId>())
                    .saturating_add(entry.connection_id.len())
                    .saturating_add(BTREE_ENTRY_BOOKKEEPING_BYTES)
            })
            .fold(0usize, usize::saturating_add);
        let local_bytes = self
            .local_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|connection_id| {
                std::mem::size_of::<u64>()
                    .saturating_add(std::mem::size_of::<quion_proto::cid::ConnectionId>())
                    .saturating_add(connection_id.len())
                    .saturating_add(BTREE_ENTRY_BOOKKEEPING_BYTES)
            })
            .fold(0usize, usize::saturating_add);
        let retired_sequence_bytes = self
            .retired_local_connection_ids_by_sequence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|connection_id| {
                std::mem::size_of::<u64>()
                    .saturating_add(std::mem::size_of::<quion_proto::cid::ConnectionId>())
                    .saturating_add(connection_id.len())
                    .saturating_add(BTREE_ENTRY_BOOKKEEPING_BYTES)
            })
            .fold(0usize, usize::saturating_add);
        let retired_id_bytes = self
            .retired_local_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|connection_id| {
                std::mem::size_of::<quion_proto::cid::ConnectionId>()
                    .saturating_add(connection_id.len())
            })
            .fold(0usize, usize::saturating_add);
        initial_peer_bytes
            .saturating_add(peer_bytes)
            .saturating_add(local_bytes)
            .saturating_add(retired_sequence_bytes)
            .saturating_add(retired_id_bytes)
    }

    pub(crate) fn register_local_connection_id(
        &self,
        sequence: u64,
        connection_id: quion_proto::cid::ConnectionId,
    ) -> bool {
        let connection_id_length = connection_id.len();
        let update = self
            .connection_id_memory_update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self
            .local_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&sequence)
        {
            return false;
        }
        let growth_bytes = std::mem::size_of::<u64>()
            .saturating_add(std::mem::size_of::<quion_proto::cid::ConnectionId>())
            .saturating_add(connection_id.len())
            .saturating_add(BTREE_ENTRY_BOOKKEEPING_BYTES);
        let Some(growth) = self.connection_id_memory.try_reserve_growth(growth_bytes) else {
            return false;
        };
        self.local_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(sequence, connection_id);
        let committed = growth.commit(self.connection_id_memory_bytes_unlocked());
        drop(update);
        if !committed {
            self.unregister_local_connection_id(sequence);
            return false;
        }
        let configured = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_local_connection_id_length(connection_id_length);
        if !configured {
            self.unregister_local_connection_id(sequence);
        }
        configured
    }

    fn unregister_local_connection_id(&self, sequence: u64) {
        let _update = self
            .connection_id_memory_update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.local_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&sequence);
        let _ = self
            .connection_id_memory
            .reconcile(self.connection_id_memory_bytes_unlocked());
    }

    pub(crate) fn register_initial_peer_connection_id(
        &self,
        connection_id: quion_proto::cid::ConnectionId,
    ) -> bool {
        let connection_id_length = connection_id.len();
        let update = self
            .connection_id_memory_update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut initial = self
            .initial_peer_connection_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if initial.is_some() {
            return initial.as_ref() == Some(&connection_id);
        }
        let growth_bytes = std::mem::size_of::<quion_proto::cid::ConnectionId>()
            .saturating_add(connection_id.len());
        let Some(growth) = self.connection_id_memory.try_reserve_growth(growth_bytes) else {
            return false;
        };
        *initial = Some(connection_id);
        drop(initial);
        let committed = growth.commit(self.connection_id_memory_bytes_unlocked());
        drop(update);
        if !committed {
            *self
                .initial_peer_connection_id
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            let _update = self
                .connection_id_memory_update
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = self
                .connection_id_memory
                .reconcile(self.connection_id_memory_bytes_unlocked());
            return false;
        }
        let configured = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_peer_connection_id_length(connection_id_length);
        if !configured {
            *self
                .initial_peer_connection_id
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            let _update = self
                .connection_id_memory_update
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = self
                .connection_id_memory
                .reconcile(self.connection_id_memory_bytes_unlocked());
        }
        configured
    }

    pub(crate) fn advertise_local_connection_id(
        &self,
        sequence: u64,
        retire_prior_to: u64,
        connection_id: quion_proto::cid::ConnectionId,
        reset_token: [u8; 16],
    ) -> Result<(), ConnectionError> {
        let sequence = VarInt::new(sequence)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let retire_prior_to = VarInt::new(retire_prior_to)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        if !self.register_local_connection_id(sequence.into_inner(), connection_id.clone()) {
            return Err(ConnectionError::EndpointMemoryLimitReached);
        }
        let result = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .queue_new_connection_id(
                sequence,
                retire_prior_to,
                connection_id.as_bytes().to_vec(),
                reset_token,
            )
            .map_err(map_proto_error);
        if let Err(error) = result {
            self.unregister_local_connection_id(sequence.into_inner());
            return Err(error);
        }
        self.pump_qlog_events();
        self.notify_runtime_activity();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_peer_stateless_reset_token(&self, token: Option<[u8; 16]>) {
        *self
            .initial_peer_stateless_reset_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = token;
        *self
            .peer_stateless_reset_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = token;
    }

    pub(crate) fn mark_runtime_driven(&self) {
        *self
            .runtime_driven
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.notify_runtime_activity();
    }

    #[cfg(test)]
    pub(crate) fn is_runtime_driven(&self) -> bool {
        *self
            .runtime_driven
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn enqueue_routed_datagram(&self, meta: quion_udp::RecvMeta, contents: Vec<u8>) {
        self.enqueue_routed_datagram_inner(RoutedDatagram::new(meta, contents), None);
    }

    pub(crate) fn enqueue_recycled_routed_datagram_with_budget(
        &self,
        meta: quion_udp::RecvMeta,
        contents: &[u8],
        budget: Arc<RoutedDatagramMemoryBudget>,
        recycled: Option<RoutedDatagram>,
    ) -> bool {
        let Some(datagram) =
            RoutedDatagram::copy_with_budget_or_reuse(meta, contents, &budget, recycled)
        else {
            return false;
        };
        self.enqueue_routed_datagram_inner(datagram, None)
    }

    pub(crate) fn enqueue_owned_routed_datagram_with_budget(
        &self,
        meta: quion_udp::RecvMeta,
        contents: Vec<u8>,
        budget: Arc<RoutedDatagramMemoryBudget>,
    ) -> bool {
        let Some(datagram) = RoutedDatagram::with_budget(meta, contents, &budget) else {
            return false;
        };
        self.enqueue_routed_datagram_inner(datagram, None)
    }

    pub(crate) fn enqueue_existing_routed_datagram(&self, datagram: RoutedDatagram) {
        self.enqueue_routed_datagram_inner(datagram, None);
    }

    fn enqueue_routed_datagram_inner(
        &self,
        mut datagram: RoutedDatagram,
        budget: Option<Arc<RoutedDatagramMemoryBudget>>,
    ) -> bool {
        let active_remote = self.remote_address();
        if self.local_initiator == StreamInitiator::Client && datagram.meta.remote != active_remote
        {
            return false;
        }
        if datagram.meta.remote != active_remote
            && self
                .candidate_remote_address()
                .is_some_and(|candidate| candidate != datagram.meta.remote)
        {
            return false;
        }
        let contents_len = datagram.contents.len();
        let mut datagrams = self
            .routed_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut queued_bytes = datagrams
            .iter()
            .map(|datagram| datagram.contents.len())
            .sum::<usize>();
        while datagrams.len() >= MAX_ROUTED_DATAGRAM_QUEUE_LEN
            || queued_bytes.saturating_add(contents_len) > MAX_ROUTED_DATAGRAM_QUEUE_BYTES
        {
            let Some(dropped) = datagrams.pop_front() else {
                break;
            };
            queued_bytes = queued_bytes.saturating_sub(dropped.contents.len());
        }
        let reservation = if let Some(budget) = budget {
            let mut reservation = budget.try_reserve(contents_len);
            while reservation.is_none() {
                let Some(dropped) = datagrams.pop_front() else {
                    return false;
                };
                queued_bytes = queued_bytes.saturating_sub(dropped.contents.len());
                drop(dropped);
                reservation = budget.try_reserve(contents_len);
            }
            reservation
        } else {
            None
        };
        datagram._memory_reservation = reservation.or_else(|| datagram._memory_reservation.take());
        datagrams.push_back(datagram);
        drop(datagrams);
        self.notify_runtime_activity();
        true
    }

    pub(crate) fn pop_routed_datagram(&self) -> Option<RoutedDatagram> {
        let mut datagrams = self
            .routed_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        datagrams.pop_front()
    }

    #[allow(dead_code)]
    pub(crate) fn routed_datagram_len(&self) -> usize {
        let datagrams = self
            .routed_datagrams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        datagrams.len()
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    /// Builds the next protected 1-RTT UDP transmit for a custom driver.
    pub fn poll_protected_one_rtt_udp_transmit(
        &self,
        builder: &mut quion_proto::crypto::packet::FramePacketBuilder,
        keys: &quion_proto::crypto::rustls::RustlsKeyStore,
    ) -> Result<Option<quion_udp::Transmit>, ConnectionError> {
        Ok(self
            .poll_protected_one_rtt_udp_transmit_with_metadata(builder, keys)?
            .map(|(transmit, _contains_ack, _path_probe)| transmit))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn poll_protected_one_rtt_udp_transmit_with_metadata(
        &self,
        builder: &mut quion_proto::crypto::packet::FramePacketBuilder,
        keys: &quion_proto::crypto::rustls::RustlsKeyStore,
    ) -> Result<Option<(quion_udp::Transmit, bool, bool)>, ConnectionError> {
        let _span = trace_span!(
            "quion.connection",
            action = "poll_protected_one_rtt_udp_transmit",
            local = %self.local,
            remote = %self.remote
        )
        .entered();
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(transmit) = proto
            .poll_protected_one_rtt_transmit(builder, keys, web_time::Instant::now())
            .map_err(map_proto_error)?
        else {
            return Ok(None);
        };
        trace!(
            bytes = transmit.contents.len(),
            "prepared protected transmit"
        );
        proto.record_packet_protection(
            "protected",
            quion_proto::crypto::EncryptionLevel::OneRtt,
            keys.current_one_rtt_key_phase(),
            transmit.contents.len(),
        );
        self.protocol_memory
            .reconcile(proto.memory_stats().payload_bytes());
        let contains_ack = transmit.contains_ack;
        let path_probe = transmit.path_probe;
        let destination = self.transmit_path_destination(path_probe, transmit.path_response);
        Ok(Some((
            quion_udp::Transmit {
                destination,
                source: Some(self.local),
                ecn: transmit.ecn.map(proto_to_udp_ecn),
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                send_at: transmit.send_at,
            },
            contains_ack,
            path_probe,
        )))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn poll_protected_one_rtt_udp_transmit_batch_with_metadata(
        &self,
        builder: &mut quion_proto::crypto::packet::FramePacketBuilder,
        keys: &quion_proto::crypto::rustls::RustlsKeyStore,
        max_transmits: usize,
        proto_output: &mut Vec<quion_proto::connection::Transmit>,
        output: &mut Vec<(quion_udp::Transmit, bool)>,
    ) -> Result<(), ConnectionError> {
        let _span = trace_span!(
            "quion.connection",
            action = "poll_protected_one_rtt_udp_transmit_batch",
            local = %self.local,
            remote = %self.remote,
            max_transmits
        )
        .entered();
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proto
            .poll_protected_one_rtt_transmit_batch_into(
                builder,
                keys,
                web_time::Instant::now(),
                max_transmits,
                proto_output,
            )
            .map_err(map_proto_error)?;
        for transmit in proto_output.iter() {
            proto.record_packet_protection(
                "protected",
                quion_proto::crypto::EncryptionLevel::OneRtt,
                keys.current_one_rtt_key_phase(),
                transmit.contents.len(),
            );
        }
        self.protocol_memory
            .reconcile(proto.memory_stats().payload_bytes());
        drop(proto);

        let mut path = self
            .path_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let active_destination = path.active_remote;
        let candidate_destination = path.candidate.map(|(remote, _)| remote);
        output.clear();
        output.reserve(proto_output.len());
        output.extend(proto_output.drain(..).map(|transmit| {
            let destination = if let Some(token) = transmit.path_response {
                path.responses.remove(&token).unwrap_or(active_destination)
            } else if transmit.path_probe {
                candidate_destination.unwrap_or(active_destination)
            } else {
                active_destination
            };
            (
                quion_udp::Transmit {
                    destination,
                    source: Some(self.local),
                    ecn: transmit.ecn.map(proto_to_udp_ecn),
                    contents: transmit.contents,
                    segment_size: transmit.segment_size,
                    send_at: transmit.send_at,
                },
                transmit.contains_ack,
            )
        }));
        Ok(())
    }

    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub(crate) fn poll_protected_zero_rtt_udp_transmit(
        &self,
        builder: &mut quion_proto::crypto::packet::CryptoPacketBuilder,
        keys: &quion_proto::crypto::rustls::RustlsKeyStore,
    ) -> Result<Option<quion_udp::Transmit>, ConnectionError> {
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(transmit) = proto
            .poll_protected_zero_rtt_transmit(builder, keys, web_time::Instant::now())
            .map_err(map_proto_error)?
        else {
            return Ok(None);
        };
        proto.record_packet_protection(
            "protected",
            quion_proto::crypto::EncryptionLevel::ZeroRtt,
            None,
            transmit.contents.len(),
        );
        self.protocol_memory
            .reconcile(proto.memory_stats().payload_bytes());
        Ok(Some(quion_udp::Transmit {
            destination: self.remote_address(),
            source: Some(self.local),
            ecn: transmit.ecn.map(proto_to_udp_ecn),
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            send_at: transmit.send_at,
        }))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    /// Opens and dispatches a protected 1-RTT packet for a custom driver.
    pub fn recv_protected_one_rtt_udp(
        &self,
        keys: &mut quion_proto::crypto::rustls::RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
        meta: &quion_udp::RecvMeta,
    ) -> Result<(), ConnectionError> {
        self.recv_protected_one_rtt_udp_with_key_update_permission(
            keys,
            packet,
            expected_dst_cid_len,
            largest_received,
            true,
            meta,
        )
        .map(|_| ())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn recv_protected_one_rtt_udp_with_key_update_permission(
        &self,
        keys: &mut quion_proto::crypto::rustls::RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
        key_update_permitted: bool,
        meta: &quion_udp::RecvMeta,
    ) -> Result<Option<OneRttReceiveState>, ConnectionError> {
        self.recv_protected_one_rtt_udp_inner(
            None,
            keys,
            packet,
            expected_dst_cid_len,
            quion_proto::connection::OneRttReceiveContext {
                largest_received,
                key_update_permitted,
            },
            meta,
        )
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn recv_protected_one_rtt_udp_with_session(
        &self,
        session: &mut quion_proto::crypto::rustls::RustlsSession,
        keys: &mut quion_proto::crypto::rustls::RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        receive_context: quion_proto::connection::OneRttReceiveContext,
        meta: &quion_udp::RecvMeta,
    ) -> Result<Option<OneRttReceiveState>, ConnectionError> {
        self.recv_protected_one_rtt_udp_inner(
            Some(session),
            keys,
            packet,
            expected_dst_cid_len,
            receive_context,
            meta,
        )
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn recv_protected_one_rtt_udp_inner(
        &self,
        session: Option<&mut quion_proto::crypto::rustls::RustlsSession>,
        keys: &mut quion_proto::crypto::rustls::RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        receive_context: quion_proto::connection::OneRttReceiveContext,
        meta: &quion_udp::RecvMeta,
    ) -> Result<Option<OneRttReceiveState>, ConnectionError> {
        let _span = trace_span!(
            "quion.connection",
            action = "recv_protected_one_rtt_udp",
            local = %self.local,
            remote = %self.remote,
            packet_len = packet.len()
        )
        .entered();
        if self.should_ignore_incoming() {
            return Ok(None);
        }
        let Some(memory_growth) = self.protocol_memory.try_reserve_growth(packet.len()) else {
            return Ok(None);
        };
        if self.local_initiator == StreamInitiator::Client && meta.remote != self.remote_address() {
            return Ok(None);
        }
        let integrity_failures_before = keys.one_rtt_integrity_failures();
        let (effects, receive_state) = {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let receive_meta = quion_proto::connection::RecvMeta {
                ecn: meta.ecn.map(udp_to_proto_ecn),
            };
            let effects = if let Some(session) = session {
                proto.recv_protected_one_rtt_with_session(
                    session,
                    keys,
                    packet,
                    expected_dst_cid_len,
                    receive_context,
                    receive_meta,
                )
            } else {
                proto.recv_protected_one_rtt_with_key_update_permission(
                    keys,
                    packet,
                    expected_dst_cid_len,
                    receive_context,
                    receive_meta,
                    web_time::Instant::now(),
                )
            };
            let receive_state = if effects.is_ok() {
                if !memory_growth.commit(proto.memory_stats().payload_bytes()) {
                    return Ok(None);
                }
                proto.record_packet_protection(
                    "opened",
                    quion_proto::crypto::EncryptionLevel::OneRtt,
                    keys.current_one_rtt_key_phase(),
                    packet.len(),
                );
                Some(OneRttReceiveState {
                    largest_received: proto
                        .ack_tracker()
                        .largest_received(quion_proto::crypto::EncryptionLevel::OneRtt),
                    largest_acked: proto
                        .largest_acked_packet_number(quion_proto::crypto::EncryptionLevel::OneRtt),
                    key_retirement_duration: proto.one_rtt_key_retirement_duration(),
                })
            } else {
                None
            };
            (effects, receive_state)
        };
        let effects = match effects {
            Ok(effects) => effects,
            Err(_error) if self.matches_stateless_reset(packet) => {
                self.ensure_closed(ConnectionError::Reset);
                return Ok(None);
            }
            Err(quion_proto::CodecError::PacketDiscard) => return Ok(None),
            Err(quion_proto::CodecError::Transport(TransportErrorCode::KeyUpdateError)) => {
                self.close_transport(
                    TransportErrorCode::KeyUpdateError,
                    VarInt::ZERO,
                    b"invalid peer key phase transition",
                )?;
                return Ok(None);
            }
            Err(error) => {
                // A packet that failed AEAD removal is silently dropped rather
                // than closing the connection (RFC 9001 §5.2). The connection is
                // only torn down once the cipher's integrity limit is reached.
                if keys.one_rtt_integrity_failures() > integrity_failures_before {
                    if keys
                        .one_rtt_integrity_limit()
                        .is_some_and(|limit| keys.one_rtt_integrity_failures() >= limit)
                    {
                        self.close_transport(
                            TransportErrorCode::AeadLimitReached,
                            VarInt::ZERO,
                            b"peer exceeded the AEAD integrity limit",
                        )?;
                        return Ok(None);
                    }
                    return Ok(None);
                }
                if matches!(error, quion_proto::CodecError::Crypto(_)) {
                    return Err(map_proto_error(error));
                }
                self.close_for_authenticated_one_rtt_error(error)?;
                return Ok(None);
            }
        };
        let now = web_time::Instant::now();
        self.note_authenticated_path(meta.remote, meta.len, &effects, now);
        self.record_activity(now);
        self.handle_effects(&effects);
        // ACKs can release congestion credit and every authenticated packet
        // can create ACK or control work. Endpoint-owned drivers must be
        // requeued immediately instead of waiting for PTO or an idle fallback.
        self.notify_runtime_activity();
        Ok(receive_state)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn recv_protected_one_rtt_udp_owned<O>(
        &self,
        session: Option<&mut quion_proto::crypto::rustls::RustlsSession>,
        keys: &mut quion_proto::crypto::rustls::RustlsKeyStore,
        packet: O,
        expected_dst_cid_len: usize,
        receive_context: quion_proto::connection::OneRttReceiveContext,
        meta: &quion_udp::RecvMeta,
    ) -> Result<Option<OneRttReceiveState>, ConnectionError>
    where
        O: AsRef<[u8]> + AsMut<[u8]> + Send + 'static,
    {
        let packet_len = packet.as_ref().len();
        let stateless_reset_candidate = stateless_reset_candidate(packet.as_ref());
        if self.should_ignore_incoming() {
            return Ok(None);
        }
        let Some(memory_growth) = self.protocol_memory.try_reserve_growth(packet_len) else {
            return Ok(None);
        };
        if self.local_initiator == StreamInitiator::Client && meta.remote != self.remote_address() {
            return Ok(None);
        }
        let integrity_failures_before = keys.one_rtt_integrity_failures();
        let (effects, receive_state) = {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let receive_meta = quion_proto::connection::RecvMeta {
                ecn: meta.ecn.map(udp_to_proto_ecn),
            };
            let effects = if let Some(session) = session {
                proto.recv_protected_one_rtt_owned_with_session(
                    session,
                    keys,
                    packet,
                    expected_dst_cid_len,
                    receive_context,
                    receive_meta,
                )
            } else {
                proto.recv_protected_one_rtt_owned_with_key_update_permission(
                    keys,
                    packet,
                    expected_dst_cid_len,
                    receive_context,
                    receive_meta,
                    web_time::Instant::now(),
                )
            };
            let receive_state = if effects.is_ok() {
                if !memory_growth.commit(proto.memory_stats().payload_bytes()) {
                    return Ok(None);
                }
                proto.record_packet_protection(
                    "opened",
                    quion_proto::crypto::EncryptionLevel::OneRtt,
                    keys.current_one_rtt_key_phase(),
                    packet_len,
                );
                Some(OneRttReceiveState {
                    largest_received: proto
                        .ack_tracker()
                        .largest_received(quion_proto::crypto::EncryptionLevel::OneRtt),
                    largest_acked: proto
                        .largest_acked_packet_number(quion_proto::crypto::EncryptionLevel::OneRtt),
                    key_retirement_duration: proto.one_rtt_key_retirement_duration(),
                })
            } else {
                None
            };
            (effects, receive_state)
        };
        let effects = match effects {
            Ok(effects) => effects,
            Err(_error)
                if stateless_reset_candidate
                    .as_ref()
                    .is_some_and(|candidate| self.matches_stateless_reset_candidate(candidate)) =>
            {
                self.ensure_closed(ConnectionError::Reset);
                return Ok(None);
            }
            Err(quion_proto::CodecError::PacketDiscard) => return Ok(None),
            Err(quion_proto::CodecError::Transport(TransportErrorCode::KeyUpdateError)) => {
                self.close_transport(
                    TransportErrorCode::KeyUpdateError,
                    VarInt::ZERO,
                    b"invalid peer key phase transition",
                )?;
                return Ok(None);
            }
            Err(error) => {
                if keys.one_rtt_integrity_failures() > integrity_failures_before {
                    if keys
                        .one_rtt_integrity_limit()
                        .is_some_and(|limit| keys.one_rtt_integrity_failures() >= limit)
                    {
                        self.close_transport(
                            TransportErrorCode::AeadLimitReached,
                            VarInt::ZERO,
                            b"peer exceeded the AEAD integrity limit",
                        )?;
                    }
                    return Ok(None);
                }
                if matches!(error, quion_proto::CodecError::Crypto(_)) {
                    return Err(map_proto_error(error));
                }
                self.close_for_authenticated_one_rtt_error(error)?;
                return Ok(None);
            }
        };
        let now = web_time::Instant::now();
        self.note_authenticated_path(meta.remote, meta.len, &effects, now);
        self.record_activity(now);
        self.handle_effects(&effects);
        self.notify_runtime_activity();
        Ok(receive_state)
    }

    fn note_authenticated_path(
        &self,
        remote: SocketAddr,
        bytes: usize,
        effects: &Effects,
        now: web_time::Instant,
    ) {
        let _span = trace_span!(
            "quion.path.authenticated",
            remote = %remote,
            bytes,
            validated = tracing::field::Empty
        )
        .entered();
        let validated = effects
            .connection_events
            .contains(&ConnectionEvent::PathValidated);
        tracing::Span::current().record("validated", validated);
        {
            let mut state = self
                .path_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for event in &effects.connection_events {
                if let ConnectionEvent::FrameReceived(quion_proto::frame::Frame::PathChallenge(
                    token,
                )) = event
                    && state.responses.len() < self.local_transport_config.max_queued_control_frames
                {
                    state.responses.insert(*token, remote);
                }
            }
            if remote == state.active_remote {
                state.active.packets_received = state.active.packets_received.saturating_add(1);
                state.active.bytes_received =
                    state.active.bytes_received.saturating_add(bytes as u64);
                if !validated {
                    return;
                }
            }
        }
        let mut start_validation = false;
        let mut promoted = false;
        let stats = self.stats();
        {
            let mut state = self
                .path_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if remote != state.active_remote {
                match state.candidate.as_mut() {
                    Some((candidate, counters)) if *candidate == remote => {
                        counters.packets_received = counters.packets_received.saturating_add(1);
                        counters.bytes_received =
                            counters.bytes_received.saturating_add(bytes as u64);
                    }
                    Some(_) => return,
                    None => {
                        state.peer_address_changes = state.peer_address_changes.saturating_add(1);
                        state.candidate = Some((
                            remote,
                            PathCounters {
                                packets_received: 1,
                                bytes_received: bytes as u64,
                                congestion_window: Some(12_000),
                                amplification_limited: true,
                                ..PathCounters::default()
                            },
                        ));
                        start_validation = true;
                    }
                }
            }
            if validated && let Some((candidate, counters)) = state.candidate.take() {
                state.active.smoothed_rtt = stats.smoothed_rtt;
                state.active.congestion_window = Some(stats.congestion_window);
                state.active.ecn_disabled = stats.ecn_disabled;
                let previous = (state.active_remote, state.active);
                state.previous.push_back(previous);
                while state.previous.len() > 4 {
                    state.previous.pop_front();
                }
                state.active_remote = candidate;
                state.active = counters;
                state.active.amplification_limited = false;
                promoted = true;
            }
        }
        if start_validation {
            let challenge = rand::random();
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.record_path_state("candidate_created");
            let _effects = proto.start_path_validation(challenge, now);
            drop(proto);
            self.notify_runtime_activity();
        }
        if promoted {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.record_path_state("candidate_promoted");
            proto.reset_path_recovery();
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn close_for_authenticated_one_rtt_error(
        &self,
        error: quion_proto::CodecError,
    ) -> Result<(), ConnectionError> {
        tracing::warn!(
            ?error,
            local = %self.local,
            remote = %self.remote,
            "closing after authenticated 1-RTT packet violation"
        );
        self.close_transport(
            error.transport_code(),
            VarInt::ZERO,
            b"authenticated 1-RTT packet violation",
        )
    }

    pub(crate) fn matches_stateless_reset(&self, packet: &[u8]) -> bool {
        let Some(candidate) = stateless_reset_candidate(packet) else {
            return false;
        };
        self.matches_stateless_reset_candidate(&candidate)
    }

    fn matches_stateless_reset_candidate(&self, candidate: &[u8; 16]) -> bool {
        if self
            .peer_stateless_reset_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(|token| candidate == token)
        {
            return true;
        }
        let initial_is_active = *self
            .largest_peer_retire_prior_to
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            == 0;
        if initial_is_active
            && self
                .initial_peer_stateless_reset_token
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .is_some_and(|token| candidate == token)
        {
            return true;
        }
        self.peer_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .any(|entry| *candidate == entry.reset_token)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn next_timeout(&self) -> Option<web_time::Instant> {
        let proto_timeout = {
            let proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.timeout()
        };
        let idle_timeout = self.idle_deadline();
        let shutdown_deadline = self.shutdown_deadline();
        earlier_deadline(
            earlier_deadline(
                earlier_deadline(proto_timeout, idle_timeout),
                self.keep_alive_deadline(),
            ),
            shutdown_deadline,
        )
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn on_timeout(&self, now: web_time::Instant) -> Result<bool, ConnectionError> {
        let _span = trace_span!(
            "quion.connection",
            action = "on_timeout",
            local = %self.local,
            remote = %self.remote
        )
        .entered();
        if self.shutdown_deadline_reached(now) {
            return Ok(true);
        }
        if self.idle_deadline().is_some_and(|deadline| now >= deadline) {
            debug!("connection idle timeout fired");
            self.set_closed(ConnectionError::TimedOut);
            return Ok(true);
        }
        let keep_alive_due = self
            .keep_alive_deadline()
            .is_some_and(|deadline| now >= deadline);
        if keep_alive_due {
            self.proto
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .queue_keep_alive()
                .map_err(map_proto_error)?;
            self.timeout_state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .last_keep_alive = Some(now);
        }
        let effects = {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let memory = proto.memory_stats();
            let maximum_retransmit_growth = memory
                .sent_crypto_bytes
                .saturating_add(memory.sent_stream_bytes)
                .saturating_add(memory.sent_control_bytes);
            let memory_growth = self
                .protocol_memory
                .try_reserve_growth(maximum_retransmit_growth)
                .ok_or(ConnectionError::EndpointMemoryLimitReached)?;
            let effects = proto.on_timeout(now).map_err(map_proto_error)?;
            if !memory_growth.commit(proto.memory_stats().payload_bytes()) {
                return Err(ConnectionError::EndpointMemoryLimitReached);
            }
            effects
        };
        let made_progress = keep_alive_due
            || !effects.connection_events.is_empty()
            || !effects.crypto_frames.is_empty()
            || !effects.ack_frames.is_empty();
        trace!(made_progress, "processed timeout tick");
        self.handle_effects(&effects);
        Ok(made_progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[allow(dead_code)]
    pub(crate) async fn wait_for_runtime_activity(&self, wakeup: Option<web_time::Instant>) {
        let notified = self.runtime_notify.notified();
        if let Some(wakeup) = wakeup {
            let now = web_time::Instant::now();
            if wakeup <= now {
                return;
            }
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(wakeup.duration_since(now)) => {}
            }
            return;
        }
        notified.await;
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub(crate) fn set_endpoint_runtime_notify(&self, notify: Arc<Notify>) {
        *self
            .endpoint_runtime_notify
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(EndpointRuntimeNotify::endpoint_only(notify));
        self.notify_runtime_activity();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub(crate) fn set_endpoint_runtime_driver_notify(
        &self,
        notify: Arc<Notify>,
        wakeup: Arc<dyn EndpointDriverWakeup>,
        driver_id: u64,
    ) {
        *self
            .endpoint_runtime_notify
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(EndpointRuntimeNotify {
            notify,
            driver: Some((wakeup, driver_id)),
        });
        self.notify_runtime_activity();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub(crate) fn endpoint_runtime_driver_id(&self) -> Option<u64> {
        self.endpoint_runtime_notify
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(|notify| notify.driver.as_ref().map(|(_, driver_id)| *driver_id))
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn record_test_sent_packet(
        &self,
        level: quion_proto::crypto::EncryptionLevel,
        packet_number: u64,
        bytes: u64,
        ack_eliciting: bool,
        now: web_time::Instant,
    ) {
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proto.record_sent_packet(level, packet_number, bytes, ack_eliciting, now);
    }

    #[cfg(test)]
    pub(crate) fn set_test_peer_stateless_reset_token(&self, token: [u8; 16]) {
        self.set_peer_stateless_reset_token(Some(token));
    }

    pub(crate) fn active_peer_connection_id(&self) -> Option<quion_proto::cid::ConnectionId> {
        let active_sequence = *self
            .active_peer_connection_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let peer_connection_ids = self
            .peer_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        active_sequence.and_then(|sequence| {
            peer_connection_ids
                .get(&sequence)
                .map(|entry| entry.connection_id.clone())
        })
    }

    pub(crate) fn take_active_peer_connection_id_update(
        &self,
    ) -> Option<quion_proto::cid::ConnectionId> {
        if !self
            .peer_connection_id_update_pending
            .swap(false, Ordering::AcqRel)
        {
            return None;
        }
        self.active_peer_connection_id()
    }

    pub(crate) fn drain_retired_local_connection_ids(&self) -> Vec<quion_proto::cid::ConnectionId> {
        if !self
            .retired_local_connection_id_pending
            .swap(false, Ordering::AcqRel)
        {
            return Vec::new();
        }
        let _update = self
            .connection_id_memory_update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let retired = self
            .retired_local_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
            .collect();
        let _ = self
            .connection_id_memory
            .reconcile(self.connection_id_memory_bytes_unlocked());
        retired
    }

    fn open_outgoing_stream(&self, kind: StreamKind) -> Result<StreamId, ConnectionError> {
        let negotiated_transport = self.negotiated_transport();
        let slot = match kind {
            StreamKind::Uni => &self.next_uni_stream,
            StreamKind::Bi => &self.next_bidi_stream,
        };
        let stream_id = self.next_stream_id(slot, kind)?;
        if let Some(max_stream_data) =
            negotiated_transport.and_then(|transport| transport.initial_send_limit(kind))
        {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto
                .register_local_stream(stream_id)
                .map_err(map_proto_error)?;
            proto
                .increase_stream_send_limit(stream_id, max_stream_data.into_inner())
                .map_err(map_proto_error)?;
            proto.record_stream_opened();
        } else {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto
                .register_local_stream(stream_id)
                .map_err(map_proto_error)?;
            proto.record_stream_opened();
        }
        Ok(stream_id)
    }

    fn send_stream_handle(&self, stream_id: StreamId) -> SendStream {
        SendStream::new(
            self.proto.clone(),
            self.closed_state.clone(),
            self.qlog.clone(),
            self.stream_write_state.clone(),
            self.stream_stop_state.clone(),
            self.protocol_memory.clone(),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            self.runtime_notify.clone(),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            self.endpoint_runtime_notify.clone(),
            stream_id,
        )
    }

    fn recv_stream_handle(&self, stream_id: StreamId) -> RecvStream {
        RecvStream::new(
            self.proto.clone(),
            self.closed_state.clone(),
            self.qlog.clone(),
            self.stream_wakers.clone(),
            self.stream_reset_state.clone(),
            self.protocol_memory.clone(),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            self.runtime_notify.clone(),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            self.endpoint_runtime_notify.clone(),
            stream_id,
        )
    }

    fn next_stream_id(
        &self,
        slot: &Mutex<u64>,
        kind: StreamKind,
    ) -> Result<StreamId, ConnectionError> {
        let mut next = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let enforce_peer_limit = self.is_established() || {
            #[cfg(feature = "zero-rtt")]
            {
                self.zero_rtt_status() != ZeroRttStatus::NotAttempted
            }
            #[cfg(not(feature = "zero-rtt"))]
            {
                false
            }
        };
        if enforce_peer_limit {
            let opened = *next / 4;
            let max_streams = self.peer_stream_limit(kind);
            if opened >= max_streams {
                let mut proto = self
                    .proto
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                proto.queue_streams_blocked(proto_stream_limit_kind(kind), max_streams);
                drop(proto);
                self.notify_runtime_activity();
                return Err(match kind {
                    StreamKind::Bi => ConnectionError::BidirectionalStreamLimitReached,
                    StreamKind::Uni => ConnectionError::UnidirectionalStreamLimitReached,
                });
            }
        }
        let stream_id = StreamId(VarInt::new(*next).unwrap_or(VarInt::MAX));
        *next = next.saturating_add(4);
        Ok(stream_id)
    }

    #[allow(dead_code)]
    pub(crate) fn wake_accept_streams(&self, stream_id: StreamId) {
        let mut wakers = self
            .accept_wakers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        wakers.wake(stream_id);
    }

    pub(crate) fn handle_effects(&self, effects: &Effects) {
        let saw_close_frame = effects.connection_events.iter().any(|event| {
            matches!(
                event,
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::ApplicationClose { .. })
                    | ConnectionEvent::FrameReceived(
                        quion_proto::frame::Frame::ConnectionClose { .. }
                    )
            )
        });
        for event in &effects.connection_events {
            match event {
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::ApplicationClose {
                    error_code,
                    reason,
                }) => {
                    self.arm_shutdown_deadline_from_proto();
                    self.set_closed(ConnectionError::ApplicationClosed {
                        code: *error_code,
                        reason: String::from_utf8_lossy(reason).into_owned(),
                    });
                }
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::ConnectionClose {
                    error_code,
                    ..
                }) => {
                    self.arm_shutdown_deadline_from_proto();
                    self.set_closed(ConnectionError::TransportError(*error_code));
                }
                ConnectionEvent::DatagramReceived { .. } => self.wake_datagram_reader(),
                ConnectionEvent::Closed => {
                    if !saw_close_frame {
                        self.ensure_closed(ConnectionError::Reset);
                    }
                }
                ConnectionEvent::StreamFrameQueued { stream_id, .. } => {
                    self.wake_accept_streams(*stream_id);
                    self.wake_stream_reader(*stream_id);
                }
                ConnectionEvent::StreamStopped {
                    stream_id,
                    error_code,
                } => {
                    self.wake_stream_writer(*stream_id);
                    self.note_stream_stopped(*stream_id, *error_code);
                }
                ConnectionEvent::StreamFinished { stream_id } => {
                    if let Some(waker) = self
                        .stream_stop_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove_waiter(*stream_id)
                    {
                        waker.wake();
                    }
                }
                ConnectionEvent::StreamReset {
                    stream_id,
                    error_code,
                    ..
                } => {
                    self.wake_accept_streams(*stream_id);
                    self.note_stream_reset(*stream_id, *error_code);
                }
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::MaxStreamData {
                    stream_id,
                    ..
                }) => {
                    self.wake_stream_reader(StreamId(*stream_id));
                    self.wake_stream_writer(StreamId(*stream_id));
                }
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::MaxData(_)) => {
                    self.wake_all_stream_writers();
                }
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::MaxStreamsBidi(
                    maximum,
                )) => {
                    self.increase_peer_stream_limit(StreamKind::Bi, *maximum);
                }
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::MaxStreamsUni(
                    maximum,
                )) => {
                    self.increase_peer_stream_limit(StreamKind::Uni, *maximum);
                }
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    connection_id,
                    reset_token,
                }) => {
                    self.note_peer_connection_id(
                        sequence.into_inner(),
                        retire_prior_to.into_inner(),
                        connection_id,
                        *reset_token,
                    );
                }
                ConnectionEvent::FrameReceived(quion_proto::frame::Frame::RetireConnectionId(
                    sequence,
                )) => match self.note_retired_local_connection_id(sequence.into_inner(), None) {
                    LocalConnectionIdRetirement::New | LocalConnectionIdRetirement::Duplicate => {}
                    LocalConnectionIdRetirement::Unknown
                    | LocalConnectionIdRetirement::PacketDestinationConnectionId
                    | LocalConnectionIdRetirement::ZeroLengthConnectionId => {
                        let _ = self.close_transport(
                            TransportErrorCode::ProtocolViolation,
                            VarInt::from_u32(0x19),
                            b"peer sent an invalid RETIRE_CONNECTION_ID",
                        );
                    }
                    LocalConnectionIdRetirement::MemoryLimit => {
                        let _ = self.close_transport(
                            TransportErrorCode::InternalError,
                            VarInt::from_u32(0x19),
                            b"endpoint connection id memory limit reached",
                        );
                    }
                },
                ConnectionEvent::RetireConnectionIdReceived {
                    sequence,
                    packet_destination_cid,
                } => match self.note_retired_local_connection_id(
                    sequence.into_inner(),
                    Some(packet_destination_cid),
                ) {
                    LocalConnectionIdRetirement::New | LocalConnectionIdRetirement::Duplicate => {}
                    LocalConnectionIdRetirement::Unknown
                    | LocalConnectionIdRetirement::PacketDestinationConnectionId
                    | LocalConnectionIdRetirement::ZeroLengthConnectionId => {
                        let _ = self.close_transport(
                            TransportErrorCode::ProtocolViolation,
                            VarInt::from_u32(0x19),
                            b"peer sent an invalid RETIRE_CONNECTION_ID",
                        );
                    }
                    LocalConnectionIdRetirement::MemoryLimit => {
                        let _ = self.close_transport(
                            TransportErrorCode::InternalError,
                            VarInt::from_u32(0x19),
                            b"endpoint connection id memory limit reached",
                        );
                    }
                },
                ConnectionEvent::PathValidationFailed => {
                    self.path_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .candidate = None;
                }
                _ => {}
            }
        }
    }

    pub(crate) fn record_activity(&self, now: web_time::Instant) {
        self.proto
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .reset_idle_send_time();
        let mut timeout_state = self
            .timeout_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        timeout_state.last_activity = Some(now);
    }

    fn idle_deadline(&self) -> Option<web_time::Instant> {
        let proto = self.proto.lock().unwrap_or_else(|p| p.into_inner());
        let floor = proto.idle_timeout_floor();
        let sent = proto.idle_send_time();
        let state = self.timeout_state.lock().unwrap_or_else(|p| p.into_inner());
        let base = state
            .last_activity?
            .max(sent.unwrap_or(state.last_activity?));
        base.checked_add(state.idle_timeout?.max(floor))
    }

    fn keep_alive_deadline(&self) -> Option<web_time::Instant> {
        if !self.is_established() || self.is_closed() {
            return None;
        }
        let mut interval = self.local_transport_config.keep_alive_interval?;
        if interval.is_zero() {
            return None;
        }
        let proto = self.proto.lock().unwrap_or_else(|p| p.into_inner());
        let state = self.timeout_state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(idle) = state.idle_timeout {
            interval = interval.min(idle.max(proto.idle_timeout_floor()) / 2);
        }
        let base = [
            state.last_activity,
            state.last_keep_alive,
            proto.last_ack_eliciting_sent(),
        ]
        .into_iter()
        .flatten()
        .max()?;
        base.checked_add(interval.max(Duration::from_millis(1)))
    }

    fn closed_error(&self) -> Option<ConnectionError> {
        self.closed_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .error
            .clone()
    }

    fn should_ignore_incoming(&self) -> bool {
        self.closed_error().is_some()
    }

    fn arm_shutdown_deadline_from_proto(&self) {
        let duration = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .close_drain_duration();
        self.arm_shutdown_deadline(duration);
    }

    fn arm_shutdown_deadline(&self, duration: Duration) {
        let mut timeout_state = self
            .timeout_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if timeout_state.shutdown_deadline.is_none() {
            timeout_state.shutdown_deadline = Some(web_time::Instant::now() + duration);
        }
    }

    fn shutdown_deadline(&self) -> Option<web_time::Instant> {
        self.timeout_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .shutdown_deadline
    }

    fn shutdown_deadline_reached(&self, now: web_time::Instant) -> bool {
        self.shutdown_deadline()
            .is_some_and(|deadline| now >= deadline)
    }

    fn set_closed(&self, error: ConnectionError) {
        let mut state = self
            .closed_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.error.is_none() {
            state.error = Some(error);
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
            drop(state);
            self.wake_datagram_reader();
            self.wake_all_stream_readers();
            self.wake_all_stream_writers();
            self.wake_all_stream_stopped();
            self.wake_all_stream_reset();
            self.accept_wakers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .wake_all();
            self.open_stream_wakers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .wake_all();
            self.notify_runtime_activity();
        }
    }

    fn ensure_closed(&self, error: ConnectionError) {
        let mut state = self
            .closed_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.error.is_none() {
            state.error = Some(error);
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
            drop(state);
            self.wake_datagram_reader();
            self.wake_all_stream_readers();
            self.wake_all_stream_writers();
            self.wake_all_stream_stopped();
            self.wake_all_stream_reset();
            self.accept_wakers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .wake_all();
            self.open_stream_wakers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .wake_all();
            self.notify_runtime_activity();
        }
    }

    #[cfg(test)]
    pub(crate) fn force_close_for_test(&self, error: ConnectionError) {
        self.set_closed(error);
    }

    #[cfg(test)]
    pub(crate) fn set_shutdown_deadline_for_test(&self, deadline: Option<web_time::Instant>) {
        self.timeout_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .shutdown_deadline = deadline;
    }

    fn notify_runtime_activity(&self) {
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        {
            if let Some(notify) = self
                .endpoint_runtime_notify
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .cloned()
            {
                notify.notify();
            } else {
                self.runtime_notify.notify_one();
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn recv_test_frame_payload(&self, payload: &[u8]) -> Result<(), ConnectionError> {
        if self.should_ignore_incoming() {
            return Ok(());
        }
        let memory_growth = self
            .protocol_memory
            .try_reserve_growth(payload.len())
            .ok_or(ConnectionError::EndpointMemoryLimitReached)?;
        let effects = {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let effects = proto
                .handle_frame_payload(
                    quion_proto::crypto::EncryptionLevel::OneRtt,
                    payload,
                    web_time::Instant::now(),
                )
                .map_err(map_proto_error)?;
            if !memory_growth.commit(proto.memory_stats().payload_bytes()) {
                return Err(ConnectionError::EndpointMemoryLimitReached);
            }
            effects
        };
        self.handle_effects(&effects);
        self.pump_qlog_events();
        Ok(())
    }

    fn pump_qlog_events(&self) {
        let (events, payload_bytes) = {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let events = proto.drain_qlog_events();
            (events, proto.memory_stats().payload_bytes())
        };
        let _ = self.protocol_memory.reconcile(payload_bytes);
        self.qlog.publish(events);
    }

    fn configure_inbound_stream_limits(
        proto: &mut quion_proto::connection::Connection,
        local_initiator: StreamInitiator,
        transport_config: &ProtoTransportConfig,
    ) {
        proto.configure_inbound_stream_limits(
            local_initiator,
            transport_config.initial_max_streams_bidi.into_inner(),
            transport_config.initial_max_streams_uni.into_inner(),
        );
    }

    fn wake_datagram_reader(&self) {
        if let Some(waker) = self
            .datagram_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .read_waker
            .take()
        {
            waker.wake();
        }
    }

    fn wake_stream_reader(&self, stream_id: StreamId) {
        if let Some(waker) = self
            .stream_wakers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .wake_reader(stream_id)
        {
            waker.wake();
        }
    }

    fn wake_all_stream_readers(&self) {
        for waker in self
            .stream_wakers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .wake_all_readers()
        {
            waker.wake();
        }
    }

    fn wake_stream_writer(&self, stream_id: StreamId) {
        if let Some(waker) = self
            .stream_write_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .wake_writer(stream_id)
        {
            waker.wake();
        }
    }

    fn wake_all_stream_writers(&self) {
        for waker in self
            .stream_write_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .wake_all()
        {
            waker.wake();
        }
    }

    fn note_stream_stopped(&self, stream_id: StreamId, error_code: VarInt) {
        if let Some(waker) = self
            .stream_stop_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_stopped(stream_id, error_code)
        {
            waker.wake();
        }
    }

    fn wake_all_stream_stopped(&self) {
        for waker in self
            .stream_stop_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .wake_all()
        {
            waker.wake();
        }
    }

    fn note_stream_reset(&self, stream_id: StreamId, error_code: VarInt) {
        if let Some(waker) = self
            .stream_reset_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_reset(stream_id, error_code)
        {
            waker.wake();
        }
    }

    fn wake_all_stream_reset(&self) {
        for waker in self
            .stream_reset_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .wake_all()
        {
            waker.wake();
        }
    }

    fn note_peer_connection_id(
        &self,
        sequence: u64,
        retire_prior_to: u64,
        connection_id: &[u8],
        reset_token: [u8; 16],
    ) {
        let Ok(connection_id) = quion_proto::cid::ConnectionId::from_slice(connection_id) else {
            return;
        };
        let _memory_update = self
            .connection_id_memory_update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut peer_connection_ids = self
            .peer_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = peer_connection_ids.get(&sequence)
            && (existing.connection_id != connection_id || existing.reset_token != reset_token)
        {
            drop(peer_connection_ids);
            drop(_memory_update);
            let _ = self.close_transport(
                TransportErrorCode::ProtocolViolation,
                VarInt::from_u32(0x18),
                b"conflicting peer connection id sequence",
            );
            return;
        }
        let initial_peer_connection_id = self
            .initial_peer_connection_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if initial_peer_connection_id
            .as_ref()
            .is_some_and(quion_proto::cid::ConnectionId::is_empty)
        {
            drop(peer_connection_ids);
            drop(_memory_update);
            let _ = self.close_transport(
                TransportErrorCode::ProtocolViolation,
                VarInt::from_u32(0x18),
                b"peer issued a connection id after selecting a zero-length connection id",
            );
            return;
        }
        if initial_peer_connection_id.as_ref().is_some_and(|initial| {
            (sequence == 0 && initial != &connection_id)
                || (sequence != 0 && initial == &connection_id)
        }) {
            drop(peer_connection_ids);
            drop(_memory_update);
            let _ = self.close_transport(
                TransportErrorCode::ProtocolViolation,
                VarInt::from_u32(0x18),
                b"peer reused or changed its initial connection id",
            );
            return;
        }
        if peer_connection_ids
            .iter()
            .any(|(registered_sequence, entry)| {
                *registered_sequence != sequence
                    && (entry.connection_id == connection_id || entry.reset_token == reset_token)
            })
        {
            drop(peer_connection_ids);
            drop(_memory_update);
            let _ = self.close_transport(
                TransportErrorCode::ProtocolViolation,
                VarInt::from_u32(0x18),
                b"peer reused a connection id or stateless reset token",
            );
            return;
        }

        let (previous_retire_prior_to, effective_retire_prior_to) = {
            let largest = self
                .largest_peer_retire_prior_to
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = *largest;
            (previous, previous.max(retire_prior_to))
        };
        let retired_entry_bytes = peer_connection_ids
            .range(..effective_retire_prior_to)
            .map(|(_, entry)| {
                std::mem::size_of::<u64>()
                    .saturating_add(std::mem::size_of::<PeerConnectionId>())
                    .saturating_add(entry.connection_id.len())
                    .saturating_add(BTREE_ENTRY_BOOKKEEPING_BYTES)
            })
            .fold(0usize, usize::saturating_add);
        let inserted_entry_bytes = if sequence >= effective_retire_prior_to
            && !peer_connection_ids.contains_key(&sequence)
        {
            std::mem::size_of::<u64>()
                .saturating_add(std::mem::size_of::<PeerConnectionId>())
                .saturating_add(connection_id.len())
                .saturating_add(BTREE_ENTRY_BOOKKEEPING_BYTES)
        } else {
            0
        };
        let Some(memory_growth) = self
            .connection_id_memory
            .try_reserve_growth(inserted_entry_bytes.saturating_sub(retired_entry_bytes))
        else {
            drop(peer_connection_ids);
            drop(_memory_update);
            let _ = self.close_transport(
                TransportErrorCode::InternalError,
                VarInt::from_u32(0x18),
                b"endpoint connection id memory limit reached",
            );
            return;
        };
        *self
            .largest_peer_retire_prior_to
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = effective_retire_prior_to;
        let mut retired_sequences = peer_connection_ids
            .range(..effective_retire_prior_to)
            .map(|(registered_sequence, _)| *registered_sequence)
            .collect::<BTreeSet<_>>();
        if previous_retire_prior_to == 0 && effective_retire_prior_to > 0 {
            retired_sequences.insert(0);
        }
        peer_connection_ids
            .retain(|registered_sequence, _| *registered_sequence >= effective_retire_prior_to);
        if sequence < effective_retire_prior_to {
            retired_sequences.insert(sequence);
        } else {
            peer_connection_ids.insert(
                sequence,
                PeerConnectionId {
                    connection_id,
                    reset_token,
                },
            );
        }
        let active = peer_connection_ids
            .iter()
            .next_back()
            .map(|(registered_sequence, entry)| (*registered_sequence, entry.reset_token));
        // The connection ID carried in the peer's first Initial packet has
        // sequence number zero and counts toward the locally advertised
        // active_connection_id_limit until retire_prior_to advances past it.
        let implicit_initial_is_active =
            effective_retire_prior_to == 0 && !peer_connection_ids.contains_key(&0);
        let active_count = peer_connection_ids
            .len()
            .saturating_add(usize::from(implicit_initial_is_active))
            as u64;
        drop(peer_connection_ids);
        if !memory_growth.commit(self.connection_id_memory_bytes_unlocked()) {
            drop(_memory_update);
            let _ = self.close_transport(
                TransportErrorCode::InternalError,
                VarInt::from_u32(0x18),
                b"endpoint connection id memory accounting failed",
            );
            return;
        }
        drop(_memory_update);

        if !retired_sequences.is_empty() {
            let mut proto = self
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut invalid_retirement = false;
            for retired_sequence in retired_sequences {
                invalid_retirement |= proto
                    .queue_retire_connection_id(
                        VarInt::new(retired_sequence).unwrap_or(VarInt::MAX),
                    )
                    .is_err();
            }
            drop(proto);
            if invalid_retirement {
                let _ = self.close_transport(
                    TransportErrorCode::ProtocolViolation,
                    VarInt::from_u32(0x18),
                    b"peer replaced a zero-length connection id",
                );
                return;
            }
        }

        let active_connection_id_limit = self.local_transport_config.active_connection_id_limit;
        let active_connection_id_limit = active_connection_id_limit.into_inner();
        if active_count > active_connection_id_limit {
            let _ = self.close_transport(
                TransportErrorCode::ConnectionIdLimitError,
                VarInt::from_u32(0x18),
                b"peer advertised too many connection ids",
            );
            return;
        }

        if let Some((active_sequence, active_token)) = active {
            let mut current_active = self
                .active_peer_connection_id
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *current_active != Some(active_sequence) {
                *current_active = Some(active_sequence);
                self.peer_connection_id_update_pending
                    .store(true, Ordering::Release);
            }
            drop(current_active);
            *self
                .peer_stateless_reset_token
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(active_token);
        }
    }

    fn note_retired_local_connection_id(
        &self,
        sequence: u64,
        packet_destination_cid: Option<&quion_proto::cid::ConnectionId>,
    ) -> LocalConnectionIdRetirement {
        let _memory_update = self
            .connection_id_memory_update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut local_connection_ids = self
            .local_connection_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let retired_by_sequence = self
            .retired_local_connection_ids_by_sequence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if local_connection_ids
            .values()
            .chain(retired_by_sequence.values())
            .any(|connection_id| connection_id.is_empty())
        {
            return LocalConnectionIdRetirement::ZeroLengthConnectionId;
        }
        let referenced_connection_id = local_connection_ids
            .get(&sequence)
            .or_else(|| retired_by_sequence.get(&sequence));
        if packet_destination_cid.is_some() && referenced_connection_id == packet_destination_cid {
            return LocalConnectionIdRetirement::PacketDestinationConnectionId;
        }
        if let Some(connection_id) = local_connection_ids.get(&sequence).cloned() {
            let growth_bytes = std::mem::size_of::<u64>()
                .saturating_add(BTREE_ENTRY_BOOKKEEPING_BYTES)
                .saturating_add(std::mem::size_of::<quion_proto::cid::ConnectionId>())
                .saturating_add(connection_id.len());
            let Some(memory_growth) = self.connection_id_memory.try_reserve_growth(growth_bytes)
            else {
                return LocalConnectionIdRetirement::MemoryLimit;
            };
            local_connection_ids.remove(&sequence);
            drop(local_connection_ids);
            drop(retired_by_sequence);
            self.retired_local_connection_ids_by_sequence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(sequence, connection_id.clone());
            self.retired_local_connection_ids
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(connection_id);
            self.retired_local_connection_id_pending
                .store(true, Ordering::Release);
            if memory_growth.commit(self.connection_id_memory_bytes_unlocked()) {
                LocalConnectionIdRetirement::New
            } else {
                LocalConnectionIdRetirement::MemoryLimit
            }
        } else if retired_by_sequence.contains_key(&sequence) {
            LocalConnectionIdRetirement::Duplicate
        } else {
            LocalConnectionIdRetirement::Unknown
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalConnectionIdRetirement {
    New,
    Duplicate,
    Unknown,
    MemoryLimit,
    PacketDestinationConnectionId,
    ZeroLengthConnectionId,
}

fn transport_parameters_qlog_event(
    owner: &'static str,
    params: &TransportParameters,
) -> quion_proto::qlog::QlogEvent {
    quion_proto::qlog::QlogEvent::TransportParametersSet {
        owner,
        initial_max_data: transport_param_value(params, transport_parameter_ids::INITIAL_MAX_DATA),
        initial_max_stream_data_bidi_local: transport_param_value(
            params,
            transport_parameter_ids::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        ),
        initial_max_stream_data_bidi_remote: transport_param_value(
            params,
            transport_parameter_ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        ),
        initial_max_stream_data_uni: transport_param_value(
            params,
            transport_parameter_ids::INITIAL_MAX_STREAM_DATA_UNI,
        ),
        initial_max_streams_bidi: transport_param_value(
            params,
            transport_parameter_ids::INITIAL_MAX_STREAMS_BIDI,
        ),
        initial_max_streams_uni: transport_param_value(
            params,
            transport_parameter_ids::INITIAL_MAX_STREAMS_UNI,
        ),
        max_idle_timeout_ms: transport_param_value(
            params,
            transport_parameter_ids::MAX_IDLE_TIMEOUT,
        ),
        max_datagram_frame_size: transport_param_value(
            params,
            transport_parameter_ids::MAX_DATAGRAM_FRAME_SIZE,
        ),
    }
}

fn transport_param_value(params: &TransportParameters, id: u64) -> Option<u64> {
    params.get_var(id).ok().flatten().map(VarInt::into_inner)
}

/// Peer transport limits and negotiated extensions applied to a connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NegotiatedTransport {
    /// Peer idle timeout in milliseconds.
    pub max_idle_timeout: Option<VarInt>,
    /// Peer maximum UDP payload size.
    pub max_udp_payload_size: Option<VarInt>,
    /// Peer connection-level send credit.
    pub initial_max_data: Option<VarInt>,
    /// Send credit for peer-local bidirectional streams.
    pub initial_max_stream_data_bidi_local: Option<VarInt>,
    /// Send credit for locally initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: Option<VarInt>,
    /// Send credit for locally initiated unidirectional streams.
    pub initial_max_stream_data_uni: Option<VarInt>,
    /// Initial outgoing bidirectional stream count.
    pub initial_max_streams_bidi: Option<VarInt>,
    /// Initial outgoing unidirectional stream count.
    pub initial_max_streams_uni: Option<VarInt>,
    /// Peer ACK delay exponent.
    pub ack_delay_exponent: VarInt,
    /// Peer maximum ACK delay in milliseconds.
    pub max_ack_delay: VarInt,
    /// Peer minimum ACK delay in microseconds, when ACK_FREQUENCY is
    /// supported.
    pub min_ack_delay: Option<VarInt>,
    /// Peer active connection ID limit.
    pub active_connection_id_limit: VarInt,
    /// Whether the peer disabled active migration.
    pub disable_active_migration: bool,
    /// Negotiated DATAGRAM frame size.
    pub max_datagram_frame_size: Option<VarInt>,
    /// Whether RESET_STREAM_AT was negotiated.
    pub reset_stream_at: bool,
}

impl NegotiatedTransport {
    fn from_peer_parameters(params: &TransportParameters) -> quion_proto::Result<Self> {
        Ok(Self {
            max_idle_timeout: params.get_var(transport_parameter_ids::MAX_IDLE_TIMEOUT)?,
            max_udp_payload_size: params.get_var(transport_parameter_ids::MAX_UDP_PAYLOAD_SIZE)?,
            initial_max_data: params.get_var(transport_parameter_ids::INITIAL_MAX_DATA)?,
            initial_max_stream_data_bidi_local: params
                .get_var(transport_parameter_ids::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL)?,
            initial_max_stream_data_bidi_remote: params
                .get_var(transport_parameter_ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)?,
            initial_max_stream_data_uni: params
                .get_var(transport_parameter_ids::INITIAL_MAX_STREAM_DATA_UNI)?,
            initial_max_streams_bidi: params
                .get_var(transport_parameter_ids::INITIAL_MAX_STREAMS_BIDI)?,
            initial_max_streams_uni: params
                .get_var(transport_parameter_ids::INITIAL_MAX_STREAMS_UNI)?,
            ack_delay_exponent: params
                .get_var(transport_parameter_ids::ACK_DELAY_EXPONENT)?
                .unwrap_or(VarInt::from_u32(3)),
            max_ack_delay: params
                .get_var(transport_parameter_ids::MAX_ACK_DELAY)?
                .unwrap_or(VarInt::from_u32(25)),
            min_ack_delay: params.get_var(transport_parameter_ids::MIN_ACK_DELAY)?,
            active_connection_id_limit: params
                .get_var(transport_parameter_ids::ACTIVE_CONNECTION_ID_LIMIT)?
                .unwrap_or(VarInt::from_u32(2)),
            disable_active_migration: params
                .get(transport_parameter_ids::DISABLE_ACTIVE_MIGRATION)
                .is_some(),
            max_datagram_frame_size: params
                .get_var(transport_parameter_ids::MAX_DATAGRAM_FRAME_SIZE)?,
            reset_stream_at: params
                .get(transport_parameter_ids::RESET_STREAM_AT)
                .is_some(),
        })
    }

    fn initial_send_limit(self, kind: StreamKind) -> Option<VarInt> {
        match kind {
            StreamKind::Uni => self.initial_max_stream_data_uni,
            StreamKind::Bi => self.initial_max_stream_data_bidi_remote,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RoutedDatagram {
    pub meta: quion_udp::RecvMeta,
    pub contents: Vec<u8>,
    _memory_reservation: Option<RoutedDatagramMemoryReservation>,
}

impl RoutedDatagram {
    #[cfg(test)]
    pub(crate) fn new(meta: quion_udp::RecvMeta, contents: Vec<u8>) -> Self {
        Self {
            meta,
            contents,
            _memory_reservation: None,
        }
    }

    pub(crate) fn copy_with_budget(
        meta: quion_udp::RecvMeta,
        contents: &[u8],
        budget: &Arc<RoutedDatagramMemoryBudget>,
    ) -> Option<Self> {
        Self::copy_with_budget_or_reuse(meta, contents, budget, None)
    }

    pub(crate) fn copy_with_budget_or_reuse(
        meta: quion_udp::RecvMeta,
        contents: &[u8],
        budget: &Arc<RoutedDatagramMemoryBudget>,
        recycled: Option<Self>,
    ) -> Option<Self> {
        if let Some(mut datagram) = recycled
            && datagram.contents.capacity() >= contents.len()
        {
            datagram.meta = meta;
            datagram.contents.clear();
            datagram.contents.extend_from_slice(contents);
            return Some(datagram);
        }
        Self::with_budget(meta, contents.to_vec(), budget)
    }

    pub(crate) fn with_budget(
        meta: quion_udp::RecvMeta,
        contents: Vec<u8>,
        budget: &Arc<RoutedDatagramMemoryBudget>,
    ) -> Option<Self> {
        let reservation = budget.try_reserve(contents.len())?;
        Some(Self {
            meta,
            contents,
            _memory_reservation: Some(reservation),
        })
    }
}

/// Shared retained-payload ceiling for every connection owned by an endpoint.
#[derive(Debug)]
pub(crate) struct EndpointMemoryBudget {
    max_bytes: usize,
    used_bytes: AtomicUsize,
}

impl EndpointMemoryBudget {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            used_bytes: AtomicUsize::new(0),
        }
    }

    pub(crate) fn try_reserve(self: &Arc<Self>, bytes: usize) -> Option<EndpointMemoryReservation> {
        self.used_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            })
            .ok()?;
        Some(EndpointMemoryReservation {
            budget: self.clone(),
            bytes,
            active: true,
        })
    }

    fn release(&self, bytes: usize) {
        let _ = self
            .used_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(bytes))
            });
    }

    pub(crate) fn used_bytes(&self) -> usize {
        self.used_bytes.load(Ordering::Relaxed)
    }

    pub(crate) const fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

#[derive(Debug)]
pub(crate) struct EndpointMemoryReservation {
    budget: Arc<EndpointMemoryBudget>,
    bytes: usize,
    active: bool,
}

impl EndpointMemoryReservation {
    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }

    fn resize(&mut self, new_bytes: usize) -> bool {
        if new_bytes > self.bytes {
            let additional = new_bytes - self.bytes;
            if self
                .budget
                .used_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    used.checked_add(additional)
                        .filter(|next| *next <= self.budget.max_bytes)
                })
                .is_err()
            {
                return false;
            }
        } else {
            self.budget.release(self.bytes - new_bytes);
        }
        self.bytes = new_bytes;
        true
    }

    fn commit(mut self) {
        self.active = false;
    }
}

impl Drop for EndpointMemoryReservation {
    fn drop(&mut self) {
        if self.active {
            self.budget.release(self.bytes);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ProtocolMemoryTracker {
    state: Mutex<ProtocolMemoryTrackerState>,
}

#[derive(Debug, Default)]
struct ProtocolMemoryTrackerState {
    budget: Option<Arc<EndpointMemoryBudget>>,
    accounted_bytes: usize,
}

impl ProtocolMemoryTracker {
    pub(crate) fn attach(&self, budget: Arc<EndpointMemoryBudget>, payload_bytes: usize) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.budget.is_some() {
            return true;
        }
        let Some(reservation) = budget.try_reserve(payload_bytes) else {
            return false;
        };
        reservation.commit();
        state.accounted_bytes = payload_bytes;
        state.budget = Some(budget);
        true
    }

    fn attach_reservation(
        &self,
        mut reservation: EndpointMemoryReservation,
        payload_bytes: usize,
    ) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.budget.is_some() || !reservation.resize(payload_bytes) {
            return false;
        }
        state.accounted_bytes = payload_bytes;
        state.budget = Some(reservation.budget.clone());
        reservation.commit();
        true
    }

    pub(crate) fn try_reserve_growth(&self, bytes: usize) -> Option<ProtocolMemoryGrowth<'_>> {
        let budget = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .budget
            .clone();
        let reservation = match budget {
            Some(budget) => Some(budget.try_reserve(bytes)?),
            None => None,
        };
        Some(ProtocolMemoryGrowth {
            tracker: self,
            reservation,
            reserved_bytes: bytes,
        })
    }

    pub(crate) fn reconcile(&self, actual_bytes: usize) -> bool {
        self.try_reserve_growth(0)
            .is_some_and(|growth| growth.commit(actual_bytes))
    }

    fn reconcile_with_reservation(
        &self,
        mut reservation: EndpointMemoryReservation,
        actual_bytes: usize,
    ) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(budget) = state.budget.as_ref() else {
            return false;
        };
        if !Arc::ptr_eq(budget, &reservation.budget) {
            return false;
        }
        let additional = actual_bytes.saturating_sub(state.accounted_bytes);
        if !reservation.resize(additional) {
            return false;
        }
        if actual_bytes < state.accounted_bytes {
            budget.release(state.accounted_bytes - actual_bytes);
        }
        reservation.commit();
        state.accounted_bytes = actual_bytes;
        true
    }

    pub(crate) fn accounted_bytes(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accounted_bytes
    }
}

impl Drop for ProtocolMemoryTracker {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(budget) = &state.budget {
            budget.release(state.accounted_bytes);
        }
    }
}

pub(crate) struct ProtocolMemoryGrowth<'a> {
    tracker: &'a ProtocolMemoryTracker,
    reservation: Option<EndpointMemoryReservation>,
    reserved_bytes: usize,
}

impl ProtocolMemoryGrowth<'_> {
    pub(crate) fn commit(mut self, actual_bytes: usize) -> bool {
        let mut state = self
            .tracker
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old_bytes = state.accounted_bytes;
        let available_after_reservation = old_bytes.saturating_add(self.reserved_bytes);
        if actual_bytes > available_after_reservation {
            let extra = actual_bytes - available_after_reservation;
            let Some(budget) = &state.budget else {
                state.accounted_bytes = actual_bytes;
                return true;
            };
            let Some(extra_reservation) = budget.try_reserve(extra) else {
                return false;
            };
            extra_reservation.commit();
        }
        if let Some(budget) = &state.budget {
            budget.release(available_after_reservation.saturating_sub(actual_bytes));
        }
        if let Some(reservation) = self.reservation.take() {
            reservation.commit();
        }
        state.accounted_bytes = actual_bytes;
        true
    }
}

#[derive(Debug)]
pub(crate) struct RoutedDatagramMemoryBudget {
    max_bytes: usize,
    used_bytes: AtomicUsize,
    endpoint_budget: Arc<EndpointMemoryBudget>,
}

impl RoutedDatagramMemoryBudget {
    pub(crate) fn new(max_bytes: usize, endpoint_budget: Arc<EndpointMemoryBudget>) -> Self {
        Self {
            max_bytes,
            used_bytes: AtomicUsize::new(0),
            endpoint_budget,
        }
    }

    fn try_reserve(self: &Arc<Self>, bytes: usize) -> Option<RoutedDatagramMemoryReservation> {
        let endpoint_reservation = self.endpoint_budget.try_reserve(bytes)?;
        self.used_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            })
            .ok()?;
        Some(RoutedDatagramMemoryReservation {
            budget: self.clone(),
            bytes,
            _endpoint_reservation: endpoint_reservation,
        })
    }

    pub(crate) fn used_bytes(&self) -> usize {
        self.used_bytes.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub(crate) struct RoutedDatagramMemoryReservation {
    budget: Arc<RoutedDatagramMemoryBudget>,
    bytes: usize,
    _endpoint_reservation: EndpointMemoryReservation,
}

impl Drop for RoutedDatagramMemoryReservation {
    fn drop(&mut self) {
        let _ = self
            .budget
            .used_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(self.bytes))
            });
    }
}

#[derive(Debug, Default)]
struct DatagramState {
    read_waker: Option<Waker>,
}

#[derive(Debug, Default)]
pub(crate) struct StreamWakers {
    readers: std::collections::BTreeMap<StreamId, RegisteredWaker>,
}

#[derive(Debug)]
struct RegisteredWaker {
    waker: Waker,
    notified: bool,
}

impl StreamWakers {
    pub(crate) fn register_reader(&mut self, stream_id: StreamId, waker: &Waker) {
        if let Some(registered) = self.readers.get_mut(&stream_id)
            && registered.waker.will_wake(waker)
        {
            registered.notified = false;
        } else {
            self.readers.insert(
                stream_id,
                RegisteredWaker {
                    waker: waker.clone(),
                    notified: false,
                },
            );
        }
    }

    fn wake_reader(&mut self, stream_id: StreamId) -> Option<Waker> {
        let registered = self.readers.get_mut(&stream_id)?;
        if registered.notified {
            return None;
        }
        registered.notified = true;
        Some(registered.waker.clone())
    }

    fn wake_all_readers(&mut self) -> Vec<Waker> {
        std::mem::take(&mut self.readers)
            .into_values()
            .map(|registered| registered.waker)
            .collect()
    }

    pub(crate) fn remove_reader(&mut self, stream_id: StreamId) {
        self.readers.remove(&stream_id);
    }
}

#[derive(Debug, Default)]
pub(crate) struct StreamWriteState {
    writers: std::collections::BTreeMap<StreamId, Waker>,
}

impl StreamWriteState {
    pub(crate) fn register_writer(&mut self, stream_id: StreamId, waker: &Waker) {
        if self
            .writers
            .get(&stream_id)
            .is_some_and(|registered| registered.will_wake(waker))
        {
            return;
        }
        self.writers.insert(stream_id, waker.clone());
    }

    pub(crate) fn wake_writer(&mut self, stream_id: StreamId) -> Option<Waker> {
        self.writers.remove(&stream_id)
    }

    fn wake_all(&mut self) -> Vec<Waker> {
        std::mem::take(&mut self.writers).into_values().collect()
    }
}

#[derive(Debug, Default)]
pub(crate) struct StreamStopState {
    active: std::collections::BTreeSet<StreamId>,
    reasons: std::collections::BTreeMap<StreamId, VarInt>,
    waiters: std::collections::BTreeMap<StreamId, Waker>,
}

impl StreamStopState {
    pub(crate) fn register_handle(&mut self, id: StreamId) {
        self.active.insert(id);
    }

    pub(crate) fn remove_handle(&mut self, id: StreamId) {
        self.active.remove(&id);
        self.reasons.remove(&id);
        self.waiters.remove(&id);
    }

    pub(crate) fn stopped_reason(&self, stream_id: StreamId) -> Option<VarInt> {
        self.reasons.get(&stream_id).copied()
    }

    pub(crate) fn register_waiter(&mut self, stream_id: StreamId, waker: &Waker) {
        if self
            .waiters
            .get(&stream_id)
            .is_some_and(|registered| registered.will_wake(waker))
        {
            return;
        }
        self.waiters.insert(stream_id, waker.clone());
    }

    fn set_stopped(&mut self, stream_id: StreamId, error_code: VarInt) -> Option<Waker> {
        if self.active.contains(&stream_id) {
            self.reasons.entry(stream_id).or_insert(error_code);
        }
        self.waiters.remove(&stream_id)
    }

    pub(crate) fn remove_waiter(&mut self, stream_id: StreamId) -> Option<Waker> {
        self.waiters.remove(&stream_id)
    }

    fn wake_all(&mut self) -> Vec<Waker> {
        std::mem::take(&mut self.waiters).into_values().collect()
    }
}

#[derive(Debug, Default)]
pub(crate) struct StreamResetState {
    active: std::collections::BTreeSet<StreamId>,
    reasons: std::collections::BTreeMap<StreamId, VarInt>,
    waiters: std::collections::BTreeMap<StreamId, Waker>,
}

impl StreamResetState {
    pub(crate) fn register_handle(&mut self, id: StreamId) {
        self.active.insert(id);
    }

    pub(crate) fn remove_handle(&mut self, id: StreamId) {
        self.active.remove(&id);
        self.reasons.remove(&id);
        self.waiters.remove(&id);
    }

    pub(crate) fn reset_reason(&self, stream_id: StreamId) -> Option<VarInt> {
        self.reasons.get(&stream_id).copied()
    }

    pub(crate) fn register_waiter(&mut self, stream_id: StreamId, waker: &Waker) {
        if self
            .waiters
            .get(&stream_id)
            .is_some_and(|registered| registered.will_wake(waker))
        {
            return;
        }
        self.waiters.insert(stream_id, waker.clone());
    }

    pub(crate) fn wake_waiter(&mut self, stream_id: StreamId) -> Option<Waker> {
        self.waiters.remove(&stream_id)
    }

    fn set_reset(&mut self, stream_id: StreamId, error_code: VarInt) -> Option<Waker> {
        if self.active.contains(&stream_id) {
            self.reasons.entry(stream_id).or_insert(error_code);
        }
        self.waiters.remove(&stream_id)
    }

    fn wake_all(&mut self) -> Vec<Waker> {
        std::mem::take(&mut self.waiters).into_values().collect()
    }
}

/// Future returned by [`Connection::read_datagram`].
pub struct ReadDatagram {
    proto: Arc<Mutex<quion_proto::connection::Connection>>,
    datagram_state: Arc<Mutex<DatagramState>>,
    closed_state: Arc<Mutex<ClosedState>>,
    protocol_memory: Arc<ProtocolMemoryTracker>,
}

impl Future for ReadDatagram {
    type Output = Result<Vec<u8>, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(error) = self
            .closed_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .error
            .clone()
        {
            return Poll::Ready(Err(error));
        }

        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(datagram) = proto.read_datagram() {
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
            return Poll::Ready(Ok(datagram));
        }
        drop(proto);

        let mut datagram_state = self
            .datagram_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !datagram_state
            .read_waker
            .as_ref()
            .is_some_and(|registered| registered.will_wake(cx.waker()))
        {
            datagram_state.read_waker = Some(cx.waker().clone());
        }
        drop(datagram_state);

        // Close the race between the empty-queue check and waker
        // registration. A datagram arriving in that interval had no waiter
        // to wake, so inspect the queue once more after publishing the waker.
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(datagram) = proto.read_datagram() {
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
            return Poll::Ready(Ok(datagram));
        }
        Poll::Pending
    }
}

/// Future returned by [`Connection::read_datagram_bytes`].
pub struct ReadDatagramBytes {
    proto: Arc<Mutex<quion_proto::connection::Connection>>,
    datagram_state: Arc<Mutex<DatagramState>>,
    closed_state: Arc<Mutex<ClosedState>>,
    protocol_memory: Arc<ProtocolMemoryTracker>,
}

impl Future for ReadDatagramBytes {
    type Output = Result<bytes::Bytes, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(error) = self
            .closed_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .error
            .clone()
        {
            return Poll::Ready(Err(error));
        }

        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(datagram) = proto.read_datagram_bytes() {
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
            return Poll::Ready(Ok(datagram));
        }
        drop(proto);

        let mut datagram_state = self
            .datagram_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !datagram_state
            .read_waker
            .as_ref()
            .is_some_and(|registered| registered.will_wake(cx.waker()))
        {
            datagram_state.read_waker = Some(cx.waker().clone());
        }
        drop(datagram_state);

        // Close the race between the empty-queue check and waker
        // registration.
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(datagram) = proto.read_datagram_bytes() {
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
            return Poll::Ready(Ok(datagram));
        }
        Poll::Pending
    }
}

const fn is_unidirectional(stream_id: StreamId) -> bool {
    stream_id.0.into_inner() & 0x02 != 0
}

fn map_proto_error(error: quion_proto::CodecError) -> ConnectionError {
    ConnectionError::TransportError(error.transport_code())
}

/// Allow room for a short-header packet number, a maximum-length connection
/// ID, AEAD tag, and STREAM-frame metadata inside the peer's UDP payload
/// limit. QUIC requires this transport parameter to be at least 1,200 bytes.
const MAX_PACKET_OVERHEAD: usize = 64;

fn max_stream_frame_data(max_udp_payload_size: Option<VarInt>, initial_mtu: u16) -> usize {
    let max_udp_payload_size = max_udp_payload_size
        .unwrap_or(VarInt::from_u32(65_527))
        .into_inner()
        .min(u64::from(initial_mtu.max(1200)));
    usize::try_from(max_udp_payload_size)
        .unwrap_or(usize::MAX)
        .saturating_sub(MAX_PACKET_OVERHEAD)
        .max(1)
}

fn peer_max_udp_payload_size(value: Option<VarInt>) -> u16 {
    value
        .unwrap_or(VarInt::from_u32(65_527))
        .into_inner()
        .clamp(1_200, 65_527) as u16
}

fn idle_timeout_from_transport(
    local: &ProtoTransportConfig,
    peer: &NegotiatedTransport,
) -> Option<Duration> {
    let local_ms = local.max_idle_timeout_ms.into_inner();
    let peer_ms = peer.max_idle_timeout.map(VarInt::into_inner).unwrap_or(0);
    let effective_ms = match (local_ms, peer_ms) {
        (0, 0) => 0,
        (0, peer_ms) => peer_ms,
        (local_ms, 0) => local_ms,
        (local_ms, peer_ms) => local_ms.min(peer_ms),
    };
    (effective_ms > 0).then(|| Duration::from_millis(effective_ms))
}

fn stateless_reset_token_from_transport_parameters(
    params: &TransportParameters,
) -> Option<[u8; 16]> {
    params
        .get(transport_parameter_ids::STATELESS_RESET_TOKEN)
        .and_then(|value| value.try_into().ok())
}

fn earlier_deadline(
    left: Option<web_time::Instant>,
    right: Option<web_time::Instant>,
) -> Option<web_time::Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn proto_to_udp_ecn(ecn: EcnCodepoint) -> quion_udp::EcnCodepoint {
    match ecn {
        EcnCodepoint::Ect0 => quion_udp::EcnCodepoint::Ect0,
        EcnCodepoint::Ect1 => quion_udp::EcnCodepoint::Ect1,
        EcnCodepoint::Ce => quion_udp::EcnCodepoint::Ce,
    }
}

pub(crate) fn udp_to_proto_ecn(ecn: quion_udp::EcnCodepoint) -> EcnCodepoint {
    match ecn {
        quion_udp::EcnCodepoint::Ect0 => EcnCodepoint::Ect0,
        quion_udp::EcnCodepoint::Ect1 => EcnCodepoint::Ect1,
        quion_udp::EcnCodepoint::Ce => EcnCodepoint::Ce,
    }
}

#[derive(Debug, Default)]
struct AcceptWakers {
    uni: Option<Waker>,
    bi: Option<Waker>,
}

#[derive(Debug, Default)]
struct OpenStreamWakers {
    uni: Option<Waker>,
    bi: Option<Waker>,
}

impl OpenStreamWakers {
    fn register(&mut self, kind: StreamKind, waker: &Waker) {
        let slot = match kind {
            StreamKind::Uni => &mut self.uni,
            StreamKind::Bi => &mut self.bi,
        };
        if !slot
            .as_ref()
            .is_some_and(|registered| registered.will_wake(waker))
        {
            *slot = Some(waker.clone());
        }
    }

    fn wake(&mut self, kind: StreamKind) {
        let slot = match kind {
            StreamKind::Uni => &mut self.uni,
            StreamKind::Bi => &mut self.bi,
        };
        if let Some(waker) = slot.take() {
            waker.wake();
        }
    }

    fn wake_all(&mut self) {
        self.wake(StreamKind::Uni);
        self.wake(StreamKind::Bi);
    }
}

impl AcceptWakers {
    fn register(&mut self, stream_id_predicate: StreamKind, waker: &Waker) {
        let slot = match stream_id_predicate {
            StreamKind::Uni => &mut self.uni,
            StreamKind::Bi => &mut self.bi,
        };
        if !slot
            .as_ref()
            .is_some_and(|registered| registered.will_wake(waker))
        {
            *slot = Some(waker.clone());
        }
    }

    #[allow(dead_code)]
    fn wake(&mut self, stream_id: StreamId) {
        let slot = if is_unidirectional(stream_id) {
            &mut self.uni
        } else {
            &mut self.bi
        };
        if let Some(waker) = slot.take() {
            waker.wake();
        }
    }

    fn wake_all(&mut self) {
        if let Some(waker) = self.uni.take() {
            waker.wake();
        }
        if let Some(waker) = self.bi.take() {
            waker.wake();
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ClosedState {
    pub(crate) error: Option<ConnectionError>,
    waker: Option<Waker>,
}

#[derive(Debug, Default)]
struct TimeoutState {
    idle_timeout: Option<Duration>,
    last_activity: Option<web_time::Instant>,
    last_keep_alive: Option<web_time::Instant>,
    shutdown_deadline: Option<web_time::Instant>,
}

#[derive(Debug)]
/// Future returned by [`Connection::closed`].
pub struct Closed {
    closed_state: Arc<Mutex<ClosedState>>,
}

impl Future for Closed {
    type Output = ConnectionError;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self
            .closed_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(error) = state.error.clone() {
            Poll::Ready(error)
        } else {
            if !state
                .waker
                .as_ref()
                .is_some_and(|registered| registered.will_wake(cx.waker()))
            {
                state.waker = Some(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamKind {
    Uni,
    Bi,
}

#[derive(Debug)]
/// Future returned by [`Connection::open_uni`].
pub struct OpenUni {
    connection: Connection,
}

impl OpenUni {
    /// Resolves synchronously when stream credit is already available.
    pub fn into_inner(self) -> Result<SendStream, ConnectionError> {
        if let Some(error) = self.connection.closed_error() {
            return Err(error);
        }
        self.connection
            .open_outgoing_stream(StreamKind::Uni)
            .map(|stream_id| self.connection.send_stream_handle(stream_id))
    }
}

impl Future for OpenUni {
    type Output = Result<SendStream, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(error) = self.connection.closed_error() {
            return Poll::Ready(Err(error));
        }
        match self.connection.open_outgoing_stream(StreamKind::Uni) {
            Ok(stream_id) => Poll::Ready(Ok(self.connection.send_stream_handle(stream_id))),
            Err(ConnectionError::UnidirectionalStreamLimitReached) => {
                self.connection
                    .open_stream_wakers
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .register(StreamKind::Uni, cx.waker());
                if let Some(error) = self.connection.closed_error() {
                    Poll::Ready(Err(error))
                } else {
                    Poll::Pending
                }
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

#[derive(Debug)]
/// Future returned by [`Connection::open_bi`].
pub struct OpenBi {
    connection: Connection,
}

impl OpenBi {
    /// Resolves synchronously when stream credit is already available.
    pub fn into_inner(self) -> Result<BiStream, ConnectionError> {
        if let Some(error) = self.connection.closed_error() {
            return Err(error);
        }
        self.connection
            .open_outgoing_stream(StreamKind::Bi)
            .map(|stream_id| {
                (
                    self.connection.send_stream_handle(stream_id),
                    self.connection.recv_stream_handle(stream_id),
                )
            })
    }
}

impl Future for OpenBi {
    type Output = Result<BiStream, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(error) = self.connection.closed_error() {
            return Poll::Ready(Err(error));
        }
        match self.connection.open_outgoing_stream(StreamKind::Bi) {
            Ok(stream_id) => Poll::Ready(Ok((
                self.connection.send_stream_handle(stream_id),
                self.connection.recv_stream_handle(stream_id),
            ))),
            Err(ConnectionError::BidirectionalStreamLimitReached) => {
                self.connection
                    .open_stream_wakers
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .register(StreamKind::Bi, cx.waker());
                if let Some(error) = self.connection.closed_error() {
                    Poll::Ready(Err(error))
                } else {
                    Poll::Pending
                }
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

fn proto_stream_limit_kind(kind: StreamKind) -> StreamLimitKind {
    match kind {
        StreamKind::Uni => StreamLimitKind::Uni,
        StreamKind::Bi => StreamLimitKind::Bidi,
    }
}

#[derive(Debug)]
/// Future returned by [`Connection::accept_uni`].
pub struct AcceptUni {
    proto: Arc<Mutex<quion_proto::connection::Connection>>,
    accept_wakers: Arc<Mutex<AcceptWakers>>,
    closed_state: Arc<Mutex<ClosedState>>,
    qlog: SharedQlogState,
    stream_wakers: Arc<Mutex<StreamWakers>>,
    stream_reset_state: Arc<Mutex<StreamResetState>>,
    protocol_memory: Arc<ProtocolMemoryTracker>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    runtime_notify: Arc<Notify>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    endpoint_runtime_notify: Arc<Mutex<Option<EndpointRuntimeNotify>>>,
}

impl Future for AcceptUni {
    type Output = Result<RecvStream, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(stream_id) = proto.accept_recv_stream_where(is_unidirectional) {
            Poll::Ready(Ok(RecvStream::new(
                self.proto.clone(),
                self.closed_state.clone(),
                self.qlog.clone(),
                self.stream_wakers.clone(),
                self.stream_reset_state.clone(),
                self.protocol_memory.clone(),
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                self.runtime_notify.clone(),
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                self.endpoint_runtime_notify.clone(),
                stream_id,
            )))
        } else {
            drop(proto);
            if let Some(error) = self
                .closed_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .error
                .clone()
            {
                return Poll::Ready(Err(error));
            }
            self.accept_wakers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .register(StreamKind::Uni, cx.waker());
            Poll::Pending
        }
    }
}

#[derive(Debug)]
/// Future returned by [`Connection::accept_bi`].
pub struct AcceptBi {
    proto: Arc<Mutex<quion_proto::connection::Connection>>,
    accept_wakers: Arc<Mutex<AcceptWakers>>,
    closed_state: Arc<Mutex<ClosedState>>,
    qlog: SharedQlogState,
    stream_wakers: Arc<Mutex<StreamWakers>>,
    stream_write_state: Arc<Mutex<StreamWriteState>>,
    stream_stop_state: Arc<Mutex<StreamStopState>>,
    stream_reset_state: Arc<Mutex<StreamResetState>>,
    negotiated_transport: Arc<Mutex<Option<NegotiatedTransport>>>,
    protocol_memory: Arc<ProtocolMemoryTracker>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    runtime_notify: Arc<Notify>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    endpoint_runtime_notify: Arc<Mutex<Option<EndpointRuntimeNotify>>>,
}

impl Future for AcceptBi {
    type Output = Result<BiStream, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let initial_send_limit = self
            .negotiated_transport
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .and_then(|transport| transport.initial_max_stream_data_bidi_local);
        let mut proto = self
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(stream_id) =
            proto.accept_recv_stream_where(|stream_id| !is_unidirectional(stream_id))
        {
            if let Some(initial_send_limit) = initial_send_limit {
                proto
                    .increase_stream_send_limit(stream_id, initial_send_limit.into_inner())
                    .map_err(map_proto_error)?;
            }
            Poll::Ready(Ok((
                SendStream::new(
                    self.proto.clone(),
                    self.closed_state.clone(),
                    self.qlog.clone(),
                    self.stream_write_state.clone(),
                    self.stream_stop_state.clone(),
                    self.protocol_memory.clone(),
                    #[cfg(all(
                        feature = "runtime-tokio",
                        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                    ))]
                    self.runtime_notify.clone(),
                    #[cfg(all(
                        feature = "runtime-tokio",
                        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                    ))]
                    self.endpoint_runtime_notify.clone(),
                    stream_id,
                ),
                RecvStream::new(
                    self.proto.clone(),
                    self.closed_state.clone(),
                    self.qlog.clone(),
                    self.stream_wakers.clone(),
                    self.stream_reset_state.clone(),
                    self.protocol_memory.clone(),
                    #[cfg(all(
                        feature = "runtime-tokio",
                        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                    ))]
                    self.runtime_notify.clone(),
                    #[cfg(all(
                        feature = "runtime-tokio",
                        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                    ))]
                    self.endpoint_runtime_notify.clone(),
                    stream_id,
                ),
            )))
        } else {
            drop(proto);
            if let Some(error) = self
                .closed_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .error
                .clone()
            {
                return Poll::Ready(Err(error));
            }
            self.accept_wakers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .register(StreamKind::Bi, cx.waker());
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Wake, Waker},
        thread,
        time::Duration,
    };

    fn counting_waker(count: Arc<AtomicUsize>) -> Waker {
        #[derive(Debug)]
        struct CountingWake {
            count: Arc<AtomicUsize>,
        }

        impl Wake for CountingWake {
            fn wake(self: Arc<Self>) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        Waker::from(Arc::new(CountingWake { count }))
    }

    fn negotiate_test_datagrams(connection: &Connection) {
        connection
            .proto
            .lock()
            .unwrap()
            .set_receive_datagram_frame_size(Some(VarInt::from_u32(65535)));
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::MAX_DATAGRAM_FRAME_SIZE,
            VarInt::from_u32(65535),
        );
        connection.mark_established(params);
    }

    #[test]
    fn connection_handle_remains_compact() {
        assert_eq!(
            std::mem::size_of::<Connection>(),
            std::mem::size_of::<Arc<ConnectionInner>>()
        );
    }

    #[test]
    fn accept_uni_registers_without_busy_waking() {
        let conn = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut accept = conn.accept_uni();

        assert!(matches!(Pin::new(&mut accept).poll(&mut cx), Poll::Pending));
        assert_eq!(wake_count.load(Ordering::SeqCst), 0);

        conn.wake_accept_streams(StreamId(VarInt::from_u32(2)));
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn accept_bi_registers_without_busy_waking() {
        let conn = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut accept = conn.accept_bi();

        assert!(matches!(Pin::new(&mut accept).poll(&mut cx), Poll::Pending));
        assert_eq!(wake_count.load(Ordering::SeqCst), 0);

        conn.wake_accept_streams(StreamId(VarInt::ZERO));
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reset_only_peer_stream_wakes_accept_and_reports_reset() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut accept = connection.accept_bi();

        assert!(matches!(Pin::new(&mut accept).poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::ResetStream {
                    stream_id: VarInt::from_u32(1),
                    error_code: VarInt::from_u32(42),
                    final_size: VarInt::ZERO,
                }
                .encode(),
            )
            .unwrap();

        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        let (_, mut recv) = match Pin::new(&mut accept).poll(&mut cx) {
            Poll::Ready(Ok(streams)) => streams,
            state => panic!("expected reset-only stream to be accepted, got {state:?}"),
        };
        assert!(matches!(
            Box::pin(recv.read_chunk(1024, true)).as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::ReadError::Reset(code))) if code == VarInt::from_u32(42)
        ));
    }

    #[test]
    fn peer_response_on_locally_opened_bidi_stream_is_not_reaccepted() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut accept = connection.accept_bi();

        assert!(matches!(Pin::new(&mut accept).poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: false,
                    data: b"response".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(Pin::new(&mut accept).poll(&mut cx), Poll::Pending));
        let mut read = Box::pin(recv.read_chunk(1024, true));
        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Ok(Some(chunk))) if chunk.bytes.as_ref() == b"response"
        ));
    }

    #[test]
    fn ecn_mapping_roundtrips_between_proto_and_udp_types() {
        for (proto, udp) in [
            (EcnCodepoint::Ect0, quion_udp::EcnCodepoint::Ect0),
            (EcnCodepoint::Ect1, quion_udp::EcnCodepoint::Ect1),
            (EcnCodepoint::Ce, quion_udp::EcnCodepoint::Ce),
        ] {
            assert_eq!(proto_to_udp_ecn(proto), udp);
            assert_eq!(udp_to_proto_ecn(udp), proto);
        }
    }

    #[test]
    fn close_queues_application_close_frame() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection.close(VarInt::from_u32(7), b"bye");

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            quion_proto::frame::Frame::ApplicationClose {
                error_code: VarInt::from_u32(7),
                reason: b"bye".to_vec(),
            }
        );
    }

    #[test]
    fn close_transport_queues_connection_close_frame() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection
            .close_transport(
                TransportErrorCode::ProtocolViolation,
                VarInt::from_u32(0x08),
                b"bad frame",
            )
            .unwrap();

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            quion_proto::frame::Frame::ConnectionClose {
                error_code: TransportErrorCode::ProtocolViolation,
                frame_type: VarInt::from_u32(0x08),
                reason: b"bad frame".to_vec(),
            }
        );
    }

    #[test]
    fn closed_future_resolves_after_local_close() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut closed = Box::pin(connection.closed());
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(closed.as_mut().poll(&mut cx), Poll::Pending));
        connection.close(VarInt::from_u32(7), b"bye");
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            closed.as_mut().poll(&mut cx),
            Poll::Ready(ConnectionError::LocallyClosed)
        ));
        assert!(connection.is_closed());
    }

    #[test]
    fn runtime_shutdown_waits_for_close_recovery_work_to_drain() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );

        connection.close(VarInt::from_u32(7), b"bye");
        assert!(!connection.runtime_shutdown_ready());

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = proto
            .poll_transmit(web_time::Instant::now())
            .expect("close frame should be queued for transmit");
        drop(proto);

        assert!(!connection.runtime_shutdown_ready());
    }

    #[test]
    fn local_close_eventually_becomes_shutdown_ready_after_deadline() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );

        connection.close(VarInt::from_u32(7), b"bye");
        connection.set_shutdown_deadline_for_test(Some(
            web_time::Instant::now() - web_time::Duration::from_millis(1),
        ));

        assert!(connection.runtime_shutdown_ready());
    }

    #[test]
    fn forced_closed_connection_is_ready_for_runtime_shutdown_without_pending_work() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );

        connection.force_close_for_test(ConnectionError::LocallyClosed);

        assert!(connection.runtime_shutdown_ready());
    }

    #[test]
    fn abort_discards_pending_close_transmit_and_is_shutdown_ready() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );

        connection.close(VarInt::from_u32(7), b"bye");
        assert!(!connection.runtime_shutdown_ready());

        connection.abort();

        assert!(connection.is_closed());
        assert!(connection.runtime_shutdown_ready());
        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(proto.poll_transmit(web_time::Instant::now()).is_none());
    }

    #[test]
    fn abort_reports_locally_closed_reason() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );

        connection.abort();

        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut closed = Box::pin(connection.closed());
        assert!(matches!(
            closed.as_mut().poll(&mut cx),
            Poll::Ready(ConnectionError::LocallyClosed)
        ));
    }

    #[test]
    fn closed_future_reports_peer_application_close() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let frame = quion_proto::frame::Frame::ApplicationClose {
            error_code: VarInt::from_u32(42),
            reason: b"done".to_vec(),
        }
        .encode();

        connection.recv_test_frame_payload(&frame).unwrap();

        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut closed = Box::pin(connection.closed());
        let expected = ConnectionError::ApplicationClosed {
            code: VarInt::from_u32(42),
            reason: "done".to_string(),
        };

        assert!(matches!(
            closed.as_mut().poll(&mut cx),
            Poll::Ready(error) if error == expected
        ));
        assert!(connection.shutdown_deadline().is_some());
    }

    #[test]
    fn closed_future_reports_peer_transport_close() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let frame = quion_proto::frame::Frame::ConnectionClose {
            error_code: TransportErrorCode::FlowControlError,
            frame_type: VarInt::from_u32(0x10),
            reason: b"flow".to_vec(),
        }
        .encode();

        connection.recv_test_frame_payload(&frame).unwrap();

        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut closed = Box::pin(connection.closed());
        assert!(matches!(
            closed.as_mut().poll(&mut cx),
            Poll::Ready(ConnectionError::TransportError(
                TransportErrorCode::FlowControlError
            ))
        ));
    }

    #[test]
    fn post_close_connection_apis_return_closed_error() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection.close(VarInt::from_u32(7), b"bye");

        assert!(matches!(
            connection.open_uni().into_inner(),
            Err(ConnectionError::LocallyClosed)
        ));
        assert!(matches!(
            connection.open_bi().into_inner(),
            Err(ConnectionError::LocallyClosed)
        ));
        assert!(matches!(
            connection.send_datagram(b"after-close"),
            Err(crate::SendDatagramError::ConnectionLost(
                ConnectionError::LocallyClosed
            ))
        ));
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut read_datagram = Box::pin(connection.read_datagram());
        assert!(matches!(
            read_datagram.as_mut().poll(&mut cx),
            Poll::Ready(Err(ConnectionError::LocallyClosed))
        ));
    }

    #[test]
    fn endpoint_memory_budget_applies_backpressure_across_connections_and_releases() {
        let budget = Arc::new(EndpointMemoryBudget::new(4));
        let first = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let second = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        );
        assert!(first.attach_endpoint_memory_budget(budget.clone()));
        assert!(second.attach_endpoint_memory_budget(budget.clone()));

        negotiate_test_datagrams(&first);
        negotiate_test_datagrams(&second);
        first.send_datagram(vec![0; 4]).unwrap();
        assert_eq!(budget.used_bytes(), 4);
        assert_eq!(
            second.send_datagram(vec![0]),
            Err(crate::SendDatagramError::EndpointMemoryLimitReached)
        );

        first.abort();
        assert_eq!(budget.used_bytes(), 0);
        second.send_datagram(vec![0]).unwrap();
        assert_eq!(budget.used_bytes(), 1);
    }

    #[test]
    fn endpoint_memory_budget_backpressures_stream_writes() {
        let budget = Arc::new(EndpointMemoryBudget::new(4));
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        assert!(connection.attach_endpoint_memory_budget(budget.clone()));
        let (mut send, _) = connection.open_bi().into_inner().unwrap();
        let stream_id = send.id().unwrap();
        {
            let mut proto = connection.proto.lock().unwrap();
            proto.increase_connection_send_limit(16);
            proto.increase_stream_send_limit(stream_id, 16).unwrap();
        }
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Box::pin(send.write_all(b"1234")).as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(budget.used_bytes(), 4);
        assert!(matches!(
            Box::pin(send.write(b"5")).as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::WriteError::EndpointMemoryLimitReached))
        ));
    }

    #[test]
    fn endpoint_memory_budget_accounts_close_reasons_and_releases_on_abort() {
        let budget = Arc::new(EndpointMemoryBudget::new(3));
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        assert!(connection.attach_endpoint_memory_budget(budget.clone()));

        connection.close(VarInt::from_u32(7), b"bye");
        assert_eq!(budget.used_bytes(), 3);

        connection.abort();
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn application_close_omits_reason_when_endpoint_budget_is_exhausted() {
        let budget = Arc::new(EndpointMemoryBudget::new(0));
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        assert!(connection.attach_endpoint_memory_budget(budget.clone()));

        connection.close(VarInt::from_u32(7), b"reason");

        let mut proto = connection.proto.lock().unwrap();
        let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, _) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
        assert!(matches!(
            frame,
            quion_proto::frame::Frame::ApplicationClose { reason, .. } if reason.is_empty()
        ));
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn post_close_existing_stream_handles_return_connection_lost() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (mut send, mut recv) = connection.open_bi().into_inner().unwrap();

        connection.close(VarInt::from_u32(7), b"bye");

        assert!(matches!(
            send.finish(),
            Err(crate::error::WriteError::ConnectionLost(
                ConnectionError::LocallyClosed
            ))
        ));
        assert!(matches!(
            send.reset(VarInt::from_u32(9)),
            Err(crate::error::WriteError::ConnectionLost(
                ConnectionError::LocallyClosed
            ))
        ));
        assert!(matches!(
            recv.stop(VarInt::from_u32(11)),
            Err(crate::error::ReadError::ConnectionLost(
                ConnectionError::LocallyClosed
            ))
        ));
    }

    #[test]
    fn post_abort_existing_stream_handles_return_connection_lost() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (mut send, mut recv) = connection.open_bi().into_inner().unwrap();

        connection.abort();

        assert!(matches!(
            send.finish(),
            Err(crate::error::WriteError::ConnectionLost(
                ConnectionError::LocallyClosed
            ))
        ));
        assert!(matches!(
            recv.stop(VarInt::from_u32(11)),
            Err(crate::error::ReadError::ConnectionLost(
                ConnectionError::LocallyClosed
            ))
        ));
    }

    #[test]
    fn read_datagram_wakes_when_peer_datagram_arrives() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let wake_count = Arc::new(AtomicUsize::new(0));
        negotiate_test_datagrams(&connection);
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut read_datagram = Box::pin(connection.read_datagram());

        assert!(matches!(
            read_datagram.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Datagram {
                    data: b"ping".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        for _ in 0..10 {
            if wake_count.load(Ordering::SeqCst) > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert!(wake_count.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            read_datagram.as_mut().poll(&mut cx),
            Poll::Ready(Ok(bytes)) if bytes == b"ping"
        ));
    }

    #[test]
    fn recv_stream_read_to_end_wakes_when_peer_stream_data_arrives() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut read = Box::pin(recv.read_to_end(1024));

        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: false,
                    data: b"hello".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        for _ in 0..10 {
            if wake_count.load(Ordering::SeqCst) > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert!(wake_count.load(Ordering::SeqCst) > 0);
        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::from_u32(5),
                    fin: true,
                    data: bytes::Bytes::new(),
                }
                .encode(),
            )
            .unwrap();
        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Ok(bytes)) if bytes == b"hello"
        ));
    }

    #[test]
    fn send_stream_stopped_wakes_when_peer_requests_stop_sending() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (mut send, _recv) = connection.open_bi().into_inner().unwrap();
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut stopped = Box::pin(send.stopped());

        assert!(matches!(stopped.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::StopSending {
                    stream_id: VarInt::ZERO,
                    error_code: VarInt::from_u32(42),
                }
                .encode(),
            )
            .unwrap();

        for _ in 0..10 {
            if wake_count.load(Ordering::SeqCst) > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert!(wake_count.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            stopped.as_mut().poll(&mut cx),
            Poll::Ready(Ok(Some(code))) if code == VarInt::from_u32(42)
        ));
        drop(stopped);
        assert!(matches!(
            Box::pin(send.write_all(b"after-stop")).as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::WriteError::Stopped(code))) if code == VarInt::from_u32(42)
        ));
        let transmit = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .poll_transmit(web_time::Instant::now())
            .unwrap();
        assert_eq!(
            quion_proto::frame::Frame::decode(&transmit.contents)
                .unwrap()
                .0,
            quion_proto::frame::Frame::ResetStream {
                stream_id: VarInt::ZERO,
                error_code: VarInt::from_u32(42),
                final_size: VarInt::ZERO,
            }
        );
    }

    #[test]
    fn send_stream_stopped_resolves_none_after_fin_is_acknowledged() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (mut send, _recv) = connection.open_bi().into_inner().unwrap();
        {
            let mut proto = connection
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.increase_connection_send_limit(16);
            proto
                .increase_stream_send_limit(StreamId(VarInt::ZERO), 16)
                .unwrap();
        }
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut write = Box::pin(send.write_all(b"done"));
        assert!(matches!(write.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        drop(write);
        send.finish().unwrap();

        let transmit = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .poll_transmit(web_time::Instant::now())
            .unwrap();
        assert!(matches!(
            quion_proto::frame::Frame::decode(&transmit.contents)
                .unwrap()
                .0,
            quion_proto::frame::Frame::Stream { fin: true, .. }
        ));

        let mut stopped = Box::pin(send.stopped());
        assert!(matches!(stopped.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Ack {
                    largest: VarInt::ZERO,
                    delay: VarInt::ZERO,
                    first_range: VarInt::ZERO,
                    ranges: Default::default(),
                    ecn: None,
                }
                .encode(),
            )
            .unwrap();

        assert!(wake_count.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            stopped.as_mut().poll(&mut cx),
            Poll::Ready(Ok(None))
        ));
    }

    #[test]
    fn send_stream_write_all_waits_for_flow_control_credit() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (mut send, _) = connection.open_bi().into_inner().unwrap();
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut write = Box::pin(send.write_all(b"hello"));

        assert!(matches!(write.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxData(VarInt::from_u32(5)).encode(),
            )
            .unwrap();
        assert!(matches!(write.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamData {
                    stream_id: VarInt::ZERO,
                    maximum: VarInt::from_u32(5),
                }
                .encode(),
            )
            .unwrap();

        assert!(wake_count.load(Ordering::SeqCst) > 0);
        assert!(matches!(write.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    }

    #[test]
    fn send_stream_write_reports_buffer_limit() {
        let transport = ProtoTransportConfig {
            max_send_buffered_stream_data: 4,
            ..ProtoTransportConfig::default()
        };
        let connection = Connection::new_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            transport,
        );
        let (mut send, _) = connection.open_bi().into_inner().unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxData(VarInt::from_u32(16)).encode(),
            )
            .unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamData {
                    stream_id: VarInt::ZERO,
                    maximum: VarInt::from_u32(16),
                }
                .encode(),
            )
            .unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut write = Box::pin(send.write(b"12345"));

        assert!(matches!(
            write.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::WriteError::BufferTooLarge))
        ));
    }

    #[test]
    fn connection_uses_configured_congestion_algorithm() {
        let transport = ProtoTransportConfig {
            congestion_algorithm: quion_proto::congestion::CongestionAlgorithm::Cubic,
            ..ProtoTransportConfig::default()
        };
        let connection = Connection::new_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            transport,
        );

        assert_eq!(
            connection.proto.lock().unwrap().congestion_algorithm(),
            quion_proto::congestion::CongestionAlgorithm::Cubic
        );
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn runtime_activity_waiter_consumes_queued_routed_datagram_signal() {
        let conn = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        conn.enqueue_routed_datagram(
            quion_udp::RecvMeta {
                local: Some("127.0.0.1:0".parse().unwrap()),
                remote: "127.0.0.1:1".parse().unwrap(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: 4,
            },
            b"ping".to_vec(),
        );
        tokio::time::timeout(
            Duration::from_millis(10),
            conn.wait_for_runtime_activity(None),
        )
        .await
        .expect("runtime activity wait timed out");
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn stream_handles_notify_endpoint_owned_runtime_driver() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let endpoint_notify = Arc::new(Notify::new());
        connection.set_endpoint_runtime_notify(endpoint_notify.clone());
        endpoint_notify.notified().await;

        let (mut send, mut recv) = connection.open_bi().into_inner().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(1), endpoint_notify.notified())
                .await
                .is_err(),
            "opening an empty stream unexpectedly notified the endpoint runtime"
        );
        send.finish().unwrap();
        tokio::time::timeout(Duration::from_millis(10), endpoint_notify.notified())
            .await
            .expect("send stream did not notify endpoint runtime");

        recv.stop(VarInt::ZERO).unwrap();
        tokio::time::timeout(Duration::from_millis(10), endpoint_notify.notified())
            .await
            .expect("receive stream did not notify endpoint runtime");
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn datagram_payload_limit_accounts_for_negotiation_headers_and_path() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        assert_eq!(connection.max_datagram_size(), None);
        assert_eq!(
            connection.send_datagram(b"x"),
            Err(crate::SendDatagramError::Unsupported)
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::MAX_DATAGRAM_FRAME_SIZE,
            VarInt::ZERO,
        );
        connection.mark_established(params);
        assert_eq!(connection.max_datagram_size(), None);
        negotiate_test_datagrams(&connection);
        let maximum = connection.max_datagram_size().unwrap();
        assert_eq!(maximum, 1200 - 64 - 3);
        assert_eq!(
            connection.send_datagram(vec![0; maximum + 1]),
            Err(crate::SendDatagramError::TooLarge {
                maximum: maximum as u64
            })
        );
        connection.send_datagram(vec![0; maximum]).unwrap();
        connection
            .proto
            .lock()
            .unwrap()
            .configure_mtu_discovery(1500, None);
        assert_eq!(connection.max_datagram_size(), Some(1500 - 64 - 3));
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn small_read_without_credit_update_does_not_wake_driver() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_send, mut recv) = connection.open_bi().into_inner().unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: false,
                    data: b"small read".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();
        let notify = Arc::new(Notify::new());
        connection.set_endpoint_runtime_notify(notify.clone());
        notify.notified().await;
        let mut bytes = [0; 10];
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"small read");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), notify.notified())
                .await
                .is_err()
        );
    }

    #[test]
    fn routed_datagram_queue_is_bounded() {
        let conn = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let meta = quion_udp::RecvMeta {
            local: Some("127.0.0.1:0".parse().unwrap()),
            remote: "127.0.0.1:1".parse().unwrap(),
            interface: None,
            ecn: None,
            segment_size: None,
            len: 1,
        };

        for i in 0..=MAX_ROUTED_DATAGRAM_QUEUE_LEN {
            conn.enqueue_routed_datagram(meta.clone(), vec![(i % u8::MAX as usize) as u8]);
        }

        let datagram = conn.pop_routed_datagram().unwrap();
        assert_eq!(datagram.contents, vec![1]);
    }

    #[test]
    fn connection_diagnostics_reports_stable_snapshot_counts() {
        let conn = Connection::new_with_qlog(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            ProtoTransportConfig::default(),
            None,
            32,
        );
        conn.enqueue_routed_datagram(
            quion_udp::RecvMeta {
                local: Some("127.0.0.1:0".parse().unwrap()),
                remote: "127.0.0.1:1".parse().unwrap(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: 4,
            },
            b"ping".to_vec(),
        );
        conn.recv_test_frame_payload(
            &quion_proto::frame::Frame::Stream {
                stream_id: VarInt::from_u32(1),
                offset: VarInt::ZERO,
                fin: false,
                data: b"data".to_vec().into(),
            }
            .encode(),
        )
        .unwrap();

        let diagnostics = conn.diagnostics();

        assert!(!diagnostics.is_closed);
        assert!(!diagnostics.is_established);
        assert_eq!(diagnostics.routed_datagrams_queued, 1);
        assert_eq!(diagnostics.routed_datagram_bytes, 4);
        assert_eq!(diagnostics.recv_stream_bytes_buffered, 4);
        assert_eq!(diagnostics.send_stream_bytes_buffered, 0);
        assert_eq!(diagnostics.stats.packets_received, 0);
        assert_eq!(diagnostics.flow_control.receive_received, 4);
        assert!(diagnostics.qlog_events_buffered > 0);
        assert_eq!(
            diagnostics.memory.qlog_events,
            diagnostics.qlog_events_buffered
        );
        assert!(diagnostics.memory.qlog_bytes > 0);
        assert_eq!(
            conn.stream_flow_control(VarInt::from_u32(1))
                .receive_received,
            Some(4)
        );
    }

    #[test]
    fn routed_datagram_rejects_peer_address_change_when_migration_is_disabled() {
        let conn = Connection::new_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            ProtoTransportConfig::default(),
        );
        conn.enqueue_routed_datagram(
            quion_udp::RecvMeta {
                local: Some("127.0.0.1:0".parse().unwrap()),
                remote: "127.0.0.1:2".parse().unwrap(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: 4,
            },
            b"drop".to_vec(),
        );

        assert_eq!(conn.routed_datagram_len(), 0);
    }

    #[test]
    fn server_routes_rebinding_candidates_with_default_migration_policy() {
        let transport = ProtoTransportConfig::default();
        let conn = Connection::server_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            transport,
        );
        conn.enqueue_routed_datagram(
            quion_udp::RecvMeta {
                local: Some("127.0.0.1:0".parse().unwrap()),
                remote: "127.0.0.1:2".parse().unwrap(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: 4,
            },
            b"keep".to_vec(),
        );

        assert_eq!(conn.routed_datagram_len(), 1);
    }

    #[test]
    fn authenticated_nat_rebinding_validates_before_switching_active_path() {
        let transport = ProtoTransportConfig {
            disable_active_migration: false,
            ..ProtoTransportConfig::default()
        };
        let original: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let rebound: SocketAddr = "127.0.0.1:4001".parse().unwrap();
        let conn =
            Connection::new_with_transport("127.0.0.1:3000".parse().unwrap(), original, transport);
        let now = web_time::Instant::now();

        conn.note_authenticated_path(rebound, 1200, &Effects::default(), now);

        assert_eq!(conn.remote_address(), original);
        assert_eq!(conn.transmit_destination(true), rebound);
        let validating = conn.diagnostics();
        assert_eq!(validating.peer_address_changes, 1);
        assert!(validating.paths.iter().any(|path| {
            path.remote_address == rebound
                && path.validation == PathValidationStatus::Validating
                && path.amplification_limited
        }));
        let probe = conn.proto.lock().unwrap().poll_transmit(now).unwrap();
        assert!(probe.path_probe);

        let mut validated = Effects::default();
        validated
            .connection_events
            .push(ConnectionEvent::PathValidated);
        conn.note_authenticated_path(rebound, 64, &validated, now);
        conn.record_path_sent_batch(rebound, 1, 48);

        assert_eq!(conn.remote_address(), rebound);
        assert_eq!(conn.transmit_destination(false), rebound);
        let diagnostics = conn.diagnostics();
        assert!(diagnostics.paths.iter().any(|path| {
            path.remote_address == rebound
                && path.validation == PathValidationStatus::Validated
                && path.packets_received == 2
                && path.packets_sent == 1
                && !path.amplification_limited
        }));
    }

    #[test]
    fn failed_candidate_path_keeps_original_active_path() {
        let transport = ProtoTransportConfig {
            disable_active_migration: false,
            ..ProtoTransportConfig::default()
        };
        let original: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let candidate: SocketAddr = "127.0.0.2:4000".parse().unwrap();
        let conn =
            Connection::new_with_transport("127.0.0.1:3000".parse().unwrap(), original, transport);
        conn.note_authenticated_path(
            candidate,
            1200,
            &Effects::default(),
            web_time::Instant::now(),
        );
        let mut failed = Effects::default();
        failed
            .connection_events
            .push(ConnectionEvent::PathValidationFailed);

        conn.handle_effects(&failed);

        assert_eq!(conn.remote_address(), original);
        assert_eq!(conn.diagnostics().paths.len(), 1);
    }

    #[test]
    fn established_datagram_send_reports_stable_negotiation_errors() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection.mark_established(TransportParameters::default());
        assert_eq!(
            connection.send_datagram(b"data"),
            Err(crate::SendDatagramError::Unsupported)
        );

        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut parameters = TransportParameters::default();
        parameters.set_var(
            transport_parameter_ids::MAX_DATAGRAM_FRAME_SIZE,
            VarInt::from_u32(3),
        );
        connection.mark_established(parameters);
        assert_eq!(
            connection.send_datagram(b"data"),
            Err(crate::SendDatagramError::TooLarge { maximum: 1 })
        );
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "current_thread")]
    async fn runtime_activity_waiter_consumes_datagram_signal() {
        let conn = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        negotiate_test_datagrams(&conn);
        conn.send_datagram(b"ping").unwrap();
        tokio::time::timeout(
            Duration::from_millis(10),
            conn.wait_for_runtime_activity(None),
        )
        .await
        .expect("runtime activity wait timed out");
    }

    #[test]
    fn send_stream_write_waits_then_returns_partial_credit_sized_chunk() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (mut send, _) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut write = Box::pin(send.write(b"hello world"));

        assert!(matches!(write.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxData(VarInt::from_u32(5)).encode(),
            )
            .unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamData {
                    stream_id: VarInt::ZERO,
                    maximum: VarInt::from_u32(5),
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(write.as_mut().poll(&mut cx), Poll::Ready(Ok(5))));
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn high_level_connection_drains_qlog_events() {
        let connection = Connection::new_with_qlog(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            ProtoTransportConfig::default(),
            None,
            64,
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_DATA,
            VarInt::from_u32(4),
        );
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAMS_BIDI,
            VarInt::from_u32(1),
        );
        connection.mark_established(params);
        let (mut send, _recv) = connection.open_bi().into_inner().unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxData(VarInt::from_u32(4)).encode(),
            )
            .unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamData {
                    stream_id: VarInt::ZERO,
                    maximum: VarInt::from_u32(4),
                }
                .encode(),
            )
            .unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Box::pin(send.write_all(b"ping")).as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        let _ = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .poll_transmit(web_time::Instant::now());

        let first = connection.drain_qlog_events();
        let second = connection.drain_qlog_events();

        assert!(first.iter().any(|event| matches!(
            event,
            quion_proto::qlog::QlogEvent::StreamDataQueued {
                stream_id: 0,
                len: 4,
                ..
            }
        )));
        assert!(first.iter().any(|event| matches!(
            event,
            quion_proto::qlog::QlogEvent::PacketSent {
                frame_type: "stream",
                ..
            }
        )));
        assert!(first.iter().any(|event| matches!(
            event,
            quion_proto::qlog::QlogEvent::TransportParametersSet {
                owner: "peer",
                initial_max_data: Some(4),
                initial_max_streams_bidi: Some(1),
                ..
            }
        )));
        assert!(first.iter().any(|event| matches!(
            event,
            quion_proto::qlog::QlogEvent::PathStateUpdated { state: "validated" }
        )));
        assert!(second.is_empty());
    }

    #[test]
    fn transport_qlog_handler_receives_events_from_stream_operations() {
        let captured = Arc::new(Mutex::new(Vec::<crate::QlogEvent>::new()));
        let mut transport = crate::config::TransportConfig::default();
        let sink = captured.clone();
        transport.set_qlog_handler(move |event| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.clone());
        });
        let connection = Connection::new_with_qlog(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            transport.clone().into_proto(),
            transport.qlog_handler(),
            transport.max_buffered_qlog_events(),
        );
        let (mut send, _) = connection.open_bi().into_inner().unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxData(VarInt::from_u32(4)).encode(),
            )
            .unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamData {
                    stream_id: VarInt::ZERO,
                    maximum: VarInt::from_u32(4),
                }
                .encode(),
            )
            .unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Box::pin(send.write_all(b"ping")).as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));

        let events = captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        assert!(events.iter().any(|event| matches!(
            event,
            crate::QlogEvent::StreamDataQueued {
                stream_id: 0,
                len: 4,
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            crate::QlogEvent::FlowControlUpdated {
                scope: "stream",
                maximum: 4,
                ..
            }
        )));
    }

    #[test]
    fn recv_stream_read_reports_peer_reset() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut read = Box::pin(recv.read_to_end(1024));

        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::ResetStream {
                    stream_id: VarInt::ZERO,
                    error_code: VarInt::from_u32(9),
                    final_size: VarInt::ZERO,
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::ReadError::Reset(code))) if code == VarInt::from_u32(9)
        ));
    }

    #[test]
    fn stopped_recv_stream_reports_peer_reset() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        recv.stop(VarInt::from_u32(11)).unwrap();
        let mut read = Box::pin(recv.read_to_end(1024));

        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::ResetStream {
                    stream_id: VarInt::ZERO,
                    error_code: VarInt::from_u32(9),
                    final_size: VarInt::ZERO,
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::ReadError::Reset(code))) if code == VarInt::from_u32(9)
        ));
    }

    #[test]
    fn recv_stream_read_exact_reports_finished_early_on_fin() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read = Box::pin(recv.read_exact(&mut buf));

        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: true,
                    data: b"short".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::ReadError::FinishedEarly))
        ));
    }

    #[test]
    fn recv_stream_read_with_empty_buffer_completes_immediately() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut buf = [];
        let mut read = Box::pin(recv.read(&mut buf));

        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Ok(Some(0)))
        ));
    }

    #[test]
    fn recv_stream_read_to_end_accumulates_until_fin() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut read = Box::pin(recv.read_to_end(16));

        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: false,
                    data: b"hello ".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();
        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::from_u32(6),
                    fin: true,
                    data: b"world".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Ok(bytes)) if bytes == b"hello world"
        ));
    }

    #[test]
    fn recv_stream_read_to_end_does_not_preallocate_the_size_limit() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut read = Box::pin(recv.read_to_end(usize::MAX));

        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: true,
                    data: b"bounded".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Ok(bytes)) if bytes == b"bounded"
        ));
    }

    #[test]
    fn recv_stream_read_to_end_allows_fin_after_exact_limit() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut read = Box::pin(recv.read_to_end(4));

        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: false,
                    data: b"data".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();
        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::from_u32(4),
                    fin: true,
                    data: bytes::Bytes::new(),
                }
                .encode(),
            )
            .unwrap();
        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Ok(bytes)) if bytes == b"data"
        ));
    }

    #[test]
    fn recv_stream_read_to_end_enforces_limit() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut read = Box::pin(recv.read_to_end(4));

        assert!(matches!(read.as_mut().poll(&mut cx), Poll::Pending));
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: true,
                    data: b"hello".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(
            read.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::ReadError::TooLong(4)))
        ));
    }

    #[test]
    fn recv_stream_read_chunk_unordered_reads_out_of_order_data() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::from_u32(5),
                    fin: true,
                    data: b"world".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        let mut read = Box::pin(recv.read_chunk(16, false));
        let chunk = match read.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(Some(chunk))) => chunk,
            other => panic!("unexpected poll state: {other:?}"),
        };

        assert_eq!(chunk.offset, 5);
        assert_eq!(chunk.bytes.as_ref(), b"world");
        assert!(chunk.fin);
    }

    #[test]
    fn recv_stream_rejects_mixing_ordered_and_unordered_reads() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (_, mut recv) = connection.open_bi().into_inner().unwrap();
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::from_u32(5),
                    fin: true,
                    data: b"world".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        let mut unordered = Box::pin(recv.read_chunk(16, false));
        assert!(matches!(
            unordered.as_mut().poll(&mut cx),
            Poll::Ready(Ok(Some(_)))
        ));
        drop(unordered);
        let mut buf = [0u8; 5];
        let mut ordered = Box::pin(recv.read(&mut buf));
        assert!(matches!(
            ordered.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::error::ReadError::IllegalOrderedState))
        ));
    }

    #[test]
    fn stream_reset_and_stop_queue_control_frames() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let (mut send, mut recv) = connection.open_bi().into_inner().unwrap();
        {
            let mut proto = connection
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.increase_connection_send_limit(5);
            proto
                .increase_stream_send_limit(StreamId(VarInt::ZERO), 5)
                .unwrap();
        }
        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Box::pin(send.write_all(b"hello")).as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        send.reset(VarInt::from_u32(7)).unwrap();
        recv.stop(VarInt::from_u32(11)).unwrap();

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let first = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let second = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let first_frame = quion_proto::frame::Frame::decode(&first.contents)
            .unwrap()
            .0;
        let second_frame = quion_proto::frame::Frame::decode(&second.contents)
            .unwrap()
            .0;
        let frames = [first_frame, second_frame];

        assert!(frames.iter().any(|frame| matches!(
            frame,
            quion_proto::frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } if *stream_id == VarInt::ZERO
                && *error_code == VarInt::from_u32(7)
                && *final_size == VarInt::from_u32(5)
        )));
        assert!(frames.iter().any(|frame| matches!(
            frame,
            quion_proto::frame::Frame::StopSending {
                stream_id,
                error_code,
            } if *stream_id == VarInt::ZERO && *error_code == VarInt::from_u32(11)
        )));
    }

    #[test]
    fn accept_bi_returns_closed_error_after_close() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut accept = connection.accept_bi();

        assert!(matches!(Pin::new(&mut accept).poll(&mut cx), Poll::Pending));
        connection.close(VarInt::from_u32(7), b"bye");
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            Pin::new(&mut accept).poll(&mut cx),
            Poll::Ready(Err(ConnectionError::LocallyClosed))
        ));
    }

    #[test]
    fn simultaneous_close_keeps_first_terminal_reason() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection.close(VarInt::from_u32(7), b"bye");
        let frame = quion_proto::frame::Frame::ApplicationClose {
            error_code: VarInt::from_u32(42),
            reason: b"peer".to_vec(),
        }
        .encode();

        connection.recv_test_frame_payload(&frame).unwrap();

        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut closed = Box::pin(connection.closed());
        assert!(matches!(
            closed.as_mut().poll(&mut cx),
            Poll::Ready(ConnectionError::LocallyClosed)
        ));
    }

    #[test]
    fn local_close_ignores_subsequent_stream_frames() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection.close(VarInt::from_u32(7), b"bye");

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: false,
                    data: b"ignored".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            proto
                .read_recv_stream(quion_proto::streams::StreamId(VarInt::ZERO), 1024, true)
                .is_none()
        );
    }

    #[test]
    fn peer_close_ignores_subsequent_stream_frames() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::ApplicationClose {
                    error_code: VarInt::from_u32(42),
                    reason: b"done".to_vec(),
                }
                .encode(),
            )
            .unwrap();

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: false,
                    data: b"ignored".to_vec().into(),
                }
                .encode(),
            )
            .unwrap();

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            proto
                .read_recv_stream(quion_proto::streams::StreamId(VarInt::ZERO), 1024, true)
                .is_none()
        );
    }

    #[test]
    fn malformed_close_frame_maps_to_transport_error_without_closing() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let malformed = vec![0x1d, 0x2a, 0x04, b'b', b'a'];

        let error = connection.recv_test_frame_payload(&malformed).unwrap_err();

        assert_eq!(
            error,
            ConnectionError::TransportError(TransportErrorCode::FrameEncodingError)
        );
        assert!(!connection.is_closed());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn authenticated_one_rtt_frame_error_closes_connection() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );

        connection
            .close_for_authenticated_one_rtt_error(quion_proto::CodecError::MalformedFrame)
            .unwrap();

        assert!(connection.is_closed());
        assert_eq!(
            connection.closed_error(),
            Some(ConnectionError::TransportError(
                TransportErrorCode::FrameEncodingError
            ))
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn stateless_reset_packet_closes_connection() {
        use quion_proto::{cid::ConnectionId, crypto::rustls::RustlsKeyStore};

        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut server_keys = RustlsKeyStore::default();
        let token = [0x5a; 16];
        connection.set_test_peer_stateless_reset_token(token);

        let mut packet = vec![0u8; 32];
        let token_offset = packet.len() - token.len();
        packet[0] = 0x40;
        packet[1..9].copy_from_slice(ConnectionId::from_slice(b"srvcid01").unwrap().as_bytes());
        packet[token_offset..].copy_from_slice(&token);

        connection
            .recv_protected_one_rtt_udp(
                &mut server_keys,
                &mut packet,
                8,
                None,
                &quion_udp::RecvMeta {
                    local: Some("127.0.0.1:0".parse().unwrap()),
                    remote: "127.0.0.1:1".parse().unwrap(),
                    interface: None,
                    ecn: None,
                    segment_size: None,
                    len: 32,
                },
            )
            .unwrap();

        assert!(connection.is_closed());
        assert!(matches!(
            connection.closed_error(),
            Some(ConnectionError::Reset)
        ));
    }

    #[test]
    fn new_connection_id_updates_active_peer_connection_id_and_reset_token() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let initial_token = [0x01; 16];
        connection.set_test_peer_stateless_reset_token(initial_token);
        let first_cid = quion_proto::cid::ConnectionId::from_slice(b"peercid1").unwrap();
        let second_cid = quion_proto::cid::ConnectionId::from_slice(b"peercid2").unwrap();
        let reset_packet = |token: [u8; 16]| {
            [0x40, 0, 0, 0, 0]
                .into_iter()
                .chain(token)
                .collect::<Vec<_>>()
        };

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::NewConnectionId {
                    sequence: VarInt::from_u32(1),
                    retire_prior_to: VarInt::ZERO,
                    connection_id: first_cid.as_bytes().to_vec(),
                    reset_token: [0x11; 16],
                }
                .encode(),
            )
            .unwrap();
        assert_eq!(
            connection.active_peer_connection_id(),
            Some(first_cid.clone())
        );
        assert_eq!(
            connection.take_active_peer_connection_id_update(),
            Some(first_cid)
        );
        assert_eq!(connection.take_active_peer_connection_id_update(), None);
        assert!(connection.matches_stateless_reset(&reset_packet(initial_token)));
        assert!(connection.matches_stateless_reset(&reset_packet([0x11; 16])));
        let mut long_header_packet = reset_packet(initial_token);
        long_header_packet[0] = 0xc0;
        assert!(!connection.matches_stateless_reset(&long_header_packet));

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::NewConnectionId {
                    sequence: VarInt::from_u32(2),
                    retire_prior_to: VarInt::from_u32(2),
                    connection_id: second_cid.as_bytes().to_vec(),
                    reset_token: [0x22; 16],
                }
                .encode(),
            )
            .unwrap();
        assert_eq!(
            connection.active_peer_connection_id(),
            Some(second_cid.clone())
        );
        assert_eq!(
            connection.take_active_peer_connection_id_update(),
            Some(second_cid)
        );
        assert_eq!(connection.take_active_peer_connection_id_update(), None);
        assert!(!connection.matches_stateless_reset(&reset_packet(initial_token)));
        assert!(!connection.matches_stateless_reset(&reset_packet([0x11; 16])));
        assert!(connection.matches_stateless_reset(&reset_packet([0x22; 16])));
        let mut retired = BTreeSet::new();
        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(transmit) = proto.poll_transmit(web_time::Instant::now()) {
            if let quion_proto::frame::Frame::RetireConnectionId(sequence) =
                quion_proto::frame::Frame::decode(&transmit.contents)
                    .unwrap()
                    .0
            {
                retired.insert(sequence.into_inner());
            }
        }
        assert_eq!(retired, BTreeSet::from([0, 1]));
    }

    #[test]
    fn conflicting_peer_connection_id_sequence_closes_connection() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        for (connection_id, reset_token) in [
            (b"peercid1".to_vec(), [0x11; 16]),
            (b"peercid2".to_vec(), [0x22; 16]),
        ] {
            connection
                .recv_test_frame_payload(
                    &quion_proto::frame::Frame::NewConnectionId {
                        sequence: VarInt::from_u32(1),
                        retire_prior_to: VarInt::ZERO,
                        connection_id,
                        reset_token,
                    }
                    .encode(),
                )
                .unwrap();
        }

        assert!(matches!(
            connection.closed_error(),
            Some(ConnectionError::TransportError(
                TransportErrorCode::ProtocolViolation
            ))
        ));
    }

    #[test]
    fn peer_cannot_reuse_connection_id_or_reset_token_across_sequences() {
        for second in [
            quion_proto::frame::Frame::NewConnectionId {
                sequence: VarInt::from_u32(2),
                retire_prior_to: VarInt::ZERO,
                connection_id: b"peercid1".to_vec(),
                reset_token: [0x22; 16],
            },
            quion_proto::frame::Frame::NewConnectionId {
                sequence: VarInt::from_u32(2),
                retire_prior_to: VarInt::ZERO,
                connection_id: b"peercid2".to_vec(),
                reset_token: [0x11; 16],
            },
        ] {
            let connection = Connection::new(
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:1".parse().unwrap(),
            );
            connection
                .recv_test_frame_payload(
                    &quion_proto::frame::Frame::NewConnectionId {
                        sequence: VarInt::from_u32(1),
                        retire_prior_to: VarInt::ZERO,
                        connection_id: b"peercid1".to_vec(),
                        reset_token: [0x11; 16],
                    }
                    .encode(),
                )
                .unwrap();
            connection
                .recv_test_frame_payload(&second.encode())
                .unwrap();

            assert!(matches!(
                connection.closed_error(),
                Some(ConnectionError::TransportError(
                    TransportErrorCode::ProtocolViolation
                ))
            ));
        }
    }

    #[test]
    fn peer_cannot_change_or_reuse_initial_connection_id() {
        for frame in [
            quion_proto::frame::Frame::NewConnectionId {
                sequence: VarInt::ZERO,
                retire_prior_to: VarInt::ZERO,
                connection_id: b"different".to_vec(),
                reset_token: [0x11; 16],
            },
            quion_proto::frame::Frame::NewConnectionId {
                sequence: VarInt::from_u32(1),
                retire_prior_to: VarInt::ZERO,
                connection_id: b"initial1".to_vec(),
                reset_token: [0x22; 16],
            },
        ] {
            let connection = Connection::new(
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:1".parse().unwrap(),
            );
            connection.register_initial_peer_connection_id(
                quion_proto::cid::ConnectionId::from_slice(b"initial1").unwrap(),
            );

            connection.recv_test_frame_payload(&frame.encode()).unwrap();

            assert!(matches!(
                connection.closed_error(),
                Some(ConnectionError::TransportError(
                    TransportErrorCode::ProtocolViolation
                ))
            ));
        }
    }

    #[test]
    fn endpoint_budget_accounts_and_releases_connection_id_metadata() {
        let budget = Arc::new(EndpointMemoryBudget::new(4096));
        {
            let connection = Connection::new(
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:1".parse().unwrap(),
            );
            assert!(connection.attach_endpoint_memory_budget(budget.clone()));
            assert!(connection.register_local_connection_id(
                0,
                quion_proto::cid::ConnectionId::from_slice(b"localcid").unwrap(),
            ));
            assert!(connection.register_initial_peer_connection_id(
                quion_proto::cid::ConnectionId::from_slice(b"peercid0").unwrap(),
            ));

            assert_eq!(budget.used_bytes(), connection.connection_id_memory_bytes());
            assert!(budget.used_bytes() > 0);
        }
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn endpoint_budget_rejects_connection_id_metadata_growth() {
        let budget = Arc::new(EndpointMemoryBudget::new(1));
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        assert!(connection.attach_endpoint_memory_budget(budget.clone()));

        assert!(!connection.register_local_connection_id(
            0,
            quion_proto::cid::ConnectionId::from_slice(b"localcid").unwrap(),
        ));
        assert_eq!(connection.connection_id_memory_bytes(), 0);
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn peer_connection_id_growth_closes_when_endpoint_budget_is_exhausted() {
        let budget = Arc::new(EndpointMemoryBudget::new(1));
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        assert!(connection.attach_endpoint_memory_budget(budget.clone()));

        connection.note_peer_connection_id(1, 0, b"peercid1", [0x11; 16]);

        assert_eq!(connection.connection_id_memory_bytes(), 0);
        assert!(matches!(
            connection.closed_error(),
            Some(ConnectionError::TransportError(
                TransportErrorCode::InternalError
            ))
        ));
        assert!(budget.used_bytes() <= budget.max_bytes());
    }

    #[test]
    fn delayed_connection_id_below_retirement_threshold_is_not_reactivated() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::NewConnectionId {
                    sequence: VarInt::from_u32(3),
                    retire_prior_to: VarInt::from_u32(3),
                    connection_id: b"peercid3".to_vec(),
                    reset_token: [0x33; 16],
                }
                .encode(),
            )
            .unwrap();
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::NewConnectionId {
                    sequence: VarInt::from_u32(2),
                    retire_prior_to: VarInt::ZERO,
                    connection_id: b"peercid2".to_vec(),
                    reset_token: [0x22; 16],
                }
                .encode(),
            )
            .unwrap();

        assert_eq!(
            connection.active_peer_connection_id(),
            Some(quion_proto::cid::ConnectionId::from_slice(b"peercid3").unwrap())
        );
        let mut retired = BTreeSet::new();
        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(transmit) = proto.poll_transmit(web_time::Instant::now()) {
            if let quion_proto::frame::Frame::RetireConnectionId(sequence) =
                quion_proto::frame::Frame::decode(&transmit.contents)
                    .unwrap()
                    .0
            {
                retired.insert(sequence.into_inner());
            }
        }
        assert_eq!(retired, BTreeSet::from([0, 2]));
    }

    #[test]
    fn retire_connection_id_drains_registered_local_connection_id() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let cid = quion_proto::cid::ConnectionId::from_slice(b"localcid").unwrap();
        connection.register_local_connection_id(1, cid.clone());

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::RetireConnectionId(VarInt::from_u32(1)).encode(),
            )
            .unwrap();

        assert_eq!(connection.drain_retired_local_connection_ids(), vec![cid]);
        assert!(connection.drain_retired_local_connection_ids().is_empty());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn retiring_packet_destination_connection_id_closes_connection() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let cid = quion_proto::cid::ConnectionId::from_slice(b"localcid").unwrap();
        assert!(connection.register_local_connection_id(1, cid.clone()));

        let effects = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .handle_opened_frame_packet(
                quion_proto::crypto::packet::OpenedFramePacket {
                    max_datagram_frame_size: None,
                    level: quion_proto::crypto::EncryptionLevel::OneRtt,
                    header: quion_proto::packet::Header::Short(quion_proto::packet::ShortHeader {
                        spin: false,
                        key_phase: false,
                        dst_cid: cid,
                        packet_number_len: 2,
                    }),
                    packet_number: 1,
                    ecn: None,
                    frames: vec![quion_proto::frame::Frame::RetireConnectionId(
                        VarInt::from_u32(1),
                    )]
                    .into(),
                    consumed: 0,
                },
                web_time::Instant::now(),
            )
            .unwrap();
        connection.handle_effects(&effects);

        assert_eq!(
            connection.closed_error(),
            Some(ConnectionError::TransportError(
                TransportErrorCode::ProtocolViolation
            ))
        );
        assert!(connection.drain_retired_local_connection_ids().is_empty());
    }

    #[test]
    fn retired_connection_id_history_preserves_packet_context_validation() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let cid = quion_proto::cid::ConnectionId::from_slice(b"localcid").unwrap();
        assert!(connection.register_local_connection_id(1, cid.clone()));
        assert_eq!(
            connection.note_retired_local_connection_id(1, None),
            LocalConnectionIdRetirement::New
        );
        assert_eq!(
            connection.drain_retired_local_connection_ids(),
            vec![cid.clone()]
        );

        assert_eq!(
            connection.note_retired_local_connection_id(1, Some(&cid)),
            LocalConnectionIdRetirement::PacketDestinationConnectionId
        );
    }

    #[test]
    fn zero_length_local_connection_id_rejects_retirement() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        assert!(connection.register_local_connection_id(0, quion_proto::cid::ConnectionId::EMPTY));

        let error = connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::RetireConnectionId(VarInt::ZERO).encode(),
            )
            .unwrap_err();
        assert_eq!(
            error,
            ConnectionError::TransportError(TransportErrorCode::ProtocolViolation)
        );
    }

    #[test]
    fn zero_length_peer_connection_id_rejects_new_connection_id() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        assert!(
            connection.register_initial_peer_connection_id(quion_proto::cid::ConnectionId::EMPTY)
        );

        let error = connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::NewConnectionId {
                    sequence: VarInt::from_u32(1),
                    retire_prior_to: VarInt::ZERO,
                    connection_id: b"peercid1".to_vec(),
                    reset_token: [7; 16],
                }
                .encode(),
            )
            .unwrap_err();
        assert_eq!(
            error,
            ConnectionError::TransportError(TransportErrorCode::ProtocolViolation)
        );
    }

    #[test]
    fn duplicate_retire_connection_id_is_idempotent() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let cid = quion_proto::cid::ConnectionId::from_slice(b"localcid").unwrap();
        connection.register_local_connection_id(1, cid.clone());
        let frame = quion_proto::frame::Frame::RetireConnectionId(VarInt::from_u32(1)).encode();

        connection.recv_test_frame_payload(&frame).unwrap();
        connection.recv_test_frame_payload(&frame).unwrap();

        assert!(!connection.is_closed());
        assert_eq!(connection.drain_retired_local_connection_ids(), vec![cid]);
    }

    #[test]
    fn retiring_unknown_connection_id_closes_connection() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::RetireConnectionId(VarInt::from_u32(7)).encode(),
            )
            .unwrap();

        assert!(matches!(
            connection.closed_error(),
            Some(ConnectionError::TransportError(
                TransportErrorCode::ProtocolViolation
            ))
        ));
    }

    #[test]
    fn exceeding_active_connection_id_limit_closes_connection() {
        let local = ProtoTransportConfig {
            active_connection_id_limit: VarInt::from_u32(3),
            ..ProtoTransportConfig::default()
        };
        let connection = Connection::new_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            local,
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::ACTIVE_CONNECTION_ID_LIMIT,
            VarInt::from_u32(1),
        );
        connection.mark_established(params);

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::NewConnectionId {
                    sequence: VarInt::from_u32(1),
                    retire_prior_to: VarInt::ZERO,
                    connection_id: b"peercid1".to_vec(),
                    reset_token: [0x11; 16],
                }
                .encode(),
            )
            .unwrap();
        assert!(!connection.is_closed());

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::NewConnectionId {
                    sequence: VarInt::from_u32(2),
                    retire_prior_to: VarInt::ZERO,
                    connection_id: b"peercid2".to_vec(),
                    reset_token: [0x22; 16],
                }
                .encode(),
            )
            .unwrap();
        assert!(!connection.is_closed());

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::NewConnectionId {
                    sequence: VarInt::from_u32(3),
                    retire_prior_to: VarInt::ZERO,
                    connection_id: b"peercid3".to_vec(),
                    reset_token: [0x33; 16],
                }
                .encode(),
            )
            .unwrap();

        assert!(matches!(
            connection.closed_error(),
            Some(ConnectionError::TransportError(
                TransportErrorCode::ConnectionIdLimitError
            ))
        ));
    }

    #[test]
    fn client_establishment_retains_handshake_space_until_confirmation() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let now = web_time::Instant::now();
        {
            let mut proto = connection
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.record_sent_crypto_packet(
                quion_proto::crypto::EncryptionLevel::Initial,
                0,
                1200,
                vec![quion_proto::crypto::stream::CryptoFrame {
                    level: quion_proto::crypto::EncryptionLevel::Initial,
                    offset: 0,
                    bytes: b"initial".to_vec(),
                }],
                now,
            );
            proto.record_sent_packet(
                quion_proto::crypto::EncryptionLevel::Handshake,
                0,
                1200,
                true,
                now,
            );
            proto.record_sent_packet(
                quion_proto::crypto::EncryptionLevel::ZeroRtt,
                0,
                600,
                true,
                now,
            );
            proto.record_sent_packet(
                quion_proto::crypto::EncryptionLevel::OneRtt,
                1,
                800,
                true,
                now,
            );
            assert_eq!(proto.stats().bytes_in_flight, 3800);
        }

        connection.mark_established(TransportParameters::default());

        let proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(proto.stats().bytes_in_flight, 2000);
        assert!(!proto.is_handshake_confirmed());
        assert_eq!(
            proto
                .ack_tracker()
                .largest_received(quion_proto::crypto::EncryptionLevel::Initial),
            None
        );
    }

    #[test]
    fn server_establishment_confirms_handshake_and_discards_handshake_space() {
        let connection = Connection::server(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let now = web_time::Instant::now();
        {
            let mut proto = connection
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.record_sent_packet(
                quion_proto::crypto::EncryptionLevel::Handshake,
                0,
                1200,
                true,
                now,
            );
            proto.record_sent_packet(
                quion_proto::crypto::EncryptionLevel::OneRtt,
                0,
                800,
                true,
                now,
            );
        }

        connection.mark_established(TransportParameters::default());

        let proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(proto.is_handshake_confirmed());
        assert_eq!(proto.stats().bytes_in_flight, 800);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn idle_extension_only_uses_first_ack_eliciting_send_after_receive() {
        let connection = Connection::new_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            ProtoTransportConfig {
                max_idle_timeout_ms: VarInt::from_u32(10_000),
                ..ProtoTransportConfig::default()
            },
        );
        connection.mark_established(TransportParameters::default());
        let now = web_time::Instant::now();
        connection.record_activity(now);
        let send = |number, seconds, ack_eliciting| {
            connection.proto.lock().unwrap().record_sent_packet(
                quion_proto::crypto::EncryptionLevel::OneRtt,
                number,
                100,
                ack_eliciting,
                now + Duration::from_secs(seconds),
            );
        };
        send(0, 1, false);
        assert_eq!(
            connection.idle_deadline(),
            Some(now + Duration::from_secs(10))
        );
        send(1, 2, true);
        send(2, 3, true);
        assert_eq!(
            connection.idle_deadline(),
            Some(now + Duration::from_secs(12))
        );
        connection.record_activity(now + Duration::from_secs(4));
        send(3, 5, true);
        assert_eq!(
            connection.idle_deadline(),
            Some(now + Duration::from_secs(15))
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn keep_alive_deadline_is_optional_and_queues_ping() {
        let connection = Connection::new_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            ProtoTransportConfig {
                max_idle_timeout_ms: VarInt::from_u32(10_000),
                keep_alive_interval: Some(Duration::from_secs(20)),
                ..ProtoTransportConfig::default()
            },
        );
        assert_eq!(connection.keep_alive_deadline(), None);
        connection.mark_established(TransportParameters::default());
        let now = web_time::Instant::now();
        connection.record_activity(now);
        let deadline = now + Duration::from_secs(5);
        assert_eq!(connection.keep_alive_deadline(), Some(deadline));
        assert!(connection.on_timeout(deadline).unwrap());
        assert!(connection.proto.lock().unwrap().has_pending_transmit());
        assert_eq!(
            connection.keep_alive_deadline(),
            Some(now + Duration::from_secs(10))
        );
        let disabled = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        disabled.mark_established(TransportParameters::default());
        assert_eq!(disabled.keep_alive_deadline(), None);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn idle_timeout_uses_negotiated_limit_and_closes_connection() {
        let transport = ProtoTransportConfig {
            max_idle_timeout_ms: VarInt::from_u32(30),
            ..ProtoTransportConfig::default()
        };
        let connection = Connection::new_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            transport,
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::MAX_IDLE_TIMEOUT,
            VarInt::from_u32(10),
        );
        connection.mark_established(params);

        let now = web_time::Instant::now();
        connection.record_activity(now);
        let timeout = connection.next_timeout().unwrap();

        let floor = connection.proto.lock().unwrap().idle_timeout_floor();
        assert_eq!(timeout, now + Duration::from_millis(10).max(floor));
        assert!(
            !connection
                .on_timeout(now + Duration::from_millis(9))
                .unwrap()
        );
        assert!(connection.on_timeout(timeout).unwrap());
        assert!(connection.is_closed());

        let waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut cx = Context::from_waker(&waker);
        let mut closed = Box::pin(connection.closed());
        assert!(matches!(
            closed.as_mut().poll(&mut cx),
            Poll::Ready(ConnectionError::TimedOut)
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn connection_timeout_api_processes_proto_timeouts() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let now = web_time::Instant::now();
        {
            let mut proto = connection
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.record_sent_packet(
                quion_proto::crypto::EncryptionLevel::Initial,
                0,
                1200,
                true,
                now,
            );
        }

        let timeout = connection
            .next_timeout()
            .expect("ack-eliciting crypto transmit should arm loss timer");
        assert!(!connection.on_timeout(now).unwrap());
        assert!(connection.on_timeout(timeout).unwrap());
    }

    #[test]
    fn established_connection_rejects_streams_without_negotiated_credit() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection.mark_established(TransportParameters::default());

        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Bi),
            Err(ConnectionError::BidirectionalStreamLimitReached)
        );
        {
            let mut proto = connection
                .proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
            let (frame, consumed) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
            assert_eq!(consumed, transmit.contents.len());
            assert_eq!(
                frame,
                quion_proto::frame::Frame::StreamsBlockedBidi(VarInt::ZERO)
            );
        }
        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Uni),
            Err(ConnectionError::UnidirectionalStreamLimitReached)
        );
        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            quion_proto::frame::Frame::StreamsBlockedUni(VarInt::ZERO)
        );
    }

    #[test]
    fn negotiated_stream_parameters_seed_outgoing_stream_credit() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_DATA,
            VarInt::from_u32(5),
        );
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAMS_BIDI,
            VarInt::from_u32(1),
        );
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            VarInt::from_u32(5),
        );
        connection.mark_established(params);

        let stream_id = connection
            .open_outgoing_stream(StreamKind::Bi)
            .expect("stream credit should allow one bidirectional stream");
        let stats = connection.stats();
        assert_eq!(stats.streams_opened, 1);
        assert!(stats.handshake_duration.is_some());
        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Bi),
            Err(ConnectionError::BidirectionalStreamLimitReached)
        );

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            quion_proto::frame::Frame::StreamsBlockedBidi(VarInt::from_u32(1))
        );
        proto.queue_stream_data(stream_id, b"hello world").unwrap();
        let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            quion_proto::frame::Frame::Stream {
                stream_id: stream_id.0,
                offset: VarInt::ZERO,
                fin: false,
                data: b"hello".to_vec().into(),
            }
        );
    }

    #[test]
    fn max_streams_frame_releases_additional_outgoing_stream_credit() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAMS_BIDI,
            VarInt::from_u32(1),
        );
        connection.mark_established(params);

        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Bi).unwrap(),
            StreamId(VarInt::ZERO)
        );
        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Bi),
            Err(ConnectionError::BidirectionalStreamLimitReached)
        );

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamsBidi(VarInt::from_u32(2)).encode(),
            )
            .unwrap();

        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Bi).unwrap(),
            StreamId(VarInt::from_u32(4))
        );
    }

    #[test]
    fn max_streams_uni_frame_releases_additional_outgoing_stream_credit() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAMS_UNI,
            VarInt::from_u32(1),
        );
        connection.mark_established(params);

        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Uni).unwrap(),
            StreamId(VarInt::from_u32(2))
        );
        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Uni),
            Err(ConnectionError::UnidirectionalStreamLimitReached)
        );

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamsUni(VarInt::from_u32(2)).encode(),
            )
            .unwrap();

        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Uni).unwrap(),
            StreamId(VarInt::from_u32(6))
        );
    }

    #[test]
    fn open_stream_futures_wake_when_peer_increases_stream_limits() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection.mark_established(TransportParameters::default());

        let bidi_wake_count = Arc::new(AtomicUsize::new(0));
        let bidi_waker = counting_waker(bidi_wake_count.clone());
        let mut bidi_context = Context::from_waker(&bidi_waker);
        let mut open_bi = Box::pin(connection.open_bi());
        assert!(matches!(
            open_bi.as_mut().poll(&mut bidi_context),
            Poll::Pending
        ));
        assert_eq!(bidi_wake_count.load(Ordering::SeqCst), 0);

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamsBidi(VarInt::from_u32(1)).encode(),
            )
            .unwrap();
        assert_eq!(bidi_wake_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            open_bi.as_mut().poll(&mut bidi_context),
            Poll::Ready(Ok(_))
        ));

        let uni_wake_count = Arc::new(AtomicUsize::new(0));
        let uni_waker = counting_waker(uni_wake_count.clone());
        let mut uni_context = Context::from_waker(&uni_waker);
        let mut open_uni = Box::pin(connection.open_uni());
        assert!(matches!(
            open_uni.as_mut().poll(&mut uni_context),
            Poll::Pending
        ));

        connection
            .recv_test_frame_payload(
                &quion_proto::frame::Frame::MaxStreamsUni(VarInt::from_u32(1)).encode(),
            )
            .unwrap();
        assert_eq!(uni_wake_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            open_uni.as_mut().poll(&mut uni_context),
            Poll::Ready(Ok(_))
        ));
    }

    #[test]
    fn pending_open_stream_future_wakes_on_connection_close() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        connection.mark_established(TransportParameters::default());
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(wake_count.clone());
        let mut context = Context::from_waker(&waker);
        let mut open = Box::pin(connection.open_bi());

        assert!(matches!(open.as_mut().poll(&mut context), Poll::Pending));
        connection.close(VarInt::ZERO, b"done");
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            open.as_mut().poll(&mut context),
            Poll::Ready(Err(ConnectionError::LocallyClosed))
        ));
    }

    #[test]
    fn negotiated_max_udp_payload_limits_stream_frame_data() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::MAX_UDP_PAYLOAD_SIZE,
            VarInt::from_u32(1200),
        );
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_DATA,
            VarInt::from_u32(2000),
        );
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAMS_BIDI,
            VarInt::from_u32(1),
        );
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            VarInt::from_u32(2000),
        );
        connection.mark_established(params);
        let stream_id = connection.open_outgoing_stream(StreamKind::Bi).unwrap();

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proto.queue_stream_data(stream_id, &[0x55; 1200]).unwrap();
        let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert!(matches!(
            frame,
            quion_proto::frame::Frame::Stream { data, .. }
                if data.len() == 1200 - MAX_PACKET_OVERHEAD
        ));
    }

    #[test]
    fn configured_initial_mtu_limits_stream_frame_data_on_known_path() {
        let connection = Connection::new_with_transport(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            ProtoTransportConfig {
                initial_mtu: 1452,
                ..ProtoTransportConfig::default()
            },
        );
        let mut params = TransportParameters::default();
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_DATA,
            VarInt::from_u32(2000),
        );
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAMS_BIDI,
            VarInt::from_u32(1),
        );
        params.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            VarInt::from_u32(2000),
        );
        connection.mark_established(params);
        let stream_id = connection.open_outgoing_stream(StreamKind::Bi).unwrap();

        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proto.queue_stream_data(stream_id, &[0x55; 1452]).unwrap();
        let transmit = proto.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, _) = quion_proto::frame::Frame::decode(&transmit.contents).unwrap();
        assert!(matches!(
            frame,
            quion_proto::frame::Frame::Stream { data, .. }
                if data.len() == 1452 - MAX_PACKET_OVERHEAD
        ));
    }

    #[test]
    fn server_connections_open_server_initiated_stream_ids() {
        let connection = Connection::server(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );

        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Bi).unwrap(),
            StreamId(VarInt::from_u32(1))
        );
        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Uni).unwrap(),
            StreamId(VarInt::from_u32(3))
        );
    }

    #[test]
    fn high_level_connection_configures_default_inbound_stream_limits() {
        let connection = Connection::server(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut proto = connection
            .proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        proto
            .receive_stream_frame(StreamId(VarInt::from_u32(396)), 0, b"ok".to_vec(), false)
            .unwrap();

        let err = proto
            .receive_stream_frame(
                StreamId(VarInt::from_u32(400)),
                0,
                b"blocked".to_vec(),
                false,
            )
            .unwrap_err();
        assert_eq!(
            err,
            quion_proto::CodecError::Transport(
                quion_proto::transport_error::TransportErrorCode::StreamLimitError
            )
        );
    }

    #[cfg(feature = "zero-rtt")]
    #[test]
    fn zero_rtt_status_is_shared_across_connection_handles() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let cloned = connection.clone();
        assert_eq!(connection.zero_rtt_status(), ZeroRttStatus::NotAttempted);

        connection.set_zero_rtt_status(ZeroRttStatus::Attempted);
        assert_eq!(cloned.zero_rtt_status(), ZeroRttStatus::Attempted);
        cloned.set_zero_rtt_status(ZeroRttStatus::Rejected);
        assert_eq!(connection.zero_rtt_status(), ZeroRttStatus::Rejected);
    }

    #[cfg(feature = "zero-rtt")]
    #[test]
    fn zero_rtt_open_and_datagram_use_cached_peer_limits() {
        let connection = Connection::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut cached = TransportParameters::default();
        cached.set_var(
            transport_parameter_ids::INITIAL_MAX_DATA,
            VarInt::from_u32(64),
        );
        cached.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAM_DATA_UNI,
            VarInt::from_u32(64),
        );
        cached.set_var(
            transport_parameter_ids::INITIAL_MAX_STREAMS_UNI,
            VarInt::from_u32(1),
        );
        connection.prepare_for_zero_rtt(&cached);
        connection.set_zero_rtt_status(ZeroRttStatus::Attempted);

        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Uni).unwrap(),
            StreamId(VarInt::from_u32(2))
        );
        assert_eq!(
            connection.open_outgoing_stream(StreamKind::Uni),
            Err(ConnectionError::UnidirectionalStreamLimitReached)
        );
        assert_eq!(
            connection.send_datagram(b"not-negotiated".to_vec()),
            Err(crate::SendDatagramError::Unsupported)
        );
    }
    #[test]
    fn path_response_on_old_path_validates_candidate_and_challenges_keep_their_source() {
        let original: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let rebound: SocketAddr = "127.0.0.1:4001".parse().unwrap();
        let conn = Connection::server_with_transport(
            "127.0.0.1:3000".parse().unwrap(),
            original,
            ProtoTransportConfig::default(),
        );
        let now = web_time::Instant::now();
        conn.note_authenticated_path(rebound, 1200, &Effects::default(), now);
        let mut effects = Effects::default();
        effects
            .connection_events
            .push(ConnectionEvent::FrameReceived(
                quion_proto::frame::Frame::PathChallenge([7; 8]),
            ));
        conn.note_authenticated_path(original, 1200, &effects, now);
        assert_eq!(conn.transmit_path_destination(true, Some([7; 8])), original);
        assert_eq!(conn.transmit_destination(true), rebound);
        effects.connection_events.clear();
        effects
            .connection_events
            .push(ConnectionEvent::PathValidated);
        conn.note_authenticated_path(original, 1200, &effects, now);
        assert_eq!(conn.remote_address(), rebound);
    }
}
