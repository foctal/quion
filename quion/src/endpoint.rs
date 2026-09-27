use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
use std::sync::atomic::AtomicBool;

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
use tokio::sync::Notify;

use hmac::{Hmac, Mac};
use quion_udp::UdpSocket;
use sha2::Sha256;
use slab::Slab;
use smallvec::SmallVec;
#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
use tracing::Instrument;
use tracing::{debug, trace, trace_span};

use crate::{
    QlogHandler,
    config::{ClientConfig, ServerConfig},
    connection::{
        Connection, EndpointMemoryBudget, EndpointMemoryReservation, ProtocolMemoryTracker,
        RoutedDatagram, RoutedDatagramMemoryBudget,
    },
    diagnostics::{EndpointDiagnostics, EndpointMemoryDiagnostics},
    error::ConnectionError,
    incoming::Incoming,
    stats::EndpointStats,
};

type ConnectionIdGenerator = dyn Fn(usize) -> quion_proto::cid::ConnectionId + Send + Sync;

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
use quion_proto::crypto::{CryptoSession, rustls::RustlsProvider};

/// Client or server QUIC endpoint owning one UDP socket and its connections.
#[derive(Clone)]
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    default_client_config: Arc<Mutex<Option<ClientConfig>>>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    default_server_config: Arc<Mutex<Option<Arc<rustls::ServerConfig>>>>,
    server_qlog_handler: Option<QlogHandler>,
    server_max_buffered_qlog_events: usize,
    transport_config: quion_proto::config::TransportConfig,
    server_connection_limits: ServerConnectionLimits,
    max_tracked_endpoint_paths: usize,
    endpoint_memory_budget: Arc<EndpointMemoryBudget>,
    routed_datagram_memory_budget: Arc<RoutedDatagramMemoryBudget>,
    routed_datagram_buffer_pool: Arc<Mutex<RoutedDatagramPool>>,
    connection_id_generator: Arc<Mutex<Arc<ConnectionIdGenerator>>>,
    stateless_reset_key: [u8; 32],
    state: Arc<Mutex<EndpointState>>,
    stats: Arc<AtomicEndpointStats>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    runtime_notify: Arc<Notify>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    endpoint_driver_scheduler: Arc<EndpointDriverScheduler>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    client_endpoint_driver_running: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct AtomicEndpointStats {
    accepted_connections: AtomicU64,
    opened_connections: AtomicU64,
    closed_connections: AtomicU64,
    rejected_connections: AtomicU64,
    packets_received: AtomicU64,
    packets_sent: AtomicU64,
    dropped_packets: AtomicU64,
}

impl AtomicEndpointStats {
    fn snapshot(&self) -> EndpointStats {
        EndpointStats {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            opened_connections: self.opened_connections.load(Ordering::Relaxed),
            closed_connections: self.closed_connections.load(Ordering::Relaxed),
            rejected_connections: self.rejected_connections.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
        }
    }
}

const MAX_UDP_RECV_BUFFER_SIZE: usize = 65_535;
const MAX_CONSECUTIVE_RUNTIME_PROGRESS: usize = 8;
/// Keep coalesced handshake datagrams within QUIC's required minimum UDP
/// payload size until per-path MTU discovery is available.
const MAX_CRYPTO_DATAGRAM_SIZE: usize = 1_200;
const MAX_ROUTED_DATAGRAM_QUEUE_LEN: usize = 2048;
const MAX_ROUTED_DATAGRAM_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const ONE_RTT_KEY_UPDATE_PACKET_THRESHOLD: u64 = u64::MAX;
const RETRY_TOKEN_LIFETIME: Duration = Duration::from_secs(30);
#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
const RUNTIME_IDLE_POLL_FALLBACK: Duration = Duration::from_millis(1);
#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
const RUNTIME_DRIVER_STOP_GRACE: Duration = Duration::from_millis(100);
const DEFAULT_RUNTIME_DRIVER_WORK_PER_TICK: usize = 32;
// Owning a decrypted packet avoids payload copies, but constructing the shared
// owner costs more than recycling a small ACK/control packet in place.
const MIN_OWNED_CLIENT_PACKET_BYTES: usize = 256;
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
const MAX_ENDPOINT_RECV_BATCH: usize = 32;

#[derive(Default)]
struct RoutedDatagramPool {
    buffers: Vec<RoutedDatagram>,
    closed: bool,
}

impl RoutedDatagramPool {
    fn close(&mut self) {
        self.closed = true;
        self.buffers.clear();
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
struct PooledRoutedDatagram {
    datagram: Option<RoutedDatagram>,
    pool: Arc<Mutex<RoutedDatagramPool>>,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl AsRef<[u8]> for PooledRoutedDatagram {
    fn as_ref(&self) -> &[u8] {
        &self
            .datagram
            .as_ref()
            .expect("routed datagram owner is present")
            .contents
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl AsMut<[u8]> for PooledRoutedDatagram {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self
            .datagram
            .as_mut()
            .expect("routed datagram owner is present")
            .contents
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl Drop for PooledRoutedDatagram {
    fn drop(&mut self) {
        let Some(mut datagram) = self.datagram.take() else {
            return;
        };
        datagram.contents.clear();
        let mut pool = self
            .pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !pool.closed && pool.buffers.len() < MAX_ENDPOINT_RECV_BATCH {
            pool.buffers.push(datagram);
        }
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
const MAX_READY_DRIVERS_PER_TICK: usize = 128;
const CID_TREE_ENTRY_BOOKKEEPING_BYTES: usize = 3 * std::mem::size_of::<usize>();

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EndpointDriverDeadline {
    at: web_time::Instant,
    driver_id: u64,
    generation: u64,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl Ord for EndpointDriverDeadline {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.driver_id.cmp(&self.driver_id))
            .then_with(|| other.generation.cmp(&self.generation))
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl PartialOrd for EndpointDriverDeadline {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
#[derive(Debug, Default)]
struct EndpointDriverScheduleState {
    ready: VecDeque<u64>,
    ready_set: BTreeSet<u64>,
    deadlines: BTreeMap<u64, (u64, Option<web_time::Instant>)>,
    deadline_heap: std::collections::BinaryHeap<EndpointDriverDeadline>,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
#[derive(Debug, Default)]
struct EndpointDriverScheduler {
    state: Mutex<EndpointDriverScheduleState>,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
struct ReadyDriverBatch {
    ids: [u64; MAX_READY_DRIVERS_PER_TICK],
    len: usize,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl IntoIterator for ReadyDriverBatch {
    type Item = u64;
    type IntoIter = std::iter::Take<std::array::IntoIter<u64, MAX_READY_DRIVERS_PER_TICK>>;

    fn into_iter(self) -> Self::IntoIter {
        self.ids.into_iter().take(self.len)
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl EndpointDriverScheduler {
    fn register(&self, driver_id: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.deadlines.entry(driver_id).or_insert((0, None));
        if state.ready_set.insert(driver_id) {
            state.ready.push_back(driver_id);
        }
    }

    fn schedule(&self, driver_id: u64, deadline: Option<web_time::Instant>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = state
            .deadlines
            .get(&driver_id)
            .map_or(1, |(generation, _)| generation.wrapping_add(1));
        state.deadlines.insert(driver_id, (generation, deadline));
        if let Some(at) = deadline {
            state.deadline_heap.push(EndpointDriverDeadline {
                at,
                driver_id,
                generation,
            });
        }
        Self::compact_deadlines_if_needed(&mut state);
    }

    fn remove(&self, driver_id: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.deadlines.remove(&driver_id);
        state.ready_set.remove(&driver_id);
    }

    fn contains(&self, driver_id: u64) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .deadlines
            .contains_key(&driver_id)
    }

    fn registered_len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .deadlines
            .len()
    }

    fn clear(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            EndpointDriverScheduleState::default();
    }

    fn take_ready(
        &self,
        now: web_time::Instant,
        limit: usize,
    ) -> (ReadyDriverBatch, Option<web_time::Instant>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::promote_due(&mut state, now);
        let mut ready = ReadyDriverBatch {
            ids: [0; MAX_READY_DRIVERS_PER_TICK],
            len: 0,
        };
        let limit = limit.min(MAX_READY_DRIVERS_PER_TICK);
        while ready.len < limit {
            let Some(driver_id) = state.ready.pop_front() else {
                break;
            };
            if state.ready_set.remove(&driver_id) && state.deadlines.contains_key(&driver_id) {
                ready.ids[ready.len] = driver_id;
                ready.len += 1;
            }
        }
        let next_deadline = Self::next_deadline_locked(&mut state);
        (ready, next_deadline)
    }

    fn has_ready(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ready
            .is_empty()
    }

    fn promote_due(state: &mut EndpointDriverScheduleState, now: web_time::Instant) {
        while state
            .deadline_heap
            .peek()
            .is_some_and(|deadline| deadline.at <= now)
        {
            let deadline = state.deadline_heap.pop().expect("peeked deadline");
            let current = state.deadlines.get(&deadline.driver_id);
            if current != Some(&(deadline.generation, Some(deadline.at))) {
                continue;
            }
            if state.ready_set.insert(deadline.driver_id) {
                state.ready.push_back(deadline.driver_id);
            }
        }
    }

    fn next_deadline_locked(state: &mut EndpointDriverScheduleState) -> Option<web_time::Instant> {
        while let Some(deadline) = state.deadline_heap.peek().copied() {
            if state.deadlines.get(&deadline.driver_id)
                == Some(&(deadline.generation, Some(deadline.at)))
            {
                return Some(deadline.at);
            }
            state.deadline_heap.pop();
        }
        None
    }

    fn compact_deadlines_if_needed(state: &mut EndpointDriverScheduleState) {
        let retained_limit = state.deadlines.len().saturating_mul(4).saturating_add(64);
        if state.deadline_heap.len() <= retained_limit {
            return;
        }
        state.deadline_heap = state
            .deadlines
            .iter()
            .filter_map(|(&driver_id, &(generation, deadline))| {
                deadline.map(|at| EndpointDriverDeadline {
                    at,
                    driver_id,
                    generation,
                })
            })
            .collect();
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl crate::connection::EndpointDriverWakeup for EndpointDriverScheduler {
    fn wake_driver(&self, driver_id: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.deadlines.contains_key(&driver_id) && state.ready_set.insert(driver_id) {
            state.ready.push_back(driver_id);
        }
    }
}

fn pending_handshake_memory_reservation_bytes(
    config: &quion_proto::config::TransportConfig,
) -> usize {
    usize::try_from(config.max_crypto_buffered_data)
        .unwrap_or(usize::MAX)
        .saturating_mul(8)
        .saturating_add(128 * 1024)
}

#[derive(Debug, Clone, Copy)]
struct ServerConnectionLimits {
    max_connections: usize,
    max_pending_handshakes: usize,
    max_established_connections: usize,
    max_endpoint_memory_bytes: usize,
    max_endpoint_routed_datagram_bytes: usize,
    max_retry_replay_entries: usize,
    retry_enabled: bool,
    max_runtime_driver_work_per_tick: usize,
}

impl ServerConnectionLimits {
    const fn from_transport(config: &crate::config::TransportConfig) -> Self {
        Self {
            max_connections: config.max_connections(),
            max_pending_handshakes: config.max_pending_handshakes(),
            max_established_connections: config.max_established_connections(),
            max_endpoint_memory_bytes: config.max_endpoint_memory_bytes(),
            max_endpoint_routed_datagram_bytes: config.max_endpoint_routed_datagram_bytes(),
            max_retry_replay_entries: config.max_retry_replay_entries(),
            retry_enabled: config.retry_enabled(),
            max_runtime_driver_work_per_tick: config.max_runtime_driver_work_per_tick(),
        }
    }
}

impl core::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Endpoint")
            .field("local_addr", &self.local_addr)
            .field(
                "has_default_client_config",
                &self
                    .default_client_config
                    .lock()
                    .ok()
                    .and_then(|slot| slot.as_ref().map(|_| ()))
                    .is_some(),
            )
            .field(
                "has_server_qlog_handler",
                &self.server_qlog_handler.is_some(),
            )
            .field("has_default_server_config", &{
                #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
                {
                    self.default_server_config
                        .lock()
                        .ok()
                        .and_then(|slot| slot.as_ref().map(|_| ()))
                        .is_some()
                }
                #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
                {
                    false
                }
            })
            .finish()
    }
}

impl Endpoint {
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn activate_endpoint_one_rtt_driver(&self, connection: &Connection, driver_id: u64) {
        self.endpoint_driver_scheduler.register(driver_id);
        connection.set_endpoint_runtime_driver_notify(
            self.runtime_notify.clone(),
            self.endpoint_driver_scheduler.clone(),
            driver_id,
        );
    }

    /// Binds a client endpoint to `bind_addr`.
    pub fn client(bind_addr: SocketAddr) -> Result<Self, crate::EndpointError> {
        Self::client_with_config(crate::config::EndpointConfig::default(), bind_addr)
    }

    /// Binds a client endpoint with endpoint-wide transport and resource
    /// limits.
    ///
    /// Connection-specific TLS and transport defaults are still installed
    /// with [`Self::set_default_client_config`]. Endpoint-wide memory,
    /// routing, and admission limits must be selected here because their
    /// accounting state is created when the socket is bound.
    pub fn client_with_config(
        config: crate::config::EndpointConfig,
        bind_addr: SocketAddr,
    ) -> Result<Self, crate::EndpointError> {
        let transport = config.transport;
        Self::new(
            bind_addr,
            transport.clone().into_proto(),
            ServerConnectionLimits::from_transport(&transport),
            transport.max_tracked_endpoint_paths(),
            None,
            crate::qlog::DEFAULT_MAX_BUFFERED_QLOG_EVENTS,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            None,
        )
    }

    /// Binds a server endpoint and installs its TLS configuration.
    pub fn server(
        server_config: ServerConfig,
        bind_addr: SocketAddr,
    ) -> Result<Self, crate::EndpointError> {
        let server_qlog_handler = server_config.transport.qlog_handler();
        let server_max_buffered_qlog_events = server_config.transport.max_buffered_qlog_events();
        let server_connection_limits =
            ServerConnectionLimits::from_transport(&server_config.transport);
        let max_tracked_endpoint_paths = server_config.transport.max_tracked_endpoint_paths();
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        let rustls = server_config.rustls.clone();
        Self::new(
            bind_addr,
            server_config.transport.clone().into_proto(),
            server_connection_limits,
            max_tracked_endpoint_paths,
            server_qlog_handler,
            server_max_buffered_qlog_events,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            rustls,
        )
    }

    fn new(
        bind_addr: SocketAddr,
        transport_config: quion_proto::config::TransportConfig,
        server_connection_limits: ServerConnectionLimits,
        max_tracked_endpoint_paths: usize,
        server_qlog_handler: Option<QlogHandler>,
        server_max_buffered_qlog_events: usize,
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        default_server_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Result<Self, crate::EndpointError> {
        let socket = UdpSocket::bind(bind_addr).map_err(|error| {
            let quion_udp::UdpError::Io(error) = error;
            crate::EndpointError::Bind { kind: error.kind() }
        })?;
        #[cfg(windows)]
        {
            // Winsock's small default can drop a congestion window while the
            // receive task is descheduled, even over loopback. Keep existing
            // larger buffers and let callers tune this per endpoint afterward.
            let configure = || -> quion_udp::Result<()> {
                if socket.recv_buffer_size()? < 1024 * 1024 {
                    socket.set_recv_buffer_size(1024 * 1024)?;
                }
                Ok(())
            };
            configure().map_err(|error| {
                let quion_udp::UdpError::Io(error) = error;
                crate::EndpointError::Bind { kind: error.kind() }
            })?;
        }
        let local_addr = socket.local_addr().map_err(|error| {
            let quion_udp::UdpError::Io(error) = error;
            crate::EndpointError::LocalAddress { kind: error.kind() }
        })?;
        let stateless_reset_key = rand::random();
        let endpoint_memory_budget = Arc::new(EndpointMemoryBudget::new(
            server_connection_limits.max_endpoint_memory_bytes,
        ));
        let state = EndpointState::new(
            fresh_proto_endpoint(
                max_tracked_endpoint_paths,
                server_connection_limits.max_retry_replay_entries,
                server_connection_limits.retry_enabled,
            ),
            endpoint_memory_budget.clone(),
        );
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        let runtime_notify = Arc::new(Notify::new());
        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            default_client_config: Arc::new(Mutex::new(None)),
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            default_server_config: Arc::new(Mutex::new(default_server_config)),
            server_qlog_handler,
            server_max_buffered_qlog_events,
            transport_config,
            server_connection_limits,
            max_tracked_endpoint_paths,
            endpoint_memory_budget: endpoint_memory_budget.clone(),
            routed_datagram_memory_budget: Arc::new(RoutedDatagramMemoryBudget::new(
                server_connection_limits.max_endpoint_routed_datagram_bytes,
                endpoint_memory_budget,
            )),
            routed_datagram_buffer_pool: Arc::new(Mutex::new(RoutedDatagramPool::default())),
            connection_id_generator: Arc::new(Mutex::new(Arc::new(default_connection_id))),
            stateless_reset_key,
            state: Arc::new(Mutex::new(state)),
            stats: Arc::new(AtomicEndpointStats::default()),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            runtime_notify,
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            endpoint_driver_scheduler: Arc::new(EndpointDriverScheduler::default()),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            client_endpoint_driver_running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Replaces the configuration used by subsequent client connections.
    pub fn set_default_client_config(&self, config: ClientConfig) {
        if let Ok(mut slot) = self.default_client_config.lock() {
            *slot = Some(config);
        }
    }

    /// Requests the operating-system UDP receive-buffer size in bytes.
    ///
    /// The effective size can be smaller than requested because operating
    /// systems apply global limits and may account for bookkeeping overhead.
    pub fn set_socket_recv_buffer_size(&self, size: usize) -> std::io::Result<()> {
        self.socket
            .set_recv_buffer_size(size)
            .map_err(udp_error_into_io)
    }

    /// Returns the effective operating-system UDP receive-buffer size.
    pub fn socket_recv_buffer_size(&self) -> std::io::Result<usize> {
        self.socket.recv_buffer_size().map_err(udp_error_into_io)
    }

    /// Requests the operating-system UDP send-buffer size in bytes.
    ///
    /// The effective size can be smaller than requested because operating
    /// systems apply global limits and may account for bookkeeping overhead.
    pub fn set_socket_send_buffer_size(&self, size: usize) -> std::io::Result<()> {
        self.socket
            .set_send_buffer_size(size)
            .map_err(udp_error_into_io)
    }

    /// Returns the effective operating-system UDP send-buffer size.
    pub fn socket_send_buffer_size(&self) -> std::io::Result<usize> {
        self.socket.send_buffer_size().map_err(udp_error_into_io)
    }

    /// Installs the generator used for locally created connection IDs.
    ///
    /// The endpoint validates that each generated ID has the requested length
    /// and does not exceed QUIC's 20-byte connection-ID limit. The generator
    /// is used for client Initial IDs and subsequently issued active IDs.
    pub fn set_connection_id_generator<F>(&self, generator: F)
    where
        F: Fn(usize) -> quion_proto::cid::ConnectionId + Send + Sync + 'static,
    {
        if let Ok(mut slot) = self.connection_id_generator.lock() {
            *slot = Arc::new(generator);
        }
    }

    /// Starts an outbound connection.
    pub fn connect(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectionError> {
        let _span = trace_span!(
            "quion.endpoint",
            action = "connect",
            local = %self.local_addr,
            remote = %server_addr,
            server_name
        )
        .entered();
        if self.is_closed() {
            return Err(ConnectionError::LocallyClosed);
        }
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.remove_inactive_client_runtime_drivers();
        }
        self.increment_opened_connections(1);
        self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
            state: "connect_started",
            packet_type: "initial",
        });
        let connection_id_length = self.client_connection_id_length();
        let original_dst_cid = self.generate_connection_id(connection_id_length)?;
        let original_src_cid = self.generate_connection_id(connection_id_length)?;
        let client_transport_config = self.client_transport_config();
        let initial_version = self.client_initial_version();
        let connection = Connection::new_with_qlog(
            self.local_addr,
            server_addr,
            client_transport_config.clone(),
            self.client_qlog_handler(),
            self.client_max_buffered_qlog_events(),
        );
        if !connection.register_local_connection_id(0, original_src_cid.clone()) {
            self.increment_rejected_connections(1);
            return Err(ConnectionError::EndpointMemoryLimitReached);
        }
        if !connection.attach_endpoint_memory_budget(self.endpoint_memory_budget.clone()) {
            self.increment_rejected_connections(1);
            return Err(ConnectionError::EndpointMemoryLimitReached);
        }
        let handshake_memory_reservation = self
            .endpoint_memory_budget
            .try_reserve(pending_handshake_memory_reservation_bytes(
                &client_transport_config,
            ))
            .ok_or(ConnectionError::EndpointMemoryLimitReached)?;
        #[cfg_attr(
            not(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            )),
            allow(unused_mut)
        )]
        let mut connecting = Connecting::new(
            connection.clone(),
            self.local_addr,
            server_addr,
            original_dst_cid.clone(),
            original_src_cid.clone(),
            initial_version,
            handshake_memory_reservation,
        );
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        self.maybe_spawn_connect_driver(
            &mut connecting,
            connection,
            server_addr,
            server_name,
            original_dst_cid,
            original_src_cid,
        )?;
        Ok(connecting)
    }

    /// Waits for the next established inbound connection.
    pub fn accept(&self) -> Accept {
        Accept {
            state: self.state.clone(),
        }
    }

    /// Gracefully closes the endpoint and its established connections.
    pub fn close(&self) {
        // Application-owned packet slices can be released after shutdown.
        // Retire the cache first so those late drops cannot retain reservations.
        self.routed_datagram_buffer_pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .close();
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        let connect_handles = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.remove_closed_connections();
            let closed_connections = state.connections.len() as u64;
            state.closed = true;
            state.incoming.clear();
            for connection in state.connections.iter().map(|(_, connection)| connection) {
                connection.close(quion_proto::VarInt::ZERO, b"endpoint closed");
            }
            state.server_initial.clear();
            state.client_crypto.clear();
            let connect_handles = std::mem::take(&mut state.connecting_drivers);
            if let Some(waker) = state.accept_waker.take() {
                waker.wake();
            }
            self.increment_closed_connections(closed_connections);
            connect_handles
        };

        #[cfg(not(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        )))]
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.remove_closed_connections();
            let closed_connections = state.connections.len() as u64;
            state.closed = true;
            state.incoming.clear();
            for connection in state.connections.iter().map(|(_, connection)| connection) {
                connection.close(quion_proto::VarInt::ZERO, b"endpoint closed");
            }
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            {
                state.server_initial.clear();
                state.client_crypto.clear();
            }
            if let Some(waker) = state.accept_waker.take() {
                waker.wake();
            }
            self.increment_closed_connections(closed_connections);
        }

        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        for handle in connect_handles {
            handle.abort();
        }

        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        self.runtime_notify.notify_waiters();
    }

    /// Immediately aborts all endpoint and connection processing.
    pub fn abort(&self) {
        // Application-owned packet slices can be released after shutdown.
        // Retire the cache first so those late drops cannot retain reservations.
        self.routed_datagram_buffer_pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .close();
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        let handles = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.remove_closed_connections();
            let closed_connections = state.connections.len() as u64;
            state.closed = true;
            state.incoming.clear();
            for connection in state.connections.iter().map(|(_, connection)| connection) {
                connection.abort();
            }
            state.aborted = true;
            state.connections.clear();
            state.routes.clear();
            state.route_cid_lengths.clear();
            state.reset_tokens.clear();
            state.reset_cid_lengths.clear();
            state.reset_proto_endpoint(fresh_proto_endpoint(
                self.max_tracked_endpoint_paths,
                self.server_connection_limits.max_retry_replay_entries,
                self.server_connection_limits.retry_enabled,
            ));
            state.server_initial.clear();
            state.client_crypto.clear();
            state.endpoint_one_rtt_drivers.clear();
            let connect_handles = std::mem::take(&mut state.connecting_drivers);
            let handles = std::mem::take(&mut state.protected_one_rtt_drivers);
            if let Some(waker) = state.accept_waker.take() {
                waker.wake();
            }
            self.increment_closed_connections(closed_connections);
            (handles, connect_handles)
        };
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        self.endpoint_driver_scheduler.clear();

        #[cfg(not(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        )))]
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.remove_closed_connections();
            let closed_connections = state.connections.len() as u64;
            state.closed = true;
            state.incoming.clear();
            for connection in state.connections.iter().map(|(_, connection)| connection) {
                connection.abort();
            }
            state.aborted = true;
            state.connections.clear();
            state.routes.clear();
            state.route_cid_lengths.clear();
            state.reset_tokens.clear();
            state.reset_cid_lengths.clear();
            state.reset_proto_endpoint(fresh_proto_endpoint(
                self.max_tracked_endpoint_paths,
                self.server_connection_limits.max_retry_replay_entries,
                self.server_connection_limits.retry_enabled,
            ));
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            {
                state.server_initial.clear();
                state.client_crypto.clear();
                state.endpoint_one_rtt_drivers.clear();
            }
            if let Some(waker) = state.accept_waker.take() {
                waker.wake();
            }
            self.increment_closed_connections(closed_connections);
        }

        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        for handle in handles.0 {
            handle.abort();
        }

        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        for handle in handles.1 {
            handle.abort();
        }

        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        self.runtime_notify.notify_waiters();
    }

    /// Returns whether endpoint shutdown has started.
    pub fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed
    }

    #[cfg(test)]
    pub(crate) fn poll_server_initial_udp_once(
        &self,
        recv_buffer: &mut [u8],
    ) -> Result<EndpointAcceptProgress, ConnectionError> {
        let _span = trace_span!(
            "quion.endpoint",
            action = "poll_server_initial_udp_once",
            local = %self.local_addr
        )
        .entered();
        let Some(meta) = self.socket.recv(recv_buffer).map_err(map_udp_error)? else {
            return Ok(EndpointAcceptProgress::default());
        };
        trace!(remote = %meta.remote, packet_len = meta.len, "received initial datagram");
        self.increment_packets_received(1);
        let packet = &recv_buffer[..meta.len];
        let mut progress = EndpointAcceptProgress {
            received_packets: 1,
            ..EndpointAcceptProgress::default()
        };
        let Ok((header, _consumed)) = quion_proto::packet::Header::decode(packet, 0) else {
            progress.dropped_packets = 1;
            self.increment_dropped_packets(1);
            return Ok(progress);
        };
        let quion_proto::packet::Header::Long(header) = header else {
            progress.dropped_packets = 1;
            self.increment_dropped_packets(1);
            return Ok(progress);
        };
        let now_ms = unix_time_ms();
        let admission = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .proto_endpoint
                .admit_initial(meta.remote, &header, meta.len, now_ms)
        }
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;

        match admission {
            quion_proto::endpoint::Admission::ExistingConnection { connection } => {
                trace!(
                    connection,
                    "routing initial datagram to existing connection"
                );
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "existing_connection_routed",
                    packet_type: "initial",
                });
                let state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(connection) = state.connections.get(connection) {
                    if self.enqueue_connection_routed_datagram(connection, meta, packet) {
                        progress.routed_existing_connections = 1;
                    } else {
                        self.increment_rejected_connections(1);
                        progress.dropped_packets = 1;
                    }
                } else {
                    progress.dropped_packets = 1;
                }
            }
            quion_proto::endpoint::Admission::NewConnection { original_dcid, .. } => {
                let at_capacity = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .server_connection_capacity_reached(
                        self.server_connection_limits,
                        &header.dst_cid,
                    );
                if at_capacity {
                    debug!(remote = %meta.remote, "dropping Initial because server connection limit is reached");
                    self.increment_rejected_connections(1);
                    progress.dropped_packets = 1;
                    self.increment_dropped_packets(1);
                    return Ok(progress);
                }
                debug!(remote = %meta.remote, "admitted new incoming connection");
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "incoming_admitted",
                    packet_type: "initial",
                });
                let connection = Connection::server_with_qlog(
                    self.local_addr,
                    meta.remote,
                    self.transport_config.clone(),
                    self.server_qlog_handler.clone(),
                    self.server_max_buffered_qlog_events,
                );
                if !connection.attach_endpoint_memory_budget(self.endpoint_memory_budget.clone()) {
                    self.increment_rejected_connections(1);
                    progress.dropped_packets = 1;
                    self.increment_dropped_packets(1);
                    return Ok(progress);
                }
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let connection_id =
                    state.register_connection(header.dst_cid.clone(), connection.clone())?;
                if let Err(error) = state.register_reset_token(
                    header.dst_cid.clone(),
                    derive_stateless_reset_token(&self.stateless_reset_key, &header.dst_cid),
                ) {
                    state.remove_connection(connection_id);
                    return Err(error);
                }
                state
                    .proto_endpoint
                    .insert_route(header.dst_cid.clone(), connection_id);
                if original_dcid != header.dst_cid {
                    if let Err(error) = state.register_connection_route(
                        original_dcid.clone(),
                        connection_id,
                        quion_proto::endpoint::ConnectionRouteKind::OriginalDestination,
                    ) {
                        state.remove_connection(connection_id);
                        return Err(error);
                    }
                    state.proto_endpoint.insert_connection_route(
                        original_dcid,
                        connection_id,
                        quion_proto::endpoint::ConnectionRouteKind::OriginalDestination,
                    );
                }
                state.incoming.push_back(Incoming::new(connection));
                if let Some(waker) = state.accept_waker.take() {
                    waker.wake();
                }
                self.increment_accepted_connections(1);
                progress.incoming_connections = 1;
            }
            quion_proto::endpoint::Admission::RetryRequired { packet } => {
                trace!(remote = %meta.remote, bytes = packet.len(), "sending retry packet");
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "retry_sent",
                    packet_type: "retry",
                });
                let transmit = quion_udp::Transmit {
                    destination: meta.remote,
                    source: Some(self.local_addr),
                    ecn: None,
                    contents: packet,
                    segment_size: None,
                    send_at: None,
                };
                if !self.send_server_budgeted(&transmit)? {
                    progress.dropped_packets = 1;
                    self.increment_dropped_packets(1);
                    return Ok(progress);
                }
                self.increment_packets_sent(1);
                progress.retry_packets_sent = 1;
            }
            quion_proto::endpoint::Admission::VersionNegotiationRequired { packet } => {
                trace!(
                    remote = %meta.remote,
                    bytes = packet.len(),
                    "sending version negotiation packet"
                );
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "version_negotiation_sent",
                    packet_type: "version_negotiation",
                });
                let transmit = quion_udp::Transmit {
                    destination: meta.remote,
                    source: Some(self.local_addr),
                    ecn: None,
                    contents: packet,
                    segment_size: None,
                    send_at: None,
                };
                if !self.send_server_budgeted(&transmit)? {
                    progress.dropped_packets = 1;
                    self.increment_dropped_packets(1);
                    return Ok(progress);
                }
                self.increment_packets_sent(1);
                progress.version_negotiation_packets_sent = 1;
            }
            quion_proto::endpoint::Admission::Drop => {
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "initial_dropped",
                    packet_type: "initial",
                });
                progress.dropped_packets = 1;
            }
        }
        self.increment_dropped_packets(progress.dropped_packets as u64);
        Ok(progress)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn poll_server_udp_once(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        recv_buffer: &mut [u8],
    ) -> Result<EndpointServerProgress, ConnectionError> {
        let Some(meta) = self.socket.recv(recv_buffer).map_err(map_udp_error)? else {
            return self.finish_server_udp_poll(
                EndpointServerProgress::default(),
                recv_buffer,
                self.server_connection_limits
                    .max_runtime_driver_work_per_tick,
            );
        };
        let mut progress =
            self.process_server_datagram(config, transport_config, meta, recv_buffer)?;
        let one_rtt_work = usize::from(progress.routed_existing_connections == 0);
        progress = self.finish_server_udp_poll(progress, recv_buffer, one_rtt_work)?;
        self.increment_dropped_packets(progress.dropped_packets as u64);
        Ok(progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn poll_server_udp_batch_once(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        recv_batch: &mut quion_udp::BatchRecv,
        recv_buffer: &mut [u8],
        max_work: usize,
    ) -> Result<EndpointServerProgress, ConnectionError> {
        let mut progress = EndpointServerProgress::default();
        let configured_max_udp_payload = transport_config
            .mtu_discovery
            .as_ref()
            .map_or(transport_config.initial_mtu, |config| config.upper_bound());
        self.refill_receive_batch_from_routed_pool(recv_batch, max_work);
        self.socket
            .recv_batch(
                recv_batch,
                max_work.clamp(1, MAX_ENDPOINT_RECV_BATCH),
                recv_buffer
                    .len()
                    .min(usize::from(configured_max_udp_payload)),
            )
            .map_err(map_udp_error)?;
        while let Some((datagram, meta)) = recv_batch.pop_front() {
            let (datagram_progress, reusable) = self.process_server_owned_datagram(
                config.clone(),
                transport_config,
                meta,
                datagram,
            )?;
            progress.merge(datagram_progress);
            if let Some(datagram) = reusable {
                recv_batch.recycle(datagram);
            }
        }
        progress = self.finish_server_udp_poll(progress, recv_buffer, max_work.max(1))?;
        self.increment_dropped_packets(progress.dropped_packets as u64);
        Ok(progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn process_server_owned_datagram(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        meta: quion_udp::RecvMeta,
        mut datagram: Vec<u8>,
    ) -> Result<(EndpointServerProgress, Option<Vec<u8>>), ConnectionError> {
        let (ranges, trailing_parse_error) = coalesced_packet_ranges(&datagram[..meta.len], 0);
        if !trailing_parse_error && ranges.len() == 1 && ranges[0] == (0, meta.len) {
            self.record_server_datagram_received(meta.remote, meta.len);
            let disposition = self.classify_server_datagram(
                config,
                transport_config,
                &meta,
                &mut datagram[..meta.len],
            )?;
            if let ServerDatagramDisposition::Route(connection) = disposition {
                self.increment_packets_received(1);
                let mut progress = EndpointServerProgress {
                    received_packets: 1,
                    ..EndpointServerProgress::default()
                };
                let packet_len = meta.len;
                datagram.truncate(packet_len);
                if self.enqueue_owned_connection_routed_datagram(&connection, meta, datagram) {
                    progress.routed_existing_connections = 1;
                } else {
                    self.increment_rejected_connections(1);
                    progress.dropped_packets = 1;
                }
                return Ok((progress, None));
            }

            self.increment_packets_received(1);
            let mut progress = EndpointServerProgress {
                received_packets: 1,
                ..EndpointServerProgress::default()
            };
            self.process_server_disposition(
                disposition,
                &meta,
                &mut datagram[..meta.len],
                &mut progress,
            )?;
            return Ok((progress, Some(datagram)));
        }

        let progress =
            self.process_server_datagram(config, transport_config, meta, &mut datagram)?;
        Ok((progress, Some(datagram)))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn process_server_datagram(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        meta: quion_udp::RecvMeta,
        recv_buffer: &mut [u8],
    ) -> Result<EndpointServerProgress, ConnectionError> {
        self.record_server_datagram_received(meta.remote, meta.len);
        self.increment_packets_received(1);
        let mut progress = EndpointServerProgress {
            received_packets: 1,
            ..EndpointServerProgress::default()
        };
        let (ranges, trailing_parse_error) = coalesced_packet_ranges(&recv_buffer[..meta.len], 0);
        if ranges.is_empty() {
            progress.dropped_packets = 1;
        }
        for (start, end) in ranges {
            let packet = &mut recv_buffer[start..end];
            let disposition =
                self.classify_server_datagram(config.clone(), transport_config, &meta, packet)?;
            self.process_server_disposition(disposition, &meta, packet, &mut progress)?;
        }
        if trailing_parse_error {
            progress.dropped_packets += 1;
        }
        Ok(progress)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn process_server_disposition(
        &self,
        disposition: ServerDatagramDisposition,
        meta: &quion_udp::RecvMeta,
        packet: &mut [u8],
        progress: &mut EndpointServerProgress,
    ) -> Result<(), ConnectionError> {
        match disposition {
            ServerDatagramDisposition::Route(connection) => {
                if self.enqueue_connection_routed_datagram(&connection, meta.clone(), packet) {
                    progress.routed_existing_connections += 1;
                } else {
                    self.increment_rejected_connections(1);
                    progress.dropped_packets += 1;
                }
            }
            ServerDatagramDisposition::Initial(mut server_initial) => {
                let (crypto_progress, response_packets) =
                    server_initial.handle_initial_packet(packet)?;
                progress.dropped_packets += crypto_progress.dropped_packets;
                progress.initial_packets_received += crypto_progress.initial_packets_received;
                progress.crypto_frames_received += crypto_progress.crypto_frames_received;
                progress.response_packets_generated += crypto_progress.response_packets_generated;
                progress.handshake_packets_generated += crypto_progress.handshake_packets_generated;
                progress.one_rtt_packets_generated += crypto_progress.one_rtt_packets_generated;
                let generated_packets = response_packets.len();
                let send_result =
                    self.send_server_crypto_flight_packets(meta.remote, response_packets)?;
                progress.response_packets_sent += send_result.sent.len();
                if send_result.sent.len() < generated_packets {
                    progress.dropped_packets += 1;
                }
                server_initial.record_crypto_packets_sent(&send_result.sent);
                server_initial.queue_pending_crypto_packets(send_result.unsent);
                self.complete_server_connection_handoff(server_initial, progress);
            }
            ServerDatagramDisposition::Handshake(mut server_initial) => {
                let (crypto_progress, response_packets) =
                    server_initial.handle_handshake_packet(packet)?;
                progress.dropped_packets += crypto_progress.dropped_packets;
                progress.handshake_packets_received += crypto_progress.handshake_packets_received;
                progress.crypto_frames_received += crypto_progress.crypto_frames_received;
                progress.response_packets_generated += crypto_progress.response_packets_generated;
                progress.handshake_packets_generated += crypto_progress.handshake_packets_generated;
                progress.one_rtt_packets_generated += crypto_progress.one_rtt_packets_generated;
                if crypto_progress.handshake_packets_received != 0 {
                    self.validate_server_path(meta.remote);
                }
                let generated_packets = response_packets.len();
                let send_result =
                    self.send_server_crypto_flight_packets(meta.remote, response_packets)?;
                progress.response_packets_sent += send_result.sent.len();
                if send_result.sent.len() < generated_packets {
                    progress.dropped_packets += 1;
                }
                server_initial.record_crypto_packets_sent(&send_result.sent);
                server_initial.queue_pending_crypto_packets(send_result.unsent);
                self.complete_server_connection_handoff(server_initial, progress);
            }
            #[cfg(feature = "zero-rtt")]
            ServerDatagramDisposition::ZeroRtt(mut server_initial) => {
                let zero_rtt_progress = server_initial.handle_zero_rtt_packet(packet)?;
                progress.dropped_packets += zero_rtt_progress.dropped_packets;
                self.complete_server_connection_handoff(server_initial, progress);
            }
            ServerDatagramDisposition::Retry(packet) => {
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "retry_sent",
                    packet_type: "retry",
                });
                let transmit = quion_udp::Transmit {
                    destination: meta.remote,
                    source: Some(self.local_addr),
                    ecn: None,
                    contents: packet,
                    segment_size: None,
                    send_at: None,
                };
                if !self.send_server_budgeted(&transmit)? {
                    progress.dropped_packets += 1;
                    return Ok(());
                }
                self.increment_packets_sent(1);
                progress.retry_packets_sent += 1;
            }
            ServerDatagramDisposition::StatelessReset(packet) => {
                let transmit = quion_udp::Transmit {
                    destination: meta.remote,
                    source: Some(self.local_addr),
                    ecn: None,
                    contents: packet,
                    segment_size: None,
                    send_at: None,
                };
                if !self.send_server_budgeted(&transmit)? {
                    progress.dropped_packets += 1;
                    return Ok(());
                }
                self.increment_packets_sent(1);
            }
            ServerDatagramDisposition::VersionNegotiation(packet) => {
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "version_negotiation_sent",
                    packet_type: "version_negotiation",
                });
                let transmit = quion_udp::Transmit {
                    destination: meta.remote,
                    source: Some(self.local_addr),
                    ecn: None,
                    contents: packet,
                    segment_size: None,
                    send_at: None,
                };
                if !self.send_server_budgeted(&transmit)? {
                    progress.dropped_packets += 1;
                    return Ok(());
                }
                self.increment_packets_sent(1);
                progress.version_negotiation_packets_sent += 1;
            }
            ServerDatagramDisposition::Drop => {
                progress.dropped_packets += 1;
            }
        }
        Ok(())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn finish_server_udp_poll(
        &self,
        mut progress: EndpointServerProgress,
        recv_buffer: &mut [u8],
        one_rtt_work: usize,
    ) -> Result<EndpointServerProgress, ConnectionError> {
        let crypto_timeout_progress = self.poll_server_crypto_timeouts_once()?;
        progress.response_packets_generated += crypto_timeout_progress.response_packets_generated;
        progress.handshake_packets_generated += crypto_timeout_progress.handshake_packets_generated;
        progress.one_rtt_packets_generated += crypto_timeout_progress.one_rtt_packets_generated;
        progress.response_packets_sent += crypto_timeout_progress.response_packets_sent;
        progress.crypto_timeouts_processed += crypto_timeout_progress.timeouts_processed;
        progress.next_crypto_timeout = self.next_server_crypto_timeout();
        if one_rtt_work != 0 {
            let one_rtt_progress = self.poll_endpoint_one_rtt_drivers(recv_buffer, one_rtt_work)?;
            progress.one_rtt_packets_sent = one_rtt_progress.sent_packets;
            progress.one_rtt_packets_received = one_rtt_progress.received_packets;
            progress.one_rtt_timeouts_processed = one_rtt_progress.timeouts_processed;
            progress.next_one_rtt_send_at = one_rtt_progress.next_send_at;
            progress.next_one_rtt_timeout = one_rtt_progress.next_timeout;
        }
        Ok(progress)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_server_crypto_timeouts_once(
        &self,
    ) -> Result<ServerInitialCryptoProgress, ConnectionError> {
        let now = web_time::Instant::now();
        let due_routes = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .server_initial
                .iter()
                .filter_map(|(route, connection)| {
                    (connection.has_pending_crypto_packets()
                        || connection
                            .next_timeout()
                            .is_some_and(|timeout| timeout <= now))
                    .then_some(route.clone())
                })
                .collect::<Vec<_>>()
        };
        let mut aggregate = ServerInitialCryptoProgress::default();
        for route_cid in due_routes {
            let (mut timeout_progress, packets, remote_addr) = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let Some(connection) = state.server_initial.get_mut(&route_cid) else {
                    continue;
                };
                let remote_addr = connection.remote_addr;
                let (progress, packets) = if connection.has_pending_crypto_packets() {
                    (
                        ServerInitialCryptoProgress::default(),
                        connection.take_pending_crypto_packets(),
                    )
                } else {
                    connection.poll_crypto_timeout(now)?
                };
                (progress, packets, remote_addr)
            };
            let send_result = self.send_server_crypto_flight_packets(remote_addr, packets)?;
            timeout_progress.response_packets_sent += send_result.sent.len();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(connection) = state.server_initial.get_mut(&route_cid) {
                    connection.record_crypto_packets_sent(&send_result.sent);
                    connection.queue_pending_crypto_packets(send_result.unsent);
                }
                if state
                    .server_initial
                    .get(&route_cid)
                    .is_some_and(|connection| !connection.is_within_endpoint_memory_reservation())
                {
                    state.server_initial.remove(&route_cid);
                    self.increment_rejected_connections(1);
                    aggregate.dropped_packets = aggregate.dropped_packets.saturating_add(1);
                }
            }
            aggregate.response_crypto_frames += timeout_progress.response_crypto_frames;
            aggregate.handshake_crypto_frames += timeout_progress.handshake_crypto_frames;
            aggregate.one_rtt_crypto_frames += timeout_progress.one_rtt_crypto_frames;
            aggregate.response_packets_generated += timeout_progress.response_packets_generated;
            aggregate.handshake_packets_generated += timeout_progress.handshake_packets_generated;
            aggregate.one_rtt_packets_generated += timeout_progress.one_rtt_packets_generated;
            aggregate.timeouts_processed += timeout_progress.timeouts_processed;
            aggregate.response_packets_sent += timeout_progress.response_packets_sent;
        }
        Ok(aggregate)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn next_server_crypto_timeout(&self) -> Option<web_time::Instant> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .server_initial
            .values()
            .filter_map(ServerInitialConnection::next_timeout)
            .min()
    }

    #[cfg(test)]
    pub(crate) fn validate_version_negotiation_packet(
        &self,
        packet: &[u8],
        original_dst_cid: &[u8],
        original_src_cid: &[u8],
        attempted_version: u32,
    ) -> Result<u32, ConnectionError> {
        let (header, consumed) = quion_proto::packet::Header::decode(packet, 0)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        if consumed != packet.len() {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        }
        let original_dst_cid = quion_proto::cid::ConnectionId::from_slice(original_dst_cid)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let original_src_cid = quion_proto::cid::ConnectionId::from_slice(original_src_cid)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        match quion_proto::endpoint::Endpoint::validate_version_negotiation(
            &header,
            &original_dst_cid,
            &original_src_cid,
            attempted_version,
            &[quion_proto::packet::QUIC_VERSION_1],
        ) {
            quion_proto::endpoint::VersionNegotiationResult::Negotiated(version) => Ok(version),
            quion_proto::endpoint::VersionNegotiationResult::NoSupportedVersion => {
                Err(ConnectionError::VersionMismatch)
            }
            quion_proto::endpoint::VersionNegotiationResult::Invalid => {
                Err(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                ))
            }
        }
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn poll_connect_initial_udp_once(
        &self,
        connecting: &mut Connecting,
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        transport_config: &quion_proto::config::TransportConfig,
    ) -> Result<EndpointConnectProgress, ConnectionError> {
        let Some(transmit) = connecting.start_rustls_client_initial_udp_transmit(
            config,
            server_name,
            transport_config,
        )?
        else {
            return Ok(EndpointConnectProgress::default());
        };
        self.socket.send(&transmit).map_err(map_udp_error)?;
        connecting.record_initial_packet_sent(transmit.contents.len());
        self.increment_packets_sent(1);
        Ok(EndpointConnectProgress {
            initial_packets_sent: 1,
        })
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn poll_client_crypto_initial_udp_once(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        transport_config: &quion_proto::config::TransportConfig,
    ) -> Result<EndpointConnectProgress, ConnectionError> {
        let transmit = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let transmit = state
                .client_crypto_mut(route_cid)?
                .start_rustls_client_initial_udp_transmit(config, server_name, transport_config)?;
            if state
                .client_crypto
                .get(route_cid)
                .is_some_and(|client| !client.is_within_endpoint_memory_reservation())
            {
                state.client_crypto.remove(route_cid);
                return Err(ConnectionError::EndpointMemoryLimitReached);
            }
            transmit
        };
        let Some(transmit) = transmit else {
            return Ok(EndpointConnectProgress::default());
        };
        self.socket.send(&transmit).map_err(map_udp_error)?;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .client_crypto_mut(route_cid)?
                .record_initial_packet_sent(transmit.contents.len());
        }
        self.increment_packets_sent(1);
        Ok(EndpointConnectProgress {
            initial_packets_sent: 1,
        })
    }

    #[cfg(all(
        feature = "zero-rtt",
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn poll_client_zero_rtt_udp_once(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<(usize, Option<web_time::Instant>), ConnectionError> {
        let now = web_time::Instant::now();
        let (transmit, connection, next_send_at) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let client = state.client_crypto_mut(route_cid)?;
            client.prepare_zero_rtt_transmit()?;
            let next_send_at = client
                .pending_zero_rtt_transmit
                .as_ref()
                .and_then(|transmit| transmit.send_at);
            let transmit = if next_send_at.is_none_or(|send_at| send_at <= now) {
                client.pending_zero_rtt_transmit.take()
            } else {
                None
            };
            (transmit, client.connection.clone(), next_send_at)
        };
        let Some(transmit) = transmit else {
            return Ok((0, next_send_at));
        };
        if let Err(error) = self.socket.send(&transmit) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Ok(client) = state.client_crypto_mut(route_cid)
                && client.pending_zero_rtt_transmit.is_none()
            {
                client.pending_zero_rtt_transmit = Some(transmit);
            }
            return Err(map_udp_error(error));
        }
        self.increment_packets_sent(1);
        connection.record_path_sent_batch(transmit.destination, 1, transmit.contents.len());
        connection.record_activity(now);
        Ok((1, None))
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn poll_connect_initial_response_udp_once(
        &self,
        connecting: &mut Connecting,
        recv_buffer: &mut [u8],
    ) -> Result<ClientInitialCryptoProgress, ConnectionError> {
        let Some(meta) = self.socket.recv(recv_buffer).map_err(map_udp_error)? else {
            return Ok(ClientInitialCryptoProgress::default());
        };
        self.increment_packets_received(1);
        let packet = &mut recv_buffer[..meta.len];
        let mut progress = connecting.handle_initial_crypto_packet(packet)?;
        if progress.dropped_packets == 0 {
            progress.initial_packets_received = 1;
        }
        self.increment_dropped_packets(progress.dropped_packets as u64);
        Ok(progress)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn poll_connect_udp_once(
        &self,
        connecting: &mut Connecting,
        recv_buffer: &mut [u8],
    ) -> Result<EndpointConnectReceiveProgress, ConnectionError> {
        let Some(meta) = self.socket.recv(recv_buffer).map_err(map_udp_error)? else {
            return Ok(EndpointConnectReceiveProgress::default());
        };
        self.increment_packets_received(1);
        let (ranges, trailing_parse_error) = coalesced_packet_ranges(&recv_buffer[..meta.len], 0);
        let mut progress = EndpointConnectReceiveProgress {
            received_packets: 1,
            ..EndpointConnectReceiveProgress::default()
        };
        if ranges.is_empty() {
            progress.dropped_packets = 1;
            return Ok(progress);
        }
        for (start, end) in ranges {
            let packet = &mut recv_buffer[start..end];
            let packet_progress = self.handle_connect_packet(connecting, packet)?;
            progress.version_negotiation_packets_received +=
                packet_progress.version_negotiation_packets_received;
            progress.retry_packets_received += packet_progress.retry_packets_received;
            progress.response_packets_sent += packet_progress.response_packets_sent;
            progress.dropped_packets += packet_progress.dropped_packets;
            merge_client_initial_progress(
                &mut progress.initial_crypto,
                packet_progress.initial_crypto,
            );
        }
        if trailing_parse_error {
            progress.dropped_packets += 1;
        }
        self.increment_dropped_packets(progress.dropped_packets as u64);
        Ok(progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn poll_client_crypto_udp_once(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
        recv_buffer: &mut [u8],
    ) -> Result<EndpointConnectReceiveProgress, ConnectionError> {
        if let Some(progress) = self.poll_client_crypto_queued_once(route_cid)? {
            self.increment_dropped_packets(progress.dropped_packets as u64);
            return Ok(progress);
        }

        if self.client_endpoint_driver_running.load(Ordering::Acquire) {
            return Ok(EndpointConnectReceiveProgress::default());
        }
        if !self.poll_client_runtime_route_once(route_cid, recv_buffer)? {
            return Ok(EndpointConnectReceiveProgress::default());
        }

        let progress = self
            .poll_client_crypto_queued_once(route_cid)?
            .unwrap_or_else(|| EndpointConnectReceiveProgress {
                received_packets: 1,
                dropped_packets: 1,
                ..EndpointConnectReceiveProgress::default()
            });
        self.increment_dropped_packets(progress.dropped_packets as u64);
        Ok(progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn poll_client_crypto_timeout_once(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<ClientInitialCryptoProgress, ConnectionError> {
        let now = web_time::Instant::now();
        let (progress, packets, server_addr) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let client = state.client_crypto_mut(route_cid)?;
            let (progress, packets) = client.poll_crypto_timeout(now)?;
            (progress, packets, client.server_addr)
        };
        if packets.is_empty() {
            return Ok(progress);
        }
        let sent_packets = self.send_connect_response_packets_to(server_addr, packets)?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .client_crypto_mut(route_cid)?
            .record_crypto_packets_sent(&sent_packets);
        Ok(ClientInitialCryptoProgress {
            response_packets_sent: sent_packets.len(),
            ..progress
        })
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn next_client_crypto_timeout(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<Option<web_time::Instant>, ConnectionError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(state.client_crypto(route_cid)?.next_timeout())
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn poll_client_crypto_queued_once(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<Option<EndpointConnectReceiveProgress>, ConnectionError> {
        let datagram = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.client_crypto_mut(route_cid)?.pop_routed_datagram()
        };
        let Some(mut datagram) = datagram else {
            return Ok(None);
        };
        let (ranges, trailing_parse_error) =
            coalesced_packet_ranges(datagram.contents.as_slice(), route_cid.len());
        if ranges.is_empty() {
            return Ok(Some(EndpointConnectReceiveProgress {
                received_packets: 1,
                dropped_packets: 1,
                ..EndpointConnectReceiveProgress::default()
            }));
        }
        let mut progress = EndpointConnectReceiveProgress {
            received_packets: 1,
            ..EndpointConnectReceiveProgress::default()
        };
        for (start, end) in ranges {
            let packet = &mut datagram.contents[start..end];
            let packet_progress =
                self.handle_client_crypto_packet(route_cid, packet, &datagram.meta)?;
            progress.version_negotiation_packets_received +=
                packet_progress.version_negotiation_packets_received;
            progress.retry_packets_received += packet_progress.retry_packets_received;
            progress.response_packets_sent += packet_progress.response_packets_sent;
            progress.dropped_packets += packet_progress.dropped_packets;
            merge_client_initial_progress(
                &mut progress.initial_crypto,
                packet_progress.initial_crypto,
            );
        }
        if trailing_parse_error {
            progress.dropped_packets += 1;
        }
        let _ = datagram.meta;
        Ok(Some(progress))
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn poll_client_runtime_route_once(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
        recv_buffer: &mut [u8],
    ) -> Result<bool, ConnectionError> {
        let Some(meta) = self.socket.recv(recv_buffer).map_err(map_udp_error)? else {
            return Ok(false);
        };
        self.increment_packets_received(1);
        let packet = &recv_buffer[..meta.len];
        let _ = self.route_client_socket_datagram(meta, packet, Some(route_cid), None)?;
        Ok(true)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn route_client_socket_datagram(
        &self,
        meta: quion_udp::RecvMeta,
        packet: &[u8],
        preferred_handshake_cid: Option<&quion_proto::cid::ConnectionId>,
        direct_connection: Option<&Connection>,
    ) -> Result<bool, ConnectionError> {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.remove_closed_connections();
            if let Some(connection) = state.route_short_connection(packet) {
                if direct_connection.is_some_and(|direct| direct.is_same_connection(&connection)) {
                    return Ok(false);
                }
                if !self.enqueue_connection_routed_datagram(&connection, meta, packet) {
                    self.increment_rejected_connections(1);
                }
                return Ok(true);
            }
            if let Some(connection) = state.connection_matching_stateless_reset(packet) {
                if !self.enqueue_connection_routed_datagram(&connection, meta, packet) {
                    self.increment_rejected_connections(1);
                }
                return Ok(true);
            }
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pending_route = preferred_handshake_cid
            .filter(|route_cid| {
                state.has_client_crypto(route_cid)
                    && packet_has_short_destination(packet, route_cid)
            })
            .cloned()
            .or_else(|| {
                state
                    .client_crypto
                    .keys()
                    .find(|route_cid| packet_has_short_destination(packet, route_cid))
                    .cloned()
            });
        if let Some(route_cid) = pending_route {
            let queued = state
                .client_crypto_mut(&route_cid)?
                .enqueue_routed_datagram_with_budget(
                    meta,
                    packet,
                    &self.routed_datagram_memory_budget,
                );
            if !queued {
                self.increment_rejected_connections(1);
            }
            drop(state);
            #[cfg(feature = "runtime-tokio")]
            self.runtime_notify.notify_waiters();
            return Ok(true);
        }

        let Ok((header, _consumed)) = quion_proto::packet::Header::decode(packet, 0) else {
            return Ok(false);
        };
        let route_cid = match header {
            quion_proto::packet::Header::VersionNegotiation { dst_cid, .. } => dst_cid,
            quion_proto::packet::Header::Long(header) => header.dst_cid,
            quion_proto::packet::Header::Short(_) => return Ok(false),
        };
        if state.has_client_crypto(&route_cid) {
            let queued = state
                .client_crypto_mut(&route_cid)?
                .enqueue_routed_datagram_with_budget(
                    meta,
                    packet,
                    &self.routed_datagram_memory_budget,
                );
            if !queued {
                self.increment_rejected_connections(1);
            }
            drop(state);
            #[cfg(feature = "runtime-tokio")]
            self.runtime_notify.notify_waiters();
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn route_owned_client_socket_datagram(
        &self,
        meta: quion_udp::RecvMeta,
        mut packet: Vec<u8>,
        drivers: &mut BTreeMap<u64, EndpointOwnedOneRttDriver>,
    ) -> Result<Option<Vec<u8>>, ConnectionError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.remove_closed_connections();
        let packet_len = meta.len.min(packet.len());
        let established_connection = state
            .route_short_connection(&packet[..packet_len])
            .or_else(|| state.connection_matching_stateless_reset(&packet[..packet_len]));
        if let Some(connection) = established_connection {
            drop(state);
            if let Some(owned) = connection
                .endpoint_runtime_driver_id()
                .and_then(|driver_id| drivers.get_mut(&driver_id))
            {
                let now = web_time::Instant::now();
                if packet_len >= MIN_OWNED_CLIENT_PACKET_BYTES {
                    packet.truncate(packet_len);
                    if let Err(driver_error) = self.process_known_client_one_rtt_datagram_owned(
                        &owned.connection,
                        &mut owned.driver,
                        packet,
                        meta,
                        now,
                    ) {
                        debug!(
                            remote = %owned.connection.remote_address(),
                            ?driver_error,
                            "endpoint-owned connection receive failed"
                        );
                        owned.connection.abort_with_runtime_error(driver_error);
                    }
                    return Ok(None);
                }
                if let Err(driver_error) = self.process_known_client_one_rtt_datagram(
                    &owned.connection,
                    &mut owned.driver,
                    &mut packet[..packet_len],
                    &meta,
                    now,
                ) {
                    debug!(
                        remote = %owned.connection.remote_address(),
                        ?driver_error,
                        "endpoint-owned connection receive failed"
                    );
                    owned.connection.abort_with_runtime_error(driver_error);
                }
                return Ok(Some(packet));
            }
            packet.truncate(packet_len);
            if !self.enqueue_owned_connection_routed_datagram(&connection, meta, packet) {
                self.increment_rejected_connections(1);
            }
            return Ok(None);
        }

        let pending_route = state
            .client_crypto
            .keys()
            .find(|route_cid| packet_has_short_destination(&packet[..packet_len], route_cid))
            .cloned();
        if let Some(route_cid) = pending_route {
            packet.truncate(packet_len);
            let queued = state
                .client_crypto_mut(&route_cid)?
                .enqueue_owned_routed_datagram_with_budget(
                    meta,
                    packet,
                    &self.routed_datagram_memory_budget,
                );
            if !queued {
                self.increment_rejected_connections(1);
            }
            drop(state);
            #[cfg(feature = "runtime-tokio")]
            self.runtime_notify.notify_waiters();
            return Ok(None);
        }

        let Ok((header, _)) = quion_proto::packet::Header::decode(&packet[..packet_len], 0) else {
            return Ok(Some(packet));
        };
        let route_cid = match header {
            quion_proto::packet::Header::VersionNegotiation { dst_cid, .. } => dst_cid,
            quion_proto::packet::Header::Long(header) => header.dst_cid,
            quion_proto::packet::Header::Short(_) => return Ok(Some(packet)),
        };
        if state.has_client_crypto(&route_cid) {
            packet.truncate(packet_len);
            let queued = state
                .client_crypto_mut(&route_cid)?
                .enqueue_owned_routed_datagram_with_budget(
                    meta,
                    packet,
                    &self.routed_datagram_memory_budget,
                );
            if !queued {
                self.increment_rejected_connections(1);
            }
            drop(state);
            #[cfg(feature = "runtime-tokio")]
            self.runtime_notify.notify_waiters();
            return Ok(None);
        }
        Ok(Some(packet))
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn send_connect_response_packets(
        &self,
        connecting: &mut Connecting,
        response_packets: Vec<CryptoFlightPacket>,
    ) -> Result<usize, ConnectionError> {
        let server_addr = connecting
            .server_addr()
            .ok_or(ConnectionError::LocallyClosed)?;
        let sent = self.send_connect_response_packets_to(server_addr, response_packets)?;
        connecting.record_crypto_packets_sent(&sent);
        Ok(sent.len())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn send_connect_response_packets_to(
        &self,
        server_addr: SocketAddr,
        response_packets: Vec<CryptoFlightPacket>,
    ) -> Result<Vec<CryptoFlightPacket>, ConnectionError> {
        let mut sent = Vec::new();
        for datagram in coalesce_crypto_flight_packets(response_packets) {
            self.socket
                .send(&quion_udp::Transmit {
                    destination: server_addr,
                    source: Some(self.local_addr),
                    // ECN validation starts with protected application traffic;
                    // crypto ACK processing does not carry ECN feedback.
                    ecn: None,
                    contents: datagram.contents,
                    segment_size: None,
                    send_at: None,
                })
                .map_err(map_udp_error)?;
            self.increment_packets_sent(datagram.packets.len() as u64);
            sent.extend(datagram.packets);
        }
        Ok(sent)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn send_server_crypto_flight_packets(
        &self,
        remote: SocketAddr,
        response_packets: Vec<CryptoFlightPacket>,
    ) -> Result<CryptoFlightSendResult, ConnectionError> {
        let mut sent = Vec::new();
        let mut unsent = Vec::new();
        let mut datagrams = coalesce_crypto_flight_packets(response_packets).into_iter();
        while let Some(datagram) = datagrams.next() {
            let transmit = quion_udp::Transmit {
                destination: remote,
                source: Some(self.local_addr),
                // ECN validation starts with protected application traffic;
                // crypto ACK processing does not carry ECN feedback.
                ecn: None,
                contents: datagram.contents,
                segment_size: None,
                send_at: None,
            };
            if !self.send_server_budgeted(&transmit)? {
                unsent.extend(datagram.packets);
                for pending in datagrams {
                    unsent.extend(pending.packets);
                }
                break;
            }
            self.increment_packets_sent(datagram.packets.len() as u64);
            sent.extend(datagram.packets);
        }
        Ok(CryptoFlightSendResult { sent, unsent })
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn handle_connect_packet(
        &self,
        connecting: &mut Connecting,
        packet: &mut [u8],
    ) -> Result<EndpointConnectReceiveProgress, ConnectionError> {
        let (header, _consumed) = quion_proto::packet::Header::decode(packet, 0)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        match &header {
            quion_proto::packet::Header::VersionNegotiation { .. } => {
                let version = connecting.validate_version_negotiation_packet(packet)?;
                connecting
                    .state
                    .as_mut()
                    .ok_or(ConnectionError::LocallyClosed)?
                    .restart_after_version_negotiation(version)?;
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "version_negotiation_received",
                    packet_type: "version_negotiation",
                });
                Ok(EndpointConnectReceiveProgress {
                    version_negotiation_packets_received: 1,
                    ..EndpointConnectReceiveProgress::default()
                })
            }
            quion_proto::packet::Header::Long(header)
                if header.ty == quion_proto::packet::PacketType::Retry =>
            {
                connecting.handle_retry_packet(packet)?;
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "retry_received",
                    packet_type: "retry",
                });
                Ok(EndpointConnectReceiveProgress {
                    retry_packets_received: 1,
                    ..EndpointConnectReceiveProgress::default()
                })
            }
            quion_proto::packet::Header::Long(header)
                if header.ty == quion_proto::packet::PacketType::Initial =>
            {
                connecting
                    .state
                    .as_mut()
                    .ok_or(ConnectionError::LocallyClosed)?
                    .observe_server_initial_source_cid(&header.src_cid)?;
                let (mut initial_crypto, response_packets) =
                    connecting.handle_initial_crypto_packet_inner(packet)?;
                if initial_crypto.dropped_packets == 0 {
                    initial_crypto.initial_packets_received = 1;
                }
                let dropped_packets = initial_crypto.dropped_packets;
                let response_packets_sent =
                    self.send_connect_response_packets(connecting, response_packets)?;
                if let Some(error) = initial_crypto.transport_error {
                    return Err(ConnectionError::TransportError(error));
                }
                Ok(EndpointConnectReceiveProgress {
                    response_packets_sent,
                    dropped_packets,
                    initial_crypto,
                    ..EndpointConnectReceiveProgress::default()
                })
            }
            quion_proto::packet::Header::Long(header)
                if header.ty == quion_proto::packet::PacketType::Handshake =>
            {
                let (mut initial_crypto, response_packets) =
                    connecting.handle_handshake_crypto_packet_inner(packet)?;
                if initial_crypto.dropped_packets == 0 {
                    initial_crypto.handshake_packets_received = 1;
                }
                let dropped_packets = initial_crypto.dropped_packets;
                let response_packets_sent =
                    self.send_connect_response_packets(connecting, response_packets)?;
                if let Some(error) = initial_crypto.transport_error {
                    return Err(ConnectionError::TransportError(error));
                }
                Ok(EndpointConnectReceiveProgress {
                    response_packets_sent,
                    dropped_packets,
                    initial_crypto,
                    ..EndpointConnectReceiveProgress::default()
                })
            }
            _ => Ok(EndpointConnectReceiveProgress {
                dropped_packets: 1,
                ..EndpointConnectReceiveProgress::default()
            }),
        }
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn handle_client_crypto_packet(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
        packet: &mut [u8],
        meta: &quion_udp::RecvMeta,
    ) -> Result<EndpointConnectReceiveProgress, ConnectionError> {
        if packet.first().is_some_and(|first| first & 0x80 == 0) {
            return self.handle_client_one_rtt_packet(route_cid, packet, meta);
        }
        let Ok((header, _consumed)) = quion_proto::packet::Header::decode(packet, route_cid.len())
        else {
            return Ok(EndpointConnectReceiveProgress {
                dropped_packets: 1,
                ..EndpointConnectReceiveProgress::default()
            });
        };
        let progress = match &header {
            quion_proto::packet::Header::VersionNegotiation { .. } => {
                {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let client = state.client_crypto_mut(route_cid)?;
                    let version = client.validate_version_negotiation_packet(packet)?;
                    client.restart_after_version_negotiation(version)?;
                }
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "version_negotiation_received",
                    packet_type: "version_negotiation",
                });
                EndpointConnectReceiveProgress {
                    version_negotiation_packets_received: 1,
                    ..EndpointConnectReceiveProgress::default()
                }
            }
            quion_proto::packet::Header::Long(header)
                if header.ty == quion_proto::packet::PacketType::Retry =>
            {
                {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state
                        .client_crypto_mut(route_cid)?
                        .handle_retry_packet(packet)?;
                }
                self.publish_endpoint_qlog(crate::QlogEvent::EndpointStateUpdated {
                    state: "retry_received",
                    packet_type: "retry",
                });
                EndpointConnectReceiveProgress {
                    retry_packets_received: 1,
                    ..EndpointConnectReceiveProgress::default()
                }
            }
            quion_proto::packet::Header::Long(header)
                if header.ty == quion_proto::packet::PacketType::Initial =>
            {
                let (initial_crypto, response_packets, server_addr) = {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let client = state.client_crypto_mut(route_cid)?;
                    client.observe_server_initial_source_cid(&header.src_cid)?;
                    let (mut initial_crypto, response_packets) =
                        client.handle_initial_crypto_packet_inner(packet)?;
                    if initial_crypto.dropped_packets == 0 {
                        initial_crypto.initial_packets_received = 1;
                    }
                    (initial_crypto, response_packets, client.server_addr)
                };
                let sent_packets =
                    self.send_connect_response_packets_to(server_addr, response_packets)?;
                let response_packets_sent = sent_packets.len();
                {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state
                        .client_crypto_mut(route_cid)?
                        .record_crypto_packets_sent(&sent_packets);
                }
                if let Some(error) = initial_crypto.transport_error {
                    return Err(ConnectionError::TransportError(error));
                }
                EndpointConnectReceiveProgress {
                    response_packets_sent,
                    dropped_packets: initial_crypto.dropped_packets,
                    initial_crypto,
                    ..EndpointConnectReceiveProgress::default()
                }
            }
            quion_proto::packet::Header::Long(header)
                if header.ty == quion_proto::packet::PacketType::Handshake =>
            {
                let (initial_crypto, response_packets, server_addr) = {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let client = state.client_crypto_mut(route_cid)?;
                    let (mut initial_crypto, response_packets) =
                        client.handle_handshake_crypto_packet_inner(packet)?;
                    if initial_crypto.dropped_packets == 0 {
                        initial_crypto.handshake_packets_received = 1;
                    }
                    (initial_crypto, response_packets, client.server_addr)
                };
                let sent_packets =
                    self.send_connect_response_packets_to(server_addr, response_packets)?;
                let response_packets_sent = sent_packets.len();
                {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state
                        .client_crypto_mut(route_cid)?
                        .record_crypto_packets_sent(&sent_packets);
                }
                if let Some(error) = initial_crypto.transport_error {
                    return Err(ConnectionError::TransportError(error));
                }
                EndpointConnectReceiveProgress {
                    response_packets_sent,
                    dropped_packets: initial_crypto.dropped_packets,
                    initial_crypto,
                    ..EndpointConnectReceiveProgress::default()
                }
            }
            quion_proto::packet::Header::Short(_) => unreachable!("short headers return above"),
            _ => EndpointConnectReceiveProgress {
                dropped_packets: 1,
                ..EndpointConnectReceiveProgress::default()
            },
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state
            .client_crypto
            .get(route_cid)
            .is_some_and(|client| !client.is_within_endpoint_memory_reservation())
        {
            state.client_crypto.remove(route_cid);
            drop(state);
            self.increment_rejected_connections(1);
            return Err(ConnectionError::EndpointMemoryLimitReached);
        }
        Ok(progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn handle_client_one_rtt_packet(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
        packet: &mut [u8],
        meta: &quion_udp::RecvMeta,
    ) -> Result<EndpointConnectReceiveProgress, ConnectionError> {
        let (mut initial_crypto, response_packets, server_addr) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let client = state.client_crypto_mut(route_cid)?;
            let (initial_crypto, response_packets) = client.handle_one_rtt_packet(packet, meta)?;
            (initial_crypto, response_packets, client.server_addr)
        };
        let sent_packets = self.send_connect_response_packets_to(server_addr, response_packets)?;
        let response_packets_sent = sent_packets.len();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .client_crypto_mut(route_cid)?
                .record_crypto_packets_sent(&sent_packets);
        }
        if initial_crypto.dropped_packets == 0 {
            initial_crypto.handshake_completed = true;
        }
        if let Some(error) = initial_crypto.transport_error {
            return Err(ConnectionError::TransportError(error));
        }
        Ok(EndpointConnectReceiveProgress {
            response_packets_sent,
            dropped_packets: initial_crypto.dropped_packets,
            initial_crypto,
            ..EndpointConnectReceiveProgress::default()
        })
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn classify_server_datagram(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        meta: &quion_udp::RecvMeta,
        packet: &mut [u8],
    ) -> Result<ServerDatagramDisposition, ConnectionError> {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.remove_closed_connections();
            if let Some(connection) = state.route_short_connection(packet) {
                return Ok(ServerDatagramDisposition::Route(connection));
            }
            if let Some(connection) = state.connection_matching_stateless_reset(packet) {
                return Ok(ServerDatagramDisposition::Route(connection));
            }
            if let Some(token) = state.stateless_reset_token_for_short_packet(packet) {
                return Ok(encode_stateless_reset(packet.len(), token).map_or(
                    ServerDatagramDisposition::Drop,
                    ServerDatagramDisposition::StatelessReset,
                ));
            }
            if state.closed {
                return Ok(ServerDatagramDisposition::Drop);
            }
        }

        let Ok((header, _consumed)) = quion_proto::packet::Header::decode(packet, 0) else {
            return Ok(ServerDatagramDisposition::Drop);
        };
        let quion_proto::packet::Header::Long(header) = header else {
            return Ok(ServerDatagramDisposition::Drop);
        };

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.remove_closed_connections();
        if let Some(connection) = state.route_connection(&header.dst_cid) {
            return Ok(ServerDatagramDisposition::Route(connection));
        }

        if header.ty == quion_proto::packet::PacketType::Initial
            && state
                .server_connection_capacity_reached(self.server_connection_limits, &header.dst_cid)
        {
            debug!(remote = %meta.remote, "dropping Initial because server connection limit is reached");
            self.increment_rejected_connections(1);
            return Ok(ServerDatagramDisposition::Drop);
        }

        match header.ty {
            quion_proto::packet::PacketType::Initial => {
                match state
                    .proto_endpoint
                    .admit_initial_on_recorded_path(meta.remote, &header, unix_time_ms())
                    .map_err(|error| ConnectionError::TransportError(error.transport_code()))?
                {
                    quion_proto::endpoint::Admission::ExistingConnection { connection } => {
                        Ok(state.connections.get(connection).cloned().map_or(
                            ServerDatagramDisposition::Drop,
                            ServerDatagramDisposition::Route,
                        ))
                    }
                    quion_proto::endpoint::Admission::NewConnection { original_dcid, .. } => {
                        let server_initial =
                            if let Some(existing) = state.server_initial.remove(&header.dst_cid) {
                                existing
                            } else {
                                let Some(reservation) = self.endpoint_memory_budget.try_reserve(
                                    pending_handshake_memory_reservation_bytes(transport_config),
                                ) else {
                                    self.increment_rejected_connections(1);
                                    return Ok(ServerDatagramDisposition::Drop);
                                };
                                let mut connection = ServerInitialConnection::new(
                                    config,
                                    transport_config,
                                    ServerInitialQlog::new(
                                        self.server_qlog_handler.clone(),
                                        self.server_max_buffered_qlog_events,
                                    ),
                                    packet,
                                    Some(&original_dcid),
                                    meta.remote,
                                    Some(derive_stateless_reset_token(
                                        &self.stateless_reset_key,
                                        &header.dst_cid,
                                    )),
                                )?;
                                connection.attach_endpoint_memory_reservation(reservation);
                                connection
                            };
                        Ok(ServerDatagramDisposition::Initial(server_initial))
                    }
                    quion_proto::endpoint::Admission::RetryRequired { packet } => {
                        Ok(ServerDatagramDisposition::Retry(packet))
                    }
                    quion_proto::endpoint::Admission::VersionNegotiationRequired { packet } => {
                        Ok(ServerDatagramDisposition::VersionNegotiation(packet))
                    }
                    quion_proto::endpoint::Admission::Drop => Ok(ServerDatagramDisposition::Drop),
                }
            }
            quion_proto::packet::PacketType::Handshake => Ok(state
                .server_initial
                .remove(&header.dst_cid)
                .map_or(ServerDatagramDisposition::Drop, |server_initial| {
                    ServerDatagramDisposition::Handshake(server_initial)
                })),
            #[cfg(feature = "zero-rtt")]
            quion_proto::packet::PacketType::ZeroRtt => Ok(state
                .server_initial
                .remove(&header.dst_cid)
                .map_or(ServerDatagramDisposition::Drop, |server_initial| {
                    ServerDatagramDisposition::ZeroRtt(server_initial)
                })),
            #[cfg(not(feature = "zero-rtt"))]
            quion_proto::packet::PacketType::ZeroRtt => Ok(ServerDatagramDisposition::Drop),
            quion_proto::packet::PacketType::Retry => Ok(ServerDatagramDisposition::Drop),
        }
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn handle_server_initial_crypto_packet(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        packet: &mut [u8],
    ) -> Result<ServerInitialCryptoProgress, ConnectionError> {
        self.handle_server_initial_crypto_packet_inner(config, transport_config, packet)
            .map(|(progress, _packets)| progress)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn poll_server_initial_crypto_udp_once(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        recv_buffer: &mut [u8],
    ) -> Result<ServerInitialCryptoProgress, ConnectionError> {
        let Some(meta) = self.socket.recv(recv_buffer).map_err(map_udp_error)? else {
            return Ok(ServerInitialCryptoProgress::default());
        };
        self.increment_packets_received(1);
        let packet = &mut recv_buffer[..meta.len];
        let route_cid = {
            let (header, _consumed) = quion_proto::packet::Header::decode(packet, 0)
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
            let quion_proto::packet::Header::Long(header) = header else {
                return Err(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                ));
            };
            header.dst_cid
        };
        let (mut progress, response_packets) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .proto_endpoint
                .path(meta.remote)
                .record_received(meta.len as u64);
            let connection = match state.server_initial.entry(route_cid.clone()) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let reservation = self
                        .endpoint_memory_budget
                        .try_reserve(pending_handshake_memory_reservation_bytes(transport_config))
                        .ok_or(ConnectionError::EndpointMemoryLimitReached)?;
                    let mut connection = ServerInitialConnection::new(
                        config,
                        transport_config,
                        ServerInitialQlog::new(
                            self.server_qlog_handler.clone(),
                            self.server_max_buffered_qlog_events,
                        ),
                        packet,
                        None,
                        meta.remote,
                        Some(derive_stateless_reset_token(
                            &self.stateless_reset_key,
                            &route_cid,
                        )),
                    )?;
                    connection.attach_endpoint_memory_reservation(reservation);
                    entry.insert(connection)
                }
            };
            let (progress, response_packets) = connection.handle_crypto_packet(packet)?;
            (progress, response_packets)
        };
        if progress.handshake_packets_received != 0 {
            self.validate_server_path(meta.remote);
        }
        let send_result = self.send_server_crypto_flight_packets(meta.remote, response_packets)?;
        progress.response_packets_sent += send_result.sent.len();
        let established = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let connection = state.server_initial.get_mut(&route_cid);
            if let Some(connection) = connection {
                connection.record_crypto_packets_sent(&send_result.sent);
                connection.queue_pending_crypto_packets(send_result.unsent);
                connection.take_established_connection(
                    self.local_addr,
                    self.endpoint_memory_budget.clone(),
                )
            } else {
                None
            }
        };
        if let Some((route_cid, connection)) = established {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let route_cid_len = route_cid.len();
            let connection_id = state.register_connection(route_cid.clone(), connection.clone())?;
            if let Err(error) = state.register_reset_token(
                route_cid.clone(),
                derive_stateless_reset_token(&self.stateless_reset_key, &route_cid),
            ) {
                state.remove_connection(connection_id);
                return Err(error);
            }
            state
                .proto_endpoint
                .insert_route(route_cid.clone(), connection_id);
            let _ = self.advertise_additional_active_connection_id(
                &mut state,
                connection_id,
                &connection,
                route_cid_len,
            );
            state.incoming.push_back(Incoming::new(connection));
            if let Some(waker) = state.accept_waker.take() {
                waker.wake();
            }
            self.increment_accepted_connections(1);
            progress.established_connections = 1;
        }
        Ok(progress)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn handle_server_initial_crypto_packet_inner(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        packet: &mut [u8],
    ) -> Result<(ServerInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        let (header, _consumed) = quion_proto::packet::Header::decode(packet, 0)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let quion_proto::packet::Header::Long(header) = header else {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        };
        let mut connection = ServerInitialConnection::new(
            config,
            transport_config,
            ServerInitialQlog::new(None, crate::qlog::DEFAULT_MAX_BUFFERED_QLOG_EVENTS),
            packet,
            None,
            SocketAddr::from(([0, 0, 0, 0], 0)),
            Some(derive_stateless_reset_token(
                &self.stateless_reset_key,
                &header.dst_cid,
            )),
        )?;
        connection.handle_initial_packet(packet)
    }

    /// Returns the bound local UDP address.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns aggregate endpoint counters.
    pub fn stats(&self) -> EndpointStats {
        self.stats.snapshot()
    }

    /// Returns a stable diagnostics snapshot without exposing internal routing
    /// tables, connection IDs, token material, or runtime task handles.
    pub fn diagnostics(&self) -> EndpointDiagnostics {
        let stats = self.stats();
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let connection_payload_bytes = state
            .connections
            .iter()
            .map(|(_, connection)| {
                let memory = connection.diagnostics().memory;
                memory
                    .protocol
                    .payload_bytes()
                    .saturating_add(memory.connection_id_bytes)
                    .saturating_add(memory.qlog_bytes)
            })
            .fold(0usize, usize::saturating_add);
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        let pending_handshake_payload_bytes = state
            .server_initial
            .values()
            .map(ServerInitialConnection::memory_payload_bytes)
            .chain(
                state
                    .client_crypto
                    .values()
                    .map(ClientCryptoConnection::memory_payload_bytes),
            )
            .fold(0usize, usize::saturating_add);
        #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
        let pending_handshake_payload_bytes = 0;
        let routed_datagram_bytes = self.routed_datagram_memory_budget.used_bytes();
        let connection_id_route_bytes = state.connection_id_route_memory_bytes();
        EndpointDiagnostics {
            stats,
            is_closed: state.closed,
            active_connections: state.connections.len(),
            pending_incoming_connections: state.incoming.len(),
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            pending_server_handshakes: state.server_initial.len(),
            #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
            pending_server_handshakes: 0,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            pending_client_handshakes: state.client_crypto.len(),
            #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
            pending_client_handshakes: 0,
            tracked_paths: state.proto_endpoint.tracked_paths(),
            max_tracked_paths: self.max_tracked_endpoint_paths,
            routed_datagram_bytes,
            max_routed_datagram_bytes: self
                .server_connection_limits
                .max_endpoint_routed_datagram_bytes,
            connection_id_routes: state.routes.len(),
            memory: EndpointMemoryDiagnostics {
                reserved_payload_bytes: self.endpoint_memory_budget.used_bytes(),
                max_payload_bytes: self.endpoint_memory_budget.max_bytes(),
                connection_payload_bytes,
                pending_handshake_payload_bytes,
                routed_datagram_bytes,
                connection_id_route_bytes,
            },
        }
    }

    #[allow(dead_code)]
    pub(crate) fn route_connection(
        &self,
        dst_cid: &quion_proto::cid::ConnectionId,
    ) -> Option<Connection> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.remove_closed_connections();
        state.route_connection(dst_cid)
    }

    #[allow(dead_code)]
    pub(crate) fn enqueue_incoming(&self, incoming: Incoming) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.incoming.push_back(incoming);
        if let Some(waker) = state.accept_waker.take() {
            waker.wake();
        }
        self.increment_accepted_connections(1);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn maybe_spawn_connect_driver(
        &self,
        connecting: &mut Connecting,
        connection: Connection,
        _server_addr: SocketAddr,
        server_name: &str,
        _original_dst_cid: quion_proto::cid::ConnectionId,
        _original_src_cid: quion_proto::cid::ConnectionId,
    ) -> Result<(), ConnectionError> {
        let Some(client_config) = self
            .default_client_config
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
        else {
            return Ok(());
        };
        let Some(runtime_config) = client_config.rustls.clone() else {
            return Ok(());
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return Ok(());
        }
        connection.set_endpoint_runtime_notify(self.runtime_notify.clone());

        let transport_config = client_config.transport.into_proto();
        let (mut tx, rx) = tokio::sync::oneshot::channel();
        let preserve = connecting.preserve_early_connection.clone();
        connecting.completion = Some(rx);
        let Some(mut client_crypto) = connecting.state.take() else {
            return Ok(());
        };
        client_crypto.initialize_rustls_client(
            runtime_config.clone(),
            server_name,
            &transport_config,
        )?;
        let route_cid = client_crypto.route_cid();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .client_crypto
                .insert(route_cid.clone(), *client_crypto);
        }
        self.ensure_client_endpoint_udp_driver();

        let endpoint = self.clone();
        let server_name = server_name.to_owned();
        let span = trace_span!(
            "quion.endpoint.driver",
            driver = "connect",
            local = %endpoint.local_addr,
            remote = %_server_addr
        );
        let driver_route_cid = route_cid.clone();
        let join = tokio::spawn(
            async move {
                let result = {
                    let drive = endpoint.drive_connecting(
                        &route_cid,
                        runtime_config,
                        &server_name,
                        &transport_config,
                    );
                    tokio::pin!(drive);
                    tokio::select! {
                        biased;
                        _ = tx.closed() => {
                            if preserve.load(Ordering::Acquire) { drive.await }
                            else { Err(ConnectionError::LocallyClosed) }
                        }
                        result = &mut drive => result,
                    }
                };
                let result = result.and_then(|()| {
                    let (connection, driver) = endpoint.take_client_crypto_handoff(&route_cid)?;
                    {
                        let mut state = endpoint
                            .state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let route_cid_len = route_cid.len();
                        let connection_id =
                            state.register_connection(route_cid.clone(), connection.clone())?;
                        state
                            .proto_endpoint
                            .insert_route(route_cid.clone(), connection_id);
                        if let Err(error) = endpoint.advertise_additional_active_connection_id(
                            &mut state,
                            connection_id,
                            &connection,
                            route_cid_len,
                        ) {
                            state.remove_connection(connection_id);
                            return Err(error);
                        }
                    }
                    let driver_id = {
                        let mut state = endpoint
                            .state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        state
                            .store_endpoint_one_rtt_driver(connection.clone(), driver.routed_only())
                    };
                    endpoint.activate_endpoint_one_rtt_driver(&connection, driver_id);
                    endpoint.ensure_client_endpoint_udp_driver();
                    connection.mark_runtime_driven();
                    endpoint.runtime_notify.notify_waiters();
                    Ok(connection)
                });
                let mut state = endpoint
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.client_crypto.remove(&route_cid);
                drop(state);
                if result.is_err() && !preserve.load(Ordering::Acquire) {
                    connection.abort();
                }
                let _ = tx.send(result.map(|connection| ConnectCompletion {
                    connection,
                    preserve,
                    delivered: false,
                }));
                endpoint.runtime_notify.notify_one();
            }
            .instrument(span),
        );
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.store_connecting_driver(ConnectingDriverHandle {
                route_cid: driver_route_cid,
                join,
            });
        }
        Ok(())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn complete_server_connection_handoff(
        &self,
        mut server_initial: ServerInitialConnection,
        progress: &mut EndpointServerProgress,
    ) {
        if !server_initial.is_within_endpoint_memory_reservation() {
            self.increment_rejected_connections(1);
            progress.dropped_packets = progress.dropped_packets.saturating_add(1);
            return;
        }
        let original_destination_cid = server_initial.original_destination_cid();
        if let Some((route_cid, connection)) = server_initial
            .take_established_connection(self.local_addr, self.endpoint_memory_budget.clone())
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let route_cid_len = route_cid.len();
            let Ok(connection_id) =
                state.register_connection(route_cid.clone(), connection.clone())
            else {
                self.increment_rejected_connections(1);
                progress.dropped_packets = progress.dropped_packets.saturating_add(1);
                return;
            };
            if state
                .register_reset_token(
                    route_cid.clone(),
                    derive_stateless_reset_token(&self.stateless_reset_key, &route_cid),
                )
                .is_err()
            {
                state.remove_connection(connection_id);
                self.increment_rejected_connections(1);
                progress.dropped_packets = progress.dropped_packets.saturating_add(1);
                return;
            }
            state
                .proto_endpoint
                .insert_route(route_cid.clone(), connection_id);
            if original_destination_cid != route_cid {
                if state
                    .register_connection_route(
                        original_destination_cid.clone(),
                        connection_id,
                        quion_proto::endpoint::ConnectionRouteKind::OriginalDestination,
                    )
                    .is_err()
                {
                    state.remove_connection(connection_id);
                    self.increment_rejected_connections(1);
                    progress.dropped_packets = progress.dropped_packets.saturating_add(1);
                    return;
                }
                state.proto_endpoint.insert_connection_route(
                    original_destination_cid,
                    connection_id,
                    quion_proto::endpoint::ConnectionRouteKind::OriginalDestination,
                );
            }
            let _ = self.advertise_additional_active_connection_id(
                &mut state,
                connection_id,
                &connection,
                route_cid_len,
            );
            state.incoming.push_back(Incoming::new(connection.clone()));
            if let Some(waker) = state.accept_waker.take() {
                waker.wake();
            }
            self.increment_accepted_connections(1);
            progress.established_connections = 1;
            if let Some(driver) = server_initial.take_protected_one_rtt_driver() {
                let driver_id = state.store_endpoint_one_rtt_driver(connection.clone(), driver);
                #[cfg(not(feature = "runtime-tokio"))]
                let _ = driver_id;
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                self.activate_endpoint_one_rtt_driver(&connection, driver_id);
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                if tokio::runtime::Handle::try_current().is_ok() {
                    connection.mark_runtime_driven();
                }
            }
        } else {
            if !server_initial.has_authenticated_packet() || server_initial.is_closed() {
                return;
            }
            let route_cid = server_initial.route_cid();
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.server_initial.insert(route_cid, server_initial);
        }
    }

    fn client_transport_config(&self) -> quion_proto::config::TransportConfig {
        self.default_client_config
            .lock()
            .ok()
            .and_then(|slot| {
                slot.as_ref()
                    .map(|config| config.transport.clone().into_proto())
            })
            .unwrap_or_else(|| self.transport_config.clone())
    }

    fn client_initial_version(&self) -> u32 {
        self.default_client_config
            .lock()
            .ok()
            .and_then(|slot| {
                slot.as_ref().map(|config| {
                    if config.version_negotiation_probe_enabled() {
                        quion_proto::packet::VERSION_NEGOTIATION_PROBE
                    } else {
                        quion_proto::packet::QUIC_VERSION_1
                    }
                })
            })
            .unwrap_or(quion_proto::packet::QUIC_VERSION_1)
    }

    /// Returns whether an endpoint that has begun shutdown has drained all
    /// runtime-owned protocol work and can stop its UDP driver task.
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn runtime_shutdown_ready(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.closed {
            return false;
        }
        state.remove_closed_connections();
        state.connections.is_empty()
            && state.server_initial.is_empty()
            && state.client_crypto.is_empty()
            && state.endpoint_one_rtt_drivers.is_empty()
            && state.connecting_drivers.is_empty()
    }

    fn client_max_buffered_qlog_events(&self) -> usize {
        self.default_client_config
            .lock()
            .ok()
            .and_then(|slot| {
                slot.as_ref()
                    .map(|config| config.transport.max_buffered_qlog_events())
            })
            .unwrap_or(crate::qlog::DEFAULT_MAX_BUFFERED_QLOG_EVENTS)
    }

    fn client_runtime_driver_work_limit(&self) -> usize {
        self.default_client_config
            .lock()
            .ok()
            .and_then(|slot| {
                slot.as_ref()
                    .map(|config| config.transport.max_runtime_driver_work_per_tick())
            })
            .unwrap_or(DEFAULT_RUNTIME_DRIVER_WORK_PER_TICK)
            .max(1)
    }

    fn client_runtime_driver_receive_limits(&self) -> (usize, usize) {
        if let Ok(slot) = self.default_client_config.lock()
            && let Some(config) = slot.as_ref()
        {
            let max_udp_payload = config.transport.mtu_discovery_config().map_or_else(
                || config.transport.initial_mtu(),
                |config| config.upper_bound(),
            );
            return (
                config.transport.max_runtime_driver_work_per_tick().max(1),
                usize::from(max_udp_payload),
            );
        }
        let max_udp_payload = self
            .transport_config
            .mtu_discovery
            .as_ref()
            .map_or(self.transport_config.initial_mtu, |config| {
                config.upper_bound()
            });
        (
            DEFAULT_RUNTIME_DRIVER_WORK_PER_TICK,
            usize::from(max_udp_payload),
        )
    }

    fn client_connection_id_length(&self) -> usize {
        let configured = self.client_transport_config().connection_id_length;
        if configured == 0 {
            8
        } else {
            usize::from(configured).min(quion_proto::cid::MAX_CONNECTION_ID_LEN)
        }
    }

    fn generate_connection_id(
        &self,
        requested_len: usize,
    ) -> Result<quion_proto::cid::ConnectionId, ConnectionError> {
        let requested_len = requested_len.min(quion_proto::cid::MAX_CONNECTION_ID_LEN);
        let generator = self
            .connection_id_generator
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let connection_id = generator(requested_len);
        if connection_id.len() != requested_len {
            return Err(ConnectionError::Runtime(
                "connection ID generator returned an unexpected length".into(),
            ));
        }
        Ok(connection_id)
    }

    fn advertise_additional_active_connection_id(
        &self,
        state: &mut EndpointState,
        connection_id: usize,
        connection: &Connection,
        connection_id_len: usize,
    ) -> Result<(), ConnectionError> {
        if connection
            .negotiated_transport()
            .unwrap_or_default()
            .active_connection_id_limit
            .into_inner()
            <= 1
        {
            return Ok(());
        }
        if connection_id_len == 0 {
            return Ok(());
        }
        let active_cid = self.generate_connection_id(connection_id_len)?;
        let reset_token = derive_stateless_reset_token(&self.stateless_reset_key, &active_cid);
        state.register_connection_route(
            active_cid.clone(),
            connection_id,
            quion_proto::endpoint::ConnectionRouteKind::Active,
        )?;
        if let Err(error) = state.register_reset_token(active_cid.clone(), reset_token) {
            state.remove_connection_route(&active_cid);
            return Err(error);
        }
        if let Err(error) =
            connection.advertise_local_connection_id(1, 0, active_cid.clone(), reset_token)
        {
            state.remove_connection_route(&active_cid);
            return Err(error);
        }
        state.proto_endpoint.insert_connection_route(
            active_cid,
            connection_id,
            quion_proto::endpoint::ConnectionRouteKind::Active,
        );
        Ok(())
    }

    fn retire_connection_routes(&self, connection: &Connection) {
        let retired = connection.drain_retired_local_connection_ids();
        if retired.is_empty() {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for cid in retired {
            state.retire_active_connection_route(&cid);
        }
    }

    fn client_qlog_handler(&self) -> Option<QlogHandler> {
        self.default_client_config.lock().ok().and_then(|slot| {
            slot.as_ref()
                .and_then(|config| config.transport.qlog_handler())
        })
    }

    fn endpoint_qlog_handler(&self) -> Option<QlogHandler> {
        self.server_qlog_handler
            .clone()
            .or_else(|| self.client_qlog_handler())
    }

    fn publish_endpoint_qlog(&self, event: crate::QlogEvent) {
        if let Some(handler) = self.endpoint_qlog_handler() {
            handler(&event);
        }
    }

    fn reserve_server_send_budget(&self, remote: SocketAddr, bytes: usize) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.proto_endpoint.can_send_to(remote, bytes as u64)
    }

    fn record_server_datagram_received(&self, remote: SocketAddr, bytes: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .proto_endpoint
            .path(remote)
            .record_received(bytes as u64);
    }

    fn validate_server_path(&self, remote: SocketAddr) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.proto_endpoint.path(remote).validate();
    }

    fn refund_server_send_budget(&self, remote: SocketAddr, bytes: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.proto_endpoint.refund_send_to(remote, bytes as u64);
    }

    fn send_server_budgeted(
        &self,
        transmit: &quion_udp::Transmit,
    ) -> Result<bool, ConnectionError> {
        let bytes = transmit.contents.len();
        if !self.reserve_server_send_budget(transmit.destination, bytes) {
            return Ok(false);
        }
        if let Err(error) = self.socket.send(transmit).map_err(map_udp_error) {
            self.refund_server_send_budget(transmit.destination, bytes);
            return Err(error);
        }
        Ok(true)
    }

    fn enqueue_connection_routed_datagram(
        &self,
        connection: &Connection,
        meta: quion_udp::RecvMeta,
        contents: &[u8],
    ) -> bool {
        let recycled = self
            .routed_datagram_buffer_pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .buffers
            .pop();
        connection.enqueue_recycled_routed_datagram_with_budget(
            meta,
            contents,
            self.routed_datagram_memory_budget.clone(),
            recycled,
        )
    }

    fn enqueue_owned_connection_routed_datagram(
        &self,
        connection: &Connection,
        meta: quion_udp::RecvMeta,
        contents: Vec<u8>,
    ) -> bool {
        connection.enqueue_owned_routed_datagram_with_budget(
            meta,
            contents,
            self.routed_datagram_memory_budget.clone(),
        )
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn refill_receive_batch_from_routed_pool(
        &self,
        batch: &mut quion_udp::BatchRecv,
        max_buffers: usize,
    ) {
        let mut pool = self
            .routed_datagram_buffer_pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for _ in 0..max_buffers.min(pool.buffers.len()) {
            let datagram = pool
                .buffers
                .pop()
                .expect("transfer count is bounded by pool length");
            batch.recycle(datagram.contents);
        }
    }

    fn increment_opened_connections(&self, count: u64) {
        self.stats
            .opened_connections
            .fetch_add(count, Ordering::Relaxed);
    }

    fn increment_accepted_connections(&self, count: u64) {
        self.stats
            .accepted_connections
            .fetch_add(count, Ordering::Relaxed);
    }

    fn increment_closed_connections(&self, count: u64) {
        self.stats
            .closed_connections
            .fetch_add(count, Ordering::Relaxed);
    }

    fn increment_rejected_connections(&self, count: u64) {
        self.stats
            .rejected_connections
            .fetch_add(count, Ordering::Relaxed);
    }

    fn increment_packets_received(&self, count: u64) {
        self.stats
            .packets_received
            .fetch_add(count, Ordering::Relaxed);
    }

    fn increment_packets_sent(&self, count: u64) {
        self.stats.packets_sent.fetch_add(count, Ordering::Relaxed);
    }

    fn increment_dropped_packets(&self, count: u64) {
        self.stats
            .dropped_packets
            .fetch_add(count, Ordering::Relaxed);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn client_crypto_ready_for_handoff(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<bool, ConnectionError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(state
            .client_crypto
            .get(route_cid)
            .is_some_and(ClientCryptoConnection::is_established_for_handoff))
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn take_client_crypto_handoff(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<(Connection, ProtectedOneRttUdpDriver), ConnectionError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut client = state
            .client_crypto
            .remove(route_cid)
            .ok_or(ConnectionError::LocallyClosed)?;
        let driver = client
            .take_protected_one_rtt_driver()
            .ok_or(ConnectionError::Unsupported)?;
        Ok((client.into_connection(), driver))
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[allow(dead_code)]
    pub(crate) fn spawn_protected_one_rtt_udp_driver(
        &self,
        connection: Connection,
        driver: ProtectedOneRttUdpDriver,
        recv_buffer_size: usize,
    ) -> ProtectedOneRttUdpDriverHandle {
        let endpoint = self.clone();
        let runtime_socket = endpoint.runtime_udp_socket();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
        let handle_connection = connection.clone();
        let span = trace_span!(
            "quion.endpoint.driver",
            driver = "protected_one_rtt",
            local = %endpoint.local_addr,
            remote = %connection.remote_address()
        );
        let join = tokio::spawn(async move {
            let mut driver = driver;
            let mut recv_buffer = vec![0; recv_buffer_size];
            let mut work_limiter =
                RuntimeWorkLimiter::new(MAX_CONSECUTIVE_RUNTIME_PROGRESS);
            loop {
                if connection.runtime_shutdown_ready() {
                    return Ok(());
                }
                tokio::select! {
                    _ = &mut stop_rx => return Ok(()),
                    result = endpoint.poll_driver_batch_and_wait(&connection, &mut driver, runtime_socket.as_ref(), &mut recv_buffer) => {
                        let made_progress = result?;
                        if work_limiter.record(made_progress) {
                            crate::Runtime::yield_now(&crate::TokioRuntime).await;
                        }
                    }
                }
            }
        }
        .instrument(span));
        ProtectedOneRttUdpDriverHandle {
            connection: handle_connection,
            stop: Some(stop_tx),
            join,
        }
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn ensure_client_endpoint_udp_driver(&self) {
        if self
            .client_endpoint_driver_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let endpoint = self.clone();
        tokio::spawn(async move {
            let result = endpoint.drive_client_endpoint_udp().await;
            endpoint
                .client_endpoint_driver_running
                .store(false, Ordering::Release);
            if let Err(error) = result {
                debug!(?error, "client endpoint UDP driver stopped with an error");
            }
        });
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    async fn drive_client_endpoint_udp(&self) -> Result<(), ConnectionError> {
        let runtime_socket = self.runtime_udp_socket();
        let mut recv_batch = quion_udp::BatchRecv::default();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let mut work_limiter = RuntimeWorkLimiter::new(MAX_CONSECUTIVE_RUNTIME_PROGRESS);
        loop {
            if self.runtime_shutdown_ready() {
                return Ok(());
            }
            let made_progress = self
                .poll_client_endpoint_udp_once_and_wait(
                    runtime_socket.as_ref(),
                    &mut recv_batch,
                    &mut recv_buffer,
                )
                .await?;
            if work_limiter.record(made_progress) {
                crate::Runtime::yield_now(&crate::TokioRuntime).await;
            }
        }
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    /// Spawns a Tokio server UDP driver with explicit TLS and transport state.
    pub fn spawn_server_udp_driver(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: quion_proto::config::TransportConfig,
        recv_buffer_size: usize,
    ) -> EndpointServerUdpDriverHandle {
        let endpoint = self.clone();
        let runtime_socket = endpoint.runtime_udp_socket();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
        let span = trace_span!(
            "quion.endpoint.driver",
            driver = "server_udp",
            local = %endpoint.local_addr
        );
        let join = tokio::spawn(
            async move {
                let mut recv_buffer = vec![0; recv_buffer_size];
                let mut recv_batch = quion_udp::BatchRecv::default();
                let mut work_limiter = RuntimeWorkLimiter::new(MAX_CONSECUTIVE_RUNTIME_PROGRESS);
                loop {
                    if endpoint.runtime_shutdown_ready() {
                        return Ok(());
                    }
                    tokio::select! {
                        _ = &mut stop_rx => return Ok(()),
                        result = endpoint.poll_server_udp_once_and_wait(
                            config.clone(),
                            &transport_config,
                            runtime_socket.as_ref(),
                            &mut recv_batch,
                            &mut recv_buffer,
                        ) => {
                            let made_progress = result?;
                            if work_limiter.record(made_progress) {
                                crate::Runtime::yield_now(&crate::TokioRuntime).await;
                            }
                        }
                    }
                }
            }
            .instrument(span),
        );
        EndpointServerUdpDriverHandle {
            stop: Some(stop_tx),
            join,
        }
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    /// Spawns a Tokio server UDP driver using the endpoint configuration.
    pub fn spawn_default_server_udp_driver(
        &self,
        recv_buffer_size: usize,
    ) -> Result<EndpointServerUdpDriverHandle, ConnectionError> {
        let config = self
            .default_server_config
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or(ConnectionError::Unsupported)?;
        Ok(self.spawn_server_udp_driver(config, self.transport_config.clone(), recv_buffer_size))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[cfg(test)]
    pub(crate) fn poll_protected_one_rtt_udp_once(
        &self,
        connection: &Connection,
        driver: &mut ProtectedOneRttUdpDriver,
        recv_buffer: &mut [u8],
    ) -> Result<EndpointDriverProgress, ConnectionError> {
        self.poll_protected_one_rtt_udp_inner(connection, driver, recv_buffer, true, true, 1)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_protected_one_rtt_udp_inner(
        &self,
        connection: &Connection,
        driver: &mut ProtectedOneRttUdpDriver,
        recv_buffer: &mut [u8],
        check_due_timeout: bool,
        report_timeout_deadline: bool,
        max_transmit_batch: usize,
    ) -> Result<EndpointDriverProgress, ConnectionError> {
        let _span = trace_span!(
            "quion.endpoint",
            action = "poll_protected_one_rtt_udp_once",
            local = %self.local_addr,
            remote = %connection.remote_address()
        )
        .entered();
        let mut progress = EndpointDriverProgress::default();
        let now = web_time::Instant::now();
        driver.retire_previous_key_if_due(now);

        if check_due_timeout
            && connection
                .next_timeout()
                .is_some_and(|timeout| timeout <= now)
            && connection.on_timeout(now)?
        {
            progress.timeouts_processed = 1;
        }

        if driver.pending_transmits.is_empty()
            && driver
                .keys
                .get(quion_proto::crypto::EncryptionLevel::OneRtt)
                .is_some()
        {
            driver.ensure_can_protect_next_packet()?;
            let next_packet_number = driver.builder.next_one_rtt_packet_number();
            if driver.initiate_key_update_if_needed()? {
                driver.note_key_phase_started(next_packet_number);
                progress.key_updates_initiated = 1;
            }
            let max_transmits = driver.protected_transmit_batch_limit(max_transmit_batch);
            connection.poll_protected_one_rtt_udp_transmit_batch_with_metadata(
                &mut driver.builder,
                &driver.keys,
                max_transmits,
                &mut driver.proto_transmits,
                &mut driver.generated_transmits,
            )?;
            driver
                .pending_transmits
                .extend(
                    driver
                        .generated_transmits
                        .drain(..)
                        .map(|(transmit, contains_ack)| PendingOneRttTransmit {
                            transmit,
                            contains_ack,
                            #[cfg(all(feature = "gso", any(target_os = "linux", test)))]
                            packet_count: 1,
                        }),
                );
        }

        while driver.pending_transmits.front().is_some_and(|pending| {
            pending
                .transmit
                .send_at
                .is_none_or(|send_at| send_at <= now)
        }) {
            let pending = driver
                .pending_transmits
                .pop_front()
                .expect("front was checked above");
            #[cfg(all(target_os = "linux", feature = "gso"))]
            let mut pending = pending;
            #[cfg(all(target_os = "linux", feature = "gso"))]
            driver.coalesce_gso_transmits(&mut pending, now);
            driver.pending_batch_ack_metadata.push(pending.contains_ack);
            driver.send_batch.push(pending.transmit);
        }
        if !driver.send_batch.is_empty() {
            let sent_count = match self.socket.send_batch(&driver.send_batch) {
                Ok(sent_count) => sent_count.min(driver.send_batch.len()),
                Err(error) => {
                    while let Some(transmit) = driver.send_batch.pop() {
                        let contains_ack = driver
                            .pending_batch_ack_metadata
                            .pop()
                            .expect("send batch metadata length matches transmits");
                        #[cfg(all(feature = "gso", any(target_os = "linux", test)))]
                        let packet_count = transmit_segment_count(&transmit);
                        driver.pending_transmits.push_front(PendingOneRttTransmit {
                            transmit,
                            contains_ack,
                            #[cfg(all(feature = "gso", any(target_os = "linux", test)))]
                            packet_count,
                        });
                    }
                    return Err(map_udp_error(error));
                }
            };
            while driver.send_batch.len() > sent_count {
                let transmit = driver.send_batch.pop().expect("batch length was checked");
                let contains_ack = driver
                    .pending_batch_ack_metadata
                    .pop()
                    .expect("send batch metadata length matches transmits");
                #[cfg(all(feature = "gso", any(target_os = "linux", test)))]
                let packet_count = transmit_segment_count(&transmit);
                driver.pending_transmits.push_front(PendingOneRttTransmit {
                    transmit,
                    contains_ack,
                    #[cfg(all(feature = "gso", any(target_os = "linux", test)))]
                    packet_count,
                });
            }
            while let Some(transmit) = driver.send_batch.pop() {
                let contains_ack = driver
                    .pending_batch_ack_metadata
                    .pop()
                    .expect("send batch metadata length matches transmits");
                let packet_count = transmit_segment_count(&transmit);
                self.increment_packets_sent(packet_count as u64);
                connection.record_path_sent_batch(
                    transmit.destination,
                    packet_count as u64,
                    transmit.contents.len(),
                );
                for packet_index in 0..packet_count {
                    driver.record_one_rtt_packet_sent(contains_ack && packet_index == 0);
                }
                progress.sent_packets += packet_count;
                trace!("sent protected one-rtt datagram");
                if transmit.segment_size.is_some() {
                    driver.send_batch.recycle_payload_buffer(transmit.contents);
                } else {
                    driver.builder.recycle_packet(transmit.contents);
                }
            }
        }
        if let Some(pending) = driver.pending_transmits.front() {
            progress.next_send_at = Some(
                pending
                    .transmit
                    .send_at
                    .unwrap_or(now + web_time::Duration::from_millis(1)),
            );
        }
        if progress.sent_packets != 0 {
            connection.record_activity(now);
        }

        if let Some(datagram) = connection.pop_routed_datagram() {
            let key_phase_before = driver.keys.current_one_rtt_key_phase();
            let sent_in_phase_before = driver.one_rtt_packets_sent_with_current_key;
            let key_update_permitted = sent_in_phase_before > 0 && !driver.peer_update_ack_pending;
            let meta = datagram.meta.clone();
            let owner = PooledRoutedDatagram {
                datagram: Some(datagram),
                pool: self.routed_datagram_buffer_pool.clone(),
            };
            let receive_state = connection.recv_protected_one_rtt_udp_owned(
                driver.tls_session.as_mut(),
                &mut driver.keys,
                owner,
                driver.expected_dst_cid_len,
                quion_proto::connection::OneRttReceiveContext {
                    largest_received: driver.largest_received,
                    key_update_permitted,
                },
                &meta,
            )?;
            if let Some(receive_state) = receive_state {
                driver.largest_received = receive_state.largest_received;
                if driver.validate_and_reset_after_peer_key_update(
                    key_phase_before,
                    sent_in_phase_before,
                )? {
                    driver.note_key_phase_started(driver.builder.next_one_rtt_packet_number());
                }
                driver.note_new_phase_packet_received(now, receive_state.key_retirement_duration);
                driver.confirm_key_phase_if_acked(receive_state.largest_acked);
            }
            if let Some(peer_connection_id) = connection.take_active_peer_connection_id_update() {
                driver
                    .builder
                    .set_destination_connection_id(peer_connection_id);
            }
            self.retire_connection_routes(connection);
            progress.received_packets = 1;
            trace!("processed routed one-rtt datagram");
        } else if !driver.routed_only {
            if max_transmit_batch > 1 {
                let received = self
                    .socket
                    .recv_batch(
                        &mut driver.recv_batch,
                        max_transmit_batch,
                        recv_buffer.len().min(2_048),
                    )
                    .map_err(map_udp_error)?;
                for _ in 0..received {
                    let Some((mut packet, meta)) = driver.recv_batch.pop_front() else {
                        break;
                    };
                    self.increment_packets_received(1);
                    let packet_len = meta.len.min(packet.len());
                    self.process_client_one_rtt_datagram(
                        connection,
                        driver,
                        &mut packet[..packet_len],
                        &meta,
                        now,
                    )?;
                    driver.recv_batch.recycle(packet);
                    progress.received_packets += 1;
                }
            } else if let Some(meta) = self.socket.recv(recv_buffer).map_err(map_udp_error)? {
                self.increment_packets_received(1);
                let packet = &mut recv_buffer[..meta.len];
                self.process_client_one_rtt_datagram(connection, driver, packet, &meta, now)?;
                progress.received_packets = 1;
            }
        }

        if report_timeout_deadline {
            progress.next_timeout =
                earlier_deadline(connection.next_timeout(), driver.previous_key_discard_at);
        }
        Ok(progress)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn process_client_one_rtt_datagram(
        &self,
        connection: &Connection,
        driver: &mut ProtectedOneRttUdpDriver,
        packet: &mut [u8],
        meta: &quion_udp::RecvMeta,
        now: web_time::Instant,
    ) -> Result<(), ConnectionError> {
        if !self.route_client_socket_datagram(meta.clone(), packet, None, Some(connection))? {
            self.process_known_client_one_rtt_datagram(connection, driver, packet, meta, now)?;
        }
        trace!(
            remote = %meta.remote,
            packet_len = meta.len,
            "routed client socket datagram"
        );
        Ok(())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn process_known_client_one_rtt_datagram(
        &self,
        connection: &Connection,
        driver: &mut ProtectedOneRttUdpDriver,
        packet: &mut [u8],
        meta: &quion_udp::RecvMeta,
        now: web_time::Instant,
    ) -> Result<(), ConnectionError> {
        let key_phase_before = driver.keys.current_one_rtt_key_phase();
        let sent_in_phase_before = driver.one_rtt_packets_sent_with_current_key;
        let key_update_permitted = sent_in_phase_before > 0 && !driver.peer_update_ack_pending;
        let receive_state = if let Some(session) = driver.tls_session.as_mut() {
            connection.recv_protected_one_rtt_udp_with_session(
                session,
                &mut driver.keys,
                packet,
                driver.expected_dst_cid_len,
                quion_proto::connection::OneRttReceiveContext {
                    largest_received: driver.largest_received,
                    key_update_permitted,
                },
                meta,
            )?
        } else {
            connection.recv_protected_one_rtt_udp_with_key_update_permission(
                &mut driver.keys,
                packet,
                driver.expected_dst_cid_len,
                driver.largest_received,
                key_update_permitted,
                meta,
            )?
        };
        if let Some(receive_state) = receive_state {
            driver.largest_received = receive_state.largest_received;
            if driver
                .validate_and_reset_after_peer_key_update(key_phase_before, sent_in_phase_before)?
            {
                driver.note_key_phase_started(driver.builder.next_one_rtt_packet_number());
            }
            driver.note_new_phase_packet_received(now, receive_state.key_retirement_duration);
            driver.confirm_key_phase_if_acked(receive_state.largest_acked);
        }
        if let Some(peer_connection_id) = connection.take_active_peer_connection_id_update() {
            driver
                .builder
                .set_destination_connection_id(peer_connection_id);
        }
        self.retire_connection_routes(connection);
        Ok(())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn process_known_client_one_rtt_datagram_owned(
        &self,
        connection: &Connection,
        driver: &mut ProtectedOneRttUdpDriver,
        packet: Vec<u8>,
        meta: quion_udp::RecvMeta,
        now: web_time::Instant,
    ) -> Result<(), ConnectionError> {
        let Some(datagram) =
            RoutedDatagram::with_budget(meta.clone(), packet, &self.routed_datagram_memory_budget)
        else {
            self.increment_rejected_connections(1);
            return Ok(());
        };
        let key_phase_before = driver.keys.current_one_rtt_key_phase();
        let sent_in_phase_before = driver.one_rtt_packets_sent_with_current_key;
        let key_update_permitted = sent_in_phase_before > 0 && !driver.peer_update_ack_pending;
        let owner = PooledRoutedDatagram {
            datagram: Some(datagram),
            pool: self.routed_datagram_buffer_pool.clone(),
        };
        let receive_state = connection.recv_protected_one_rtt_udp_owned(
            driver.tls_session.as_mut(),
            &mut driver.keys,
            owner,
            driver.expected_dst_cid_len,
            quion_proto::connection::OneRttReceiveContext {
                largest_received: driver.largest_received,
                key_update_permitted,
            },
            &meta,
        )?;
        if let Some(receive_state) = receive_state {
            driver.largest_received = receive_state.largest_received;
            if driver
                .validate_and_reset_after_peer_key_update(key_phase_before, sent_in_phase_before)?
            {
                driver.note_key_phase_started(driver.builder.next_one_rtt_packet_number());
            }
            driver.note_new_phase_packet_received(now, receive_state.key_retirement_duration);
            driver.confirm_key_phase_if_acked(receive_state.largest_acked);
        }
        if let Some(peer_connection_id) = connection.take_active_peer_connection_id_update() {
            driver
                .builder
                .set_destination_connection_id(peer_connection_id);
        }
        self.retire_connection_routes(connection);
        Ok(())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_endpoint_one_rtt_drivers(
        &self,
        recv_buffer: &mut [u8],
        max_work_per_driver: usize,
    ) -> Result<EndpointDriverProgress, ConnectionError> {
        let drivers = self.take_endpoint_one_rtt_drivers();
        let (aggregate, retained) =
            self.poll_taken_endpoint_one_rtt_drivers(drivers, recv_buffer, max_work_per_driver);
        self.restore_endpoint_one_rtt_drivers(retained);
        Ok(aggregate)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn take_endpoint_one_rtt_drivers(&self) -> BTreeMap<u64, EndpointOwnedOneRttDriver> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut state.endpoint_one_rtt_drivers)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn restore_endpoint_one_rtt_drivers(
        &self,
        mut drivers: BTreeMap<u64, EndpointOwnedOneRttDriver>,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Abort can clear endpoint state while a batch is polled outside this
        // lock. Do not resurrect a terminal driver when returning that batch.
        drivers.retain(|_id, owned| {
            // A packet routed before abort can be queued after abort cleared
            // the connection, making runtime_shutdown_ready false again.
            if state.aborted {
                owned.connection.abort();
            }
            if !state.aborted && !owned.connection.runtime_shutdown_ready() {
                return true;
            }
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            self.endpoint_driver_scheduler.remove(*_id);
            false
        });
        // A handshake can register another driver while the current batch is
        // polled without the endpoint lock. Preserve those new drivers.
        state.restore_endpoint_one_rtt_drivers(drivers);
        state.remove_closed_connections();
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_taken_endpoint_one_rtt_drivers(
        &self,
        mut drivers: BTreeMap<u64, EndpointOwnedOneRttDriver>,
        recv_buffer: &mut [u8],
        max_work_per_driver: usize,
    ) -> (
        EndpointDriverProgress,
        BTreeMap<u64, EndpointOwnedOneRttDriver>,
    ) {
        let mut aggregate = EndpointDriverProgress::default();
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        if self.endpoint_driver_scheduler.registered_len() != drivers.len() {
            for (driver_id, owned) in &drivers {
                if !self.endpoint_driver_scheduler.contains(*driver_id) {
                    self.activate_endpoint_one_rtt_driver(&owned.connection, *driver_id);
                }
            }
        }
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        let (driver_ids, scheduled_deadline) = self.endpoint_driver_scheduler.take_ready(
            web_time::Instant::now(),
            MAX_READY_DRIVERS_PER_TICK.min(max_work_per_driver.max(1)),
        );
        #[cfg(not(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        )))]
        let (driver_ids, scheduled_deadline) = (drivers.keys().copied().collect::<Vec<_>>(), None);
        aggregate.next_timeout = scheduled_deadline;

        for driver_id in driver_ids {
            if !drivers.contains_key(&driver_id) {
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                crate::connection::EndpointDriverWakeup::wake_driver(
                    self.endpoint_driver_scheduler.as_ref(),
                    driver_id,
                );
                continue;
            }
            let mut remove_driver = false;
            let mut next_deadline = None;
            #[cfg(feature = "runtime-tokio")]
            let mut made_progress = false;
            if let Some(owned) = drivers.get_mut(&driver_id) {
                if owned.connection.runtime_shutdown_ready() {
                    remove_driver = true;
                } else {
                    for iteration in 0..max_work_per_driver.max(1) {
                        match self.poll_protected_one_rtt_udp_inner(
                            &owned.connection,
                            &mut owned.driver,
                            recv_buffer,
                            iteration == 0,
                            false,
                            max_work_per_driver.max(1),
                        ) {
                            Ok(progress) => {
                                aggregate.sent_packets += progress.sent_packets;
                                aggregate.received_packets += progress.received_packets;
                                aggregate.timeouts_processed += progress.timeouts_processed;
                                aggregate.next_send_at =
                                    earlier_deadline(aggregate.next_send_at, progress.next_send_at);
                                aggregate.next_timeout =
                                    earlier_deadline(aggregate.next_timeout, progress.next_timeout);
                                next_deadline = earlier_deadline(
                                    next_deadline,
                                    earlier_deadline(progress.next_send_at, progress.next_timeout),
                                );
                                let iteration_progress = progress.sent_packets != 0
                                    || progress.received_packets != 0
                                    || progress.timeouts_processed != 0;
                                #[cfg(feature = "runtime-tokio")]
                                {
                                    made_progress = iteration_progress;
                                }
                                if !iteration_progress {
                                    break;
                                }
                                if progress.timeouts_processed != 0 {
                                    break;
                                }
                            }
                            Err(driver_error) => {
                                debug!(
                                    remote = %owned.connection.remote_address(),
                                    ?driver_error,
                                    "endpoint-owned connection driver stopped with an error"
                                );
                                owned.connection.abort_with_runtime_error(driver_error);
                                break;
                            }
                        }
                    }
                    if !owned.connection.runtime_shutdown_ready() {
                        next_deadline = earlier_deadline(
                            next_deadline,
                            earlier_deadline(
                                owned.connection.next_timeout(),
                                owned.driver.previous_key_discard_at,
                            ),
                        );
                    } else {
                        remove_driver = true;
                    }
                }
            }
            if remove_driver {
                drivers.remove(&driver_id);
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                self.endpoint_driver_scheduler.remove(driver_id);
            } else {
                aggregate.next_timeout = earlier_deadline(aggregate.next_timeout, next_deadline);
                #[cfg(all(
                    feature = "runtime-tokio",
                    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
                ))]
                if drivers.contains_key(&driver_id) {
                    self.endpoint_driver_scheduler
                        .schedule(driver_id, next_deadline);
                    // Restore readiness when the work budget interrupts progress.
                    // A poll that made no progress must wait for a new wakeup or
                    // deadline, even if the protocol still has queued frames.
                    // Pending paced transmits also block further packet generation,
                    // but routed receives can still be processed immediately.
                    if made_progress
                        && drivers.get(&driver_id).is_some_and(|owned| {
                            owned.connection.routed_datagram_len() != 0
                                || (owned.driver.pending_transmits.is_empty()
                                    && owned.connection.runtime_has_immediate_work())
                        })
                    {
                        crate::connection::EndpointDriverWakeup::wake_driver(
                            self.endpoint_driver_scheduler.as_ref(),
                            driver_id,
                        );
                    }
                }
            }
        }
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        if self.endpoint_driver_scheduler.has_ready() {
            aggregate.next_timeout =
                earlier_deadline(aggregate.next_timeout, Some(web_time::Instant::now()));
        }
        (aggregate, drivers)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[allow(dead_code)]
    async fn poll_driver_batch_and_wait(
        &self,
        connection: &Connection,
        driver: &mut ProtectedOneRttUdpDriver,
        runtime_socket: Option<&tokio::net::UdpSocket>,
        recv_buffer: &mut [u8],
    ) -> Result<bool, ConnectionError> {
        let mut made_progress = false;
        let mut next_send_at = None;
        let mut next_timeout = None;
        for iteration in 0..self.client_runtime_driver_work_limit() {
            let progress = self.poll_protected_one_rtt_udp_inner(
                connection,
                driver,
                recv_buffer,
                iteration == 0,
                false,
                self.client_runtime_driver_work_limit(),
            )?;
            next_send_at = earlier_deadline(next_send_at, progress.next_send_at);
            next_timeout = earlier_deadline(next_timeout, progress.next_timeout);
            let iteration_progress = progress.sent_packets != 0
                || progress.received_packets != 0
                || progress.timeouts_processed != 0;
            if !iteration_progress {
                break;
            }
            made_progress = true;
        }
        next_timeout = earlier_deadline(
            next_timeout,
            earlier_deadline(connection.next_timeout(), driver.previous_key_discard_at),
        );
        let next_wakeup = match (next_send_at, next_timeout) {
            (Some(send_at), Some(timeout)) => Some(send_at.min(timeout)),
            (Some(send_at), None) => Some(send_at),
            (None, Some(timeout)) => Some(timeout),
            (None, None) => None,
        };
        if let Some(wakeup) = next_wakeup {
            let now = web_time::Instant::now();
            if wakeup <= now {
                return Ok(made_progress);
            }
            if !made_progress {
                self.wait_for_connection_driver_activity(connection, runtime_socket, Some(wakeup))
                    .await;
                return Ok(false);
            }
        }
        if !made_progress {
            self.wait_for_connection_driver_activity(connection, runtime_socket, None)
                .await;
        }
        Ok(made_progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    async fn poll_client_endpoint_udp_once_and_wait(
        &self,
        runtime_socket: Option<&tokio::net::UdpSocket>,
        recv_batch: &mut quion_udp::BatchRecv,
        recv_buffer: &mut [u8],
    ) -> Result<bool, ConnectionError> {
        let (max_work, max_udp_payload) = self.client_runtime_driver_receive_limits();
        let mut drivers = self.take_endpoint_one_rtt_drivers();
        self.refill_receive_batch_from_routed_pool(recv_batch, max_work);
        let received = match self
            .socket
            .recv_batch(
                recv_batch,
                max_work.min(MAX_ENDPOINT_RECV_BATCH),
                recv_buffer.len().min(max_udp_payload),
            )
            .map_err(map_udp_error)
        {
            Ok(received) => received,
            Err(error) => {
                self.restore_endpoint_one_rtt_drivers(drivers);
                return Err(error);
            }
        };
        let mut receive_error = None;
        for _ in 0..received {
            let Some((packet, meta)) = recv_batch.pop_front() else {
                break;
            };
            self.increment_packets_received(1);
            match self.route_owned_client_socket_datagram(meta, packet, &mut drivers) {
                Ok(Some(packet)) => recv_batch.recycle(packet),
                Ok(None) => {}
                Err(error) => {
                    receive_error = Some(error);
                    break;
                }
            }
        }

        let (progress, retained) =
            self.poll_taken_endpoint_one_rtt_drivers(drivers, recv_buffer, max_work);
        self.restore_endpoint_one_rtt_drivers(retained);
        if let Some(error) = receive_error {
            return Err(error);
        }
        let made_progress = received != 0
            || progress.sent_packets != 0
            || progress.received_packets != 0
            || progress.timeouts_processed != 0;
        let next_wakeup = earlier_deadline(progress.next_send_at, progress.next_timeout);
        if let Some(wakeup) = next_wakeup {
            let now = web_time::Instant::now();
            if wakeup <= now {
                return Ok(made_progress);
            }
            if !made_progress {
                self.wait_for_server_runtime_activity(runtime_socket, Some(wakeup))
                    .await;
                return Ok(false);
            }
        }
        if !made_progress {
            self.wait_for_server_runtime_activity(runtime_socket, None)
                .await;
        }
        Ok(made_progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    async fn poll_server_udp_once_and_wait(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        runtime_socket: Option<&tokio::net::UdpSocket>,
        recv_batch: &mut quion_udp::BatchRecv,
        recv_buffer: &mut [u8],
    ) -> Result<bool, ConnectionError> {
        let max_work = self
            .server_connection_limits
            .max_runtime_driver_work_per_tick
            .max(1);
        let progress = self.poll_server_udp_batch_once(
            config,
            transport_config,
            recv_batch,
            recv_buffer,
            max_work,
        )?;
        let next_wakeup = earlier_deadline(
            earlier_deadline(progress.next_one_rtt_send_at, progress.next_one_rtt_timeout),
            progress.next_crypto_timeout,
        );
        let made_progress = progress.received_packets != 0
            || progress.crypto_timeouts_processed != 0
            || progress.response_packets_sent != 0
            || progress.one_rtt_packets_sent != 0
            || progress.one_rtt_packets_received != 0
            || progress.one_rtt_timeouts_processed != 0;
        if let Some(wakeup) = next_wakeup {
            let now = web_time::Instant::now();
            if wakeup <= now {
                return Ok(made_progress);
            }
            if !made_progress {
                self.wait_for_server_runtime_activity(runtime_socket, Some(wakeup))
                    .await;
                return Ok(false);
            }
        }
        if !made_progress {
            self.wait_for_server_runtime_activity(runtime_socket, None)
                .await;
        }
        Ok(made_progress)
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn runtime_udp_socket(&self) -> Option<tokio::net::UdpSocket> {
        let socket = self.socket.try_clone_std().map_err(map_udp_error).ok()?;
        tokio::net::UdpSocket::from_std(socket).ok()
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[allow(dead_code)]
    async fn wait_for_connection_driver_activity(
        &self,
        connection: &Connection,
        runtime_socket: Option<&tokio::net::UdpSocket>,
        wakeup: Option<web_time::Instant>,
    ) {
        if connection.runtime_has_pending_work() {
            return;
        }
        if let Some(socket) = runtime_socket {
            clear_runtime_socket_readiness(socket);
        }
        match (runtime_socket, wakeup) {
            (Some(socket), Some(wakeup)) => {
                let now = web_time::Instant::now();
                if wakeup <= now {
                    return;
                }
                let notified = connection.wait_for_runtime_activity(Some(wakeup));
                tokio::pin!(notified);
                if connection.runtime_has_pending_work() {
                    return;
                }
                tokio::select! {
                    _ = &mut notified => {}
                    _ = socket.readable() => {}
                    _ = tokio::time::sleep(wakeup.duration_since(now)) => {}
                }
            }
            (Some(socket), None) => {
                let notified = connection.wait_for_runtime_activity(None);
                tokio::pin!(notified);
                if connection.runtime_has_pending_work() {
                    return;
                }
                tokio::select! {
                    _ = &mut notified => {}
                    _ = socket.readable() => {}
                }
            }
            (None, wakeup) => connection.wait_for_runtime_activity(wakeup).await,
        }
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    async fn wait_for_server_runtime_activity(
        &self,
        runtime_socket: Option<&tokio::net::UdpSocket>,
        wakeup: Option<web_time::Instant>,
    ) {
        let notified = self.runtime_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        // Register first, then recheck shutdown: notify_waiters does not retain
        // a permit when abort/close raced with entry into this wait.
        if self.runtime_shutdown_ready() || self.endpoint_driver_scheduler.has_ready() {
            return;
        }
        let wakeup = if runtime_socket.is_none() {
            earlier_deadline(
                wakeup,
                Some(web_time::Instant::now() + RUNTIME_IDLE_POLL_FALLBACK),
            )
        } else {
            wakeup
        };
        match runtime_socket {
            Some(socket) => {
                let readiness = socket.try_io(tokio::io::Interest::READABLE, || {
                    self.socket.peek_for_readiness()
                });
                if !matches!(readiness, Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock)
                {
                    return;
                }
                let now = web_time::Instant::now();
                let Some(wakeup) = wakeup else {
                    tokio::select! {
                        _ = &mut notified => {}
                        _ = socket.readable() => {}
                    }
                    return;
                };
                if wakeup <= now {
                    return;
                }
                tokio::select! {
                    _ = &mut notified => {}
                    _ = socket.readable() => {}
                    _ = tokio::time::sleep(wakeup.duration_since(now)) => {}
                }
            }
            None => {
                let Some(wakeup) = wakeup else {
                    notified.await;
                    return;
                };
                let now = web_time::Instant::now();
                if wakeup <= now {
                    return;
                }
                tokio::select! {
                    _ = &mut notified => {}
                    _ = tokio::time::sleep(wakeup.duration_since(now)) => {}
                }
            }
        }
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    async fn wait_for_connect_runtime_activity(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
        runtime_socket: Option<&tokio::net::UdpSocket>,
        deadline: Option<web_time::Instant>,
    ) {
        let notified = self.runtime_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state
                .client_crypto
                .get(route_cid)
                .is_none_or(|client| !client.routed_datagrams.is_empty())
            {
                return;
            }
        }
        let fallback = web_time::Instant::now() + RUNTIME_IDLE_POLL_FALLBACK;
        let wakeup = earlier_deadline(deadline, Some(fallback));
        match runtime_socket {
            Some(socket) => {
                clear_runtime_socket_readiness(socket);
                let now = web_time::Instant::now();
                let Some(wakeup) = wakeup else {
                    tokio::select! {
                        _ = &mut notified => {}
                        _ = socket.readable() => {}
                    }
                    return;
                };
                if wakeup <= now {
                    return;
                }
                tokio::select! {
                    _ = &mut notified => {}
                    _ = socket.readable() => {}
                    _ = tokio::time::sleep(wakeup.duration_since(now)) => {}
                }
            }
            None => {
                let Some(wakeup) = wakeup else {
                    notified.await;
                    return;
                };
                let now = web_time::Instant::now();
                if wakeup <= now {
                    return;
                }
                tokio::select! {
                    _ = &mut notified => {}
                    _ = tokio::time::sleep(wakeup.duration_since(now)) => {}
                }
            }
        }
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    async fn drive_connecting(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        transport_config: &quion_proto::config::TransportConfig,
    ) -> Result<(), ConnectionError> {
        trace!(
            local = %self.local_addr,
            route_cid_len = route_cid.len(),
            server_name,
            "driving client connection establishment"
        );
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let runtime_socket = self.runtime_udp_socket();
        let deadline = connect_deadline(transport_config);
        let mut work_limiter = RuntimeWorkLimiter::new(MAX_CONSECUTIVE_RUNTIME_PROGRESS);
        loop {
            if deadline.is_some_and(|deadline| deadline <= web_time::Instant::now()) {
                return Err(ConnectionError::TimedOut);
            }
            let send_progress = self.poll_client_crypto_initial_udp_once(
                route_cid,
                config.clone(),
                server_name,
                transport_config,
            )?;
            #[cfg(feature = "zero-rtt")]
            let (zero_rtt_packets_sent, next_zero_rtt_send_at) =
                self.poll_client_zero_rtt_udp_once(route_cid)?;
            #[cfg(not(feature = "zero-rtt"))]
            let (zero_rtt_packets_sent, next_zero_rtt_send_at) =
                (0usize, None::<web_time::Instant>);
            if self.client_crypto_ready_for_handoff(route_cid)? {
                debug!("client crypto is ready for one-rtt handoff");
                return Ok(());
            }
            let recv_progress = self.poll_client_crypto_udp_once(route_cid, &mut recv_buffer)?;
            if self.client_crypto_ready_for_handoff(route_cid)? {
                debug!("client crypto is ready for one-rtt handoff");
                return Ok(());
            }
            let timeout_progress = self.poll_client_crypto_timeout_once(route_cid)?;
            if send_progress.initial_packets_sent == 0
                && zero_rtt_packets_sent == 0
                && !connect_receive_made_progress(&recv_progress)
                && timeout_progress.response_packets_sent == 0
                && timeout_progress.timeouts_processed == 0
            {
                work_limiter.record(false);
                let wakeup = earlier_deadline(
                    earlier_deadline(deadline, self.next_client_crypto_timeout(route_cid)?),
                    next_zero_rtt_send_at,
                );
                let connecting_runtime_socket =
                    (!self.client_endpoint_driver_running.load(Ordering::Acquire))
                        .then_some(runtime_socket.as_ref())
                        .flatten();
                self.wait_for_connect_runtime_activity(
                    route_cid,
                    connecting_runtime_socket,
                    wakeup,
                )
                .await;
            } else {
                let made_progress = send_progress.initial_packets_sent != 0
                    || zero_rtt_packets_sent != 0
                    || connect_receive_made_progress(&recv_progress)
                    || timeout_progress.response_packets_sent != 0
                    || timeout_progress.timeouts_processed != 0;
                if work_limiter.record(made_progress) {
                    crate::Runtime::yield_now(&crate::TokioRuntime).await;
                }
            }
        }
    }
}

#[derive(Debug, Default)]
struct EndpointState {
    incoming: VecDeque<Incoming>,
    accept_waker: Option<Waker>,
    closed: bool,
    aborted: bool,
    proto_endpoint: quion_proto::endpoint::Endpoint,
    connections: Slab<Connection>,
    routes: BTreeMap<quion_proto::cid::ConnectionId, EndpointConnectionRoute>,
    route_cid_lengths: BTreeSet<usize>,
    reset_tokens: BTreeMap<quion_proto::cid::ConnectionId, [u8; 16]>,
    reset_cid_lengths: BTreeSet<usize>,
    connection_id_memory: Arc<ProtocolMemoryTracker>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    server_initial: BTreeMap<quion_proto::cid::ConnectionId, ServerInitialConnection>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    client_crypto: BTreeMap<quion_proto::cid::ConnectionId, ClientCryptoConnection>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    endpoint_one_rtt_drivers: BTreeMap<u64, EndpointOwnedOneRttDriver>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    next_endpoint_driver_id: u64,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    protected_one_rtt_drivers: Vec<ProtectedOneRttUdpDriverHandle>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    connecting_drivers: Vec<ConnectingDriverHandle>,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
struct EndpointOwnedOneRttDriver {
    id: u64,
    connection: Connection,
    driver: ProtectedOneRttUdpDriver,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl std::fmt::Debug for EndpointOwnedOneRttDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointOwnedOneRttDriver")
            .field("id", &self.id)
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
struct ConnectingDriverHandle {
    route_cid: quion_proto::cid::ConnectionId,
    join: tokio::task::JoinHandle<()>,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl std::fmt::Debug for ConnectingDriverHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectingDriverHandle")
            .field("route_cid_len", &self.route_cid.len())
            .field("is_finished", &self.join.is_finished())
            .finish()
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl ConnectingDriverHandle {
    fn abort(&self) {
        self.join.abort();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EndpointConnectionRoute {
    connection: usize,
    kind: quion_proto::endpoint::ConnectionRouteKind,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeWorkLimiter {
    max_work_per_tick: usize,
    work_this_tick: usize,
}

impl RuntimeWorkLimiter {
    fn new(max_work_per_tick: usize) -> Self {
        Self {
            max_work_per_tick: max_work_per_tick.max(1),
            work_this_tick: 0,
        }
    }

    fn record(&mut self, made_progress: bool) -> bool {
        if !made_progress {
            self.work_this_tick = 0;
            // An idle poll can return immediately because of readiness or an
            // expired deadline. Yield even when its wait did not suspend.
            return true;
        }
        self.work_this_tick += 1;
        if self.work_this_tick >= self.max_work_per_tick {
            self.work_this_tick = 0;
            return true;
        }
        false
    }
}

impl EndpointState {
    fn new(
        proto_endpoint: quion_proto::endpoint::Endpoint,
        endpoint_memory_budget: Arc<EndpointMemoryBudget>,
    ) -> Self {
        let state = Self {
            proto_endpoint,
            ..Self::default()
        };
        debug_assert!(state.connection_id_memory.attach(endpoint_memory_budget, 0));
        state
    }

    fn connection_id_memory_bytes(&self) -> usize {
        let route_bytes = self
            .routes
            .keys()
            .map(|cid| {
                std::mem::size_of::<quion_proto::cid::ConnectionId>()
                    .saturating_add(cid.len())
                    .saturating_add(std::mem::size_of::<EndpointConnectionRoute>())
                    .saturating_add(CID_TREE_ENTRY_BOOKKEEPING_BYTES)
                    // The sans-I/O endpoint retains a second route entry.
                    .saturating_mul(2)
            })
            .fold(0usize, usize::saturating_add);
        let reset_token_bytes = self
            .reset_tokens
            .keys()
            .map(|cid| {
                std::mem::size_of::<quion_proto::cid::ConnectionId>()
                    .saturating_add(cid.len())
                    .saturating_add(std::mem::size_of::<[u8; 16]>())
                    .saturating_add(CID_TREE_ENTRY_BOOKKEEPING_BYTES)
            })
            .fold(0usize, usize::saturating_add);
        let length_index_bytes = self
            .route_cid_lengths
            .len()
            .saturating_add(self.reset_cid_lengths.len())
            .saturating_mul(
                std::mem::size_of::<usize>().saturating_add(CID_TREE_ENTRY_BOOKKEEPING_BYTES),
            );
        route_bytes
            .saturating_add(reset_token_bytes)
            .saturating_add(length_index_bytes)
    }

    fn reconcile_connection_id_memory(&self) {
        let reconciled = self
            .connection_id_memory
            .reconcile(self.connection_id_memory_bytes());
        debug_assert!(reconciled);
    }

    fn connection_id_route_memory_bytes(&self) -> usize {
        self.connection_id_memory.accounted_bytes()
    }

    fn route_growth_upper_bound(&self, cid: &quion_proto::cid::ConnectionId) -> usize {
        if self.routes.contains_key(cid) {
            return 0;
        }
        std::mem::size_of::<quion_proto::cid::ConnectionId>()
            .saturating_add(cid.len())
            .saturating_add(std::mem::size_of::<EndpointConnectionRoute>())
            .saturating_add(CID_TREE_ENTRY_BOOKKEEPING_BYTES)
            .saturating_mul(2)
            .saturating_add(if self.route_cid_lengths.contains(&cid.len()) {
                0
            } else {
                std::mem::size_of::<usize>().saturating_add(CID_TREE_ENTRY_BOOKKEEPING_BYTES)
            })
    }

    fn reset_token_growth_upper_bound(&self, cid: &quion_proto::cid::ConnectionId) -> usize {
        if self.reset_tokens.contains_key(cid) {
            return 0;
        }
        std::mem::size_of::<quion_proto::cid::ConnectionId>()
            .saturating_add(cid.len())
            .saturating_add(std::mem::size_of::<[u8; 16]>())
            .saturating_add(CID_TREE_ENTRY_BOOKKEEPING_BYTES)
            .saturating_add(if self.reset_cid_lengths.contains(&cid.len()) {
                0
            } else {
                std::mem::size_of::<usize>().saturating_add(CID_TREE_ENTRY_BOOKKEEPING_BYTES)
            })
    }

    fn reset_proto_endpoint(&mut self, proto_endpoint: quion_proto::endpoint::Endpoint) {
        self.proto_endpoint = proto_endpoint;
        self.reconcile_connection_id_memory();
    }

    fn register_connection(
        &mut self,
        dst_cid: quion_proto::cid::ConnectionId,
        connection: Connection,
    ) -> Result<usize, ConnectionError> {
        let id = self.connections.insert(connection);
        if let Err(error) = self.register_connection_route(
            dst_cid,
            id,
            quion_proto::endpoint::ConnectionRouteKind::InitialDestination,
        ) {
            self.connections.remove(id);
            return Err(error);
        }
        Ok(id)
    }

    fn register_connection_route(
        &mut self,
        cid: quion_proto::cid::ConnectionId,
        connection: usize,
        kind: quion_proto::endpoint::ConnectionRouteKind,
    ) -> Result<(), ConnectionError> {
        let route = EndpointConnectionRoute { connection, kind };
        if let Some(existing) = self.routes.get(&cid) {
            return if *existing == route {
                Ok(())
            } else {
                Err(ConnectionError::ConnectionIdCollision)
            };
        }
        let tracker = self.connection_id_memory.clone();
        let Some(growth) = tracker.try_reserve_growth(self.route_growth_upper_bound(&cid)) else {
            return Err(ConnectionError::EndpointMemoryLimitReached);
        };
        let previous = self.routes.insert(cid.clone(), route);
        self.route_cid_lengths.insert(cid.len());
        if growth.commit(self.connection_id_memory_bytes()) {
            Ok(())
        } else {
            if let Some(previous) = previous {
                self.routes.insert(cid, previous);
            } else {
                self.routes.remove(&cid);
            }
            self.refresh_route_cid_lengths();
            Err(ConnectionError::EndpointMemoryLimitReached)
        }
    }

    fn register_reset_token(
        &mut self,
        cid: quion_proto::cid::ConnectionId,
        token: [u8; 16],
    ) -> Result<(), ConnectionError> {
        if let Some(existing) = self.reset_tokens.get(&cid) {
            return if *existing == token {
                Ok(())
            } else {
                Err(ConnectionError::ConnectionIdCollision)
            };
        }
        let tracker = self.connection_id_memory.clone();
        let Some(growth) = tracker.try_reserve_growth(self.reset_token_growth_upper_bound(&cid))
        else {
            return Err(ConnectionError::EndpointMemoryLimitReached);
        };
        let previous = self.reset_tokens.insert(cid.clone(), token);
        self.reset_cid_lengths.insert(cid.len());
        if growth.commit(self.connection_id_memory_bytes()) {
            Ok(())
        } else {
            if let Some(previous) = previous {
                self.reset_tokens.insert(cid, previous);
            } else {
                self.reset_tokens.remove(&cid);
            }
            self.refresh_reset_cid_lengths();
            Err(ConnectionError::EndpointMemoryLimitReached)
        }
    }

    #[cfg(test)]
    fn retire_connection_route(
        &mut self,
        cid: &quion_proto::cid::ConnectionId,
        connection: usize,
    ) -> bool {
        let Some(route) = self.routes.get(cid) else {
            return false;
        };
        if route.connection != connection
            || !matches!(
                route.kind,
                quion_proto::endpoint::ConnectionRouteKind::InitialDestination
                    | quion_proto::endpoint::ConnectionRouteKind::Active
            )
        {
            return false;
        }
        self.routes.remove(cid);
        self.reset_tokens.remove(cid);
        self.refresh_route_cid_lengths();
        self.refresh_reset_cid_lengths();
        self.reconcile_connection_id_memory();
        true
    }

    fn retire_active_connection_route(&mut self, cid: &quion_proto::cid::ConnectionId) -> bool {
        let Some(route) = self.routes.get(cid) else {
            return false;
        };
        if !matches!(
            route.kind,
            quion_proto::endpoint::ConnectionRouteKind::InitialDestination
                | quion_proto::endpoint::ConnectionRouteKind::Active
        ) {
            return false;
        }
        self.routes.remove(cid);
        self.proto_endpoint.remove_route(cid);
        self.reset_tokens.remove(cid);
        self.refresh_route_cid_lengths();
        self.refresh_reset_cid_lengths();
        self.reconcile_connection_id_memory();
        true
    }

    fn route_connection(&self, dst_cid: &quion_proto::cid::ConnectionId) -> Option<Connection> {
        self.routes
            .get(dst_cid)
            .and_then(|route| self.connections.get(route.connection))
            .cloned()
    }

    fn connection_matching_stateless_reset(&self, packet: &[u8]) -> Option<Connection> {
        self.connections
            .iter()
            .map(|(_, connection)| connection)
            .find(|connection| connection.matches_stateless_reset(packet))
            .cloned()
    }

    fn remove_connection(&mut self, connection: usize) {
        if self.connections.contains(connection) {
            self.connections.remove(connection);
        }
        let stale_cids = self
            .routes
            .iter()
            .filter_map(|(cid, route)| (route.connection == connection).then_some(cid.clone()))
            .collect::<Vec<_>>();
        for cid in stale_cids {
            self.routes.remove(&cid);
            self.proto_endpoint.remove_route(&cid);
            self.reset_tokens.remove(&cid);
        }
        self.refresh_route_cid_lengths();
        self.refresh_reset_cid_lengths();
        self.reconcile_connection_id_memory();
    }

    fn remove_connection_route(&mut self, cid: &quion_proto::cid::ConnectionId) {
        self.routes.remove(cid);
        self.proto_endpoint.remove_route(cid);
        self.reset_tokens.remove(cid);
        self.refresh_route_cid_lengths();
        self.refresh_reset_cid_lengths();
        self.reconcile_connection_id_memory();
    }

    fn remove_closed_connections(&mut self) -> usize {
        let closed = self
            .connections
            .iter()
            .filter_map(|(id, connection)| connection.runtime_shutdown_ready().then_some(id))
            .collect::<Vec<_>>();
        if closed.is_empty() {
            return 0;
        }
        for id in &closed {
            self.remove_connection(*id);
        }
        closed.len()
    }

    fn server_connection_capacity_reached(
        &self,
        limits: ServerConnectionLimits,
        dst_cid: &quion_proto::cid::ConnectionId,
    ) -> bool {
        if self.route_connection(dst_cid).is_some() {
            return false;
        }
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        if self.server_initial.contains_key(dst_cid) {
            return false;
        }
        let established = self.connections.len();
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        let pending = self.server_initial.len();
        #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
        let pending = 0usize;
        established.saturating_add(pending) >= limits.max_connections
            || pending >= limits.max_pending_handshakes
            || established >= limits.max_established_connections
    }

    fn refresh_route_cid_lengths(&mut self) {
        self.route_cid_lengths = self
            .routes
            .keys()
            .map(quion_proto::cid::ConnectionId::len)
            .collect();
    }

    fn refresh_reset_cid_lengths(&mut self) {
        self.reset_cid_lengths = self
            .reset_tokens
            .keys()
            .map(quion_proto::cid::ConnectionId::len)
            .collect();
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn route_short_connection(&self, packet: &[u8]) -> Option<Connection> {
        for len in self.route_cid_lengths.iter().copied() {
            let Ok((header, _consumed)) = quion_proto::packet::Header::decode(packet, len) else {
                continue;
            };
            let quion_proto::packet::Header::Short(header) = header else {
                continue;
            };
            if let Some(connection) = self.route_connection(&header.dst_cid) {
                return Some(connection);
            }
        }
        None
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn stateless_reset_token_for_short_packet(&self, packet: &[u8]) -> Option<[u8; 16]> {
        for len in self.reset_cid_lengths.iter().copied() {
            let Ok((header, _consumed)) = quion_proto::packet::Header::decode(packet, len) else {
                continue;
            };
            let quion_proto::packet::Header::Short(header) = header else {
                continue;
            };
            if let Some(token) = self.reset_tokens.get(&header.dst_cid) {
                return Some(*token);
            }
        }
        None
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn client_crypto_mut(
        &mut self,
        route_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<&mut ClientCryptoConnection, ConnectionError> {
        self.client_crypto
            .get_mut(route_cid)
            .ok_or(ConnectionError::LocallyClosed)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn client_crypto(
        &self,
        route_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<&ClientCryptoConnection, ConnectionError> {
        self.client_crypto
            .get(route_cid)
            .ok_or(ConnectionError::LocallyClosed)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn has_client_crypto(&self, route_cid: &quion_proto::cid::ConnectionId) -> bool {
        self.client_crypto.contains_key(route_cid)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn store_endpoint_one_rtt_driver(
        &mut self,
        connection: Connection,
        driver: ProtectedOneRttUdpDriver,
    ) -> u64 {
        let driver_id = self.next_endpoint_driver_id;
        self.next_endpoint_driver_id = self.next_endpoint_driver_id.wrapping_add(1);
        self.endpoint_one_rtt_drivers.insert(
            driver_id,
            EndpointOwnedOneRttDriver {
                id: driver_id,
                connection,
                driver,
            },
        );
        driver_id
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn restore_endpoint_one_rtt_drivers(
        &mut self,
        mut retained: BTreeMap<u64, EndpointOwnedOneRttDriver>,
    ) {
        self.endpoint_one_rtt_drivers.append(&mut retained);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[allow(dead_code)]
    fn store_protected_one_rtt_driver(&mut self, handle: ProtectedOneRttUdpDriverHandle) {
        self.remove_inactive_client_runtime_drivers();
        self.protected_one_rtt_drivers.push(handle);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn remove_inactive_client_runtime_drivers(&mut self) {
        self.protected_one_rtt_drivers.retain(|handle| {
            if handle.connection.is_closed() {
                handle.join.abort();
                return false;
            }
            !handle.is_finished()
        });
        self.connecting_drivers
            .retain(|handle| !handle.join.is_finished());
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn store_connecting_driver(&mut self, handle: ConnectingDriverHandle) {
        self.connecting_drivers
            .retain(|handle| !handle.join.is_finished());
        self.connecting_drivers.push(handle);
    }
}

/// Future returned by [`Endpoint::accept`].
pub struct Accept {
    state: Arc<Mutex<EndpointState>>,
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EndpointAcceptProgress {
    pub received_packets: usize,
    pub routed_existing_connections: usize,
    pub retry_packets_sent: usize,
    pub version_negotiation_packets_sent: usize,
    pub incoming_connections: usize,
    pub dropped_packets: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EndpointConnectProgress {
    pub initial_packets_sent: usize,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EndpointServerProgress {
    pub received_packets: usize,
    pub routed_existing_connections: usize,
    pub retry_packets_sent: usize,
    pub version_negotiation_packets_sent: usize,
    pub initial_packets_received: usize,
    pub handshake_packets_received: usize,
    pub crypto_frames_received: usize,
    pub response_packets_generated: usize,
    pub handshake_packets_generated: usize,
    pub one_rtt_packets_generated: usize,
    pub response_packets_sent: usize,
    pub established_connections: usize,
    pub crypto_timeouts_processed: usize,
    pub next_crypto_timeout: Option<web_time::Instant>,
    pub one_rtt_packets_sent: usize,
    pub one_rtt_packets_received: usize,
    pub one_rtt_timeouts_processed: usize,
    pub next_one_rtt_send_at: Option<web_time::Instant>,
    pub next_one_rtt_timeout: Option<web_time::Instant>,
    pub dropped_packets: usize,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl EndpointServerProgress {
    fn merge(&mut self, other: Self) {
        self.received_packets += other.received_packets;
        self.routed_existing_connections += other.routed_existing_connections;
        self.retry_packets_sent += other.retry_packets_sent;
        self.version_negotiation_packets_sent += other.version_negotiation_packets_sent;
        self.initial_packets_received += other.initial_packets_received;
        self.handshake_packets_received += other.handshake_packets_received;
        self.crypto_frames_received += other.crypto_frames_received;
        self.response_packets_generated += other.response_packets_generated;
        self.handshake_packets_generated += other.handshake_packets_generated;
        self.one_rtt_packets_generated += other.one_rtt_packets_generated;
        self.response_packets_sent += other.response_packets_sent;
        self.established_connections += other.established_connections;
        self.crypto_timeouts_processed += other.crypto_timeouts_processed;
        self.next_crypto_timeout =
            earlier_deadline(self.next_crypto_timeout, other.next_crypto_timeout);
        self.one_rtt_packets_sent += other.one_rtt_packets_sent;
        self.one_rtt_packets_received += other.one_rtt_packets_received;
        self.one_rtt_timeouts_processed += other.one_rtt_timeouts_processed;
        self.next_one_rtt_send_at =
            earlier_deadline(self.next_one_rtt_send_at, other.next_one_rtt_send_at);
        self.next_one_rtt_timeout =
            earlier_deadline(self.next_one_rtt_timeout, other.next_one_rtt_timeout);
        self.dropped_packets += other.dropped_packets;
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EndpointConnectReceiveProgress {
    pub received_packets: usize,
    pub version_negotiation_packets_received: usize,
    pub retry_packets_received: usize,
    pub response_packets_sent: usize,
    pub dropped_packets: usize,
    pub initial_crypto: ClientInitialCryptoProgress,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientInitialCryptoProgress {
    pub initial_packets_received: usize,
    pub handshake_packets_received: usize,
    pub crypto_frames_received: usize,
    pub response_crypto_frames: usize,
    pub handshake_crypto_frames: usize,
    pub one_rtt_crypto_frames: usize,
    pub response_packets_generated: usize,
    pub handshake_packets_generated: usize,
    pub one_rtt_packets_generated: usize,
    pub response_packets_sent: usize,
    pub timeouts_processed: usize,
    pub handshake_keys_installed: bool,
    pub one_rtt_keys_installed: bool,
    pub peer_transport_parameters_received: bool,
    pub handshake_completed: bool,
    pub tls_handshaking: bool,
    pub dropped_packets: usize,
    pub transport_error: Option<quion_proto::transport_error::TransportErrorCode>,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerInitialCryptoProgress {
    pub initial_packets_received: usize,
    pub handshake_packets_received: usize,
    pub crypto_frames_received: usize,
    pub response_crypto_frames: usize,
    pub handshake_crypto_frames: usize,
    pub one_rtt_crypto_frames: usize,
    pub response_packets_generated: usize,
    pub handshake_packets_generated: usize,
    pub one_rtt_packets_generated: usize,
    pub timeouts_processed: usize,
    pub response_packets_sent: usize,
    pub established_connections: usize,
    pub handshake_keys_installed: bool,
    pub one_rtt_keys_installed: bool,
    pub peer_transport_parameters_received: bool,
    pub handshake_completed: bool,
    pub tls_handshaking: bool,
    pub dropped_packets: usize,
    pub transport_error: Option<quion_proto::transport_error::TransportErrorCode>,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub(crate) struct ServerInitialConnection {
    proto: quion_proto::connection::Connection,
    local_transport_config: quion_proto::config::TransportConfig,
    qlog: ServerInitialQlog,
    session: quion_proto::crypto::rustls::RustlsSession,
    keys: quion_proto::crypto::rustls::RustlsKeyStore,
    crypto_level: quion_proto::crypto::EncryptionLevel,
    peer_transport_parameters: Option<quion_proto::transport_parameters::TransportParameters>,
    local_connection_id: quion_proto::cid::ConnectionId,
    original_destination_connection_id: quion_proto::cid::ConnectionId,
    peer_initial_source_cid: quion_proto::cid::ConnectionId,
    remote_addr: SocketAddr,
    established_connection_taken: bool,
    initial: quion_proto::crypto::initial::InitialPacketProtector,
    builder: quion_proto::crypto::packet::CryptoPacketBuilder,
    initial_discarded: bool,
    largest_initial_received: Option<u64>,
    largest_handshake_received: Option<u64>,
    #[cfg(feature = "zero-rtt")]
    largest_zero_rtt_received: Option<u64>,
    #[cfg(feature = "zero-rtt")]
    zero_rtt_accepted: bool,
    pending_crypto_packets: VecDeque<CryptoFlightPacket>,
    authenticated_packet_received: bool,
    endpoint_memory_reservation: Option<EndpointMemoryReservation>,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Clone)]
struct ServerInitialQlog {
    handler: Option<crate::QlogHandler>,
    max_buffered_events: usize,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl ServerInitialQlog {
    fn new(handler: Option<crate::QlogHandler>, max_buffered_events: usize) -> Self {
        Self {
            handler,
            max_buffered_events,
        }
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
enum ServerDatagramDisposition {
    Route(Connection),
    Initial(ServerInitialConnection),
    Handshake(ServerInitialConnection),
    #[cfg(feature = "zero-rtt")]
    ZeroRtt(ServerInitialConnection),
    Retry(Vec<u8>),
    StatelessReset(Vec<u8>),
    VersionNegotiation(Vec<u8>),
    Drop,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl std::fmt::Debug for ServerInitialConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerInitialConnection")
            .finish_non_exhaustive()
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug, Default)]
struct CryptoFlight {
    packets: Vec<CryptoFlightPacket>,
    initial_crypto_frames: usize,
    handshake_crypto_frames: usize,
    one_rtt_crypto_frames: usize,
    initial_packets_generated: usize,
    handshake_packets_generated: usize,
    one_rtt_packets_generated: usize,
    handshake_keys_installed: bool,
    one_rtt_keys_installed: bool,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug, Clone)]
pub(crate) struct CryptoFlightPacket {
    level: quion_proto::crypto::EncryptionLevel,
    packet_number: u64,
    frames: Vec<quion_proto::crypto::stream::CryptoFrame>,
    contents: Vec<u8>,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl CryptoFlightPacket {
    fn len(&self) -> usize {
        self.contents.len()
    }

    const fn is_long_header(&self) -> bool {
        matches!(
            self.level,
            quion_proto::crypto::EncryptionLevel::Initial
                | quion_proto::crypto::EncryptionLevel::Handshake
        )
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug)]
struct CryptoFlightDatagram {
    packets: Vec<CryptoFlightPacket>,
    contents: Vec<u8>,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug, Default)]
struct CryptoFlightSendResult {
    sent: Vec<CryptoFlightPacket>,
    unsent: Vec<CryptoFlightPacket>,
}

/// Coalesce adjacent long-header crypto packets without exceeding the
/// conservative initial-path payload limit.  Short-header 1-RTT packets stay
/// separate: a short-header packet can only terminate a coalesced datagram.
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn coalesce_crypto_flight_packets(packets: Vec<CryptoFlightPacket>) -> Vec<CryptoFlightDatagram> {
    let mut datagrams: Vec<CryptoFlightDatagram> = Vec::new();
    for packet in packets {
        let packet_len = packet.len();
        if packet.is_long_header()
            && let Some(datagram) = datagrams.last_mut()
            && datagram
                .packets
                .iter()
                .all(CryptoFlightPacket::is_long_header)
            && datagram.contents.len().saturating_add(packet_len) <= MAX_CRYPTO_DATAGRAM_SIZE
        {
            datagram.contents.extend_from_slice(&packet.contents);
            datagram.packets.push(packet);
            continue;
        }
        datagrams.push(CryptoFlightDatagram {
            contents: packet.contents.clone(),
            packets: vec![packet],
        });
    }
    datagrams
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn build_crypto_frame_packet(
    builder: &mut quion_proto::crypto::packet::CryptoPacketBuilder,
    keys: &quion_proto::crypto::rustls::RustlsKeyStore,
    initial: &quion_proto::crypto::initial::InitialPacketProtector,
    frame: quion_proto::crypto::stream::CryptoFrame,
) -> Result<CryptoFlightPacket, ConnectionError> {
    match frame.level {
        quion_proto::crypto::EncryptionLevel::Initial => {
            let packet_number = builder
                .next_packet_number(quion_proto::crypto::EncryptionLevel::Initial)
                .ok_or(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                ))?;
            let packet = builder
                .build_initial_padded(initial, std::slice::from_ref(&frame), 1200)
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
            Ok(CryptoFlightPacket {
                level: quion_proto::crypto::EncryptionLevel::Initial,
                packet_number,
                frames: vec![frame],
                contents: packet,
            })
        }
        quion_proto::crypto::EncryptionLevel::Handshake => {
            let packet_number = builder
                .next_packet_number(quion_proto::crypto::EncryptionLevel::Handshake)
                .ok_or(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                ))?;
            let packet = builder
                .build_handshake(keys, std::slice::from_ref(&frame))
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
            Ok(CryptoFlightPacket {
                level: quion_proto::crypto::EncryptionLevel::Handshake,
                packet_number,
                frames: vec![frame],
                contents: packet,
            })
        }
        quion_proto::crypto::EncryptionLevel::OneRtt => {
            let packet_number = builder
                .next_packet_number(quion_proto::crypto::EncryptionLevel::OneRtt)
                .ok_or(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                ))?;
            let packet = builder
                .build_one_rtt(keys, std::slice::from_ref(&frame))
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
            Ok(CryptoFlightPacket {
                level: quion_proto::crypto::EncryptionLevel::OneRtt,
                packet_number,
                frames: vec![frame],
                contents: packet,
            })
        }
        quion_proto::crypto::EncryptionLevel::ZeroRtt => Err(ConnectionError::TransportError(
            quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
        )),
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn build_crypto_close_packet(
    builder: &mut quion_proto::crypto::packet::CryptoPacketBuilder,
    keys: &quion_proto::crypto::rustls::RustlsKeyStore,
    initial: &quion_proto::crypto::initial::InitialPacketProtector,
    level: quion_proto::crypto::EncryptionLevel,
    error_code: quion_proto::transport_error::TransportErrorCode,
) -> Result<CryptoFlightPacket, ConnectionError> {
    let packet_number =
        builder
            .next_packet_number(level)
            .ok_or(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ))?;
    let frame = quion_proto::frame::Frame::ConnectionClose {
        error_code,
        frame_type: quion_proto::VarInt::ZERO,
        reason: b"authenticated packet violation".to_vec(),
    };
    let contents = match level {
        quion_proto::crypto::EncryptionLevel::Initial => builder
            .build_initial_frames_padded(initial, std::slice::from_ref(&frame), 1200)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?,
        quion_proto::crypto::EncryptionLevel::Handshake => builder
            .build_handshake_frames(keys, std::slice::from_ref(&frame))
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?,
        quion_proto::crypto::EncryptionLevel::OneRtt => builder
            .build_one_rtt_frames(keys, std::slice::from_ref(&frame))
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?,
        quion_proto::crypto::EncryptionLevel::ZeroRtt => {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        }
    };
    Ok(CryptoFlightPacket {
        level,
        packet_number,
        frames: Vec::new(),
        contents,
    })
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn build_crypto_frame_flight(
    builder: &mut quion_proto::crypto::packet::CryptoPacketBuilder,
    keys: &quion_proto::crypto::rustls::RustlsKeyStore,
    initial: &quion_proto::crypto::initial::InitialPacketProtector,
    frames: Vec<quion_proto::crypto::stream::CryptoFrame>,
) -> Result<CryptoFlight, ConnectionError> {
    let mut flight = CryptoFlight::default();
    let mut fragments = Vec::new();
    for frame in frames {
        let capacity = builder
            .max_payload_len(frame.level, MAX_CRYPTO_DATAGRAM_SIZE)
            .saturating_sub(17);
        if capacity == 0 {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        }
        for (index, bytes) in frame.bytes.chunks(capacity).enumerate() {
            fragments.push(quion_proto::crypto::stream::CryptoFrame {
                level: frame.level,
                offset: frame.offset + (index * capacity) as u64,
                bytes: bytes.to_vec(),
            });
        }
    }
    for frame in fragments {
        match frame.level {
            quion_proto::crypto::EncryptionLevel::Initial => {
                flight.initial_crypto_frames += 1;
                flight.initial_packets_generated += 1;
            }
            quion_proto::crypto::EncryptionLevel::Handshake => {
                flight.handshake_crypto_frames += 1;
                flight.handshake_packets_generated += 1;
            }
            quion_proto::crypto::EncryptionLevel::OneRtt => {
                flight.one_rtt_crypto_frames += 1;
                flight.one_rtt_packets_generated += 1;
            }
            quion_proto::crypto::EncryptionLevel::ZeroRtt => {}
        }
        flight
            .packets
            .push(build_crypto_frame_packet(builder, keys, initial, frame)?);
    }
    Ok(flight)
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn emit_crypto_flight(
    proto: &mut quion_proto::connection::Connection,
    session: &mut quion_proto::crypto::rustls::RustlsSession,
    keys: &mut quion_proto::crypto::rustls::RustlsKeyStore,
    crypto_level: &mut quion_proto::crypto::EncryptionLevel,
    builder: &mut quion_proto::crypto::packet::CryptoPacketBuilder,
    initial: &quion_proto::crypto::initial::InitialPacketProtector,
) -> Result<CryptoFlight, ConnectionError> {
    let mut flight = CryptoFlight::default();
    for _ in 0..8 {
        let level = *crypto_level;
        let mut bytes = Vec::new();
        let key_change = session.write_handshake(&mut bytes);
        if !bytes.is_empty() {
            let effects = proto
                .queue_crypto_bytes(
                    level,
                    &bytes,
                    builder
                        .max_payload_len(level, MAX_CRYPTO_DATAGRAM_SIZE)
                        .saturating_sub(17 + proto.crypto_ack_size(level))
                        .max(1),
                )
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
            for frame in effects.crypto_frames {
                let level = frame.level;
                let packet = if let Some(ack) = proto.take_crypto_ack(level) {
                    let packet_number = builder.next_packet_number(level).ok_or(
                        ConnectionError::TransportError(
                            quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                        ),
                    )?;
                    let crypto = frame
                        .clone()
                        .into_frame()
                        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
                    let wire_frames = [ack, crypto];
                    let contents = match level {
                        quion_proto::crypto::EncryptionLevel::Initial => builder
                            .build_initial_frames_padded(initial, &wire_frames, 1200)
                            .map_err(|error| {
                                ConnectionError::TransportError(error.transport_code())
                            })?,
                        quion_proto::crypto::EncryptionLevel::Handshake => builder
                            .build_handshake_frames(keys, &wire_frames)
                            .map_err(|error| {
                                ConnectionError::TransportError(error.transport_code())
                            })?,
                        quion_proto::crypto::EncryptionLevel::ZeroRtt
                        | quion_proto::crypto::EncryptionLevel::OneRtt => {
                            return Err(ConnectionError::TransportError(
                                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                            ));
                        }
                    };
                    CryptoFlightPacket {
                        level,
                        packet_number,
                        frames: vec![frame],
                        contents,
                    }
                } else {
                    build_crypto_frame_packet(builder, keys, initial, frame)?
                };
                flight.packets.push(packet);
                match level {
                    quion_proto::crypto::EncryptionLevel::Initial => {
                        flight.initial_crypto_frames += 1;
                        flight.initial_packets_generated += 1;
                    }
                    quion_proto::crypto::EncryptionLevel::Handshake => {
                        flight.handshake_crypto_frames += 1;
                        flight.handshake_packets_generated += 1;
                    }
                    quion_proto::crypto::EncryptionLevel::OneRtt => {
                        flight.one_rtt_crypto_frames += 1;
                        flight.one_rtt_packets_generated += 1;
                    }
                    quion_proto::crypto::EncryptionLevel::ZeroRtt => {
                        return Err(ConnectionError::TransportError(
                            quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                        ));
                    }
                }
            }
        }
        let Some(key_change) = key_change else {
            break;
        };
        *crypto_level = keys.install(key_change);
        match *crypto_level {
            quion_proto::crypto::EncryptionLevel::Handshake => {
                flight.handshake_keys_installed = true;
            }
            quion_proto::crypto::EncryptionLevel::OneRtt => {
                flight.one_rtt_keys_installed = true;
            }
            quion_proto::crypto::EncryptionLevel::Initial
            | quion_proto::crypto::EncryptionLevel::ZeroRtt => {}
        }
    }
    // When TLS produced no CRYPTO at a matching level, an ACK-only packet is
    // still required (notably for the server's receipt of ClientFinished).
    for level in [
        quion_proto::crypto::EncryptionLevel::Initial,
        quion_proto::crypto::EncryptionLevel::Handshake,
    ] {
        let Some(frame) = proto.take_crypto_ack(level) else {
            continue;
        };
        let packet_number =
            builder
                .next_packet_number(level)
                .ok_or(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                ))?;
        let contents = match level {
            quion_proto::crypto::EncryptionLevel::Initial => builder
                .build_initial_frames_padded(initial, std::slice::from_ref(&frame), 1200)
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?,
            quion_proto::crypto::EncryptionLevel::Handshake => builder
                .build_handshake_frames(keys, std::slice::from_ref(&frame))
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?,
            quion_proto::crypto::EncryptionLevel::ZeroRtt
            | quion_proto::crypto::EncryptionLevel::OneRtt => unreachable!(),
        };
        flight.packets.push(CryptoFlightPacket {
            level,
            packet_number,
            frames: Vec::new(),
            contents,
        });
        match level {
            quion_proto::crypto::EncryptionLevel::Initial => {
                flight.initial_packets_generated += 1;
            }
            quion_proto::crypto::EncryptionLevel::Handshake => {
                flight.handshake_packets_generated += 1;
            }
            quion_proto::crypto::EncryptionLevel::ZeroRtt
            | quion_proto::crypto::EncryptionLevel::OneRtt => unreachable!(),
        }
    }
    Ok(flight)
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn install_peer_transport_parameters(
    session: &quion_proto::crypto::rustls::RustlsSession,
    slot: &mut Option<quion_proto::transport_parameters::TransportParameters>,
) -> Result<bool, ConnectionError> {
    if slot.is_some() {
        return Ok(false);
    }
    let Some(bytes) = session.peer_transport_parameters() else {
        return Ok(false);
    };
    let params = quion_proto::transport_parameters::TransportParameters::decode(&bytes)
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
    params
        .validate_quic_basics()
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
    *slot = Some(params);
    Ok(true)
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn apply_session_security_context(
    connection: &Connection,
    session: &quion_proto::crypto::rustls::RustlsSession,
) {
    connection.set_peer_security_context(session.peer_certificates(), session.alpn_protocol());
    connection.set_tls_exporter(session.exporter());
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl ServerInitialConnection {
    fn new(
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        qlog: ServerInitialQlog,
        first_packet: &[u8],
        original_destination_connection_id: Option<&quion_proto::cid::ConnectionId>,
        remote_addr: SocketAddr,
        stateless_reset_token: Option<[u8; 16]>,
    ) -> Result<Self, ConnectionError> {
        let (header, _consumed) = quion_proto::packet::Header::decode(first_packet, 0)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let quion_proto::packet::Header::Long(header) = header else {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        };
        if header.ty != quion_proto::packet::PacketType::Initial {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        }

        let initial_keys =
            quion_proto::crypto::initial::InitialKeys::derive(header.version, &header.dst_cid)
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let initial = quion_proto::crypto::initial::InitialPacketProtector::new(
            &initial_keys,
            quion_proto::crypto::Side::Server,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let transport_parameters =
            quion_proto::transport_parameters::TransportParameters::from_config(
                transport_config,
                &header.dst_cid,
                Some(original_destination_connection_id.unwrap_or(&header.dst_cid)),
                original_destination_connection_id
                    .filter(|cid| **cid != header.dst_cid)
                    .map(|_| &header.dst_cid),
                transport_config.max_datagram_frame_size,
                stateless_reset_token,
            )
            .encode();
        let provider = RustlsProvider;
        let session = provider
            .start_server_with_transport_parameters(config, transport_parameters)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let local_connection_id = header.dst_cid.clone();
        let original_destination_connection_id = original_destination_connection_id
            .cloned()
            .unwrap_or_else(|| header.dst_cid.clone());
        let peer_initial_source_cid = header.src_cid.clone();
        let builder =
            quion_proto::crypto::packet::CryptoPacketBuilder::new(header.src_cid, header.dst_cid);
        let mut proto = quion_proto::connection::Connection::new();
        proto.set_max_buffered_qlog_events(if qlog.handler.is_some() {
            qlog.max_buffered_events.max(4096)
        } else {
            qlog.max_buffered_events
        });
        Connection::configure_proto_for_transport(
            &mut proto,
            quion_proto::streams::StreamInitiator::Server,
            transport_config,
        );
        Ok(Self {
            proto,
            local_transport_config: transport_config.clone(),
            qlog,
            session,
            keys: quion_proto::crypto::rustls::RustlsKeyStore::default(),
            crypto_level: quion_proto::crypto::EncryptionLevel::Initial,
            peer_transport_parameters: None,
            local_connection_id,
            original_destination_connection_id,
            peer_initial_source_cid,
            remote_addr,
            established_connection_taken: false,
            initial,
            builder,
            initial_discarded: false,
            largest_initial_received: None,
            largest_handshake_received: None,
            #[cfg(feature = "zero-rtt")]
            largest_zero_rtt_received: None,
            #[cfg(feature = "zero-rtt")]
            zero_rtt_accepted: false,
            pending_crypto_packets: VecDeque::new(),
            authenticated_packet_received: false,
            endpoint_memory_reservation: None,
        })
    }

    fn attach_endpoint_memory_reservation(&mut self, reservation: EndpointMemoryReservation) {
        self.endpoint_memory_reservation = Some(reservation);
    }

    fn is_within_endpoint_memory_reservation(&self) -> bool {
        self.endpoint_memory_reservation
            .as_ref()
            .is_none_or(|reservation| self.memory_payload_bytes() <= reservation.bytes())
    }

    pub(crate) fn handle_initial_packet(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(ServerInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        let (mut progress, packets) = self.handle_initial_packet_inner(packet)?;
        if progress.dropped_packets == 0 {
            progress.initial_packets_received = 1;
        }
        Ok((progress, packets))
    }

    pub(crate) fn is_handshake_complete(&self) -> bool {
        !self.session.is_handshaking()
    }

    pub(crate) fn has_one_rtt_keys(&self) -> bool {
        self.keys.has_one_rtt()
    }

    #[cfg(test)]
    pub(crate) fn peer_transport_parameters(
        &self,
    ) -> Option<&quion_proto::transport_parameters::TransportParameters> {
        self.peer_transport_parameters.as_ref()
    }

    #[cfg(test)]
    pub(crate) const fn largest_initial_received(&self) -> Option<u64> {
        self.largest_initial_received
    }

    #[cfg(test)]
    pub(crate) const fn largest_handshake_received(&self) -> Option<u64> {
        self.largest_handshake_received
    }

    pub(crate) fn take_established_connection(
        &mut self,
        local: SocketAddr,
        endpoint_memory_budget: Arc<EndpointMemoryBudget>,
    ) -> Option<(quion_proto::cid::ConnectionId, Connection)> {
        if self.established_connection_taken
            || !self.is_handshake_complete()
            || self.has_pending_crypto_packets()
        {
            return None;
        }
        let peer_transport_parameters = self.peer_transport_parameters.clone()?;
        let connection = Connection::server_with_qlog(
            local,
            self.remote_addr,
            self.local_transport_config.clone(),
            self.qlog.handler.clone(),
            self.qlog.max_buffered_events,
        );
        let payload_bytes = self.proto.memory_stats().payload_bytes();
        let memory_attached = if let Some(reservation) = self.endpoint_memory_reservation.take() {
            connection.adopt_endpoint_memory_reservation(reservation, payload_bytes)
        } else {
            connection.reserve_endpoint_memory_budget(endpoint_memory_budget, payload_bytes)
        };
        if !memory_attached {
            let _ = self.proto.abort();
            self.pending_crypto_packets.clear();
            return None;
        }
        if !connection.register_local_connection_id(0, self.local_connection_id.clone())
            || !connection.register_initial_peer_connection_id(self.peer_initial_source_cid.clone())
        {
            let _ = self.proto.abort();
            self.pending_crypto_packets.clear();
            return None;
        }
        connection.install_server_proto(std::mem::take(&mut self.proto));
        apply_session_security_context(&connection, &self.session);
        #[cfg(feature = "zero-rtt")]
        if self.zero_rtt_accepted {
            connection.set_zero_rtt_status(crate::ZeroRttStatus::Accepted);
        }
        connection.mark_established(peer_transport_parameters);
        self.established_connection_taken = true;
        Some((self.local_connection_id.clone(), connection))
    }

    pub(crate) fn route_cid(&self) -> quion_proto::cid::ConnectionId {
        self.local_connection_id.clone()
    }

    pub(crate) fn original_destination_cid(&self) -> quion_proto::cid::ConnectionId {
        self.original_destination_connection_id.clone()
    }

    pub(crate) fn next_timeout(&self) -> Option<web_time::Instant> {
        self.proto.timeout()
    }

    pub(crate) fn has_pending_crypto_packets(&self) -> bool {
        !self.pending_crypto_packets.is_empty()
    }

    fn memory_payload_bytes(&self) -> usize {
        self.proto
            .memory_stats()
            .payload_bytes()
            .saturating_add(
                self.pending_crypto_packets
                    .iter()
                    .map(|packet| {
                        packet.contents.len().saturating_add(
                            packet
                                .frames
                                .iter()
                                .map(|frame| frame.bytes.len())
                                .fold(0usize, usize::saturating_add),
                        )
                    })
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(self.local_connection_id.len())
            .saturating_add(self.original_destination_connection_id.len())
            .saturating_add(self.peer_initial_source_cid.len())
    }

    pub(crate) const fn has_authenticated_packet(&self) -> bool {
        self.authenticated_packet_received
    }

    pub(crate) const fn is_closed(&self) -> bool {
        self.proto.is_closed()
    }

    pub(crate) fn take_pending_crypto_packets(&mut self) -> Vec<CryptoFlightPacket> {
        self.pending_crypto_packets.drain(..).collect()
    }

    pub(crate) fn queue_pending_crypto_packets(&mut self, packets: Vec<CryptoFlightPacket>) {
        self.pending_crypto_packets.extend(packets);
    }

    pub(crate) fn poll_crypto_timeout(
        &mut self,
        now: web_time::Instant,
    ) -> Result<(ServerInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        if self.proto.timeout().is_none_or(|timeout| timeout > now) {
            return Ok((ServerInitialCryptoProgress::default(), Vec::new()));
        }
        let effects = self
            .proto
            .on_timeout(now)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let flight = build_crypto_frame_flight(
            &mut self.builder,
            &self.keys,
            &self.initial,
            effects.crypto_frames,
        )?;
        Ok((
            ServerInitialCryptoProgress {
                response_crypto_frames: flight.initial_crypto_frames,
                handshake_crypto_frames: flight.handshake_crypto_frames,
                one_rtt_crypto_frames: flight.one_rtt_crypto_frames,
                response_packets_generated: flight.initial_packets_generated,
                handshake_packets_generated: flight.handshake_packets_generated,
                one_rtt_packets_generated: flight.one_rtt_packets_generated,
                timeouts_processed: 1,
                ..ServerInitialCryptoProgress::default()
            },
            flight.packets,
        ))
    }

    pub(crate) fn record_crypto_packets_sent(&mut self, packets: &[CryptoFlightPacket]) {
        let now = web_time::Instant::now();
        for packet in packets {
            let _effects = if packet.frames.is_empty() {
                self.proto.record_sent_packet(
                    packet.level,
                    packet.packet_number,
                    packet.contents.len() as u64,
                    false,
                    now,
                )
            } else {
                self.proto.record_sent_crypto_packet(
                    packet.level,
                    packet.packet_number,
                    packet.contents.len() as u64,
                    packet.frames.clone(),
                    now,
                )
            };
        }
        // RFC 9001 §4.9: a server discards Initial keys after sending its
        // first Handshake packet. Do this only after the UDP send succeeded,
        // so anti-amplification blocking cannot suppress Initial recovery.
        if packets
            .iter()
            .any(|packet| packet.level == quion_proto::crypto::EncryptionLevel::Handshake)
        {
            self.discard_initial_state();
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn take_protected_one_rtt_driver(&mut self) -> Option<ProtectedOneRttUdpDriver> {
        if !self.has_one_rtt_keys() {
            return None;
        }
        let next_one_rtt_packet_number = self
            .builder
            .next_packet_number(quion_proto::crypto::EncryptionLevel::OneRtt)
            .unwrap_or(0);
        self.keys.discard_handshake();
        #[cfg(feature = "zero-rtt")]
        self.keys.discard_zero_rtt();
        Some(
            ProtectedOneRttUdpDriver::new(
                quion_proto::crypto::packet::FramePacketBuilder::with_next_one_rtt_packet_number(
                    self.peer_initial_source_cid.clone(),
                    next_one_rtt_packet_number,
                ),
                std::mem::take(&mut self.keys),
                self.local_connection_id.len(),
            )
            .routed_only(),
        )
    }

    pub(crate) fn handle_handshake_packet(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(ServerInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        let opened = match quion_proto::crypto::packet::CryptoPacketOpener::open_handshake(
            &self.keys,
            packet,
            self.largest_handshake_received,
        ) {
            Ok(opened) => opened,
            Err(quion_proto::CodecError::PacketDiscard) => {
                return Ok((
                    ServerInitialCryptoProgress {
                        dropped_packets: 1,
                        ..ServerInitialCryptoProgress::default()
                    },
                    Vec::new(),
                ));
            }
            Err(error) => {
                return self.close_authenticated_crypto_error(
                    quion_proto::crypto::EncryptionLevel::Handshake,
                    error.transport_code(),
                );
            }
        };
        self.largest_handshake_received = Some(
            self.largest_handshake_received
                .map_or(opened.packet_number, |largest| {
                    largest.max(opened.packet_number)
                }),
        );
        let (mut progress, packets) = self.handle_opened_crypto_packet(opened)?;
        if progress.dropped_packets == 0 {
            progress.handshake_packets_received = 1;
        }
        Ok((progress, packets))
    }

    #[cfg(feature = "zero-rtt")]
    pub(crate) fn handle_zero_rtt_packet(
        &mut self,
        packet: &mut [u8],
    ) -> Result<ServerInitialCryptoProgress, ConnectionError> {
        let opened = match quion_proto::crypto::packet::CryptoPacketOpener::open_zero_rtt(
            &self.keys,
            packet,
            self.largest_zero_rtt_received,
        ) {
            Ok(opened) => opened,
            Err(quion_proto::CodecError::PacketDiscard) => {
                return Ok(ServerInitialCryptoProgress {
                    dropped_packets: 1,
                    ..ServerInitialCryptoProgress::default()
                });
            }
            Err(error) => {
                return Err(ConnectionError::TransportError(error.transport_code()));
            }
        };
        self.largest_zero_rtt_received = Some(
            self.largest_zero_rtt_received
                .map_or(opened.packet_number, |largest| {
                    largest.max(opened.packet_number)
                }),
        );
        self.authenticated_packet_received = true;
        self.proto
            .handle_opened_crypto_packet(&mut self.session, opened)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        Ok(ServerInitialCryptoProgress::default())
    }

    #[cfg(test)]
    pub(crate) fn handle_crypto_packet(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(ServerInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        let (header, _consumed) = quion_proto::packet::Header::decode(packet, 0)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let quion_proto::packet::Header::Long(header) = header else {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        };
        match header.ty {
            quion_proto::packet::PacketType::Initial => self.handle_initial_packet(packet),
            quion_proto::packet::PacketType::Handshake => self.handle_handshake_packet(packet),
            _ => Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            )),
        }
    }

    fn handle_initial_packet_inner(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(ServerInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        if self.initial_discarded {
            return Ok((ServerInitialCryptoProgress::default(), Vec::new()));
        }
        let opened = match quion_proto::crypto::packet::CryptoPacketOpener::open_initial(
            &self.initial,
            packet,
            self.largest_initial_received,
        ) {
            Ok(opened) => opened,
            Err(quion_proto::CodecError::PacketDiscard) => {
                return Ok((
                    ServerInitialCryptoProgress {
                        dropped_packets: 1,
                        ..ServerInitialCryptoProgress::default()
                    },
                    Vec::new(),
                ));
            }
            Err(error) => {
                return self.close_authenticated_crypto_error(
                    quion_proto::crypto::EncryptionLevel::Initial,
                    error.transport_code(),
                );
            }
        };
        self.largest_initial_received = Some(
            self.largest_initial_received
                .map_or(opened.packet_number, |largest| {
                    largest.max(opened.packet_number)
                }),
        );
        self.handle_opened_crypto_packet(opened)
    }

    fn close_authenticated_crypto_error(
        &mut self,
        level: quion_proto::crypto::EncryptionLevel,
        error_code: quion_proto::transport_error::TransportErrorCode,
    ) -> Result<(ServerInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        self.authenticated_packet_received = true;
        self.proto
            .close_transport(
                error_code,
                quion_proto::VarInt::ZERO,
                b"authenticated handshake packet violation",
            )
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let packet = build_crypto_close_packet(
            &mut self.builder,
            &self.keys,
            &self.initial,
            level,
            error_code,
        )?;
        let mut progress = ServerInitialCryptoProgress {
            transport_error: Some(error_code),
            ..ServerInitialCryptoProgress::default()
        };
        match level {
            quion_proto::crypto::EncryptionLevel::Initial => {
                progress.response_packets_generated = 1;
            }
            quion_proto::crypto::EncryptionLevel::Handshake => {
                progress.handshake_packets_generated = 1;
            }
            quion_proto::crypto::EncryptionLevel::OneRtt
            | quion_proto::crypto::EncryptionLevel::ZeroRtt => {}
        }
        Ok((progress, vec![packet]))
    }

    fn discard_initial_state(&mut self) {
        if self.initial_discarded {
            return;
        }
        self.proto
            .discard_packet_space(quion_proto::crypto::EncryptionLevel::Initial);
        self.initial_discarded = true;
    }

    #[cfg(test)]
    const fn initial_state_discarded(&self) -> bool {
        self.initial_discarded
    }

    fn handle_opened_crypto_packet(
        &mut self,
        opened: quion_proto::crypto::packet::OpenedCryptoPacket,
    ) -> Result<(ServerInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        self.authenticated_packet_received = true;
        let effects = self
            .proto
            .handle_opened_crypto_packet(&mut self.session, opened)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let crypto_frames_received = effects
            .connection_events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    quion_proto::connection::ConnectionEvent::CryptoDataReceived(_)
                )
            })
            .count();
        let flight = emit_crypto_flight(
            &mut self.proto,
            &mut self.session,
            &mut self.keys,
            &mut self.crypto_level,
            &mut self.builder,
            &self.initial,
        )?;
        #[cfg(feature = "zero-rtt")]
        {
            self.zero_rtt_accepted |= self.session.install_zero_rtt_keys(&mut self.keys);
        }
        let peer_transport_parameters_received =
            install_peer_transport_parameters(&self.session, &mut self.peer_transport_parameters)?;
        if peer_transport_parameters_received {
            self.peer_transport_parameters
                .as_ref()
                .ok_or(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::InternalError,
                ))?
                .validate_client_parameters(&self.peer_initial_source_cid)
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        }
        let handshake_completed = !self.session.is_handshaking();
        if handshake_completed {
            self.keys.discard_handshake();
        }
        Ok((
            ServerInitialCryptoProgress {
                crypto_frames_received,
                response_crypto_frames: flight.initial_crypto_frames,
                handshake_crypto_frames: flight.handshake_crypto_frames,
                one_rtt_crypto_frames: flight.one_rtt_crypto_frames,
                response_packets_generated: flight.initial_packets_generated,
                handshake_packets_generated: flight.handshake_packets_generated,
                one_rtt_packets_generated: flight.one_rtt_packets_generated,
                handshake_keys_installed: flight.handshake_keys_installed,
                one_rtt_keys_installed: flight.one_rtt_keys_installed,
                peer_transport_parameters_received,
                handshake_completed,
                tls_handshaking: self.session.is_handshaking(),
                ..ServerInitialCryptoProgress::default()
            },
            flight.packets,
        ))
    }
}

impl Future for Accept {
    type Output = Option<Incoming>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(incoming) = state.incoming.pop_front() {
            return Poll::Ready(Some(incoming));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        if !state
            .accept_waker
            .as_ref()
            .is_some_and(|registered| registered.will_wake(cx.waker()))
        {
            state.accept_waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub(crate) struct ProtectedOneRttUdpDriver {
    builder: quion_proto::crypto::packet::FramePacketBuilder,
    keys: quion_proto::crypto::rustls::RustlsKeyStore,
    expected_dst_cid_len: usize,
    largest_received: Option<u64>,
    pending_transmits: VecDeque<PendingOneRttTransmit>,
    proto_transmits: Vec<quion_proto::connection::Transmit>,
    generated_transmits: Vec<(quion_udp::Transmit, bool)>,
    recv_batch: quion_udp::BatchRecv,
    send_batch: quion_udp::BatchSend,
    pending_batch_ack_metadata: Vec<bool>,
    routed_only: bool,
    tls_session: Option<quion_proto::crypto::rustls::RustlsSession>,
    one_rtt_packets_sent_with_current_key: u64,
    key_update_packet_threshold: u64,
    current_phase_first_packet_number: Option<u64>,
    previous_key_discard_at: Option<web_time::Instant>,
    peer_update_ack_pending: bool,
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl ProtectedOneRttUdpDriver {
    pub(crate) fn new(
        builder: quion_proto::crypto::packet::FramePacketBuilder,
        keys: quion_proto::crypto::rustls::RustlsKeyStore,
        expected_dst_cid_len: usize,
    ) -> Self {
        Self {
            builder,
            keys,
            expected_dst_cid_len,
            largest_received: None,
            pending_transmits: VecDeque::new(),
            proto_transmits: Vec::new(),
            generated_transmits: Vec::new(),
            recv_batch: quion_udp::BatchRecv::default(),
            send_batch: quion_udp::BatchSend::default(),
            pending_batch_ack_metadata: Vec::new(),
            routed_only: false,
            tls_session: None,
            one_rtt_packets_sent_with_current_key: 0,
            key_update_packet_threshold: ONE_RTT_KEY_UPDATE_PACKET_THRESHOLD,
            current_phase_first_packet_number: None,
            previous_key_discard_at: None,
            peer_update_ack_pending: false,
        }
    }

    pub(crate) fn routed_only(mut self) -> Self {
        self.routed_only = true;
        self
    }

    #[cfg(all(feature = "gso", any(target_os = "linux", test)))]
    fn coalesce_gso_transmits(
        &mut self,
        pending: &mut PendingOneRttTransmit,
        now: web_time::Instant,
    ) {
        const MAX_GSO_SEGMENTS: usize = 64;

        if pending.transmit.segment_size.is_some() || pending.transmit.contents.len() < 1_200 {
            return;
        }
        let segment_size = pending.transmit.contents.len();
        while pending.packet_count < MAX_GSO_SEGMENTS {
            let Some(next) = self.pending_transmits.front() else {
                break;
            };
            if next.packet_count != 1
                || next.transmit.segment_size.is_some()
                || next.transmit.contents.len() != segment_size
                || next.transmit.destination != pending.transmit.destination
                || next.transmit.source != pending.transmit.source
                || next.transmit.ecn != pending.transmit.ecn
                || next.transmit.send_at.is_some_and(|send_at| send_at > now)
            {
                break;
            }
            let next = self
                .pending_transmits
                .pop_front()
                .expect("front was checked above");
            if pending.packet_count == 1 {
                let mut aggregate = self.send_batch.take_payload_buffer();
                aggregate.extend_from_slice(&pending.transmit.contents);
                let packet = std::mem::replace(&mut pending.transmit.contents, aggregate);
                self.builder.recycle_packet(packet);
            }
            pending
                .transmit
                .contents
                .extend_from_slice(&next.transmit.contents);
            self.builder.recycle_packet(next.transmit.contents);
            pending.contains_ack |= next.contains_ack;
            pending.packet_count += 1;
        }
        if pending.packet_count > 1 {
            pending.transmit.segment_size = Some(segment_size);
        }
    }

    fn with_tls_session(mut self, session: quion_proto::crypto::rustls::RustlsSession) -> Self {
        self.tls_session = Some(session);
        self
    }

    /// Effective key-update threshold, capped so an update is always initiated
    /// strictly before the negotiated cipher's AEAD confidentiality limit
    /// (RFC 9001 Section 6.6).
    fn effective_key_update_threshold(&self) -> u64 {
        match self.keys.one_rtt_confidentiality_limit() {
            Some(limit) => self
                .key_update_packet_threshold
                .min(limit.saturating_sub(1).max(1)),
            None => self.key_update_packet_threshold,
        }
    }

    fn initiate_key_update_if_needed(&mut self) -> Result<bool, ConnectionError> {
        if self.one_rtt_packets_sent_with_current_key < self.effective_key_update_threshold() {
            return Ok(false);
        }
        if self.current_phase_first_packet_number.is_some() {
            return Ok(false);
        }
        if self
            .keys
            .initiate_one_rtt_key_update()
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?
        {
            self.one_rtt_packets_sent_with_current_key = 0;
            return Ok(true);
        }
        Err(ConnectionError::TransportError(
            quion_proto::transport_error::TransportErrorCode::AeadLimitReached,
        ))
    }

    fn record_one_rtt_packet_sent(&mut self, contains_ack: bool) {
        self.one_rtt_packets_sent_with_current_key =
            self.one_rtt_packets_sent_with_current_key.saturating_add(1);
        if contains_ack {
            self.peer_update_ack_pending = false;
        }
    }

    fn ensure_can_protect_next_packet(&self) -> Result<(), ConnectionError> {
        if self
            .keys
            .one_rtt_confidentiality_limit()
            .is_some_and(|limit| self.one_rtt_packets_sent_with_current_key >= limit)
        {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::AeadLimitReached,
            ));
        }
        Ok(())
    }

    fn protected_transmit_batch_limit(&self, requested: usize) -> usize {
        let confidentiality_remaining = self
            .keys
            .one_rtt_confidentiality_limit()
            .map_or(u64::MAX, |limit| {
                limit.saturating_sub(self.one_rtt_packets_sent_with_current_key)
            });
        let update_remaining = if self.current_phase_first_packet_number.is_none() {
            self.effective_key_update_threshold()
                .saturating_sub(self.one_rtt_packets_sent_with_current_key)
        } else {
            u64::MAX
        };
        usize::try_from(confidentiality_remaining.min(update_remaining))
            .unwrap_or(usize::MAX)
            .min(requested.max(1))
            .max(1)
    }

    fn note_key_phase_started(&mut self, first_packet_number: u64) {
        self.current_phase_first_packet_number = Some(first_packet_number);
    }

    fn confirm_key_phase_if_acked(&mut self, largest_acked: Option<u64>) -> bool {
        let Some(first_packet_number) = self.current_phase_first_packet_number else {
            return false;
        };
        if largest_acked.is_none_or(|largest| largest < first_packet_number) {
            return false;
        }
        self.current_phase_first_packet_number = None;
        true
    }

    fn note_new_phase_packet_received(
        &mut self,
        now: web_time::Instant,
        retirement_duration: std::time::Duration,
    ) {
        if self.previous_key_discard_at.is_none()
            && self.keys.has_previous_one_rtt_key()
            && self
                .keys
                .current_one_rtt_phase_first_packet_number()
                .is_some()
        {
            self.previous_key_discard_at = Some(now + retirement_duration);
        }
    }

    fn retire_previous_key_if_due(&mut self, now: web_time::Instant) -> bool {
        if self
            .previous_key_discard_at
            .is_none_or(|deadline| deadline > now)
        {
            return false;
        }
        self.keys.discard_previous_one_rtt_key();
        self.previous_key_discard_at = None;
        true
    }

    /// Reset the per-key-phase send counter after a peer-initiated key update
    /// and reject updates that arrive too quickly.
    ///
    /// RFC 9001 §6.1 forbids a peer from initiating a new key update before it
    /// has received an acknowledgement for a packet sent in the current phase.
    /// That can only happen after we have sent at least one packet in the phase
    /// being superseded, so a phase change observed while we have sent nothing
    /// in the prior phase is treated as a `KEY_UPDATE_ERROR`.
    fn validate_and_reset_after_peer_key_update(
        &mut self,
        before: Option<bool>,
        sent_in_phase_before: u64,
    ) -> Result<bool, ConnectionError> {
        let after = self.keys.current_one_rtt_key_phase();
        let peer_updated = matches!((before, after), (Some(b), Some(a)) if b != a);
        if peer_updated {
            if sent_in_phase_before == 0 {
                return Err(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::KeyUpdateError,
                ));
            }
            self.one_rtt_packets_sent_with_current_key = 0;
            self.peer_update_ack_pending = true;
        }
        Ok(peer_updated)
    }

    #[cfg(test)]
    fn set_key_update_packet_threshold(&mut self, threshold: u64) {
        self.key_update_packet_threshold = threshold.max(1);
    }

    #[cfg(test)]
    const fn one_rtt_packets_sent_with_current_key(&self) -> u64 {
        self.one_rtt_packets_sent_with_current_key
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
struct PendingOneRttTransmit {
    transmit: quion_udp::Transmit,
    contains_ack: bool,
    #[cfg(all(feature = "gso", any(target_os = "linux", test)))]
    packet_count: usize,
}

fn transmit_segment_count(transmit: &quion_udp::Transmit) -> usize {
    transmit
        .segment_size
        .filter(|segment_size| *segment_size != 0)
        .map_or(1, |segment_size| {
            transmit.contents.len().div_ceil(segment_size)
        })
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EndpointDriverProgress {
    pub sent_packets: usize,
    pub received_packets: usize,
    pub timeouts_processed: usize,
    pub key_updates_initiated: usize,
    pub next_send_at: Option<web_time::Instant>,
    pub next_timeout: Option<web_time::Instant>,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
pub(crate) struct ProtectedOneRttUdpDriverHandle {
    connection: Connection,
    #[allow(dead_code)]
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<Result<(), ConnectionError>>,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl std::fmt::Debug for ProtectedOneRttUdpDriverHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedOneRttUdpDriverHandle")
            .field("is_finished", &self.is_finished())
            .finish()
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl ProtectedOneRttUdpDriverHandle {
    pub(crate) fn is_finished(&self) -> bool {
        self.join.is_finished()
    }

    pub(crate) fn abort(&self) {
        self.connection.abort();
        self.join.abort();
    }

    #[allow(dead_code)]
    pub(crate) async fn stop(mut self) -> Result<(), ConnectionError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match tokio::time::timeout(RUNTIME_DRIVER_STOP_GRACE, &mut self.join).await {
            Ok(Ok(result)) => return result,
            Ok(Err(error)) if error.is_cancelled() => return Ok(()),
            Ok(Err(error)) => {
                return Err(ConnectionError::Runtime(format!(
                    "protected 1-RTT driver task failed: {error}"
                )));
            }
            Err(_elapsed) => self.join.abort(),
        }
        match self.join.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(ConnectionError::Runtime(format!(
                "protected 1-RTT driver task failed: {error}"
            ))),
        }
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
/// Handle for an endpoint-owned Tokio server UDP driver task.
pub struct EndpointServerUdpDriverHandle {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<Result<(), ConnectionError>>,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl EndpointServerUdpDriverHandle {
    /// Returns whether the driver task has completed.
    pub fn is_finished(&self) -> bool {
        self.join.is_finished()
    }

    /// Aborts the driver task immediately.
    pub fn abort(&self) {
        self.join.abort();
    }

    /// Requests graceful driver shutdown and waits for completion.
    pub async fn stop(mut self) -> Result<(), ConnectionError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match tokio::time::timeout(RUNTIME_DRIVER_STOP_GRACE, &mut self.join).await {
            Ok(Ok(result)) => return result,
            Ok(Err(error)) if error.is_cancelled() => return Ok(()),
            Ok(Err(error)) => {
                return Err(ConnectionError::Runtime(format!(
                    "server UDP driver task failed: {error}"
                )));
            }
            Err(_elapsed) => self.join.abort(),
        }
        match self.join.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(ConnectionError::Runtime(format!(
                "server UDP driver task failed: {error}"
            ))),
        }
    }
}

#[derive(Debug)]
/// Future that progresses an outbound QUIC and TLS handshake.
pub struct Connecting {
    state: Option<Box<ClientCryptoConnection>>,
    #[cfg(feature = "zero-rtt")]
    early_connection: Option<Connection>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    completion: Option<tokio::sync::oneshot::Receiver<Result<ConnectCompletion, ConnectionError>>>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    preserve_early_connection: Arc<AtomicBool>,
}

#[cfg(all(
    feature = "zero-rtt",
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
#[derive(Debug)]
/// Future resolving the server's decision for a client 0-RTT attempt.
pub struct ZeroRttAccepted {
    completion: tokio::sync::oneshot::Receiver<Result<ConnectCompletion, ConnectionError>>,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
#[derive(Debug)]
struct ConnectCompletion {
    connection: Connection,
    preserve: Arc<AtomicBool>,
    delivered: bool,
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl ConnectCompletion {
    fn into_connection(mut self) -> Connection {
        self.delivered = true;
        self.connection.clone()
    }
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl Drop for ConnectCompletion {
    fn drop(&mut self) {
        if !self.delivered && !self.preserve.load(Ordering::Acquire) {
            self.connection.abort();
        }
    }
}

#[derive(Debug)]
struct ClientCryptoConnection {
    connection: Connection,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    original_initial_dst_cid: quion_proto::cid::ConnectionId,
    original_dst_cid: quion_proto::cid::ConnectionId,
    original_src_cid: quion_proto::cid::ConnectionId,
    attempted_version: u32,
    initial_token: Vec<u8>,
    retry_source_cid: Option<quion_proto::cid::ConnectionId>,
    peer_initial_source_cid: Option<quion_proto::cid::ConnectionId>,
    initial_transmitted: bool,
    initial_send_offset: usize,
    last_initial_send_start: usize,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    initial_builder: quion_proto::crypto::packet::CryptoPacketBuilder,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    tls_session: Option<quion_proto::crypto::rustls::RustlsSession>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    client_initial_crypto: Vec<u8>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    tls_keys: quion_proto::crypto::rustls::RustlsKeyStore,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    tls_crypto_level: quion_proto::crypto::EncryptionLevel,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    peer_transport_parameters: Option<quion_proto::transport_parameters::TransportParameters>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    initial_discarded: bool,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    handshake_runtime_prepared: bool,
    largest_initial_received: Option<u64>,
    largest_handshake_received: Option<u64>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    largest_one_rtt_received: Option<u64>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pending_one_rtt_effects: Vec<quion_proto::connection::Effects>,
    #[cfg(feature = "zero-rtt")]
    zero_rtt_attempted: bool,
    #[cfg(feature = "zero-rtt")]
    zero_rtt_was_rejected: bool,
    #[cfg(feature = "zero-rtt")]
    zero_rtt_peer_transport_parameters:
        Option<quion_proto::transport_parameters::TransportParameters>,
    #[cfg(feature = "zero-rtt")]
    pending_zero_rtt_transmit: Option<quion_udp::Transmit>,
    routed_datagrams: VecDeque<RoutedDatagram>,
    endpoint_memory_reservation: Option<EndpointMemoryReservation>,
}

impl Connecting {
    fn new(
        connection: Connection,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        original_dst_cid: quion_proto::cid::ConnectionId,
        original_src_cid: quion_proto::cid::ConnectionId,
        attempted_version: u32,
        endpoint_memory_reservation: EndpointMemoryReservation,
    ) -> Self {
        Self {
            state: Some(Box::new(ClientCryptoConnection::new(
                connection.clone(),
                local_addr,
                server_addr,
                original_dst_cid,
                original_src_cid,
                attempted_version,
                Some(endpoint_memory_reservation),
            ))),
            #[cfg(feature = "zero-rtt")]
            early_connection: Some(connection),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            completion: None,
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            preserve_early_connection: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(all(
        feature = "zero-rtt",
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    /// Converts a resumed handshake into an immediately usable 0-RTT
    /// connection.
    ///
    /// This succeeds only when cached TLS and QUIC transport state supplied
    /// usable early-data keys. Data written through the returned connection
    /// is replayable and must be restricted to idempotent operations. Await
    /// the returned future to learn whether the server accepted the attempt.
    #[allow(clippy::result_large_err)]
    pub fn into_0rtt(mut self) -> Result<(Connection, ZeroRttAccepted), Self> {
        let available = self.early_connection.as_ref().is_some_and(|connection| {
            connection.zero_rtt_status() == crate::ZeroRttStatus::Attempted
        }) && self.completion.is_some();
        if !available {
            return Err(self);
        }
        let connection = self
            .early_connection
            .take()
            .expect("availability check requires an early connection");
        let completion = self
            .completion
            .take()
            .expect("availability check requires a completion receiver");
        self.preserve_early_connection
            .store(true, Ordering::Release);
        Ok((connection, ZeroRttAccepted { completion }))
    }

    /// Returns the original destination connection ID.
    pub fn original_destination_cid(&self) -> &[u8] {
        self.state
            .as_ref()
            .map_or(&[], |state| state.original_dst_cid.as_bytes())
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn record_crypto_packets_sent(&mut self, packets: &[CryptoFlightPacket]) {
        if let Some(state) = self.state.as_mut() {
            state.record_crypto_packets_sent(packets);
        }
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn record_initial_packet_sent(&mut self, bytes: usize) {
        if let Some(state) = self.state.as_mut() {
            state.record_initial_packet_sent(bytes);
        }
    }

    /// Returns the original client source connection ID.
    pub fn original_source_cid(&self) -> &[u8] {
        self.state
            .as_ref()
            .map_or(&[], |state| state.original_src_cid.as_bytes())
    }

    /// Returns the QUIC version attempted by this handshake.
    pub const fn attempted_version(&self) -> u32 {
        match &self.state {
            Some(state) => state.attempted_version,
            None => quion_proto::packet::QUIC_VERSION_1,
        }
    }

    #[cfg(test)]
    fn set_attempted_version(&mut self, version: u32) {
        if let Some(state) = self.state.as_mut() {
            state.attempted_version = version;
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            state.initial_builder.set_version(version);
        }
    }

    #[cfg(test)]
    fn initial_token(&self) -> &[u8] {
        self.state
            .as_ref()
            .map_or(&[], |state| state.initial_token.as_slice())
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn has_tls_session(&self) -> bool {
        self.state
            .as_ref()
            .and_then(|state| state.tls_session.as_ref())
            .is_some()
    }

    #[cfg(test)]
    fn initial_transmitted(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| state.initial_transmitted)
    }

    #[cfg(test)]
    fn server_addr(&self) -> Option<SocketAddr> {
        self.state.as_ref().map(|state| state.server_addr)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn is_handshake_complete(&self) -> bool {
        self.state
            .as_ref()
            .and_then(|state| state.tls_session.as_ref())
            .is_some_and(|session| !session.is_handshaking())
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn has_one_rtt_keys(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| state.tls_keys.has_one_rtt())
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn peer_transport_parameters(
        &self,
    ) -> Option<&quion_proto::transport_parameters::TransportParameters> {
        self.state
            .as_ref()
            .and_then(|state| state.peer_transport_parameters.as_ref())
    }

    #[cfg(test)]
    pub(crate) fn set_initial_token(&mut self, token: impl Into<Vec<u8>>) {
        if let Some(state) = self.state.as_mut() {
            state.set_initial_token(token);
        }
    }

    #[cfg(test)]
    pub(crate) fn handle_retry_packet(&mut self, packet: &[u8]) -> Result<(), ConnectionError> {
        self.state
            .as_mut()
            .ok_or(ConnectionError::LocallyClosed)?
            .handle_retry_packet(packet)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn start_rustls_client_initial_udp_transmit(
        &mut self,
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        transport_config: &quion_proto::config::TransportConfig,
    ) -> Result<Option<quion_udp::Transmit>, ConnectionError> {
        self.state
            .as_mut()
            .ok_or(ConnectionError::LocallyClosed)?
            .start_rustls_client_initial_udp_transmit(config, server_name, transport_config)
    }

    #[cfg(test)]
    pub(crate) fn validate_version_negotiation_packet(
        &self,
        packet: &[u8],
    ) -> Result<u32, ConnectionError> {
        self.state
            .as_ref()
            .ok_or(ConnectionError::LocallyClosed)?
            .validate_version_negotiation_packet(packet)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn poll_initial_udp_transmit(
        &mut self,
        crypto_data: &[u8],
    ) -> Result<Option<quion_udp::Transmit>, ConnectionError> {
        self.state
            .as_mut()
            .ok_or(ConnectionError::LocallyClosed)?
            .poll_initial_udp_transmit(crypto_data)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    pub(crate) fn handle_initial_crypto_packet(
        &mut self,
        packet: &mut [u8],
    ) -> Result<ClientInitialCryptoProgress, ConnectionError> {
        let (mut progress, _packets) = self.handle_initial_crypto_packet_inner(packet)?;
        if progress.dropped_packets == 0 {
            progress.initial_packets_received = 1;
        }
        Ok(progress)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn handle_initial_crypto_packet_inner(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(ClientInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        self.state
            .as_mut()
            .ok_or(ConnectionError::LocallyClosed)?
            .handle_initial_crypto_packet_inner(packet)
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn handle_handshake_crypto_packet_inner(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(ClientInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        self.state
            .as_mut()
            .ok_or(ConnectionError::LocallyClosed)?
            .handle_handshake_crypto_packet_inner(packet)
    }
}

impl Future for Connecting {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        #[cfg(not(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        )))]
        let _ = cx;
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        if let Some(completion) = self.completion.as_mut() {
            return match Pin::new(completion).poll(cx) {
                Poll::Ready(Ok(result)) => {
                    Poll::Ready(result.map(ConnectCompletion::into_connection))
                }
                Poll::Ready(Err(_)) => Poll::Ready(Err(ConnectionError::LocallyClosed)),
                Poll::Pending => Poll::Pending,
            };
        }
        Poll::Ready(
            self.state
                .take()
                .map(|state| (*state).into_connection())
                .ok_or(ConnectionError::LocallyClosed),
        )
    }
}

#[cfg(all(
    feature = "zero-rtt",
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
impl Future for ZeroRttAccepted {
    type Output = Result<bool, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.completion).poll(cx) {
            Poll::Ready(Ok(Ok(connection))) => {
                Poll::Ready(Ok(connection.into_connection().zero_rtt_status()
                    == crate::ZeroRttStatus::Accepted))
            }
            Poll::Ready(Ok(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(ConnectionError::LocallyClosed)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl ClientCryptoConnection {
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn memory_payload_bytes(&self) -> usize {
        let connection_memory = self.connection.diagnostics().memory;
        connection_memory
            .protocol
            .payload_bytes()
            .saturating_add(connection_memory.connection_id_bytes)
            .saturating_add(self.initial_token.len())
            .saturating_add(self.original_initial_dst_cid.len())
            .saturating_add(self.original_dst_cid.len())
            .saturating_add(self.original_src_cid.len())
            .saturating_add(
                self.retry_source_cid
                    .as_ref()
                    .map_or(0, quion_proto::cid::ConnectionId::len),
            )
            .saturating_add(self.client_initial_crypto.len())
            .saturating_add(self.pending_one_rtt_effects_memory_bytes())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn pending_memory_payload_bytes(&self) -> usize {
        self.initial_token
            .len()
            .saturating_add(self.original_initial_dst_cid.len())
            .saturating_add(self.original_dst_cid.len())
            .saturating_add(self.original_src_cid.len())
            .saturating_add(
                self.retry_source_cid
                    .as_ref()
                    .map_or(0, quion_proto::cid::ConnectionId::len),
            )
            .saturating_add(
                self.connection
                    .with_proto(|proto| proto.memory_stats().payload_bytes()),
            )
            .saturating_add(self.client_initial_crypto.len())
            .saturating_add(self.pending_one_rtt_effects_memory_bytes())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn is_within_endpoint_memory_reservation(&self) -> bool {
        self.endpoint_memory_reservation
            .as_ref()
            .is_none_or(|reservation| self.pending_memory_payload_bytes() <= reservation.bytes())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn pending_one_rtt_effects_memory_bytes(&self) -> usize {
        self.pending_one_rtt_effects
            .iter()
            .map(|effects| {
                std::mem::size_of::<quion_proto::connection::Effects>()
                    .saturating_add(effects.connection_events.len().saturating_mul(
                        std::mem::size_of::<quion_proto::connection::ConnectionEvent>(),
                    ))
                    .saturating_add(
                        effects
                            .connection_events
                            .iter()
                            .map(|event| match event {
                                quion_proto::connection::ConnectionEvent::FrameReceived(frame) => {
                                    frame.encoded_len()
                                }
                                quion_proto::connection::ConnectionEvent::CryptoDataReceived(
                                    data,
                                ) => data.bytes.len(),
                                _ => 0,
                            })
                            .fold(0usize, usize::saturating_add),
                    )
                    .saturating_add(
                        effects.ack_frames.len().saturating_mul(std::mem::size_of::<
                            quion_proto::recovery::ack::GeneratedAck,
                        >()),
                    )
                    .saturating_add(
                        effects
                            .qlog_events
                            .len()
                            .saturating_mul(std::mem::size_of::<quion_proto::qlog::QlogEvent>()),
                    )
                    .saturating_add(
                        effects
                            .wakeups
                            .len()
                            .saturating_mul(std::mem::size_of::<quion_proto::timer::Deadline>()),
                    )
            })
            .fold(0usize, usize::saturating_add)
    }

    fn new(
        connection: Connection,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        original_dst_cid: quion_proto::cid::ConnectionId,
        original_src_cid: quion_proto::cid::ConnectionId,
        attempted_version: u32,
        endpoint_memory_reservation: Option<EndpointMemoryReservation>,
    ) -> Self {
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        let initial_builder = {
            let mut builder = quion_proto::crypto::packet::CryptoPacketBuilder::new(
                original_dst_cid.clone(),
                original_src_cid.clone(),
            );
            builder.set_version(attempted_version);
            builder
        };
        Self {
            connection,
            local_addr,
            server_addr,
            original_initial_dst_cid: original_dst_cid.clone(),
            original_dst_cid: original_dst_cid.clone(),
            original_src_cid: original_src_cid.clone(),
            attempted_version,
            initial_token: Vec::new(),
            retry_source_cid: None,
            peer_initial_source_cid: None,
            initial_transmitted: false,
            initial_send_offset: 0,
            last_initial_send_start: 0,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            initial_builder,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            tls_session: None,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            client_initial_crypto: Vec::new(),
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            tls_keys: quion_proto::crypto::rustls::RustlsKeyStore::default(),
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            tls_crypto_level: quion_proto::crypto::EncryptionLevel::Initial,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            peer_transport_parameters: None,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            initial_discarded: false,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            handshake_runtime_prepared: false,
            largest_initial_received: None,
            largest_handshake_received: None,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            largest_one_rtt_received: None,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            pending_one_rtt_effects: Vec::new(),
            #[cfg(feature = "zero-rtt")]
            zero_rtt_attempted: false,
            #[cfg(feature = "zero-rtt")]
            zero_rtt_was_rejected: false,
            #[cfg(feature = "zero-rtt")]
            zero_rtt_peer_transport_parameters: None,
            #[cfg(feature = "zero-rtt")]
            pending_zero_rtt_transmit: None,
            routed_datagrams: VecDeque::new(),
            endpoint_memory_reservation,
        }
    }

    fn route_cid(&self) -> quion_proto::cid::ConnectionId {
        self.original_src_cid.clone()
    }

    fn into_connection(self) -> Connection {
        let connection = self.connection;
        for datagram in self.routed_datagrams {
            connection.enqueue_existing_routed_datagram(datagram);
        }
        connection
    }

    #[cfg(test)]
    fn enqueue_routed_datagram(&mut self, meta: quion_udp::RecvMeta, contents: Vec<u8>) {
        self.enqueue_routed_datagram_inner(RoutedDatagram::new(meta, contents));
    }

    fn enqueue_routed_datagram_with_budget(
        &mut self,
        meta: quion_udp::RecvMeta,
        contents: &[u8],
        budget: &Arc<RoutedDatagramMemoryBudget>,
    ) -> bool {
        let Some(datagram) = RoutedDatagram::copy_with_budget(meta, contents, budget) else {
            return false;
        };
        self.enqueue_routed_datagram_inner(datagram);
        true
    }

    fn enqueue_owned_routed_datagram_with_budget(
        &mut self,
        meta: quion_udp::RecvMeta,
        contents: Vec<u8>,
        budget: &Arc<RoutedDatagramMemoryBudget>,
    ) -> bool {
        let Some(datagram) = RoutedDatagram::with_budget(meta, contents, budget) else {
            return false;
        };
        self.enqueue_routed_datagram_inner(datagram);
        true
    }

    fn enqueue_routed_datagram_inner(&mut self, datagram: RoutedDatagram) {
        let contents_len = datagram.contents.len();
        let mut queued_bytes = self
            .routed_datagrams
            .iter()
            .map(|datagram| datagram.contents.len())
            .sum::<usize>();
        while self.routed_datagrams.len() >= MAX_ROUTED_DATAGRAM_QUEUE_LEN
            || queued_bytes.saturating_add(contents_len) > MAX_ROUTED_DATAGRAM_QUEUE_BYTES
        {
            let Some(dropped) = self.routed_datagrams.pop_front() else {
                break;
            };
            queued_bytes = queued_bytes.saturating_sub(dropped.contents.len());
        }
        self.routed_datagrams.push_back(datagram);
    }

    fn pop_routed_datagram(&mut self) -> Option<RoutedDatagram> {
        self.routed_datagrams.pop_front()
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn next_timeout(&self) -> Option<web_time::Instant> {
        self.connection.with_proto(|proto| proto.timeout())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn record_crypto_packets_sent(&mut self, packets: &[CryptoFlightPacket]) {
        let now = web_time::Instant::now();
        self.connection.with_proto_mut(|proto| {
            for packet in packets {
                let _effects = if packet.frames.is_empty() {
                    proto.record_sent_packet(
                        packet.level,
                        packet.packet_number,
                        packet.contents.len() as u64,
                        false,
                        now,
                    )
                } else {
                    proto.record_sent_crypto_packet(
                        packet.level,
                        packet.packet_number,
                        packet.contents.len() as u64,
                        packet.frames.clone(),
                        now,
                    )
                };
            }
        });
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn record_initial_packet_sent(&mut self, bytes: usize) {
        let packet_number = self
            .initial_builder
            .next_packet_number(quion_proto::crypto::EncryptionLevel::Initial)
            .unwrap_or(1)
            .saturating_sub(1);
        let frame = quion_proto::crypto::stream::CryptoFrame {
            level: quion_proto::crypto::EncryptionLevel::Initial,
            offset: self.last_initial_send_start as u64,
            bytes: self.client_initial_crypto
                [self.last_initial_send_start..self.initial_send_offset]
                .to_vec(),
        };
        self.connection.with_proto_mut(|proto| {
            let _ = proto.record_sent_crypto_packet(
                quion_proto::crypto::EncryptionLevel::Initial,
                packet_number,
                bytes as u64,
                vec![frame],
                web_time::Instant::now(),
            );
        });
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_crypto_timeout(
        &mut self,
        now: web_time::Instant,
    ) -> Result<(ClientInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        if self
            .connection
            .with_proto(|proto| proto.timeout())
            .is_none_or(|timeout| timeout > now)
        {
            return Ok((ClientInitialCryptoProgress::default(), Vec::new()));
        }
        let initial = self.initial_packet_protector()?;
        let effects = self
            .connection
            .with_proto_mut(|proto| proto.on_timeout(now))
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let flight = build_crypto_frame_flight(
            &mut self.initial_builder,
            &self.tls_keys,
            &initial,
            effects.crypto_frames,
        )?;
        Ok((
            ClientInitialCryptoProgress {
                response_crypto_frames: flight.initial_crypto_frames,
                handshake_crypto_frames: flight.handshake_crypto_frames,
                one_rtt_crypto_frames: flight.one_rtt_crypto_frames,
                response_packets_generated: flight.initial_packets_generated,
                handshake_packets_generated: flight.handshake_packets_generated,
                one_rtt_packets_generated: flight.one_rtt_packets_generated,
                timeouts_processed: 1,
                ..ClientInitialCryptoProgress::default()
            },
            flight.packets,
        ))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn handle_one_rtt_packet(
        &mut self,
        packet: &mut [u8],
        meta: &quion_udp::RecvMeta,
    ) -> Result<(ClientInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        if self
            .tls_session
            .as_ref()
            .is_none_or(CryptoSession::is_handshaking)
        {
            return Ok((
                ClientInitialCryptoProgress {
                    dropped_packets: 1,
                    tls_handshaking: true,
                    ..ClientInitialCryptoProgress::default()
                },
                Vec::new(),
            ));
        }
        let connection = self.connection.clone();
        let session = self
            .tls_session
            .as_mut()
            .ok_or(ConnectionError::Unsupported)?;
        let effects = match connection.with_proto_mut(|proto| {
            proto.recv_protected_one_rtt_with_session(
                session,
                &mut self.tls_keys,
                packet,
                self.original_src_cid.len(),
                quion_proto::connection::OneRttReceiveContext {
                    largest_received: self.largest_one_rtt_received,
                    key_update_permitted: true,
                },
                quion_proto::connection::RecvMeta {
                    ecn: meta.ecn.map(crate::connection::udp_to_proto_ecn),
                },
            )
        }) {
            Ok(effects) => effects,
            Err(quion_proto::CodecError::PacketDiscard) => {
                return Ok((
                    ClientInitialCryptoProgress {
                        dropped_packets: 1,
                        handshake_completed: true,
                        ..ClientInitialCryptoProgress::default()
                    },
                    Vec::new(),
                ));
            }
            Err(error) => {
                let error_code = error.transport_code();
                connection
                    .with_proto_mut(|proto| {
                        proto.close_transport(
                            error_code,
                            quion_proto::VarInt::ZERO,
                            b"authenticated one-rtt packet violation",
                        )
                    })
                    .map_err(|close_error| {
                        ConnectionError::TransportError(close_error.transport_code())
                    })?;
                let initial = self.initial_packet_protector()?;
                let packet = build_crypto_close_packet(
                    &mut self.initial_builder,
                    &self.tls_keys,
                    &initial,
                    quion_proto::crypto::EncryptionLevel::OneRtt,
                    error_code,
                )?;
                return Ok((
                    ClientInitialCryptoProgress {
                        one_rtt_packets_generated: 1,
                        handshake_completed: true,
                        transport_error: Some(error_code),
                        ..ClientInitialCryptoProgress::default()
                    },
                    vec![packet],
                ));
            }
        };
        self.largest_one_rtt_received = connection.with_proto(|proto| {
            proto
                .ack_tracker()
                .largest_received(quion_proto::crypto::EncryptionLevel::OneRtt)
        });
        self.pending_one_rtt_effects.push(effects);
        Ok((
            ClientInitialCryptoProgress {
                handshake_completed: true,
                ..ClientInitialCryptoProgress::default()
            },
            Vec::new(),
        ))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn initial_packet_protector(
        &self,
    ) -> Result<quion_proto::crypto::initial::InitialPacketProtector, ConnectionError> {
        let initial_keys = quion_proto::crypto::initial::InitialKeys::derive(
            self.attempted_version,
            &self.original_dst_cid,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        quion_proto::crypto::initial::InitialPacketProtector::new(
            &initial_keys,
            quion_proto::crypto::Side::Client,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn is_established_for_handoff(&self) -> bool {
        self.handshake_runtime_prepared
            && self
                .connection
                .with_proto(|proto| proto.is_handshake_confirmed())
            && self.peer_transport_parameters.is_some()
            && self.tls_keys.has_one_rtt()
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn largest_initial_received(&self) -> Option<u64> {
        self.largest_initial_received
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    fn largest_handshake_received(&self) -> Option<u64> {
        self.largest_handshake_received
    }

    fn set_initial_token(&mut self, token: impl Into<Vec<u8>>) {
        self.initial_token = token.into();
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        self.initial_builder
            .set_initial_token(self.initial_token.clone());
    }

    fn handle_retry_packet(&mut self, packet: &[u8]) -> Result<(), ConnectionError> {
        let (header, _tag) =
            quion_proto::packet::decode_retry_packet(packet, &self.original_initial_dst_cid)
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        if header.ty != quion_proto::packet::PacketType::Retry
            || header.version != self.attempted_version
            || header.dst_cid != self.original_src_cid
            || header.token.is_empty()
        {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        }
        self.retry_source_cid = Some(header.src_cid.clone());
        self.peer_initial_source_cid = None;
        self.original_dst_cid = header.src_cid;
        self.set_initial_token(header.token);
        self.initial_transmitted = false;
        self.initial_send_offset = 0;
        self.last_initial_send_start = 0;
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        {
            self.connection.with_proto_mut(|proto| {
                proto.discard_packet_space(quion_proto::crypto::EncryptionLevel::Initial);
                #[cfg(feature = "zero-rtt")]
                if self.zero_rtt_attempted {
                    proto.reject_zero_rtt();
                }
            });
            #[cfg(feature = "zero-rtt")]
            if self.zero_rtt_attempted {
                self.zero_rtt_attempted = false;
                self.zero_rtt_was_rejected = true;
                self.zero_rtt_peer_transport_parameters = None;
                self.pending_zero_rtt_transmit = None;
                self.tls_keys.discard_zero_rtt();
                self.connection
                    .set_zero_rtt_status(crate::ZeroRttStatus::Rejected);
            }
            self.initial_builder = quion_proto::crypto::packet::CryptoPacketBuilder::new(
                self.original_dst_cid.clone(),
                self.original_src_cid.clone(),
            );
            self.initial_builder.set_version(self.attempted_version);
            self.initial_builder
                .set_initial_token(self.initial_token.clone());
        }
        Ok(())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn observe_server_initial_source_cid(
        &mut self,
        source_cid: &quion_proto::cid::ConnectionId,
    ) -> Result<(), ConnectionError> {
        if self
            .peer_initial_source_cid
            .as_ref()
            .is_some_and(|existing| existing != source_cid)
        {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        }
        if self.peer_initial_source_cid.is_none() {
            self.peer_initial_source_cid = Some(source_cid.clone());
            self.initial_builder
                .set_destination_connection_id(source_cid.clone());
        }
        Ok(())
    }

    fn validate_version_negotiation_packet(&self, packet: &[u8]) -> Result<u32, ConnectionError> {
        let (header, consumed) = quion_proto::packet::Header::decode(packet, 0)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        if consumed != packet.len() {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        }
        match quion_proto::endpoint::Endpoint::validate_version_negotiation(
            &header,
            &self.original_dst_cid,
            &self.original_src_cid,
            self.attempted_version,
            &[quion_proto::packet::QUIC_VERSION_1],
        ) {
            quion_proto::endpoint::VersionNegotiationResult::Negotiated(version) => Ok(version),
            quion_proto::endpoint::VersionNegotiationResult::NoSupportedVersion => {
                Err(ConnectionError::VersionMismatch)
            }
            quion_proto::endpoint::VersionNegotiationResult::Invalid => {
                Err(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
                ))
            }
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn restart_after_version_negotiation(&mut self, version: u32) -> Result<(), ConnectionError> {
        if version != quion_proto::packet::QUIC_VERSION_1 || version == self.attempted_version {
            return Err(ConnectionError::VersionMismatch);
        }
        self.attempted_version = version;
        self.original_dst_cid = self.original_initial_dst_cid.clone();
        self.initial_token.clear();
        self.retry_source_cid = None;
        self.peer_initial_source_cid = None;
        self.initial_transmitted = false;
        self.initial_send_offset = 0;
        self.last_initial_send_start = 0;
        self.initial_builder = quion_proto::crypto::packet::CryptoPacketBuilder::new(
            self.original_dst_cid.clone(),
            self.original_src_cid.clone(),
        );
        self.initial_builder.set_version(version);
        self.connection.reset_proto_for_handshake();
        self.tls_session = None;
        self.client_initial_crypto.clear();
        self.tls_keys = quion_proto::crypto::rustls::RustlsKeyStore::default();
        self.tls_crypto_level = quion_proto::crypto::EncryptionLevel::Initial;
        self.peer_transport_parameters = None;
        self.initial_discarded = false;
        self.handshake_runtime_prepared = false;
        self.largest_initial_received = None;
        self.largest_handshake_received = None;
        self.largest_one_rtt_received = None;
        self.pending_one_rtt_effects.clear();
        #[cfg(feature = "zero-rtt")]
        {
            self.zero_rtt_attempted = false;
            self.zero_rtt_was_rejected = false;
            self.zero_rtt_peer_transport_parameters = None;
            self.pending_zero_rtt_transmit = None;
            self.connection
                .set_zero_rtt_status(crate::ZeroRttStatus::NotAttempted);
        }
        self.routed_datagrams.clear();
        Ok(())
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn take_protected_one_rtt_driver(&mut self) -> Option<ProtectedOneRttUdpDriver> {
        if !self.tls_keys.has_one_rtt()
            || !self
                .connection
                .with_proto(|proto| proto.is_handshake_confirmed())
        {
            return None;
        }
        let peer_transport_parameters = self.peer_transport_parameters.clone()?;
        let next_one_rtt_packet_number = self
            .initial_builder
            .next_packet_number(quion_proto::crypto::EncryptionLevel::OneRtt)
            .unwrap_or(0);
        let reservation = self.endpoint_memory_reservation.take()?;
        if !self.connection.finish_client_handshake(reservation) {
            return None;
        }
        #[cfg(feature = "zero-rtt")]
        self.connection
            .set_zero_rtt_status(if self.zero_rtt_attempted {
                if self
                    .tls_session
                    .as_ref()
                    .and_then(quion_proto::crypto::rustls::RustlsSession::client_zero_rtt_accepted)
                    .unwrap_or(false)
                {
                    crate::ZeroRttStatus::Accepted
                } else {
                    crate::ZeroRttStatus::Rejected
                }
            } else if self.zero_rtt_was_rejected {
                crate::ZeroRttStatus::Rejected
            } else {
                crate::ZeroRttStatus::NotAttempted
            });
        self.connection.mark_established(peer_transport_parameters);
        for effects in self.pending_one_rtt_effects.drain(..) {
            self.connection.handle_effects(&effects);
        }
        self.tls_keys.discard_handshake();
        #[cfg(feature = "zero-rtt")]
        self.tls_keys.discard_zero_rtt();
        let tls_session = self.tls_session.take()?;
        Some(
            ProtectedOneRttUdpDriver::new(
                quion_proto::crypto::packet::FramePacketBuilder::with_next_one_rtt_packet_number(
                    self.peer_initial_source_cid.clone()?,
                    next_one_rtt_packet_number,
                ),
                std::mem::take(&mut self.tls_keys),
                self.original_src_cid.len(),
            )
            .with_tls_session(tls_session),
        )
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn start_rustls_client_initial_udp_transmit(
        &mut self,
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        transport_config: &quion_proto::config::TransportConfig,
    ) -> Result<Option<quion_udp::Transmit>, ConnectionError> {
        self.initialize_rustls_client(config, server_name, transport_config)?;
        let crypto_data = self.client_initial_crypto.clone();
        self.poll_initial_udp_transmit(&crypto_data)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn initialize_rustls_client(
        &mut self,
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        transport_config: &quion_proto::config::TransportConfig,
    ) -> Result<(), ConnectionError> {
        if self.tls_session.is_none() {
            let transport_parameters =
                quion_proto::transport_parameters::TransportParameters::from_config(
                    transport_config,
                    &self.original_src_cid,
                    None,
                    None,
                    transport_config.max_datagram_frame_size,
                    None,
                )
                .encode();
            let server_name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
                .map_err(|error| ConnectionError::Runtime(error.to_string()))?;
            let provider = RustlsProvider;
            let mut session = provider
                .start_client_with_transport_parameters(config, server_name, transport_parameters)
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
            let key_change = session.write_handshake(&mut self.client_initial_crypto);
            if let Some(key_change) = key_change {
                self.tls_crypto_level = self.tls_keys.install(key_change);
            }
            #[cfg(feature = "zero-rtt")]
            {
                self.zero_rtt_attempted = session.install_zero_rtt_keys(&mut self.tls_keys);
                if self.zero_rtt_attempted {
                    let mut cached = None;
                    install_peer_transport_parameters(&session, &mut cached)?;
                    let cached = cached.ok_or(ConnectionError::TransportError(
                        quion_proto::transport_error::TransportErrorCode::TransportParameterError,
                    ))?;
                    self.connection.prepare_for_zero_rtt(&cached);
                    self.zero_rtt_peer_transport_parameters = Some(cached);
                    self.connection
                        .set_zero_rtt_status(crate::ZeroRttStatus::Attempted);
                }
            }
            self.tls_session = Some(session);
        }
        Ok(())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_initial_udp_transmit(
        &mut self,
        crypto_data: &[u8],
    ) -> Result<Option<quion_udp::Transmit>, ConnectionError> {
        if self.initial_transmitted {
            return Ok(None);
        }
        self.initial_builder
            .set_initial_token(self.initial_token.clone());
        let keys = quion_proto::crypto::initial::InitialKeys::derive(
            self.attempted_version,
            &self.original_dst_cid,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let protector = quion_proto::crypto::initial::InitialPacketProtector::new(
            &keys,
            quion_proto::crypto::Side::Client,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let capacity = self
            .initial_builder
            .max_payload_len(
                quion_proto::crypto::EncryptionLevel::Initial,
                MAX_CRYPTO_DATAGRAM_SIZE,
            )
            .saturating_sub(17);
        if capacity == 0 {
            return Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::ProtocolViolation,
            ));
        }
        let start = self.initial_send_offset;
        let end = start.saturating_add(capacity).min(crypto_data.len());
        let frame = quion_proto::crypto::stream::CryptoFrame {
            level: quion_proto::crypto::EncryptionLevel::Initial,
            offset: start as u64,
            bytes: crypto_data[start..end].to_vec(),
        };
        let packet = self
            .initial_builder
            .build_initial_padded(&protector, &[frame], 1200)
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        self.last_initial_send_start = start;
        self.initial_send_offset = end;
        self.initial_transmitted = end == crypto_data.len();
        Ok(Some(quion_udp::Transmit {
            destination: self.server_addr,
            source: Some(self.local_addr),
            // ECN validation starts with protected application traffic;
            // crypto ACK processing does not carry ECN feedback.
            ecn: None,
            contents: packet,
            segment_size: None,
            send_at: None,
        }))
    }

    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    fn prepare_zero_rtt_transmit(&mut self) -> Result<(), ConnectionError> {
        if !self.zero_rtt_attempted || self.pending_zero_rtt_transmit.is_some() {
            return Ok(());
        }
        self.pending_zero_rtt_transmit = self
            .connection
            .poll_protected_zero_rtt_udp_transmit(&mut self.initial_builder, &self.tls_keys)?;
        Ok(())
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn handle_initial_crypto_packet_inner(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(ClientInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        if self.tls_session.is_none() {
            return Err(ConnectionError::Unsupported);
        }
        if self.initial_discarded {
            return Ok((ClientInitialCryptoProgress::default(), Vec::new()));
        }
        let initial_keys = quion_proto::crypto::initial::InitialKeys::derive(
            self.attempted_version,
            &self.original_dst_cid,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let initial = quion_proto::crypto::initial::InitialPacketProtector::new(
            &initial_keys,
            quion_proto::crypto::Side::Client,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let opened = match quion_proto::crypto::packet::CryptoPacketOpener::open_initial(
            &initial,
            packet,
            self.largest_initial_received,
        ) {
            Ok(opened) => opened,
            Err(quion_proto::CodecError::PacketDiscard) => {
                return Ok((
                    ClientInitialCryptoProgress {
                        dropped_packets: 1,
                        ..ClientInitialCryptoProgress::default()
                    },
                    Vec::new(),
                ));
            }
            Err(error) => {
                return self.close_authenticated_crypto_error(
                    quion_proto::crypto::EncryptionLevel::Initial,
                    &initial,
                    error.transport_code(),
                );
            }
        };
        self.largest_initial_received = Some(
            self.largest_initial_received
                .map_or(opened.packet_number, |largest| {
                    largest.max(opened.packet_number)
                }),
        );
        self.handle_opened_crypto_packet(opened, initial)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn handle_handshake_crypto_packet_inner(
        &mut self,
        packet: &mut [u8],
    ) -> Result<(ClientInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        let initial_keys = quion_proto::crypto::initial::InitialKeys::derive(
            self.attempted_version,
            &self.original_dst_cid,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let initial = quion_proto::crypto::initial::InitialPacketProtector::new(
            &initial_keys,
            quion_proto::crypto::Side::Client,
        )
        .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let opened = match quion_proto::crypto::packet::CryptoPacketOpener::open_handshake(
            &self.tls_keys,
            packet,
            self.largest_handshake_received,
        ) {
            Ok(opened) => opened,
            Err(quion_proto::CodecError::PacketDiscard) => {
                return Ok((
                    ClientInitialCryptoProgress {
                        dropped_packets: 1,
                        ..ClientInitialCryptoProgress::default()
                    },
                    Vec::new(),
                ));
            }
            Err(error) => {
                return self.close_authenticated_crypto_error(
                    quion_proto::crypto::EncryptionLevel::Handshake,
                    &initial,
                    error.transport_code(),
                );
            }
        };
        self.largest_handshake_received = Some(
            self.largest_handshake_received
                .map_or(opened.packet_number, |largest| {
                    largest.max(opened.packet_number)
                }),
        );
        let result = self.handle_opened_crypto_packet(opened, initial);
        // RFC 9001 §4.9: a client discards Initial keys after successfully
        // processing its first Handshake packet.
        if result.is_ok() {
            self.discard_initial_state();
        }
        result
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn close_authenticated_crypto_error(
        &mut self,
        level: quion_proto::crypto::EncryptionLevel,
        initial: &quion_proto::crypto::initial::InitialPacketProtector,
        error_code: quion_proto::transport_error::TransportErrorCode,
    ) -> Result<(ClientInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        self.connection
            .with_proto_mut(|proto| {
                proto.close_transport(
                    error_code,
                    quion_proto::VarInt::ZERO,
                    b"authenticated handshake packet violation",
                )
            })
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let packet = build_crypto_close_packet(
            &mut self.initial_builder,
            &self.tls_keys,
            initial,
            level,
            error_code,
        )?;
        let mut progress = ClientInitialCryptoProgress {
            transport_error: Some(error_code),
            ..ClientInitialCryptoProgress::default()
        };
        match level {
            quion_proto::crypto::EncryptionLevel::Initial => {
                progress.response_packets_generated = 1;
            }
            quion_proto::crypto::EncryptionLevel::Handshake => {
                progress.handshake_packets_generated = 1;
            }
            quion_proto::crypto::EncryptionLevel::OneRtt
            | quion_proto::crypto::EncryptionLevel::ZeroRtt => {}
        }
        Ok((progress, vec![packet]))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn discard_initial_state(&mut self) {
        if self.initial_discarded {
            return;
        }
        self.connection.with_proto_mut(|proto| {
            proto.discard_packet_space(quion_proto::crypto::EncryptionLevel::Initial);
        });
        self.initial_discarded = true;
    }

    #[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    const fn initial_state_discarded(&self) -> bool {
        self.initial_discarded
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn handle_opened_crypto_packet(
        &mut self,
        opened: quion_proto::crypto::packet::OpenedCryptoPacket,
        initial: quion_proto::crypto::initial::InitialPacketProtector,
    ) -> Result<(ClientInitialCryptoProgress, Vec<CryptoFlightPacket>), ConnectionError> {
        let connection = self.connection.clone();
        let session = self
            .tls_session
            .as_mut()
            .ok_or(ConnectionError::Unsupported)?;
        let effects = connection
            .with_proto_mut(|proto| proto.handle_opened_crypto_packet(session, opened))
            .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        let crypto_frames_received = effects
            .connection_events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    quion_proto::connection::ConnectionEvent::CryptoDataReceived(_)
                )
            })
            .count();
        let flight = connection.with_proto_mut(|proto| {
            emit_crypto_flight(
                proto,
                session,
                &mut self.tls_keys,
                &mut self.tls_crypto_level,
                &mut self.initial_builder,
                &initial,
            )
        })?;
        let handshake_completed = !session.is_handshaking();
        let peer_transport_parameters_received = if handshake_completed {
            install_peer_transport_parameters(session, &mut self.peer_transport_parameters)?
        } else {
            false
        };
        if peer_transport_parameters_received {
            #[cfg(feature = "zero-rtt")]
            if self.zero_rtt_attempted
                && session.client_zero_rtt_accepted().unwrap_or(false)
                && let Some(cached) = self.zero_rtt_peer_transport_parameters.as_ref()
            {
                self.peer_transport_parameters
                    .as_ref()
                    .ok_or(ConnectionError::TransportError(
                        quion_proto::transport_error::TransportErrorCode::InternalError,
                    ))?
                    .validate_zero_rtt_compatibility(cached)
                    .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
            }
            self.peer_transport_parameters
                .as_ref()
                .ok_or(ConnectionError::TransportError(
                    quion_proto::transport_error::TransportErrorCode::InternalError,
                ))?
                .validate_server_parameters(
                    &self.original_initial_dst_cid,
                    self.peer_initial_source_cid
                        .as_ref()
                        .ok_or(ConnectionError::TransportError(
                        quion_proto::transport_error::TransportErrorCode::TransportParameterError,
                    ))?,
                    self.retry_source_cid.as_ref(),
                )
                .map_err(|error| ConnectionError::TransportError(error.transport_code()))?;
        }
        if handshake_completed
            && !self.handshake_runtime_prepared
            && let Some(peer_transport_parameters) = self.peer_transport_parameters.clone()
        {
            #[cfg(feature = "zero-rtt")]
            let zero_rtt_accepted =
                self.zero_rtt_attempted && session.client_zero_rtt_accepted().unwrap_or(false);
            #[cfg(not(feature = "zero-rtt"))]
            let zero_rtt_accepted = false;
            if let Some(peer_initial_source_cid) = self.peer_initial_source_cid.clone()
                && !self
                    .connection
                    .register_initial_peer_connection_id(peer_initial_source_cid)
            {
                return Err(ConnectionError::EndpointMemoryLimitReached);
            }
            apply_session_security_context(&self.connection, session);
            connection.with_proto_mut(|proto| {
                connection.prepare_proto_for_establishment(
                    proto,
                    &peer_transport_parameters,
                    zero_rtt_accepted,
                );
            });
            self.handshake_runtime_prepared = true;
        }
        let progress = ClientInitialCryptoProgress {
            crypto_frames_received,
            response_crypto_frames: flight.initial_crypto_frames,
            handshake_crypto_frames: flight.handshake_crypto_frames,
            one_rtt_crypto_frames: flight.one_rtt_crypto_frames,
            response_packets_generated: flight.initial_packets_generated,
            handshake_packets_generated: flight.handshake_packets_generated,
            one_rtt_packets_generated: flight.one_rtt_packets_generated,
            handshake_keys_installed: flight.handshake_keys_installed,
            one_rtt_keys_installed: flight.one_rtt_keys_installed,
            peer_transport_parameters_received,
            handshake_completed,
            tls_handshaking: session.is_handshaking(),
            ..ClientInitialCryptoProgress::default()
        };
        Ok((progress, flight.packets))
    }
}

fn map_udp_error(error: quion_udp::UdpError) -> ConnectionError {
    ConnectionError::Udp(error.to_string())
}

fn udp_error_into_io(error: quion_udp::UdpError) -> std::io::Error {
    let quion_udp::UdpError::Io(error) = error;
    error
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
fn connect_deadline(
    transport_config: &quion_proto::config::TransportConfig,
) -> Option<web_time::Instant> {
    let idle_ms = transport_config.max_idle_timeout_ms.into_inner();
    let timeout_ms = if idle_ms == 0 {
        30_000
    } else {
        idle_ms.min(30_000)
    };
    Some(web_time::Instant::now() + Duration::from_millis(timeout_ms))
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
fn clear_runtime_socket_readiness(socket: &tokio::net::UdpSocket) {
    // The nonblocking receive immediately before the wait observed
    // WouldBlock through the shared standard socket. Clear Tokio's
    // level-triggered readiness so a stale readable bit cannot create a busy
    // loop.
    let _ = socket.try_io(tokio::io::Interest::READABLE, || {
        Err::<(), _>(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    });
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

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn merge_client_initial_progress(
    total: &mut ClientInitialCryptoProgress,
    current: ClientInitialCryptoProgress,
) {
    total.initial_packets_received += current.initial_packets_received;
    total.handshake_packets_received += current.handshake_packets_received;
    total.crypto_frames_received += current.crypto_frames_received;
    total.response_crypto_frames += current.response_crypto_frames;
    total.handshake_crypto_frames += current.handshake_crypto_frames;
    total.one_rtt_crypto_frames += current.one_rtt_crypto_frames;
    total.response_packets_generated += current.response_packets_generated;
    total.handshake_packets_generated += current.handshake_packets_generated;
    total.one_rtt_packets_generated += current.one_rtt_packets_generated;
    total.response_packets_sent += current.response_packets_sent;
    total.timeouts_processed += current.timeouts_processed;
    total.dropped_packets += current.dropped_packets;
    total.handshake_keys_installed |= current.handshake_keys_installed;
    total.one_rtt_keys_installed |= current.one_rtt_keys_installed;
    total.peer_transport_parameters_received |= current.peer_transport_parameters_received;
    total.handshake_completed |= current.handshake_completed;
    total.tls_handshaking = current.tls_handshaking;
    total.transport_error = total.transport_error.or(current.transport_error);
}

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
fn connect_receive_made_progress(progress: &EndpointConnectReceiveProgress) -> bool {
    progress.received_packets != 0
        || progress.version_negotiation_packets_received != 0
        || progress.retry_packets_received != 0
        || progress.response_packets_sent != 0
        || progress.dropped_packets != 0
        || progress.initial_crypto.initial_packets_received != 0
        || progress.initial_crypto.handshake_packets_received != 0
        || progress.initial_crypto.crypto_frames_received != 0
        || progress.initial_crypto.response_packets_generated != 0
        || progress.initial_crypto.handshake_packets_generated != 0
        || progress.initial_crypto.one_rtt_packets_generated != 0
        || progress.initial_crypto.handshake_keys_installed
        || progress.initial_crypto.one_rtt_keys_installed
        || progress.initial_crypto.peer_transport_parameters_received
        || progress.initial_crypto.handshake_completed
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn coalesced_packet_len(packet: &[u8], expected_dst_cid_len: usize) -> quion_proto::Result<usize> {
    let (header, consumed) = quion_proto::packet::Header::decode(packet, expected_dst_cid_len)?;
    match header {
        quion_proto::packet::Header::Long(header) => match header.ty {
            quion_proto::packet::PacketType::Initial
            | quion_proto::packet::PacketType::ZeroRtt
            | quion_proto::packet::PacketType::Handshake => {
                let payload_len = header
                    .length
                    .ok_or(quion_proto::error::CodecError::MalformedPacket)?
                    .into_inner() as usize;
                consumed
                    .checked_add(payload_len)
                    .filter(|total| *total <= packet.len())
                    .ok_or(quion_proto::error::CodecError::UnexpectedEnd)
            }
            quion_proto::packet::PacketType::Retry => Ok(packet.len()),
        },
        quion_proto::packet::Header::Short(_)
        | quion_proto::packet::Header::VersionNegotiation { .. } => Ok(packet.len()),
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn packet_has_short_destination(
    packet: &[u8],
    destination: &quion_proto::cid::ConnectionId,
) -> bool {
    quion_proto::packet::Header::decode(packet, destination.len())
        .ok()
        .is_some_and(|(header, _)| {
            matches!(
                header,
                quion_proto::packet::Header::Short(header)
                    if header.dst_cid == *destination
            )
        })
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn coalesced_packet_ranges(
    packet: &[u8],
    expected_dst_cid_len: usize,
) -> (SmallVec<[(usize, usize); 4]>, bool) {
    let mut ranges = SmallVec::new();
    let mut cursor = 0usize;
    while cursor < packet.len() {
        match coalesced_packet_len(&packet[cursor..], expected_dst_cid_len) {
            Ok(length) if length > 0 => {
                let end = cursor + length;
                ranges.push((cursor, end));
                if end >= packet.len() {
                    return (ranges, false);
                }
                cursor = end;
            }
            _ => {
                let had_valid_prefix = !ranges.is_empty();
                return (ranges, had_valid_prefix);
            }
        }
    }
    (ranges, false)
}

fn fresh_proto_endpoint(
    max_tracked_paths: usize,
    max_retry_replay_entries: usize,
    retry_enabled: bool,
) -> quion_proto::endpoint::Endpoint {
    let retry_source_cid_bytes: [u8; 8] = rand::random();
    let retry_source_cid = quion_proto::cid::ConnectionId::from_slice(&retry_source_cid_bytes)
        .expect("8-byte retry source CID is valid");
    let mut endpoint = quion_proto::endpoint::Endpoint::with_retry(
        quion_proto::token::RetryTokenManager::new(
            quion_proto::token::RetryTokenKey::new(rand::random(), rand::random()),
            RETRY_TOKEN_LIFETIME,
        ),
        retry_source_cid,
    );
    endpoint.set_max_tracked_paths(max_tracked_paths);
    endpoint.set_max_retry_replay_entries(max_retry_replay_entries);
    endpoint.set_retry_enabled(retry_enabled);
    endpoint
}

fn default_connection_id(len: usize) -> quion_proto::cid::ConnectionId {
    let len = len.min(quion_proto::cid::MAX_CONNECTION_ID_LEN);
    let bytes: [u8; 20] = rand::random();
    quion_proto::cid::ConnectionId::from_slice(&bytes[..len])
        .expect("bounded connection ID length must be valid")
}

fn derive_stateless_reset_token(
    key: &[u8; 32],
    connection_id: &quion_proto::cid::ConnectionId,
) -> [u8; 16] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("fixed stateless reset key length must be valid for HMAC-SHA256");
    mac.update(connection_id.as_bytes());
    let mut token = [0u8; 16];
    token.copy_from_slice(&mac.finalize().into_bytes()[..16]);
    token
}

fn encode_stateless_reset(packet_len: usize, token: [u8; 16]) -> Option<Vec<u8>> {
    if packet_len <= 21 {
        return None;
    }
    let total_len = packet_len.saturating_sub(1).clamp(21, 43);
    let mut packet = vec![0u8; total_len];
    let prefix_len = total_len - token.len();
    for byte in &mut packet[..prefix_len] {
        *byte = rand::random();
    }
    packet[0] &= 0x3f;
    packet[0] |= 0x40;
    packet[prefix_len..].copy_from_slice(&token);
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake},
        thread,
        time::Duration,
    };

    #[test]
    fn endpoint_binds_to_requested_address() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        assert_ne!(endpoint.local_addr().port(), 0);
    }

    #[test]
    fn endpoint_bind_reports_stable_error_kind() {
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = occupied.local_addr().unwrap();

        let error = Endpoint::client(address).unwrap_err();

        assert_eq!(
            error,
            crate::EndpointError::Bind {
                kind: std::io::ErrorKind::AddrInUse,
            }
        );
    }

    #[cfg(all(
        feature = "gso",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn gso_coalescing_requires_matching_full_sized_transmits() {
        use quion_proto::{
            cid::ConnectionId,
            crypto::{packet::FramePacketBuilder, rustls::RustlsKeyStore},
        };

        let builder = FramePacketBuilder::new(ConnectionId::from_slice(b"peer-cid").unwrap());
        let mut driver = ProtectedOneRttUdpDriver::new(builder, RustlsKeyStore::default(), 8);
        let destination = "127.0.0.1:4433".parse().unwrap();
        driver.pending_transmits.push_back(PendingOneRttTransmit {
            transmit: quion_udp::Transmit {
                destination,
                source: None,
                ecn: Some(quion_udp::EcnCodepoint::Ect0),
                contents: vec![2; 1_452],
                segment_size: None,
                send_at: None,
            },
            contains_ack: true,
            packet_count: 1,
        });
        driver.pending_transmits.push_back(PendingOneRttTransmit {
            transmit: quion_udp::Transmit {
                destination,
                source: None,
                ecn: Some(quion_udp::EcnCodepoint::Ect0),
                contents: vec![3; 1_400],
                segment_size: None,
                send_at: None,
            },
            contains_ack: false,
            packet_count: 1,
        });
        let mut pending = PendingOneRttTransmit {
            transmit: quion_udp::Transmit {
                destination,
                source: None,
                ecn: Some(quion_udp::EcnCodepoint::Ect0),
                contents: vec![1; 1_452],
                segment_size: None,
                send_at: None,
            },
            contains_ack: false,
            packet_count: 1,
        };

        driver.coalesce_gso_transmits(&mut pending, web_time::Instant::now());

        assert_eq!(pending.packet_count, 2);
        assert_eq!(pending.transmit.segment_size, Some(1_452));
        assert_eq!(pending.transmit.contents.len(), 2 * 1_452);
        assert!(pending.contains_ack);
        assert_eq!(driver.pending_transmits.len(), 1);
        assert_eq!(
            driver
                .pending_transmits
                .front()
                .unwrap()
                .transmit
                .contents
                .len(),
            1_400
        );
    }

    #[test]
    fn client_endpoint_memory_limit_rejects_handshake_and_releases_on_drop() {
        let mut endpoint_config = crate::EndpointConfig::default();
        endpoint_config.transport.set_max_endpoint_memory_bytes(0);
        let endpoint =
            Endpoint::client_with_config(endpoint_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(matches!(
            endpoint.connect("127.0.0.1:4433".parse().unwrap(), "localhost"),
            Err(ConnectionError::EndpointMemoryLimitReached)
        ));
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 0);

        let mut endpoint_config = crate::EndpointConfig::default();
        endpoint_config
            .transport
            .set_max_endpoint_memory_bytes(1024 * 1024);
        let endpoint =
            Endpoint::client_with_config(endpoint_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();
        assert!(endpoint.endpoint_memory_budget.used_bytes() > 0);
        drop(connecting);
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 0);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn assert_socket_handshake_flood_respects_endpoint_memory_limit(retry_enabled: bool) {
        let proto_transport = quion_proto::config::TransportConfig::default();
        let handshake_reservation = pending_handshake_memory_reservation_bytes(&proto_transport);
        let memory_limit = handshake_reservation.saturating_mul(2);
        let mut transport = crate::config::TransportConfig::default();
        transport
            .set_retry_enabled(retry_enabled)
            .set_max_pending_handshakes(64)
            .set_max_endpoint_memory_bytes(memory_limit);
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let tls_server_config = Arc::new(test_server_config());
        let tls_client_config = Arc::new(test_client_config());
        let mut server_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        for _ in 0..12 {
            let client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let mut connecting = client.connect(server.local_addr(), "localhost").unwrap();
            let initial = connecting
                .start_rustls_client_initial_udp_transmit(
                    tls_client_config.clone(),
                    "localhost",
                    &proto_transport,
                )
                .unwrap()
                .unwrap();
            client.socket.send(&initial).unwrap();
            connecting.record_initial_packet_sent(initial.contents.len());
            let _ = poll_until_server_udp_progress(
                &server,
                tls_server_config.clone(),
                &proto_transport,
                &mut server_buffer,
            );

            if retry_enabled {
                let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
                let progress =
                    poll_until_connect_receive(&client, &mut connecting, &mut client_buffer);
                assert_eq!(progress.retry_packets_received, 1);
                let retried_initial = connecting
                    .start_rustls_client_initial_udp_transmit(
                        tls_client_config.clone(),
                        "localhost",
                        &proto_transport,
                    )
                    .unwrap()
                    .unwrap();
                client.socket.send(&retried_initial).unwrap();
                connecting.record_initial_packet_sent(retried_initial.contents.len());
                let _ = poll_until_server_udp_progress(
                    &server,
                    tls_server_config.clone(),
                    &proto_transport,
                    &mut server_buffer,
                );
            }

            let diagnostics = server.diagnostics();
            assert!(diagnostics.memory.reserved_payload_bytes <= memory_limit);
            assert_eq!(diagnostics.memory.max_payload_bytes, memory_limit);
            assert!(diagnostics.pending_server_handshakes <= 2);
        }

        let diagnostics = server.diagnostics();
        assert!((1..=2).contains(&diagnostics.pending_server_handshakes));
        assert!(
            (handshake_reservation..=memory_limit)
                .contains(&diagnostics.memory.reserved_payload_bytes)
        );
        assert!(diagnostics.stats.rejected_connections > 0);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn retry_disabled_socket_handshake_flood_respects_endpoint_memory_limit() {
        assert_socket_handshake_flood_respects_endpoint_memory_limit(false);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn retry_enabled_socket_handshake_flood_respects_endpoint_memory_limit() {
        assert_socket_handshake_flood_respects_endpoint_memory_limit(true);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn crypto_flight_packet(
        level: quion_proto::crypto::EncryptionLevel,
        len: usize,
    ) -> CryptoFlightPacket {
        CryptoFlightPacket {
            level,
            packet_number: 0,
            frames: Vec::new(),
            contents: vec![0; len],
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn initial_crypto_retransmissions_are_padded_and_authenticated() {
        use quion_proto::{
            cid::ConnectionId,
            crypto::{
                EncryptionLevel, Side,
                initial::{InitialKeys, InitialPacketProtector},
                packet::{CryptoPacketBuilder, CryptoPacketOpener},
                rustls::RustlsKeyStore,
                stream::CryptoFrame,
            },
        };
        let dcid = ConnectionId::from_slice(b"retry-dcid").unwrap();
        let initial_keys = InitialKeys::derive(quion_proto::packet::QUIC_VERSION_1, &dcid).unwrap();
        let sender = InitialPacketProtector::new(&initial_keys, Side::Client).unwrap();
        let receiver = InitialPacketProtector::new(&initial_keys, Side::Server).unwrap();
        let keys = RustlsKeyStore::default();
        let mut builder = CryptoPacketBuilder::new(dcid, ConnectionId::EMPTY);
        let frame = CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 0,
            bytes: b"retransmitted ClientHello".to_vec(),
        };
        for number in 0..2 {
            let mut packet =
                build_crypto_frame_packet(&mut builder, &keys, &sender, frame.clone()).unwrap();
            assert_eq!(packet.contents.len(), 1200);
            let opened =
                CryptoPacketOpener::open_initial(&receiver, &mut packet.contents, None).unwrap();
            assert_eq!(opened.packet_number, number);
            assert!(opened.frames.iter().any(|decoded| matches!(decoded,
                quion_proto::frame::Frame::Crypto { data, .. } if data.as_slice() == b"retransmitted ClientHello")));
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn coalesces_adjacent_long_header_crypto_packets_within_path_limit() {
        let datagrams = coalesce_crypto_flight_packets(vec![
            crypto_flight_packet(quion_proto::crypto::EncryptionLevel::Initial, 500),
            crypto_flight_packet(quion_proto::crypto::EncryptionLevel::Handshake, 600),
            crypto_flight_packet(quion_proto::crypto::EncryptionLevel::OneRtt, 100),
        ]);

        assert_eq!(datagrams.len(), 2);
        assert_eq!(datagrams[0].contents.len(), 1_100);
        assert_eq!(datagrams[0].packets.len(), 2);
        assert_eq!(datagrams[1].contents.len(), 100);
        assert_eq!(datagrams[1].packets.len(), 1);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn does_not_coalesce_crypto_packets_past_initial_path_limit() {
        let datagrams = coalesce_crypto_flight_packets(vec![
            crypto_flight_packet(quion_proto::crypto::EncryptionLevel::Initial, 800),
            crypto_flight_packet(quion_proto::crypto::EncryptionLevel::Handshake, 500),
        ]);

        assert_eq!(datagrams.len(), 2);
        assert_eq!(datagrams[0].contents.len(), 800);
        assert_eq!(datagrams[1].contents.len(), 500);
    }

    #[test]
    fn endpoint_retry_tokens_are_not_shared_between_instances() {
        let issuer = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let verifier = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let remote = "127.0.0.1:4433".parse().unwrap();
        let initial = test_initial_header(Vec::new());

        let retry_token = {
            let mut state = issuer
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let admission = state
                .proto_endpoint
                .admit_initial(remote, &initial, 1200, 10)
                .unwrap();
            let quion_proto::endpoint::Admission::RetryRequired { packet } = admission else {
                panic!("expected retry");
            };
            let (retry, _tag) =
                quion_proto::packet::decode_retry_packet(&packet, &initial.dst_cid).unwrap();
            retry.token
        };

        let retry_initial = test_initial_header(retry_token);
        let mut state = verifier
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            state
                .proto_endpoint
                .admit_initial(remote, &retry_initial, 1200, 20)
                .is_err()
        );
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test]
    async fn restoring_polled_drivers_does_not_resurrect_aborted_connections() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        let cid = quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap();
        let driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(cid.clone()),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        );
        let driver_id = {
            let mut state = endpoint.state.lock().unwrap();
            state.register_connection(cid, connection.clone()).unwrap();
            state.store_endpoint_one_rtt_driver(connection.clone(), driver)
        };
        endpoint.activate_endpoint_one_rtt_driver(&connection, driver_id);
        let polled = endpoint.take_endpoint_one_rtt_drivers();
        endpoint.abort();
        // The runtime restores its local batch after abort cleared endpoint state.
        endpoint.restore_endpoint_one_rtt_drivers(polled);
        assert!(endpoint.runtime_shutdown_ready());
        assert_eq!(endpoint.endpoint_driver_scheduler.registered_len(), 0);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test]
    async fn restoring_polled_drivers_after_abort_discards_late_routed_datagrams() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        let cid = quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap();
        let driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(cid.clone()),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        );
        let driver_id = {
            let mut state = endpoint.state.lock().unwrap();
            state.register_connection(cid, connection.clone()).unwrap();
            state.store_endpoint_one_rtt_driver(connection.clone(), driver)
        };
        endpoint.activate_endpoint_one_rtt_driver(&connection, driver_id);
        let polled = endpoint.take_endpoint_one_rtt_drivers();
        endpoint.abort();

        // Routing can retain a connection before abort and enqueue its packet
        // after abort clears the queue, while the driver batch is still polled.
        let meta = quion_udp::RecvMeta {
            local: Some(endpoint.local_addr()),
            remote: connection.remote_address(),
            interface: None,
            ecn: None,
            segment_size: None,
            len: 4,
        };
        assert!(endpoint.enqueue_connection_routed_datagram(&connection, meta, &[1; 4]));
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 4);
        endpoint.restore_endpoint_one_rtt_drivers(polled);

        assert!(endpoint.runtime_shutdown_ready());
        assert_eq!(endpoint.endpoint_driver_scheduler.registered_len(), 0);
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 0);
        assert_eq!(connection.routed_datagram_len(), 0);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test]
    async fn endpoint_wait_observes_shutdown_before_notification_registration() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let socket = endpoint.runtime_udp_socket().unwrap();
        // Shutdown may race with the driver's transition from polling to waiting.
        endpoint.abort();
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            endpoint.wait_for_server_runtime_activity(Some(&socket), None),
        )
        .await
        .expect("shutdown must not require a later UDP packet or notification");
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawned_udp_driver_stops_cleanly() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        let dst = quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap();
        let builder = quion_proto::crypto::packet::FramePacketBuilder::new(dst);
        let driver = ProtectedOneRttUdpDriver::new(
            builder,
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        );

        let handle = endpoint.spawn_protected_one_rtt_udp_driver(connection, driver, 1500);
        assert!(!handle.is_finished());
        tokio::time::timeout(Duration::from_secs(1), handle.stop())
            .await
            .expect("driver stop should return promptly")
            .unwrap();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_udp_driver_exits_when_endpoint_closes_after_drain() {
        let (_, server_crypto) = test_client_server_configs();
        let endpoint = Endpoint::server(
            ServerConfig::builder()
                .with_rustls_config(server_crypto)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let handle = endpoint.spawn_default_server_udp_driver(1500).unwrap();

        endpoint.close();

        tokio::time::timeout(Duration::from_secs(1), handle.stop())
            .await
            .expect("server driver should exit after endpoint shutdown")
            .unwrap();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawned_udp_driver_exits_after_connection_shutdown() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        let dst = quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap();
        let builder = quion_proto::crypto::packet::FramePacketBuilder::new(dst);
        let driver = ProtectedOneRttUdpDriver::new(
            builder,
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        );

        let handle = endpoint.spawn_protected_one_rtt_udp_driver(connection.clone(), driver, 1500);
        connection.force_close_for_test(ConnectionError::LocallyClosed);

        tokio::time::timeout(std::time::Duration::from_secs(1), handle.stop())
            .await
            .expect("driver should stop after shutdown")
            .unwrap();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inactive_client_udp_driver_is_removed_before_connection_churn() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        let dst = quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap();
        let builder = quion_proto::crypto::packet::FramePacketBuilder::new(dst);
        let driver = ProtectedOneRttUdpDriver::new(
            builder,
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        );
        let handle = endpoint.spawn_protected_one_rtt_udp_driver(connection.clone(), driver, 1500);
        {
            let mut state = endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.store_protected_one_rtt_driver(handle);
            assert_eq!(state.protected_one_rtt_drivers.len(), 1);
        }

        connection.abort();
        let _connecting = endpoint
            .connect("127.0.0.1:9".parse().unwrap(), "localhost")
            .unwrap();

        let state = endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(state.protected_one_rtt_drivers.is_empty());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_one_rtt_udp_driver_processes_due_connection_timeout() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        let now = web_time::Instant::now();
        connection.record_test_sent_packet(
            quion_proto::crypto::EncryptionLevel::OneRtt,
            0,
            1200,
            true,
            now - web_time::Duration::from_secs(60),
        );
        let dst = quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap();
        let mut driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(dst),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        )
        .routed_only();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        let progress = endpoint
            .poll_protected_one_rtt_udp_once(&connection, &mut driver, &mut recv_buffer)
            .unwrap();

        assert_eq!(progress.timeouts_processed, 1);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_one_rtt_udp_once_closes_on_stateless_reset_packet() {
        use quion_proto::{cid::ConnectionId, crypto::rustls::RustlsKeyStore};

        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let peer = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = Connection::new(endpoint.local_addr(), peer.local_addr().unwrap());
        let token = [0x5a; 16];
        connection.set_test_peer_stateless_reset_token(token);
        let dst = ConnectionId::from_slice(b"srvcid01").unwrap();
        let mut driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(dst.clone()),
            RustlsKeyStore::default(),
            dst.len(),
        );

        let mut packet = vec![0u8; 32];
        let token_offset = packet.len() - token.len();
        packet[0] = 0x40;
        packet[1..1 + dst.len()].copy_from_slice(dst.as_bytes());
        packet[token_offset..].copy_from_slice(&token);
        peer.send(&quion_udp::Transmit {
            destination: endpoint.local_addr(),
            source: peer.local_addr().ok(),
            ecn: None,
            contents: packet,
            segment_size: None,
            send_at: None,
        })
        .unwrap();

        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
        let progress = loop {
            let progress = endpoint
                .poll_protected_one_rtt_udp_once(&connection, &mut driver, &mut recv_buffer)
                .unwrap();
            if progress.received_packets > 0 || std::time::Instant::now() >= deadline {
                break progress;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        };

        assert_eq!(progress.received_packets, 1);
        assert!(connection.is_closed());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_udp_once_polls_endpoint_one_rtt_driver_without_new_datagram() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let connection = Connection::server(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        connection.record_test_sent_packet(
            quion_proto::crypto::EncryptionLevel::OneRtt,
            0,
            1200,
            true,
            web_time::Instant::now() - web_time::Duration::from_secs(60),
        );
        let driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(
                quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap(),
            ),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        )
        .routed_only();
        {
            let mut state = endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.store_endpoint_one_rtt_driver(connection, driver);
        }
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        let progress = endpoint
            .poll_server_udp_once(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut recv_buffer,
            )
            .unwrap();

        assert_eq!(progress.received_packets, 0);
        assert_eq!(progress.one_rtt_timeouts_processed, 1);
        assert!(progress.next_one_rtt_timeout.is_some());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_udp_once_reports_future_one_rtt_driver_deadline_without_fixed_polling() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let connection = Connection::server(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        let now = web_time::Instant::now();
        connection.record_test_sent_packet(
            quion_proto::crypto::EncryptionLevel::OneRtt,
            0,
            1200,
            true,
            now,
        );
        let driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(
                quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap(),
            ),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        )
        .routed_only();
        {
            let mut state = endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.store_endpoint_one_rtt_driver(connection, driver);
        }
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        let progress = endpoint
            .poll_server_udp_once(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut recv_buffer,
            )
            .unwrap();

        assert_eq!(progress.received_packets, 0);
        assert_eq!(progress.one_rtt_timeouts_processed, 0);
        assert!(progress.next_one_rtt_timeout.is_some_and(|at| at > now));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn restoring_polled_server_drivers_preserves_concurrently_registered_driver() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let make_owned = |id, port| EndpointOwnedOneRttDriver {
            id,
            connection: Connection::server(
                endpoint.local_addr(),
                SocketAddr::from(([127, 0, 0, 1], port)),
            ),
            driver: ProtectedOneRttUdpDriver::new(
                quion_proto::crypto::packet::FramePacketBuilder::new(
                    quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap(),
                ),
                quion_proto::crypto::rustls::RustlsKeyStore::default(),
                6,
            )
            .routed_only(),
        };
        let retained = make_owned(0, 9);
        let registered_while_polling = make_owned(1, 10);
        let mut state = endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .endpoint_one_rtt_drivers
            .insert(1, registered_while_polling);

        state.restore_endpoint_one_rtt_drivers(BTreeMap::from([(0, retained)]));

        assert_eq!(state.endpoint_one_rtt_drivers.len(), 2);
        assert_eq!(
            state.endpoint_one_rtt_drivers[&1]
                .connection
                .remote_address(),
            SocketAddr::from(([127, 0, 0, 1], 10))
        );
        assert_eq!(
            state.endpoint_one_rtt_drivers[&0]
                .connection
                .remote_address(),
            SocketAddr::from(([127, 0, 0, 1], 9))
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_udp_once_prunes_shutdown_ready_one_rtt_driver() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let connection = Connection::server(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        connection.force_close_for_test(ConnectionError::LocallyClosed);
        let driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(
                quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap(),
            ),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        )
        .routed_only();
        {
            let mut state = endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.store_endpoint_one_rtt_driver(connection, driver);
        }
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        let progress = endpoint
            .poll_server_udp_once(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut recv_buffer,
            )
            .unwrap();

        assert_eq!(progress.received_packets, 0);
        assert_eq!(progress.one_rtt_packets_sent, 0);
        assert_eq!(progress.one_rtt_packets_received, 0);
        let state = endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(state.endpoint_one_rtt_drivers.is_empty());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_udp_once_prunes_local_close_after_shutdown_deadline() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let connection = Connection::server(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
        connection.close(quion_proto::VarInt::from_u32(7), b"bye");
        connection.set_shutdown_deadline_for_test(Some(
            web_time::Instant::now() - web_time::Duration::from_millis(1),
        ));
        let driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(
                quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap(),
            ),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        )
        .routed_only();
        {
            let mut state = endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.store_endpoint_one_rtt_driver(connection, driver);
        }
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        endpoint
            .poll_server_udp_once(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut recv_buffer,
            )
            .unwrap();

        let state = endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(state.endpoint_one_rtt_drivers.is_empty());
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawned_server_udp_driver_stops_cleanly() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let handle = endpoint.spawn_server_udp_driver(
            Arc::new(test_server_config()),
            Default::default(),
            1500,
        );

        assert!(!handle.is_finished());
        tokio::time::timeout(Duration::from_secs(1), handle.stop())
            .await
            .expect("server driver stop should return promptly")
            .unwrap();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_awaits_handshake_and_returns_established_connection() {
        let (client_crypto, server_crypto) = test_client_server_configs();
        let server_events = Arc::new(Mutex::new(Vec::<crate::QlogEvent>::new()));
        let mut server_transport = crate::config::TransportConfig::default();
        let event_sink = server_events.clone();
        server_transport.set_qlog_handler(move |event| {
            event_sink
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.clone());
        });
        let client_config = ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .build();
        let server_crypto = Arc::new(server_crypto);
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let server_endpoint = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(server_transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_driver = server_endpoint.spawn_server_udp_driver(
            server_crypto.clone(),
            quion_proto::config::TransportConfig::default(),
            1500,
        );
        let connection = tokio::time::timeout(Duration::from_secs(1), async {
            client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .unwrap()
                .await
        })
        .await
        .expect("connect timed out")
        .unwrap();

        assert!(connection.is_established());
        assert!(connection.is_runtime_driven());
        assert!(connection.peer_transport_parameters().is_some());
        assert!(connection.stats().latest_rtt.is_some());
        #[cfg(feature = "zero-rtt")]
        assert_eq!(
            connection.zero_rtt_status(),
            crate::ZeroRttStatus::NotAttempted
        );
        {
            let client_state = client_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(client_state.client_crypto.is_empty());
            assert_eq!(client_state.connections.len(), 1);
            assert!(!client_state.routes.is_empty());
        }

        let incoming = tokio::time::timeout(Duration::from_secs(1), server_endpoint.accept())
            .await
            .expect("accept timed out")
            .expect("endpoint closed");
        let accepted = tokio::time::timeout(Duration::from_secs(1), incoming)
            .await
            .expect("incoming timed out")
            .unwrap();
        assert!(accepted.is_established());
        assert!(accepted.is_runtime_driven());
        assert!(accepted.stats().latest_rtt.is_some());
        assert!(!connection.stats().ecn_disabled);
        assert!(!accepted.stats().ecn_disabled);
        let _ = accepted.drain_qlog_events();
        assert!(
            server_events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .any(|event| matches!(
                    event,
                    crate::QlogEvent::PacketReceived {
                        level: "initial",
                        ..
                    }
                ))
        );
        #[cfg(feature = "zero-rtt")]
        assert_eq!(
            accepted.zero_rtt_status(),
            crate::ZeroRttStatus::NotAttempted
        );
        {
            let server_state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(server_state.server_initial.is_empty());
        }

        connection.abort();
        accepted.abort();
        client_endpoint.abort();
        server_endpoint.abort();
        tokio::task::yield_now().await;
        tokio::time::timeout(Duration::from_secs(1), server_driver.stop())
            .await
            .expect("server driver stop should return promptly")
            .unwrap();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_endpoint_driver_routes_multiple_established_connections() {
        const TEST_TIMEOUT: Duration = Duration::from_secs(2);

        let (client_crypto, server_crypto) = test_client_server_configs();
        let client_config = ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .build();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_driver = server_endpoint.spawn_server_udp_driver(
            Arc::new(server_crypto),
            quion_proto::config::TransportConfig::default(),
            1500,
        );

        let exercise = tokio::time::timeout(TEST_TIMEOUT, async {
            let first_connecting = client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .map_err(|_| "first connect setup failed")?;
            let second_connecting = client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .map_err(|_| "second connect setup failed")?;
            let (first_client, second_client) = tokio::try_join!(
                async {
                    first_connecting
                        .await
                        .map_err(|_| "first client handshake failed")
                },
                async {
                    second_connecting
                        .await
                        .map_err(|_| "second client handshake failed")
                }
            )?;
            let client_connections = vec![first_client, second_client];
            let mut server_connections = Vec::new();
            for _ in 0..2 {
                let incoming = server_endpoint
                    .accept()
                    .await
                    .ok_or("endpoint closed before accept")?;
                let server = incoming.await.map_err(|_| "server handshake failed")?;
                server_connections.push(server);
            }

            {
                let state = client_endpoint
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                assert_eq!(state.connections.len(), 2);
                assert!(state.protected_one_rtt_drivers.is_empty());
            }
            assert!(
                client_endpoint
                    .client_endpoint_driver_running
                    .load(Ordering::Acquire)
            );

            for (index, server) in server_connections.iter().enumerate() {
                let (mut send, _) = server
                    .open_bi()
                    .await
                    .map_err(|_| "server did not open a stream")?;
                send.write_all(&[index as u8])
                    .await
                    .map_err(|_| "server stream write failed")?;
                send.finish().map_err(|_| "server stream finish failed")?;
            }
            let mut received_values = Vec::new();
            for client in &client_connections {
                let (_, mut recv) = client
                    .accept_bi()
                    .await
                    .map_err(|_| "client did not accept a routed stream")?;
                let received = recv
                    .read_to_end(1)
                    .await
                    .map_err(|_| "client routed stream read failed")?;
                received_values.extend(received);
            }
            received_values.sort_unstable();
            assert_eq!(received_values, [0, 1]);

            Ok::<_, &'static str>((client_connections, server_connections))
        })
        .await;

        if let Ok(Ok((clients, servers))) = &exercise {
            for connection in clients.iter().chain(servers.iter()) {
                connection.abort();
            }
        }
        client_endpoint.abort();
        server_endpoint.abort();
        tokio::task::yield_now().await;
        tokio::time::timeout(TEST_TIMEOUT, server_driver.stop())
            .await
            .expect("server driver stop should return promptly")
            .unwrap();

        exercise
            .expect("multi-connection client driver exercise timed out")
            .expect("multi-connection client driver exercise failed");
    }

    #[cfg(all(
        feature = "zero-rtt",
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resumed_connection_reports_server_zero_rtt_acceptance() {
        const TEST_TIMEOUT: Duration = Duration::from_secs(5);

        let (mut client_crypto, mut server_crypto) = test_client_server_configs();
        client_crypto.enable_early_data = true;
        server_crypto.max_early_data_size = u32::MAX;
        let client_config = ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_zero_rtt()
            .build();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let mut endpoint_transport = crate::TransportConfig::default();
        // Retry rejects a client's 0-RTT attempt by definition, so this test
        // disables Retry to exercise the acceptance path.
        endpoint_transport.set_retry_enabled(false);
        let server_endpoint = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(endpoint_transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_driver = server_endpoint.spawn_server_udp_driver(
            Arc::new(server_crypto),
            quion_proto::config::TransportConfig::default(),
            1500,
        );

        let exercise = tokio::time::timeout(TEST_TIMEOUT, async {
            let first = client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .map_err(|_| "initial connect setup failed")?
                .await
                .map_err(|_| "initial connection failed")?;
            let first_incoming = server_endpoint
                .accept()
                .await
                .ok_or("endpoint closed before initial accept")?;
            let first_server = first_incoming
                .await
                .map_err(|_| "initial server handshake failed")?;
            let resumed = client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .map_err(|_| "resumed connect setup failed")?
                .await
                .map_err(|_| "resumed connection failed")?;
            let resumed_incoming = server_endpoint
                .accept()
                .await
                .ok_or("endpoint closed before resumed accept")?;
            let resumed_server = resumed_incoming
                .await
                .map_err(|_| "resumed server handshake failed")?;
            Ok::<_, &'static str>((first, first_server, resumed, resumed_server))
        })
        .await;

        let statuses = exercise.as_ref().ok().and_then(|result| {
            result
                .as_ref()
                .ok()
                .map(|(first, _first_server, resumed, resumed_server)| {
                    (
                        first.zero_rtt_status(),
                        resumed.zero_rtt_status(),
                        resumed_server.zero_rtt_status(),
                    )
                })
        });
        if let Ok(Ok((first, first_server, resumed, resumed_server))) = &exercise {
            first.abort();
            first_server.abort();
            resumed.abort();
            resumed_server.abort();
        }
        client_endpoint.abort();
        server_endpoint.abort();
        tokio::task::yield_now().await;
        tokio::time::timeout(TEST_TIMEOUT, server_driver.stop())
            .await
            .expect("server driver stop should return promptly")
            .unwrap();

        exercise
            .expect("resumed connection exercise timed out")
            .expect("resumed connection exercise failed");
        let (first_status, resumed_status, resumed_server_status) =
            statuses.expect("successful exercise must report statuses");
        assert_eq!(first_status, crate::ZeroRttStatus::NotAttempted);
        assert_eq!(resumed_status, crate::ZeroRttStatus::Accepted);
        assert_eq!(resumed_server_status, crate::ZeroRttStatus::Accepted);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_runtime_routes_post_handshake_datagrams_without_duplicate_accepts() {
        let (client_crypto, server_crypto) = test_client_server_configs();
        let client_config = ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .build();
        let server_crypto = Arc::new(server_crypto);
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_driver = server_endpoint.spawn_server_udp_driver(
            server_crypto,
            quion_proto::config::TransportConfig::default(),
            1500,
        );

        let connection = tokio::time::timeout(Duration::from_secs(1), async {
            client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .unwrap()
                .await
        })
        .await
        .expect("connect timed out")
        .unwrap();
        let incoming = tokio::time::timeout(Duration::from_secs(1), server_endpoint.accept())
            .await
            .expect("accept timed out")
            .expect("endpoint closed");
        let accepted = tokio::time::timeout(Duration::from_secs(1), incoming)
            .await
            .expect("incoming timed out")
            .unwrap();

        let (mut send, _) = tokio::time::timeout(Duration::from_secs(1), connection.open_bi())
            .await
            .expect("client did not open a stream")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), send.write_all(b"runtime-ping"))
            .await
            .expect("client stream write timed out")
            .unwrap();
        send.finish().unwrap();

        let (_, mut recv) = tokio::time::timeout(Duration::from_secs(1), accepted.accept_bi())
            .await
            .expect("server did not accept routed 1-RTT stream")
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), recv.read_to_end(1024))
            .await
            .expect("server did not receive routed 1-RTT stream data")
            .unwrap();
        assert_eq!(received, b"runtime-ping");

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = Arc::new(TestWaker {
            wake_count: wake_count.clone(),
        })
        .into();
        let mut cx = Context::from_waker(&waker);
        let mut second_accept = pin!(server_endpoint.accept());
        assert!(matches!(
            second_accept.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        assert_eq!(wake_count.load(Ordering::SeqCst), 0);

        connection.abort();
        accepted.abort();
        client_endpoint.abort();
        server_endpoint.abort();
        tokio::time::timeout(Duration::from_secs(1), server_driver.stop())
            .await
            .expect("server driver stop should return promptly")
            .unwrap();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_udp_driver_stop_returns_promptly() {
        let (_client_crypto, server_crypto) = test_client_server_configs();
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let handle = endpoint.spawn_server_udp_driver(
            Arc::new(server_crypto),
            quion_proto::config::TransportConfig::default(),
            1500,
        );

        tokio::time::timeout(Duration::from_secs(1), handle.stop())
            .await
            .expect("server driver stop should return promptly")
            .unwrap();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_udp_driver_stop_returns_after_endpoint_close() {
        let (_client_crypto, server_crypto) = test_client_server_configs();
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let handle = endpoint.spawn_server_udp_driver(
            Arc::new(server_crypto),
            quion_proto::config::TransportConfig::default(),
            1500,
        );

        endpoint.close();

        tokio::time::timeout(Duration::from_secs(1), handle.stop())
            .await
            .expect("server driver stop should return after endpoint close")
            .unwrap();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn endpoint_close_aborts_pending_connecting_future() {
        let (client_crypto, server_crypto) = test_client_server_configs();
        let client_config = ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .build();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let server_endpoint = Endpoint::server(
            ServerConfig::builder()
                .with_rustls_config(server_crypto)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();

        let connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        client_endpoint.close();

        let error = tokio::time::timeout(Duration::from_millis(100), connecting)
            .await
            .expect("connecting future should resolve after endpoint close")
            .expect_err("connecting future should fail after endpoint close");
        assert_eq!(error, ConnectionError::LocallyClosed);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_times_out_when_handshake_makes_no_progress() {
        let (client_crypto, _server_crypto) = test_client_server_configs();
        let mut transport = crate::config::TransportConfig::default();
        transport.set_max_idle_timeout(quion_proto::VarInt::from_u32(20));
        let client_config = ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_transport_config(transport)
            .build();
        let silent_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let silent_addr = silent_socket.local_addr().unwrap();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);

        let error = tokio::time::timeout(Duration::from_secs(1), async {
            client_endpoint
                .connect(silent_addr, "localhost")
                .unwrap()
                .await
        })
        .await
        .expect("connect future should resolve at handshake timeout")
        .expect_err("connect should fail when the peer never responds");

        assert_eq!(error, ConnectionError::TimedOut);
        drop(silent_socket);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_uses_configured_connection_id_length() {
        let mut transport = crate::config::TransportConfig::default();
        transport.set_connection_id_length(12);
        let config = ClientConfig::builder()
            .with_transport_config(transport)
            .build();
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config);

        let connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();

        assert_eq!(connecting.original_destination_cid().len(), 12);
        assert_eq!(connecting.original_source_cid().len(), 12);
        endpoint.abort();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_uses_custom_connection_id_generator() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_connection_id_generator(|len| {
            let bytes = [0xa5; quion_proto::cid::MAX_CONNECTION_ID_LEN];
            quion_proto::cid::ConnectionId::from_slice(&bytes[..len])
                .expect("requested connection ID length must fit")
        });

        let connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();

        assert_eq!(connecting.original_destination_cid(), &[0xa5; 8]);
        assert_eq!(connecting.original_source_cid(), &[0xa5; 8]);
        endpoint.abort();
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_uses_default_client_transport_config() {
        const TEST_TIMEOUT: Duration = Duration::from_secs(5);

        let (client_crypto, server_crypto) = test_client_server_configs();
        let mut client_transport = crate::config::TransportConfig::default();
        client_transport
            .set_initial_max_data(quion_proto::VarInt::from_u32(4_096))
            .set_initial_max_streams_bidi(quion_proto::VarInt::from_u32(7));
        let client_config = ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_transport_config(client_transport)
            .build();
        let server_crypto = Arc::new(server_crypto);
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let server_driver = server_endpoint.spawn_server_udp_driver(
            server_crypto,
            quion_proto::config::TransportConfig::default(),
            1500,
        );

        let exercise = tokio::time::timeout(TEST_TIMEOUT, async {
            let client = client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .map_err(|_| "connect setup failed")?
                .await
                .map_err(|_| "client handshake failed")?;
            let incoming = server_endpoint
                .accept()
                .await
                .ok_or("endpoint closed before accept")?;
            let accepted = incoming.await.map_err(|_| "server handshake failed")?;
            let peer_transport_parameters = accepted
                .peer_transport_parameters()
                .ok_or("peer transport parameters missing")?;
            let initial_max_data = peer_transport_parameters
                .get_var(quion_proto::transport_parameters::ids::INITIAL_MAX_DATA)
                .map_err(|_| "initial_max_data is malformed")?;
            let initial_max_streams_bidi = peer_transport_parameters
                .get_var(quion_proto::transport_parameters::ids::INITIAL_MAX_STREAMS_BIDI)
                .map_err(|_| "initial_max_streams_bidi is malformed")?;
            Ok::<_, &'static str>((client, accepted, initial_max_data, initial_max_streams_bidi))
        })
        .await;
        if let Ok(Ok((client, accepted, _, _))) = &exercise {
            client.abort();
            accepted.abort();
        }
        client_endpoint.abort();
        server_endpoint.abort();
        tokio::time::timeout(TEST_TIMEOUT, server_driver.stop())
            .await
            .expect("server driver stop should return promptly")
            .unwrap();

        let (_, _, initial_max_data, initial_max_streams_bidi) = exercise
            .expect("transport configuration exercise timed out")
            .expect("transport configuration exercise failed");
        assert_eq!(initial_max_data, Some(quion_proto::VarInt::from_u32(4_096)));
        assert_eq!(
            initial_max_streams_bidi,
            Some(quion_proto::VarInt::from_u32(7))
        );
    }

    #[test]
    fn accept_waits_for_incoming_connection_and_wakes() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = Arc::new(TestWaker {
            wake_count: wake_count.clone(),
        })
        .into();
        let mut cx = Context::from_waker(&waker);
        let mut accept = pin!(endpoint.accept());

        assert!(matches!(accept.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(wake_count.load(Ordering::SeqCst), 0);

        endpoint.enqueue_incoming(Incoming::new(Connection::new(
            endpoint.local_addr(),
            "127.0.0.1:4433".parse().unwrap(),
        )));

        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            accept.as_mut().poll(&mut cx),
            Poll::Ready(Some(_))
        ));
    }

    #[test]
    fn endpoint_close_wakes_accept_and_returns_none() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = Arc::new(TestWaker {
            wake_count: wake_count.clone(),
        })
        .into();
        let mut cx = Context::from_waker(&waker);
        let mut accept = pin!(endpoint.accept());

        assert!(matches!(accept.as_mut().poll(&mut cx), Poll::Pending));
        endpoint.close();

        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert!(endpoint.is_closed());
        assert!(matches!(accept.as_mut().poll(&mut cx), Poll::Ready(None)));
    }

    #[test]
    fn endpoint_diagnostics_reports_stable_snapshot_counts() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let before = endpoint.diagnostics();
        assert!(!before.is_closed);
        assert_eq!(before.stats.accepted_connections, 0);
        assert_eq!(before.active_connections, 0);
        assert_eq!(before.pending_incoming_connections, 0);
        assert_eq!(before.memory.payload_bytes(), 0);

        endpoint.close();
        let after = endpoint.diagnostics();

        assert!(after.is_closed);
        assert_eq!(after.stats.closed_connections, 0);
        assert_eq!(after.pending_server_handshakes, 0);
        assert_eq!(after.pending_client_handshakes, 0);
        assert_eq!(after.memory.payload_bytes(), 0);
    }

    #[test]
    fn runtime_work_limiter_yields_after_configured_progress_budget() {
        let mut limiter = RuntimeWorkLimiter::new(2);

        assert!(!limiter.record(true));
        assert!(limiter.record(true));
        assert!(!limiter.record(true));
        assert!(limiter.record(false));
        assert!(!limiter.record(true));
        assert!(limiter.record(true));
    }

    #[test]
    fn runtime_work_limiter_yields_when_polls_make_no_progress() {
        let mut limiter = RuntimeWorkLimiter::new(32);
        for _ in 0..64 {
            assert!(limiter.record(false));
        }
    }

    #[test]
    fn runtime_work_limiter_treats_zero_as_one() {
        let mut limiter = RuntimeWorkLimiter::new(0);

        assert!(limiter.record(true));
        assert!(limiter.record(false));
        assert!(limiter.record(true));
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn endpoint_driver_scheduler_deduplicates_ready_work_and_preserves_fairness() {
        let scheduler = EndpointDriverScheduler::default();
        let now = web_time::Instant::now();
        scheduler.register(1);
        scheduler.register(2);
        crate::connection::EndpointDriverWakeup::wake_driver(&scheduler, 1);
        crate::connection::EndpointDriverWakeup::wake_driver(&scheduler, 1);

        let (first, _) = scheduler.take_ready(now, 1);
        assert_eq!(first.into_iter().collect::<Vec<_>>(), vec![1]);
        assert!(scheduler.has_ready());

        let (second, _) = scheduler.take_ready(now, 1);
        assert_eq!(second.into_iter().collect::<Vec<_>>(), vec![2]);
        assert!(!scheduler.has_ready());

        crate::connection::EndpointDriverWakeup::wake_driver(&scheduler, 1);
        crate::connection::EndpointDriverWakeup::wake_driver(&scheduler, 1);
        let (deduplicated, _) = scheduler.take_ready(now, 2);
        assert_eq!(deduplicated.into_iter().collect::<Vec<_>>(), vec![1]);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn endpoint_driver_scheduler_ignores_stale_deadlines_and_bounds_heap_growth() {
        let scheduler = EndpointDriverScheduler::default();
        let now = web_time::Instant::now();
        scheduler.register(7);
        let _ = scheduler.take_ready(now, 1);
        let stale = now + Duration::from_millis(10);
        let current = now + Duration::from_millis(20);
        scheduler.schedule(7, Some(stale));
        scheduler.schedule(7, Some(current));

        let (early, next) = scheduler.take_ready(now + Duration::from_millis(11), 1);
        assert_eq!(early.into_iter().count(), 0);
        assert_eq!(next, Some(current));

        for offset in 21..1_000 {
            scheduler.schedule(7, Some(now + Duration::from_millis(offset)));
        }
        let heap_len = scheduler
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .deadline_heap
            .len();
        assert!(heap_len <= 68);

        let (due, _) = scheduler.take_ready(now + Duration::from_secs(1), 1);
        assert_eq!(due.into_iter().collect::<Vec<_>>(), vec![7]);
    }

    #[test]
    fn endpoint_close_starts_graceful_shutdown_for_established_connections() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap());
        let route_cid = quion_proto::cid::ConnectionId::from_slice(b"endpoint").unwrap();
        {
            let mut state = endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .register_connection(route_cid, connection.clone())
                .unwrap();
        }

        endpoint.close();

        assert!(endpoint.is_closed());
        assert!(connection.is_closed());
        assert!(!connection.runtime_shutdown_ready());
        let state = endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(state.connections.len(), 1);
    }

    #[test]
    fn endpoint_abort_discards_established_connections_immediately() {
        let endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap());
        let route_cid = quion_proto::cid::ConnectionId::from_slice(b"endpoint").unwrap();
        {
            let mut state = endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .register_connection(route_cid, connection.clone())
                .unwrap();
        }

        endpoint.abort();

        assert!(endpoint.is_closed());
        assert!(connection.is_closed());
        assert!(connection.runtime_shutdown_ready());
        let state = endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(state.connections.len(), 0);
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 0);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_connection_limit_preserves_existing_routes_and_rejects_new_ones() {
        let mut transport = crate::config::TransportConfig::default();
        transport.set_max_connections(1);
        let endpoint = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(endpoint.server_connection_limits.max_connections, 1);
        let existing_cid = quion_proto::cid::ConnectionId::from_slice(b"existing").unwrap();
        let new_cid = quion_proto::cid::ConnectionId::from_slice(b"new-peer").unwrap();
        let connection =
            Connection::server(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap());
        let mut state = endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .register_connection(existing_cid.clone(), connection)
            .unwrap();

        assert!(
            !state.server_connection_capacity_reached(
                endpoint.server_connection_limits,
                &existing_cid
            )
        );
        assert!(
            state.server_connection_capacity_reached(endpoint.server_connection_limits, &new_cid)
        );
        assert!(state.server_connection_capacity_reached(
            ServerConnectionLimits {
                max_connections: 0,
                max_pending_handshakes: 1024,
                max_established_connections: 1024,
                max_endpoint_memory_bytes: 512 * 1024 * 1024,
                max_endpoint_routed_datagram_bytes: 64 * 1024 * 1024,
                max_retry_replay_entries: 1 << 16,
                retry_enabled: true,
                max_runtime_driver_work_per_tick: DEFAULT_RUNTIME_DRIVER_WORK_PER_TICK,
            },
            &new_cid
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_connection_capacity_respects_separate_pending_and_established_limits() {
        let mut state = EndpointState::default();
        let existing_cid = quion_proto::cid::ConnectionId::from_slice(b"existing").unwrap();
        let new_cid = quion_proto::cid::ConnectionId::from_slice(b"new-peer").unwrap();
        let connection = Connection::server(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:4433".parse().unwrap(),
        );
        state
            .register_connection(existing_cid.clone(), connection)
            .unwrap();

        let pending_blocked = ServerConnectionLimits {
            max_connections: 1024,
            max_pending_handshakes: 0,
            max_established_connections: 1024,
            max_endpoint_memory_bytes: 512 * 1024 * 1024,
            max_endpoint_routed_datagram_bytes: 64 * 1024 * 1024,
            max_retry_replay_entries: 1 << 16,
            retry_enabled: true,
            max_runtime_driver_work_per_tick: DEFAULT_RUNTIME_DRIVER_WORK_PER_TICK,
        };
        assert!(state.server_connection_capacity_reached(pending_blocked, &new_cid));
        assert!(!state.server_connection_capacity_reached(pending_blocked, &existing_cid));

        let established_blocked = ServerConnectionLimits {
            max_connections: 1024,
            max_pending_handshakes: 1024,
            max_established_connections: 1,
            max_endpoint_memory_bytes: 512 * 1024 * 1024,
            max_endpoint_routed_datagram_bytes: 64 * 1024 * 1024,
            max_retry_replay_entries: 1 << 16,
            retry_enabled: true,
            max_runtime_driver_work_per_tick: DEFAULT_RUNTIME_DRIVER_WORK_PER_TICK,
        };
        assert!(state.server_connection_capacity_reached(established_blocked, &new_cid));
        assert!(!state.server_connection_capacity_reached(established_blocked, &existing_cid));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_connection_capacity_is_released_after_closed_connection_cleanup() {
        let mut state = EndpointState::default();
        let existing_cid = quion_proto::cid::ConnectionId::from_slice(b"existing").unwrap();
        let new_cid = quion_proto::cid::ConnectionId::from_slice(b"new-peer").unwrap();
        let connection = Connection::server(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:4433".parse().unwrap(),
        );
        state
            .register_connection(existing_cid, connection.clone())
            .unwrap();
        let limits = ServerConnectionLimits {
            max_connections: 1,
            max_pending_handshakes: 1024,
            max_established_connections: 1024,
            max_endpoint_memory_bytes: 512 * 1024 * 1024,
            max_endpoint_routed_datagram_bytes: 64 * 1024 * 1024,
            max_retry_replay_entries: 1 << 16,
            retry_enabled: true,
            max_runtime_driver_work_per_tick: DEFAULT_RUNTIME_DRIVER_WORK_PER_TICK,
        };

        assert!(state.server_connection_capacity_reached(limits, &new_cid));

        connection.abort();
        assert_eq!(state.remove_closed_connections(), 1);
        assert!(!state.server_connection_capacity_reached(limits, &new_cid));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn endpoint_routed_datagram_memory_budget_rejects_and_releases() {
        let mut transport = crate::config::TransportConfig::default();
        transport.set_max_endpoint_routed_datagram_bytes(4);
        transport.set_max_endpoint_memory_bytes(4);
        let endpoint = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let connection =
            Connection::server(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap());
        let meta = quion_udp::RecvMeta {
            local: Some(endpoint.local_addr()),
            remote: "127.0.0.1:4433".parse().unwrap(),
            interface: None,
            ecn: None,
            segment_size: None,
            len: 4,
        };

        assert!(endpoint.enqueue_connection_routed_datagram(&connection, meta.clone(), &[1; 4]));
        assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 4);
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 4);
        assert!(!endpoint.enqueue_connection_routed_datagram(&connection, meta.clone(), &[2]));
        assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 4);

        let datagram = connection.pop_routed_datagram().unwrap();
        assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 4);
        drop(datagram);
        assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 0);
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 0);
        let owned = vec![3; 4];
        let owned_pointer = owned.as_ptr();
        assert!(endpoint.enqueue_owned_connection_routed_datagram(&connection, meta, owned));
        let datagram = connection.pop_routed_datagram().unwrap();
        assert_eq!(datagram.contents.as_ptr(), owned_pointer);
        assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 4);
        drop(datagram);
        assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 0);
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn abort_releases_pooled_datagrams_and_prevents_late_recycling() {
        for drop_before_abort in [true, false] {
            let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let connection = Connection::new(endpoint.local_addr(), "127.0.0.1:9".parse().unwrap());
            let meta = quion_udp::RecvMeta {
                local: Some(endpoint.local_addr()),
                remote: connection.remote_address(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: 4,
            };
            assert!(endpoint.enqueue_connection_routed_datagram(&connection, meta, &[1; 4]));
            let mut packet = Some(bytes::Bytes::from_owner(PooledRoutedDatagram {
                datagram: connection.pop_routed_datagram(),
                pool: endpoint.routed_datagram_buffer_pool.clone(),
            }));
            if drop_before_abort {
                drop(packet.take());
            }
            endpoint.abort();
            drop(packet);
            assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 0);
            assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 0);
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn routed_datagram_buffer_pool_reuses_accounted_storage() {
        let mut transport = crate::config::TransportConfig::default();
        transport.set_max_endpoint_routed_datagram_bytes(16);
        transport.set_max_endpoint_memory_bytes(16);
        let endpoint = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let connection =
            Connection::server(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap());
        let meta = quion_udp::RecvMeta {
            local: Some(endpoint.local_addr()),
            remote: "127.0.0.1:4433".parse().unwrap(),
            interface: None,
            ecn: None,
            segment_size: None,
            len: 4,
        };

        assert!(endpoint.enqueue_connection_routed_datagram(&connection, meta.clone(), &[1; 4]));
        let datagram = connection.pop_routed_datagram().unwrap();
        let allocation = datagram.contents.as_ptr();
        let packet = bytes::Bytes::from_owner(PooledRoutedDatagram {
            datagram: Some(datagram),
            pool: endpoint.routed_datagram_buffer_pool.clone(),
        });
        let retained_payload = packet.slice(1..3);
        drop(packet);
        assert!(
            endpoint
                .routed_datagram_buffer_pool
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .buffers
                .is_empty()
        );
        drop(retained_payload);
        assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 4);
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 4);

        assert!(endpoint.enqueue_connection_routed_datagram(&connection, meta, &[2; 4]));
        let datagram = connection.pop_routed_datagram().unwrap();
        assert_eq!(datagram.contents.as_ptr(), allocation);
        assert_eq!(datagram.contents, [2; 4]);
        drop(datagram);
        assert_eq!(endpoint.routed_datagram_memory_budget.used_bytes(), 0);
        assert_eq!(endpoint.endpoint_memory_budget.used_bytes(), 0);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn current_client_driver_processes_its_short_packet_without_routing_copy() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let remote = "127.0.0.1:4433".parse().unwrap();
        let connection = Connection::new(endpoint.local_addr(), remote);
        let cid = quion_proto::cid::ConnectionId::from_slice(b"direct01").unwrap();
        {
            let mut state = endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .register_connection(cid.clone(), connection.clone())
                .unwrap();
        }
        let packet = quion_proto::packet::Header::Short(quion_proto::packet::ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: cid,
            packet_number_len: 1,
        })
        .encode();
        let meta = quion_udp::RecvMeta {
            local: Some(endpoint.local_addr()),
            remote,
            interface: None,
            ecn: None,
            segment_size: None,
            len: packet.len(),
        };

        assert!(
            !endpoint
                .route_client_socket_datagram(meta.clone(), &packet, None, Some(&connection),)
                .unwrap()
        );
        assert_eq!(connection.routed_datagram_len(), 0);

        assert!(
            endpoint
                .route_client_socket_datagram(meta, &packet, None, None)
                .unwrap()
        );
        assert_eq!(connection.routed_datagram_len(), 1);
    }

    #[test]
    fn endpoint_connect_returns_closed_error_after_close() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();

        endpoint.close();

        assert!(matches!(
            endpoint.connect("127.0.0.1:4433".parse().unwrap(), "localhost"),
            Err(ConnectionError::LocallyClosed)
        ));
    }

    #[test]
    fn endpoint_state_routes_original_active_and_migration_connection_ids() {
        let mut state = EndpointState::default();
        let connection = Connection::new(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:4433".parse().unwrap(),
        );
        let initial = quion_proto::cid::ConnectionId::from_slice(b"initial").unwrap();
        let original = quion_proto::cid::ConnectionId::from_slice(b"original").unwrap();
        let active = quion_proto::cid::ConnectionId::from_slice(b"active").unwrap();
        let migration = quion_proto::cid::ConnectionId::from_slice(b"migration").unwrap();
        let connection_id = state
            .register_connection(initial.clone(), connection.clone())
            .unwrap();
        assert!(
            state
                .register_connection_route(
                    original.clone(),
                    connection_id,
                    quion_proto::endpoint::ConnectionRouteKind::OriginalDestination,
                )
                .is_ok()
        );
        assert!(
            state
                .register_connection_route(
                    active.clone(),
                    connection_id,
                    quion_proto::endpoint::ConnectionRouteKind::Active,
                )
                .is_ok()
        );
        assert!(
            state
                .register_connection_route(
                    migration.clone(),
                    connection_id,
                    quion_proto::endpoint::ConnectionRouteKind::Migration,
                )
                .is_ok()
        );

        assert!(state.route_connection(&initial).is_some());
        assert!(state.route_connection(&original).is_some());
        assert!(state.route_connection(&active).is_some());
        assert!(state.route_connection(&migration).is_some());

        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        {
            let short = quion_proto::packet::Header::Short(quion_proto::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: active.clone(),
                packet_number_len: 1,
            })
            .encode();
            assert!(state.route_short_connection(&short).is_some());
        }

        assert!(!state.retire_connection_route(&original, connection_id));
        assert!(state.retire_connection_route(&initial, connection_id));
        assert!(state.retire_connection_route(&active, connection_id));
        assert!(state.route_connection(&initial).is_none());
        assert!(state.route_connection(&original).is_some());
        assert!(state.route_connection(&active).is_none());
        assert!(state.route_connection(&migration).is_some());
    }

    #[test]
    fn endpoint_budget_accounts_and_releases_connection_id_routes() {
        let budget = Arc::new(EndpointMemoryBudget::new(4096));
        {
            let mut state =
                EndpointState::new(quion_proto::endpoint::Endpoint::new(), budget.clone());
            let connection = Connection::new(
                "127.0.0.1:1234".parse().unwrap(),
                "127.0.0.1:4433".parse().unwrap(),
            );
            let cid = quion_proto::cid::ConnectionId::from_slice(b"routecid").unwrap();
            let connection_id = state.register_connection(cid.clone(), connection).unwrap();
            assert!(state.register_reset_token(cid.clone(), [0x44; 16]).is_ok());
            state
                .proto_endpoint
                .insert_route(cid.clone(), connection_id);

            assert_eq!(
                budget.used_bytes(),
                state.connection_id_route_memory_bytes()
            );
            assert!(budget.used_bytes() > 0);

            state.remove_connection(connection_id);
            assert_eq!(budget.used_bytes(), 0);
            assert_eq!(state.connection_id_route_memory_bytes(), 0);
        }
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn endpoint_budget_rejects_connection_id_route_growth_transactionally() {
        let budget = Arc::new(EndpointMemoryBudget::new(1));
        let mut state = EndpointState::new(quion_proto::endpoint::Endpoint::new(), budget.clone());
        let connection = Connection::new(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:4433".parse().unwrap(),
        );
        let cid = quion_proto::cid::ConnectionId::from_slice(b"routecid").unwrap();

        assert!(matches!(
            state.register_connection(cid.clone(), connection),
            Err(ConnectionError::EndpointMemoryLimitReached)
        ));
        assert!(state.connections.is_empty());
        assert!(state.routes.is_empty());
        assert_eq!(state.connection_id_route_memory_bytes(), 0);
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn connection_id_route_collision_preserves_existing_owner_and_token() {
        let mut state = EndpointState::default();
        let cid = quion_proto::cid::ConnectionId::from_slice(b"collision").unwrap();
        let first = Connection::new(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:4433".parse().unwrap(),
        );
        let second = Connection::new(
            "127.0.0.1:1235".parse().unwrap(),
            "127.0.0.1:4434".parse().unwrap(),
        );
        let first_id = state
            .register_connection(cid.clone(), first.clone())
            .unwrap();
        assert!(state.register_reset_token(cid.clone(), [0x11; 16]).is_ok());

        assert!(matches!(
            state.register_connection(cid.clone(), second),
            Err(ConnectionError::ConnectionIdCollision)
        ));
        assert_eq!(state.connections.len(), 1);
        assert_eq!(
            state
                .route_connection(&cid)
                .map(|route| route.remote_address()),
            Some(first.remote_address())
        );
        assert!(matches!(
            state.register_reset_token(cid.clone(), [0x22; 16]),
            Err(ConnectionError::ConnectionIdCollision)
        ));
        assert_eq!(state.reset_tokens.get(&cid), Some(&[0x11; 16]));
        assert_eq!(
            state.routes.get(&cid).map(|route| route.connection),
            Some(first_id)
        );
    }

    #[test]
    fn server_applies_tracked_endpoint_path_limit() {
        let mut transport = crate::config::TransportConfig::default();
        transport.set_max_tracked_endpoint_paths(1);
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let first = "127.0.0.1:1001".parse().unwrap();
        let second = "127.0.0.1:1002".parse().unwrap();
        let mut state = server
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        state.proto_endpoint.path(first).record_received(10);
        state.proto_endpoint.path(second).record_received(20);

        assert_eq!(state.proto_endpoint.tracked_paths(), 1);
        assert!(state.proto_endpoint.path_budget(first).is_none());
        assert!(state.proto_endpoint.path_budget(second).is_some());
        drop(state);
        let diagnostics = server.diagnostics();
        assert_eq!(diagnostics.tracked_paths, 1);
        assert_eq!(diagnostics.max_tracked_paths, 1);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn endpoint_state_matches_stateless_reset_token_for_unknown_short_packet() {
        let mut state = EndpointState::default();
        let cid = quion_proto::cid::ConnectionId::from_slice(b"resetcid").unwrap();
        let token = [0x5a; 16];
        assert!(state.register_reset_token(cid.clone(), token).is_ok());
        let packet = quion_proto::packet::Header::Short(quion_proto::packet::ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: cid,
            packet_number_len: 1,
        })
        .encode();

        assert_eq!(
            state.stateless_reset_token_for_short_packet(&packet),
            Some(token)
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn retiring_active_connection_id_invalidates_stateless_reset_token() {
        let mut state = EndpointState::default();
        let cid = quion_proto::cid::ConnectionId::from_slice(b"retired1").unwrap();
        let token = [0x6d; 16];
        assert!(
            state
                .register_connection_route(
                    cid.clone(),
                    0,
                    quion_proto::endpoint::ConnectionRouteKind::Active,
                )
                .is_ok()
        );
        assert!(state.register_reset_token(cid.clone(), token).is_ok());
        let packet = quion_proto::packet::Header::Short(quion_proto::packet::ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: cid.clone(),
            packet_number_len: 1,
        })
        .encode();
        assert_eq!(
            state.stateless_reset_token_for_short_packet(&packet),
            Some(token)
        );

        assert!(state.retire_active_connection_route(&cid));

        assert_eq!(state.stateless_reset_token_for_short_packet(&packet), None);
        assert!(!state.reset_cid_lengths.contains(&cid.len()));
    }

    #[test]
    fn encode_stateless_reset_appends_token_and_looks_like_short_header() {
        let token = [0xa5; 16];
        let packet = encode_stateless_reset(64, token).unwrap();

        assert!((21..=43).contains(&packet.len()));
        assert!(packet.len() < 64);
        assert_eq!(&packet[packet.len() - 16..], &token);
        assert_eq!(packet[0] & 0x80, 0);
        assert_eq!(packet[0] & 0x40, 0x40);
    }

    #[test]
    fn stateless_reset_is_not_generated_when_it_cannot_be_smaller() {
        assert_eq!(encode_stateless_reset(21, [0xa5; 16]), None);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn closed_endpoint_drops_new_initial_admission() {
        let server = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        server.close();
        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial_packet(Vec::new()),
                segment_size: None,
                send_at: None,
            })
            .unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        let progress = server
            .poll_server_udp_once(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut recv_buffer,
            )
            .unwrap();

        assert_eq!(progress.received_packets, 1);
        assert!(progress.dropped_packets >= 1);
        let mut incoming = Box::pin(server.accept());
        let waker = Arc::new(TestWaker {
            wake_count: Arc::new(AtomicUsize::new(0)),
        })
        .into();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(incoming.as_mut().poll(&mut cx), Poll::Ready(None)));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_udp_once_sends_stateless_reset_for_unknown_short_packet() {
        let server = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let cid = quion_proto::cid::ConnectionId::from_slice(b"resetcid").unwrap();
        let token = [0x6b; 16];
        {
            let mut state = server
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(state.register_reset_token(cid.clone(), token).is_ok());
        }
        let mut short = quion_proto::packet::Header::Short(quion_proto::packet::ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: cid,
            packet_number_len: 1,
        })
        .encode();
        short.resize(64, 0);
        let short_len = short.len();
        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: short,
                segment_size: None,
                send_at: None,
            })
            .unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        let progress = server
            .poll_server_udp_once(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut recv_buffer,
            )
            .unwrap();

        assert_eq!(progress.received_packets, 1);
        let meta = recv_retry(&client, &mut recv_buffer);
        let packet = &recv_buffer[..meta.len];
        assert!(packet.len() < short_len);
        assert_eq!(&packet[packet.len() - 16..], &token);
        assert_eq!(packet[0] & 0x80, 0);
        assert_eq!(packet[0] & 0x40, 0x40);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_routes_peer_stateless_reset_before_generating_a_response() {
        let server = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let route_cid = quion_proto::cid::ConnectionId::from_slice(b"routecid").unwrap();
        let connection = Connection::server(server.local_addr(), client.local_addr().unwrap());
        let peer_reset_token = [0x7c; 16];
        connection.set_test_peer_stateless_reset_token(peer_reset_token);
        let driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(
                quion_proto::cid::ConnectionId::from_slice(b"peercid1").unwrap(),
            ),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            route_cid.len(),
        )
        .routed_only();
        {
            let mut state = server
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .register_connection(route_cid, connection.clone())
                .unwrap();
            state.store_endpoint_one_rtt_driver(connection.clone(), driver);
        }
        let mut reset = vec![0x40; 32];
        let token_offset = reset.len() - peer_reset_token.len();
        reset[token_offset..].copy_from_slice(&peer_reset_token);
        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: reset,
                segment_size: None,
                send_at: None,
            })
            .unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        let progress = server
            .poll_server_udp_once(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut recv_buffer,
            )
            .unwrap();

        assert_eq!(progress.routed_existing_connections, 1);
        assert_eq!(progress.one_rtt_packets_received, 0);
        assert_eq!(server.stats().packets_received, 1);
        let progress = server
            .poll_server_udp_once(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut recv_buffer,
            )
            .unwrap();
        assert_eq!(progress.one_rtt_packets_received, 1);
        assert_eq!(server.stats().packets_received, 1);
        assert!(connection.is_closed());
        assert!(matches!(
            connection.open_uni().into_inner(),
            Err(ConnectionError::Reset)
        ));
        assert!(client.recv(&mut recv_buffer).unwrap().is_none());
    }

    #[test]
    fn server_initial_udp_once_sends_retry_then_enqueues_validated_incoming() {
        let server = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let initial = initial_packet(Vec::new());

        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial,
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let progress = poll_until_progress(&server, &mut recv_buffer);
        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.retry_packets_sent, 1);

        let retry_meta = recv_retry(&client, &mut recv_buffer);
        let retry_packet = &recv_buffer[..retry_meta.len];
        let original_dcid = quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap();
        let (retry_header, _) =
            quion_proto::packet::decode_retry_packet(retry_packet, &original_dcid).unwrap();
        assert_eq!(retry_header.ty, quion_proto::packet::PacketType::Retry);
        let retry_token = retry_header.token.clone();
        let retry_source_cid = retry_header.src_cid.clone();

        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial_packet_for_destination(
                    retry_source_cid.clone(),
                    retry_token.clone(),
                ),
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let progress = poll_until_progress(&server, &mut recv_buffer);
        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.incoming_connections, 1);
        let routed_cid = retry_source_cid.clone();
        assert!(server.route_connection(&routed_cid).is_some());

        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial_packet_for_destination(retry_source_cid, retry_token),
                segment_size: None,
                send_at: None,
            })
            .unwrap();
        let progress = poll_until_progress(&server, &mut recv_buffer);
        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.routed_existing_connections, 1);
        assert_eq!(progress.dropped_packets, 0);
        let routed = server.route_connection(&routed_cid).unwrap();
        assert_eq!(routed.routed_datagram_len(), 1);

        let mut accept = pin!(server.accept());
        let waker = Arc::new(TestWaker {
            wake_count: Arc::new(AtomicUsize::new(0)),
        })
        .into();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            accept.as_mut().poll(&mut cx),
            Poll::Ready(Some(_))
        ));
    }

    #[test]
    fn server_connection_limit_drops_validated_new_initial() {
        let mut transport = crate::config::TransportConfig::default();
        transport.set_max_connections(0);
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial_packet(Vec::new()),
                segment_size: None,
                send_at: None,
            })
            .unwrap();
        let _ = poll_until_progress(&server, &mut recv_buffer);
        let retry_meta = recv_retry(&client, &mut recv_buffer);
        let retry_packet = &recv_buffer[..retry_meta.len];
        let original_dcid = quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap();
        let (retry_header, _) =
            quion_proto::packet::decode_retry_packet(retry_packet, &original_dcid).unwrap();

        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial_packet_for_destination(retry_header.src_cid, retry_header.token),
                segment_size: None,
                send_at: None,
            })
            .unwrap();
        let progress = poll_until_progress(&server, &mut recv_buffer);

        assert_eq!(progress.incoming_connections, 0);
        assert_eq!(progress.dropped_packets, 1);
        assert_eq!(server.stats().rejected_connections, 1);
        assert_eq!(server.stats().dropped_packets, 1);
        assert!(server.route_connection(&original_dcid).is_none());
    }

    #[test]
    fn server_initial_udp_once_respects_anti_amplification_budget_for_retry() {
        let server = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: small_initial_packet(Vec::new()),
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let progress = poll_until_progress(&server, &mut recv_buffer);
        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.retry_packets_sent, 0);
        assert_eq!(progress.dropped_packets, 1);
        assert!(client.recv(&mut recv_buffer).unwrap().is_none());
    }

    #[test]
    fn server_initial_udp_once_sends_version_negotiation() {
        let captured = Arc::new(Mutex::new(Vec::<crate::QlogEvent>::new()));
        let mut transport = crate::config::TransportConfig::default();
        let sink = captured.clone();
        transport.set_qlog_handler(move |event| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.clone());
        });
        let server = Endpoint::server(
            ServerConfig::builder()
                .with_transport_config(transport)
                .build()
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial_packet_with_version(0x0a0a_0a0a, Vec::new()),
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let progress = poll_until_progress(&server, &mut recv_buffer);
        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.version_negotiation_packets_sent, 1);

        let meta = recv_retry(&client, &mut recv_buffer);
        let packet = &recv_buffer[..meta.len];
        let (header, consumed) = quion_proto::packet::Header::decode(packet, 0).unwrap();
        assert_eq!(consumed, packet.len());
        assert!(matches!(
            header,
            quion_proto::packet::Header::VersionNegotiation { .. }
        ));
        let events = captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(events.iter().any(|event| matches!(
            event,
            crate::QlogEvent::EndpointStateUpdated {
                state: "version_negotiation_sent",
                packet_type: "version_negotiation",
            }
        )));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn coalesced_server_datagram_counts_amplification_credit_once() {
        let server = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let peer = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let remote = peer.local_addr().unwrap();
        let mut datagram = initial_packet_with_version(0x0a0a_0a0a, Vec::new());
        datagram.extend(initial_packet_with_version(0x0a0a_0a0a, Vec::new()));
        datagram.extend_from_slice(&[0xc0, 0x00, 0x00]);
        let datagram_len = datagram.len();
        let meta = quion_udp::RecvMeta {
            local: Some(server.local_addr()),
            remote,
            interface: None,
            ecn: None,
            segment_size: None,
            len: datagram_len,
        };

        let progress = server
            .process_server_datagram(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                meta,
                &mut datagram,
            )
            .unwrap();

        assert_eq!(progress.version_negotiation_packets_sent, 2);
        assert_eq!(progress.dropped_packets, 1);
        let state = server
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            state
                .proto_endpoint
                .path_budget(remote)
                .map(|budget| budget.bytes_received),
            Some(datagram_len as u64)
        );
        assert!(
            !state
                .proto_endpoint
                .path_budget(remote)
                .is_some_and(|budget| budget.validated)
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_udp_once_classifies_datagrams_before_connection_handoff() {
        let server = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial_packet_with_version(0x0a0a_0a0a, Vec::new()),
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let progress = poll_until_server_udp_progress(
            &server,
            Arc::new(test_server_config()),
            &quion_proto::config::TransportConfig::default(),
            &mut recv_buffer,
        );
        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.version_negotiation_packets_sent, 1);

        let routed_cid = quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap();
        let routed = Connection::server(server.local_addr(), client.local_addr().unwrap());
        {
            let mut state = server
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let connection_id = state
                .register_connection(routed_cid.clone(), routed.clone())
                .unwrap();
            state
                .proto_endpoint
                .insert_route(routed_cid.clone(), connection_id);
        }
        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: initial_packet_with_version(0x0a0a_0a0a, Vec::new()),
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let progress = poll_until_server_udp_progress(
            &server,
            Arc::new(test_server_config()),
            &quion_proto::config::TransportConfig::default(),
            &mut recv_buffer,
        );
        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.routed_existing_connections, 1);
        assert_eq!(progress.version_negotiation_packets_sent, 0);
        assert_eq!(routed.routed_datagram_len(), 1);

        let retry = quion_proto::packet::encode_retry_packet(
            quion_proto::packet::QUIC_VERSION_1,
            quion_proto::cid::ConnectionId::from_slice(b"client-scid").unwrap(),
            quion_proto::cid::ConnectionId::from_slice(b"retry-scid").unwrap(),
            b"retry-token".to_vec(),
            &routed_cid,
        )
        .unwrap();
        client
            .send(&quion_udp::Transmit {
                destination: server.local_addr(),
                source: client.local_addr().ok(),
                ecn: None,
                contents: retry,
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let progress = poll_until_server_udp_progress(
            &server,
            Arc::new(test_server_config()),
            &quion_proto::config::TransportConfig::default(),
            &mut recv_buffer,
        );
        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.dropped_packets, 1);
        assert_eq!(server.stats().dropped_packets, 1);
    }

    #[test]
    fn high_level_validates_version_negotiation_packet() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let original_dst = b"server";
        let original_src = b"client";
        let packet = quion_proto::packet::Header::VersionNegotiation {
            dst_cid: quion_proto::cid::ConnectionId::from_slice(original_src).unwrap(),
            src_cid: quion_proto::cid::ConnectionId::from_slice(original_dst).unwrap(),
            versions: vec![quion_proto::packet::QUIC_VERSION_1],
        }
        .encode();

        let version = endpoint
            .validate_version_negotiation_packet(&packet, original_dst, original_src, 0x0a0a_0a0a)
            .unwrap();
        assert_eq!(version, quion_proto::packet::QUIC_VERSION_1);
    }

    #[test]
    fn high_level_rejects_version_negotiation_without_supported_version() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let original_dst = b"server";
        let original_src = b"client";
        let packet = quion_proto::packet::Header::VersionNegotiation {
            dst_cid: quion_proto::cid::ConnectionId::from_slice(original_src).unwrap(),
            src_cid: quion_proto::cid::ConnectionId::from_slice(original_dst).unwrap(),
            versions: vec![0x0a0a_0a0a],
        }
        .encode();

        assert_eq!(
            endpoint.validate_version_negotiation_packet(
                &packet,
                original_dst,
                original_src,
                quion_proto::packet::QUIC_VERSION_1,
            ),
            Err(ConnectionError::VersionMismatch)
        );
    }

    #[test]
    fn connecting_validates_version_negotiation_against_its_cids() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();
        connecting.set_attempted_version(0x0a0a_0a0a);
        let packet = quion_proto::packet::Header::VersionNegotiation {
            dst_cid: quion_proto::cid::ConnectionId::from_slice(connecting.original_source_cid())
                .unwrap(),
            src_cid: quion_proto::cid::ConnectionId::from_slice(
                connecting.original_destination_cid(),
            )
            .unwrap(),
            versions: vec![quion_proto::packet::QUIC_VERSION_1],
        }
        .encode();

        let version = connecting
            .validate_version_negotiation_packet(&packet)
            .unwrap();
        assert_eq!(version, quion_proto::packet::QUIC_VERSION_1);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn connect_udp_once_handles_version_negotiation() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let peer = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect(peer.local_addr().unwrap(), "localhost")
            .unwrap();
        connecting.set_attempted_version(0x0a0a_0a0a);
        let packet = quion_proto::packet::Header::VersionNegotiation {
            dst_cid: quion_proto::cid::ConnectionId::from_slice(connecting.original_source_cid())
                .unwrap(),
            src_cid: quion_proto::cid::ConnectionId::from_slice(
                connecting.original_destination_cid(),
            )
            .unwrap(),
            versions: vec![quion_proto::packet::QUIC_VERSION_1],
        }
        .encode();
        peer.send(&quion_udp::Transmit {
            destination: endpoint.local_addr(),
            source: peer.local_addr().ok(),
            ecn: None,
            contents: packet,
            segment_size: None,
            send_at: None,
        })
        .unwrap();

        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let progress = poll_until_connect_receive(&endpoint, &mut connecting, &mut recv_buffer);

        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.version_negotiation_packets_received, 1);
        assert_eq!(
            connecting.attempted_version(),
            quion_proto::packet::QUIC_VERSION_1
        );
        assert!(!connecting.initial_transmitted());
        let retransmit = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap();
        assert!(retransmit.is_some());
        assert!(connecting.initial_transmitted());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn connect_udp_once_handles_retry() {
        let captured = Arc::new(Mutex::new(Vec::<crate::QlogEvent>::new()));
        let mut transport = crate::config::TransportConfig::default();
        let sink = captured.clone();
        transport.set_qlog_handler(move |event| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.clone());
        });
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(
            crate::ClientConfig::builder()
                .with_transport_config(transport)
                .build(),
        );
        let peer = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect(peer.local_addr().unwrap(), "localhost")
            .unwrap();
        let retry_src = quion_proto::cid::ConnectionId::from_slice(b"retry-scid").unwrap();
        let retry = quion_proto::packet::encode_retry_packet(
            connecting.attempted_version(),
            quion_proto::cid::ConnectionId::from_slice(connecting.original_source_cid()).unwrap(),
            retry_src.clone(),
            b"retry-token".to_vec(),
            &quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap(),
        )
        .unwrap();
        peer.send(&quion_udp::Transmit {
            destination: endpoint.local_addr(),
            source: peer.local_addr().ok(),
            ecn: None,
            contents: retry,
            segment_size: None,
            send_at: None,
        })
        .unwrap();

        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let progress = poll_until_connect_receive(&endpoint, &mut connecting, &mut recv_buffer);

        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.retry_packets_received, 1);
        assert_eq!(connecting.original_destination_cid(), retry_src.as_bytes());
        assert_eq!(connecting.initial_token(), b"retry-token");
        let events = captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(events.iter().any(|event| matches!(
            event,
            crate::QlogEvent::EndpointStateUpdated {
                state: "connect_started",
                packet_type: "initial",
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            crate::QlogEvent::EndpointStateUpdated {
                state: "retry_received",
                packet_type: "retry",
            }
        )));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn connecting_builds_padded_initial_udp_transmit() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();
        connecting.set_initial_token(b"retry-token".to_vec());

        let transmit = connecting
            .poll_initial_udp_transmit(b"client hello")
            .unwrap()
            .unwrap();

        assert_eq!(transmit.destination, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(transmit.source, Some(endpoint.local_addr()));
        assert_eq!(transmit.ecn, None);
        assert!(transmit.contents.len() >= 1200);
        assert!(
            connecting
                .poll_initial_udp_transmit(b"client hello")
                .unwrap()
                .is_none()
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn connecting_starts_rustls_and_builds_initial_udp_transmit() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();

        let transmit = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap();

        assert_eq!(transmit.destination, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(transmit.source, Some(endpoint.local_addr()));
        assert!(transmit.contents.len() >= 1200);
        assert!(connecting.has_tls_session());
    }

    #[test]
    fn connecting_handles_retry_and_allows_initial_retransmit() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();
        let retry_src = quion_proto::cid::ConnectionId::from_slice(b"retry-scid").unwrap();
        let retry = quion_proto::packet::encode_retry_packet(
            connecting.attempted_version(),
            quion_proto::cid::ConnectionId::from_slice(connecting.original_source_cid()).unwrap(),
            retry_src.clone(),
            b"retry-token".to_vec(),
            &quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap(),
        )
        .unwrap();

        connecting.handle_retry_packet(&retry).unwrap();

        assert_eq!(connecting.original_destination_cid(), retry_src.as_bytes());
        assert_eq!(connecting.initial_token(), b"retry-token");
        assert!(!connecting.initial_transmitted());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn large_client_initial_is_fragmented_and_recovered_with_token_overhead() {
        use quion_proto::{
            crypto::{
                EncryptionLevel, Side,
                initial::{InitialKeys, InitialPacketProtector},
                packet::CryptoPacketOpener,
            },
            frame::Frame,
        };
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();
        let state = connecting.state.as_mut().unwrap();
        state.set_initial_token(vec![9; 512]);
        state.client_initial_crypto = vec![7; 5000];
        let keys =
            InitialKeys::derive(quion_proto::packet::QUIC_VERSION_1, &state.original_dst_cid)
                .unwrap();
        let receiver = InitialPacketProtector::new(&keys, Side::Server).unwrap();
        let input = state.client_initial_crypto.clone();
        let mut received = Vec::new();
        let mut count = 0;
        while let Some(mut packet) = state.poll_initial_udp_transmit(&input).unwrap() {
            assert_eq!(packet.contents.len(), 1200);
            state.record_initial_packet_sent(packet.contents.len());
            let opened =
                CryptoPacketOpener::open_initial(&receiver, &mut packet.contents, None).unwrap();
            for frame in opened.frames {
                if let Frame::Crypto { offset, data } = frame {
                    assert_eq!(offset.into_inner() as usize, received.len());
                    received.extend(data);
                }
            }
            count += 1;
            assert!(count <= 16);
        }
        assert!(count > 1);
        assert_eq!(received, input);
        assert_eq!(
            state
                .connection
                .with_proto(|proto| proto.memory_stats().sent_crypto_bytes),
            input.len()
        );
        let timeout = state.next_timeout().unwrap();
        let (_, retransmits) = state.poll_crypto_timeout(timeout).unwrap();
        assert!(!retransmits.is_empty());
        assert!(retransmits.iter().all(
            |packet| packet.level == EncryptionLevel::Initial && packet.contents.len() == 1200
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn retry_resets_client_initial_packet_number_space() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();
        connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            connecting
                .state
                .as_ref()
                .unwrap()
                .initial_builder
                .next_packet_number(quion_proto::crypto::EncryptionLevel::Initial),
            Some(1)
        );
        let retry_source = quion_proto::cid::ConnectionId::from_slice(b"retry-scid").unwrap();
        let retry = quion_proto::packet::encode_retry_packet(
            connecting.attempted_version(),
            quion_proto::cid::ConnectionId::from_slice(connecting.original_source_cid()).unwrap(),
            retry_source,
            b"retry-token".to_vec(),
            &quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap(),
        )
        .unwrap();

        connecting.handle_retry_packet(&retry).unwrap();

        assert_eq!(
            connecting
                .state
                .as_ref()
                .unwrap()
                .initial_builder
                .next_packet_number(quion_proto::crypto::EncryptionLevel::Initial),
            Some(0)
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn endpoint_sends_connect_initial_udp_once() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let peer = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = endpoint
            .connect(peer.local_addr().unwrap(), "localhost")
            .unwrap();
        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];

        let progress = endpoint
            .poll_connect_initial_udp_once(
                &mut connecting,
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap();

        assert_eq!(progress.initial_packets_sent, 1);
        let meta = recv_retry(&peer, &mut recv_buffer);
        assert!(meta.len >= 1200);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_opens_initial_and_feeds_rustls() {
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let mut packet = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap()
            .contents;

        let progress = server_endpoint
            .handle_server_initial_crypto_packet(
                Arc::new(test_server_config()),
                &quion_proto::config::TransportConfig::default(),
                &mut packet,
            )
            .unwrap();

        assert_eq!(progress.crypto_frames_received, 1);
        assert!(progress.response_crypto_frames > 0);
        assert_eq!(
            progress.response_packets_generated,
            progress.response_crypto_frames
        );
        assert!(progress.handshake_keys_installed);
        assert!(progress.tls_handshaking);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_silently_discards_unauthenticated_initial_packet() {
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let mut packet = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap()
            .contents;
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        let mut server_initial = ServerInitialConnection::new(
            Arc::new(test_server_config()),
            &quion_proto::config::TransportConfig::default(),
            ServerInitialQlog::new(None, crate::qlog::DEFAULT_MAX_BUFFERED_QLOG_EVENTS),
            &packet,
            None,
            client_endpoint.local_addr(),
            Some([0; 16]),
        )
        .unwrap();
        let (progress, response_packets) =
            server_initial.handle_initial_packet(&mut packet).unwrap();

        assert_eq!(progress.dropped_packets, 1);
        assert_eq!(progress.initial_packets_received, 0);
        assert_eq!(progress.crypto_frames_received, 0);
        assert_eq!(progress.response_packets_generated, 0);
        assert!(response_packets.is_empty());
        assert!(!server_initial.has_authenticated_packet());

        let mut endpoint_progress = EndpointServerProgress::default();
        server_endpoint.complete_server_connection_handoff(server_initial, &mut endpoint_progress);
        assert_eq!(server_endpoint.diagnostics().pending_server_handshakes, 0);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_sends_initial_close_for_authenticated_frame_error() {
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let first_packet = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap()
            .contents;
        let (header, _) = quion_proto::packet::Header::decode(&first_packet, 0).unwrap();
        let quion_proto::packet::Header::Long(header) = header else {
            panic!("expected Initial header");
        };
        let initial_keys =
            quion_proto::crypto::initial::InitialKeys::derive(header.version, &header.dst_cid)
                .unwrap();
        let client_initial = quion_proto::crypto::initial::InitialPacketProtector::new(
            &initial_keys,
            quion_proto::crypto::Side::Client,
        )
        .unwrap();
        let malformed_close = [0x1d, 0x2a, 0x04, b'b', b'a'];
        let mut malformed_packet = client_initial
            .protect_initial_packet(
                quion_proto::packet::LongHeader {
                    ty: quion_proto::packet::PacketType::Initial,
                    version: header.version,
                    dst_cid: header.dst_cid,
                    src_cid: header.src_cid,
                    token: header.token,
                    length: None,
                    packet_number_len: 2,
                },
                1,
                &malformed_close,
            )
            .unwrap();
        let mut server_initial = ServerInitialConnection::new(
            Arc::new(test_server_config()),
            &quion_proto::config::TransportConfig::default(),
            ServerInitialQlog::new(None, crate::qlog::DEFAULT_MAX_BUFFERED_QLOG_EVENTS),
            &first_packet,
            None,
            client_endpoint.local_addr(),
            Some([0; 16]),
        )
        .unwrap();

        let (progress, close_packets) = server_initial
            .handle_initial_packet(&mut malformed_packet)
            .unwrap();

        assert_eq!(
            progress.transport_error,
            Some(quion_proto::transport_error::TransportErrorCode::FrameEncodingError)
        );
        assert_eq!(progress.response_packets_generated, 1);
        assert!(server_initial.is_closed());
        assert_eq!(close_packets.len(), 1);
        let mut close_packet = close_packets[0].contents.clone();
        let opened = quion_proto::crypto::packet::CryptoPacketOpener::open_initial(
            &client_initial,
            &mut close_packet,
            None,
        )
        .unwrap();
        assert!(matches!(
            opened.frames.as_slice(),
            [
                quion_proto::frame::Frame::ConnectionClose {
                    error_code:
                        quion_proto::transport_error::TransportErrorCode::FrameEncodingError,
                    ..
                },
                ..
            ]
        ));

        let mut endpoint_progress = EndpointServerProgress::default();
        server_endpoint.complete_server_connection_handoff(server_initial, &mut endpoint_progress);
        assert_eq!(server_endpoint.diagnostics().pending_server_handshakes, 0);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn client_silently_discards_unauthenticated_initial_packet() {
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = client_endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();
        connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap();

        let original_dst_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap();
        let client_route_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_source_cid()).unwrap();
        let initial_keys = quion_proto::crypto::initial::InitialKeys::derive(
            quion_proto::packet::QUIC_VERSION_1,
            &original_dst_cid,
        )
        .unwrap();
        let server_initial = quion_proto::crypto::initial::InitialPacketProtector::new(
            &initial_keys,
            quion_proto::crypto::Side::Server,
        )
        .unwrap();
        let mut builder = quion_proto::crypto::packet::CryptoPacketBuilder::new(
            client_route_cid,
            original_dst_cid,
        );
        let frames = [quion_proto::crypto::stream::CryptoFrame {
            level: quion_proto::crypto::EncryptionLevel::Initial,
            offset: 0,
            bytes: b"server hello".to_vec(),
        }];
        let mut packet = builder.build_initial(&server_initial, &frames).unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        let progress = connecting
            .handle_initial_crypto_packet(&mut packet)
            .unwrap();

        assert_eq!(progress.dropped_packets, 1);
        assert_eq!(progress.initial_packets_received, 0);
        assert_eq!(progress.crypto_frames_received, 0);
        assert_eq!(progress.response_packets_generated, 0);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn client_sends_initial_close_for_authenticated_frame_error() {
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut connecting = client_endpoint
            .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
            .unwrap();
        connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap();

        let original_dst_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap();
        let client_route_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_source_cid()).unwrap();
        let initial_keys = quion_proto::crypto::initial::InitialKeys::derive(
            quion_proto::packet::QUIC_VERSION_1,
            &original_dst_cid,
        )
        .unwrap();
        let server_initial = quion_proto::crypto::initial::InitialPacketProtector::new(
            &initial_keys,
            quion_proto::crypto::Side::Server,
        )
        .unwrap();
        let malformed_close = [0x1d, 0x2a, 0x04, b'b', b'a'];
        let mut malformed_packet = server_initial
            .protect_initial_packet(
                quion_proto::packet::LongHeader {
                    ty: quion_proto::packet::PacketType::Initial,
                    version: quion_proto::packet::QUIC_VERSION_1,
                    dst_cid: client_route_cid,
                    src_cid: original_dst_cid,
                    token: Vec::new(),
                    length: None,
                    packet_number_len: 2,
                },
                0,
                &malformed_close,
            )
            .unwrap();

        let (progress, close_packets) = connecting
            .handle_initial_crypto_packet_inner(&mut malformed_packet)
            .unwrap();

        assert_eq!(
            progress.transport_error,
            Some(quion_proto::transport_error::TransportErrorCode::FrameEncodingError)
        );
        assert_eq!(progress.response_packets_generated, 1);
        assert_eq!(close_packets.len(), 1);
        let mut close_packet = close_packets[0].contents.clone();
        let opened = quion_proto::crypto::packet::CryptoPacketOpener::open_initial(
            &server_initial,
            &mut close_packet,
            None,
        )
        .unwrap();
        assert!(matches!(
            opened.frames.as_slice(),
            [
                quion_proto::frame::Frame::ConnectionClose {
                    error_code:
                        quion_proto::transport_error::TransportErrorCode::FrameEncodingError,
                    ..
                },
                ..
            ]
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_initial_crypto_udp_once_sends_response_packets() {
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap();
        client_endpoint.socket.send(&client_initial).unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());

        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let progress = poll_until_server_crypto_progress(
            &server_endpoint,
            Arc::new(test_server_config()),
            &quion_proto::config::TransportConfig::default(),
            &mut recv_buffer,
        );

        assert_eq!(progress.initial_packets_received, 1);
        assert_eq!(progress.crypto_frames_received, 1);
        assert!(progress.response_packets_sent > 0);
        let route_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap();
        let recovery_timeout = {
            let state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .server_initial
                .get(&route_cid)
                .and_then(ServerInitialConnection::next_timeout)
        };
        assert!(recovery_timeout.is_some());
        let (timeout_progress, retransmit_packets) = {
            let mut state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state
                .server_initial
                .get_mut(&route_cid)
                .unwrap()
                .poll_crypto_timeout(recovery_timeout.unwrap())
                .unwrap()
        };
        assert_eq!(timeout_progress.timeouts_processed, 1);
        assert!(!retransmit_packets.is_empty());

        let meta = recv_retry(&client_endpoint.socket, &mut recv_buffer);
        let response_packet = &mut recv_buffer[..meta.len];
        let (header, _) = quion_proto::packet::Header::decode(response_packet, 0).unwrap();
        assert!(matches!(
            header,
            quion_proto::packet::Header::Long(quion_proto::packet::LongHeader {
                ty: quion_proto::packet::PacketType::Initial,
                ..
            })
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_crypto_flight_preserves_packets_blocked_by_amplification_budget() {
        let server = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let peer = quion_udp::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let remote = peer.local_addr().unwrap();
        let packet = CryptoFlightPacket {
            level: quion_proto::crypto::EncryptionLevel::Initial,
            packet_number: 0,
            frames: Vec::new(),
            contents: vec![0x40],
        };

        let blocked = server
            .send_server_crypto_flight_packets(remote, vec![packet.clone()])
            .unwrap();

        assert!(blocked.sent.is_empty());
        assert_eq!(blocked.unsent.len(), 1);

        {
            let mut state = server
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.proto_endpoint.path(remote).record_received(1);
        }

        let sent = server
            .send_server_crypto_flight_packets(remote, blocked.unsent)
            .unwrap();

        assert_eq!(sent.sent.len(), 1);
        assert!(sent.unsent.is_empty());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_initial_crypto_udp_once_retains_exchange_state() {
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap();
        client_endpoint.socket.send(&client_initial).unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());

        let mut recv_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let progress = poll_until_server_crypto_progress(
            &server_endpoint,
            Arc::new(test_server_config()),
            &quion_proto::config::TransportConfig::default(),
            &mut recv_buffer,
        );

        assert_eq!(progress.initial_packets_received, 1);
        let state = server_endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(state.server_initial.len(), 1);
        let routed_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap();
        assert!(state.server_initial.contains_key(&routed_cid));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn client_opens_server_initial_response_and_feeds_rustls() {
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(test_client_config()),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap();
        client_endpoint.socket.send(&client_initial).unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());

        let mut server_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let server_progress = poll_until_server_crypto_progress(
            &server_endpoint,
            Arc::new(test_server_config()),
            &quion_proto::config::TransportConfig::default(),
            &mut server_buffer,
        );
        assert!(server_progress.response_packets_sent > 0);

        let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let client_progress = poll_until_client_initial_response(
            &client_endpoint,
            &mut connecting,
            &mut client_buffer,
        );

        assert_eq!(client_progress.initial_packets_received, 1);
        assert!(client_progress.crypto_frames_received > 0);
        assert!(client_progress.handshake_keys_installed);
        assert!(client_progress.tls_handshaking);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn connect_udp_once_opens_server_handshake_packet() {
        let (client_config, server_config) = test_client_server_configs();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(client_config),
                "localhost",
                &quion_proto::config::TransportConfig::default(),
            )
            .unwrap()
            .unwrap();
        client_endpoint.socket.send(&client_initial).unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());

        let mut server_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let server_progress = poll_until_server_crypto_progress(
            &server_endpoint,
            Arc::new(server_config),
            &quion_proto::config::TransportConfig::default(),
            &mut server_buffer,
        );
        assert!(server_progress.handshake_packets_generated > 0);
        assert!(server_progress.response_packets_sent > 1);
        let route_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap();
        assert!(
            server_endpoint
                .state
                .lock()
                .unwrap()
                .server_initial
                .get(&route_cid)
                .is_some_and(ServerInitialConnection::initial_state_discarded)
        );

        let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let mut saw_initial = false;
        let mut saw_handshake = false;
        for _ in 0..50 {
            let progress = client_endpoint
                .poll_connect_udp_once(&mut connecting, &mut client_buffer)
                .unwrap();
            saw_initial |= progress.initial_crypto.initial_packets_received > 0;
            saw_handshake |= progress.initial_crypto.handshake_packets_received > 0;
            if saw_initial && saw_handshake {
                assert!(progress.initial_crypto.crypto_frames_received > 0);
                assert!(progress.response_packets_sent > 0);
                assert!(
                    connecting
                        .state
                        .as_ref()
                        .is_some_and(|client| client.initial_state_discarded())
                );
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert!(saw_initial);
        assert!(saw_handshake);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn server_crypto_udp_once_opens_client_handshake_packet() {
        let (client_config, server_config) = test_client_server_configs();
        let server_config = Arc::new(server_config);
        let transport_config = quion_proto::config::TransportConfig::default();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(client_config),
                "localhost",
                &transport_config,
            )
            .unwrap()
            .unwrap();
        client_endpoint.socket.send(&client_initial).unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());

        let mut server_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let server_progress = poll_until_server_crypto_progress(
            &server_endpoint,
            server_config.clone(),
            &transport_config,
            &mut server_buffer,
        );
        assert!(server_progress.handshake_packets_generated > 0);

        let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        for _ in 0..50 {
            let progress = client_endpoint
                .poll_connect_udp_once(&mut connecting, &mut client_buffer)
                .unwrap();
            if progress.initial_crypto.handshake_packets_received > 0 {
                assert!(progress.response_packets_sent > 0);
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        let mut saw_client_handshake = false;
        for _ in 0..50 {
            let progress = server_endpoint
                .poll_server_initial_crypto_udp_once(
                    server_config.clone(),
                    &transport_config,
                    &mut server_buffer,
                )
                .unwrap();
            if progress.handshake_packets_received > 0 {
                assert!(progress.crypto_frames_received > 0);
                saw_client_handshake = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert!(saw_client_handshake);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn connect_udp_once_processes_coalesced_server_crypto_packets() {
        let (client_config, server_config) = test_client_server_configs();
        let server_config = Arc::new(server_config);
        let transport_config = quion_proto::config::TransportConfig::default();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(client_config),
                "localhost",
                &transport_config,
            )
            .unwrap()
            .unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());
        let mut client_initial = client_initial.contents;

        let (_server_progress, response_packets) = server_endpoint
            .handle_server_initial_crypto_packet_inner(
                server_config,
                &transport_config,
                &mut client_initial,
            )
            .unwrap();
        assert!(response_packets.len() >= 2);

        let mut coalesced = response_packets[0].contents.clone();
        coalesced.extend_from_slice(&response_packets[1].contents);
        server_endpoint
            .socket
            .send(&quion_udp::Transmit {
                destination: client_endpoint.local_addr(),
                source: Some(server_endpoint.local_addr()),
                ecn: Some(quion_udp::EcnCodepoint::Ect0),
                contents: coalesced,
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let mut progress = EndpointConnectReceiveProgress::default();
        for _ in 0..50 {
            progress = client_endpoint
                .poll_connect_udp_once(&mut connecting, &mut client_buffer)
                .unwrap();
            if progress.received_packets > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.initial_crypto.initial_packets_received, 1);
        assert_eq!(progress.initial_crypto.handshake_packets_received, 1);
        assert_eq!(progress.dropped_packets, 0);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn connect_udp_once_keeps_valid_coalesced_prefix_when_tail_is_malformed() {
        let (client_config, server_config) = test_client_server_configs();
        let server_config = Arc::new(server_config);
        let transport_config = quion_proto::config::TransportConfig::default();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(client_config),
                "localhost",
                &transport_config,
            )
            .unwrap()
            .unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());
        let mut client_initial = client_initial.contents;

        let (_server_progress, response_packets) = server_endpoint
            .handle_server_initial_crypto_packet_inner(
                server_config,
                &transport_config,
                &mut client_initial,
            )
            .unwrap();
        assert!(!response_packets.is_empty());

        let mut coalesced = response_packets[0].contents.clone();
        coalesced.extend_from_slice(&[0xc0, 0x00, 0x00, 0x00]);
        server_endpoint
            .socket
            .send(&quion_udp::Transmit {
                destination: client_endpoint.local_addr(),
                source: Some(server_endpoint.local_addr()),
                ecn: Some(quion_udp::EcnCodepoint::Ect0),
                contents: coalesced,
                segment_size: None,
                send_at: None,
            })
            .unwrap();

        let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let mut progress = EndpointConnectReceiveProgress::default();
        for _ in 0..50 {
            progress = client_endpoint
                .poll_connect_udp_once(&mut connecting, &mut client_buffer)
                .unwrap();
            if progress.received_packets > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.initial_crypto.initial_packets_received, 1);
        assert!(progress.dropped_packets >= 1);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn unconfirmed_client_crypto(
        transport_config: quion_proto::config::TransportConfig,
    ) -> (Endpoint, Endpoint, Connecting) {
        let (client_config, server_config) = test_client_server_configs();
        let server_config = Arc::new(server_config);
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(client_config),
                "localhost",
                &transport_config,
            )
            .unwrap()
            .unwrap();
        client_endpoint.socket.send(&client_initial).unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());

        let mut server_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        for _ in 0..100 {
            let _ = server_endpoint
                .poll_server_initial_crypto_udp_once(
                    server_config.clone(),
                    &transport_config,
                    &mut server_buffer,
                )
                .unwrap();
            let _ = client_endpoint
                .poll_connect_udp_once(&mut connecting, &mut client_buffer)
                .unwrap();
            if connecting.is_handshake_complete()
                && connecting.has_one_rtt_keys()
                && connecting.peer_transport_parameters().is_some()
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(connecting.is_handshake_complete());
        assert!(connecting.has_one_rtt_keys());
        assert!(connecting.peer_transport_parameters().is_some());
        assert!(
            !connecting
                .state
                .as_ref()
                .unwrap()
                .connection
                .with_proto(|proto| proto.is_handshake_confirmed())
        );
        (client_endpoint, server_endpoint, connecting)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn authenticated_one_rtt_violation_before_confirmation_builds_encrypted_close() {
        let (client_endpoint, server_endpoint, mut connecting) =
            unconfirmed_client_crypto(quion_proto::config::TransportConfig::default());
        let route_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap();
        let mut invalid_packet = {
            let mut state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let server = state.server_initial.get_mut(&route_cid).unwrap();
            let next_packet_number = server
                .builder
                .next_packet_number(quion_proto::crypto::EncryptionLevel::OneRtt)
                .unwrap();
            quion_proto::crypto::packet::FramePacketBuilder::with_next_one_rtt_packet_number(
                server.peer_initial_source_cid.clone(),
                next_packet_number,
            )
            .build_one_rtt(
                &server.keys,
                &[quion_proto::frame::Frame::Stream {
                    // A server cannot send on a client-initiated unidirectional stream.
                    stream_id: quion_proto::VarInt::from_u32(2),
                    offset: quion_proto::VarInt::ZERO,
                    fin: false,
                    data: b"invalid".to_vec().into(),
                }],
            )
            .unwrap()
        };
        let client = connecting.state.as_mut().unwrap();
        let (progress, mut responses) = client
            .handle_one_rtt_packet(
                &mut invalid_packet,
                &quion_udp::RecvMeta {
                    local: Some(client_endpoint.local_addr()),
                    remote: server_endpoint.local_addr(),
                    interface: None,
                    ecn: None,
                    segment_size: None,
                    len: 0,
                },
            )
            .unwrap();

        assert_eq!(
            progress.transport_error,
            Some(quion_proto::transport_error::TransportErrorCode::StreamStateError)
        );
        assert_eq!(progress.one_rtt_packets_generated, 1);
        assert_eq!(responses.len(), 1);
        assert!(!client.is_established_for_handoff());

        let response = &mut responses[0].contents;
        let opened = {
            let mut state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let server = state.server_initial.get_mut(&route_cid).unwrap();
            quion_proto::crypto::packet::FramePacketOpener::open_one_rtt(
                &mut server.keys,
                response,
                server.local_connection_id.len(),
                None,
            )
            .unwrap()
        };
        assert!(matches!(
            opened.frames.first(),
            Some(quion_proto::frame::Frame::ConnectionClose {
                error_code: quion_proto::transport_error::TransportErrorCode::StreamStateError,
                ..
            })
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn unauthenticated_short_packet_before_confirmation_is_silently_discarded() {
        let (client_endpoint, server_endpoint, mut connecting) =
            unconfirmed_client_crypto(quion_proto::config::TransportConfig::default());
        let client = connecting.state.as_mut().unwrap();
        let mut truncated = [0x40];

        let (progress, responses) = client
            .handle_one_rtt_packet(
                &mut truncated,
                &quion_udp::RecvMeta {
                    local: Some(client_endpoint.local_addr()),
                    remote: server_endpoint.local_addr(),
                    interface: None,
                    ecn: None,
                    segment_size: None,
                    len: 1,
                },
            )
            .unwrap();

        assert_eq!(progress.dropped_packets, 1);
        assert_eq!(progress.transport_error, None);
        assert!(responses.is_empty());
        assert!(!client.connection.with_proto(|proto| proto.is_closed()));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn crypto_udp_progression_reaches_handshake_completion() {
        let (client_config, server_config) = test_client_server_configs();
        let server_config = Arc::new(server_config);
        let transport_config = quion_proto::config::TransportConfig::default();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(client_config),
                "localhost",
                &transport_config,
            )
            .unwrap()
            .unwrap();
        client_endpoint.socket.send(&client_initial).unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());

        let mut server_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let mut client_completed = false;
        let mut server_completed = false;
        for _ in 0..100 {
            let _ = server_endpoint
                .poll_server_initial_crypto_udp_once(
                    server_config.clone(),
                    &transport_config,
                    &mut server_buffer,
                )
                .unwrap();
            let _ = client_endpoint
                .poll_connect_udp_once(&mut connecting, &mut client_buffer)
                .unwrap();

            client_completed = connecting.is_handshake_complete()
                && connecting.has_one_rtt_keys()
                && connecting.peer_transport_parameters().is_some();
            server_completed = {
                let state = server_endpoint
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state
                    .server_initial
                    .get(
                        &quion_proto::cid::ConnectionId::from_slice(
                            connecting.original_destination_cid(),
                        )
                        .unwrap(),
                    )
                    .is_some_and(|connection| {
                        connection.is_handshake_complete()
                            && connection.has_one_rtt_keys()
                            && connection.peer_transport_parameters().is_some()
                    })
            };
            if client_completed && server_completed {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        assert!(client_completed);
        assert!(server_completed);
        {
            let state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(
                state
                    .proto_endpoint
                    .path_budget(client_endpoint.local_addr())
                    .is_some_and(|budget| budget.validated)
            );
        }
        let route_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap();
        let client_state = connecting.state.as_mut().unwrap();
        assert_eq!(client_state.largest_initial_received(), Some(0));
        assert!(client_state.largest_handshake_received().is_some());
        assert!(
            !client_state
                .connection
                .with_proto(|proto| proto.is_handshake_confirmed())
        );
        assert!(
            client_state
                .tls_keys
                .get(quion_proto::crypto::EncryptionLevel::Handshake)
                .is_some()
        );
        let recovery_timeout = client_state
            .connection
            .with_proto(|proto| proto.timeout())
            .unwrap();
        let (timeout_progress, retransmission) =
            client_state.poll_crypto_timeout(recovery_timeout).unwrap();
        assert_eq!(timeout_progress.timeouts_processed, 1);
        assert!(timeout_progress.handshake_packets_generated > 0);
        assert!(retransmission.iter().any(|packet| {
            packet.level == quion_proto::crypto::EncryptionLevel::Handshake
                && !packet.frames.is_empty()
        }));
        let server_largest = {
            let state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let connection = state.server_initial.get(&route_cid).unwrap();
            (
                connection.largest_initial_received(),
                connection.largest_handshake_received(),
            )
        };
        assert_eq!(server_largest.0, Some(0));
        assert!(server_largest.1.is_some());
        let mut handshake_done = {
            let mut state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let server = state.server_initial.get_mut(&route_cid).unwrap();
            let next_packet_number = server
                .builder
                .next_packet_number(quion_proto::crypto::EncryptionLevel::OneRtt)
                .unwrap();
            quion_proto::crypto::packet::FramePacketBuilder::with_next_one_rtt_packet_number(
                server.peer_initial_source_cid.clone(),
                next_packet_number,
            )
            .build_one_rtt(&server.keys, &[quion_proto::frame::Frame::HandshakeDone])
            .unwrap()
        };
        client_state
            .handle_one_rtt_packet(
                &mut handshake_done,
                &quion_udp::RecvMeta {
                    local: Some(client_endpoint.local_addr()),
                    remote: server_endpoint.local_addr(),
                    interface: None,
                    ecn: None,
                    segment_size: None,
                    len: 0,
                },
            )
            .unwrap();
        assert!(client_state.is_established_for_handoff());
        let connection = client_state.connection.clone();
        let driver = client_state.take_protected_one_rtt_driver().unwrap();
        assert!(connection.is_established());
        assert!(
            driver
                .keys
                .get(quion_proto::crypto::EncryptionLevel::Handshake)
                .is_none()
        );
        assert!(connection.peer_transport_parameters().is_some());
        let negotiated = connection.negotiated_transport().unwrap();
        assert_eq!(
            negotiated.initial_max_data,
            Some(transport_config.initial_max_data)
        );
        assert_eq!(
            negotiated.initial_max_streams_bidi,
            Some(transport_config.initial_max_streams_bidi)
        );
        assert_eq!(
            negotiated.max_idle_timeout,
            Some(transport_config.max_idle_timeout_ms)
        );
        assert_eq!(negotiated.max_ack_delay, quion_proto::VarInt::from_u32(25));
        assert_eq!(
            negotiated.min_ack_delay,
            Some(quion_proto::VarInt::from_u32(1_000))
        );
        assert!(connection.send_datagram(b"not-negotiated").is_err());

        let mut accept = pin!(server_endpoint.accept());
        let waker = Arc::new(TestWaker {
            wake_count: Arc::new(AtomicUsize::new(0)),
        })
        .into();
        let mut cx = Context::from_waker(&waker);
        let incoming = match accept.as_mut().poll(&mut cx) {
            Poll::Ready(Some(incoming)) => incoming,
            other => panic!("expected established incoming connection, got {other:?}"),
        };
        let mut incoming = pin!(incoming);
        let accepted = match incoming.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(connection)) => connection,
            other => panic!("expected accepted connection, got {other:?}"),
        };
        assert!(accepted.is_established());
        assert!(accepted.negotiated_transport().is_some());
    }

    /// Drive a full loopback handshake and return the established client
    /// connection together with its protected 1-RTT driver. The server endpoint
    /// is returned so callers keep its socket bound for the duration of a test.
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn established_client_driver() -> (
        Endpoint,
        Endpoint,
        Connection,
        ProtectedOneRttUdpDriver,
        Vec<u8>,
    ) {
        let (client_config, server_config) = test_client_server_configs();
        let server_config = Arc::new(server_config);
        let transport_config = quion_proto::config::TransportConfig {
            max_datagram_frame_size: Some(quion_proto::VarInt::from_u32(1200)),
            ..quion_proto::config::TransportConfig::default()
        };
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_endpoint = Endpoint::server(
            ServerConfig::builder().build().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut connecting = client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap();
        let client_initial = connecting
            .start_rustls_client_initial_udp_transmit(
                Arc::new(client_config),
                "localhost",
                &transport_config,
            )
            .unwrap()
            .unwrap();
        client_endpoint.socket.send(&client_initial).unwrap();
        connecting.record_initial_packet_sent(client_initial.contents.len());

        let mut server_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        let mut client_buffer = vec![0; MAX_UDP_RECV_BUFFER_SIZE];
        for _ in 0..100 {
            let _ = server_endpoint
                .poll_server_initial_crypto_udp_once(
                    server_config.clone(),
                    &transport_config,
                    &mut server_buffer,
                )
                .unwrap();
            let _ = client_endpoint
                .poll_connect_udp_once(&mut connecting, &mut client_buffer)
                .unwrap();
            if connecting.is_handshake_complete()
                && connecting.has_one_rtt_keys()
                && connecting.peer_transport_parameters().is_some()
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        let route_cid =
            quion_proto::cid::ConnectionId::from_slice(connecting.original_destination_cid())
                .unwrap();
        let mut handshake_done = {
            let mut state = server_endpoint
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let server = state.server_initial.get_mut(&route_cid).unwrap();
            let next_packet_number = server
                .builder
                .next_packet_number(quion_proto::crypto::EncryptionLevel::OneRtt)
                .unwrap();
            quion_proto::crypto::packet::FramePacketBuilder::with_next_one_rtt_packet_number(
                server.peer_initial_source_cid.clone(),
                next_packet_number,
            )
            .build_one_rtt(&server.keys, &[quion_proto::frame::Frame::HandshakeDone])
            .unwrap()
        };
        let client_state = connecting.state.as_mut().unwrap();
        client_state
            .handle_one_rtt_packet(
                &mut handshake_done,
                &quion_udp::RecvMeta {
                    local: Some(client_endpoint.local_addr()),
                    remote: server_endpoint.local_addr(),
                    interface: None,
                    ecn: None,
                    segment_size: None,
                    len: 0,
                },
            )
            .unwrap();
        assert!(client_state.is_established_for_handoff());
        let connection = client_state.connection.clone();
        let driver = client_state.take_protected_one_rtt_driver().unwrap();
        (
            client_endpoint,
            server_endpoint,
            connection,
            driver,
            client_buffer,
        )
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn endpoint_driver_resumes_queued_datagrams_after_work_budget_is_exhausted() {
        let (endpoint, _peer, connection, driver, mut buffer) = established_client_driver();
        connection.send_datagram(b"first").unwrap();
        connection.send_datagram(b"second").unwrap();
        let mut drivers = BTreeMap::new();
        drivers.insert(
            0,
            EndpointOwnedOneRttDriver {
                id: 0,
                connection,
                driver,
            },
        );

        // The first poll can send an MTU probe before the queued datagrams.
        // Each subsequent poll must remain ready without another application wakeup.
        for _ in 0..8 {
            let (progress, retained) =
                endpoint.poll_taken_endpoint_one_rtt_drivers(drivers, &mut buffer, 1);
            drivers = retained;
            assert_eq!(progress.sent_packets, 1);
            if drivers[&0].connection.diagnostics().send_datagrams_queued == 0 {
                break;
            }
            assert!(endpoint.endpoint_driver_scheduler.has_ready());
        }
        assert_eq!(
            drivers[&0].connection.diagnostics().send_datagrams_queued,
            0
        );
        assert!(!endpoint.endpoint_driver_scheduler.has_ready());
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn endpoint_driver_waits_when_datagram_exceeds_remaining_congestion_window() {
        let (endpoint, _peer, connection, driver, mut buffer) = established_client_driver();
        let stats = connection.stats();
        connection.record_test_sent_packet(
            quion_proto::crypto::EncryptionLevel::OneRtt,
            driver.builder.next_one_rtt_packet_number(),
            stats.congestion_window - stats.bytes_in_flight - 100,
            true,
            web_time::Instant::now(),
        );
        connection.send_datagram(vec![0; 1_000]).unwrap();
        assert!(connection.runtime_has_immediate_work());
        let mut drivers = BTreeMap::new();
        drivers.insert(
            0,
            EndpointOwnedOneRttDriver {
                id: 0,
                connection,
                driver,
            },
        );

        let (progress, drivers) =
            endpoint.poll_taken_endpoint_one_rtt_drivers(drivers, &mut buffer, 32);

        assert_eq!(progress.sent_packets, 0);
        assert_eq!(
            drivers[&0].connection.diagnostics().send_datagrams_queued,
            1
        );
        assert!(!endpoint.endpoint_driver_scheduler.has_ready());
        assert!(
            progress
                .next_timeout
                .is_some_and(|at| at > web_time::Instant::now())
        );
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn endpoint_driver_waits_for_paced_transmit_with_more_datagrams_queued() {
        let (endpoint, peer, connection, mut driver, mut buffer) = established_client_driver();
        connection.send_datagram(b"queued").unwrap();
        let send_at = web_time::Instant::now() + Duration::from_secs(10);
        driver.pending_transmits.push_back(PendingOneRttTransmit {
            transmit: quion_udp::Transmit {
                destination: peer.local_addr(),
                source: None,
                ecn: None,
                contents: vec![0; 100],
                segment_size: None,
                send_at: Some(send_at),
            },
            contains_ack: false,
            #[cfg(all(feature = "gso", any(target_os = "linux", test)))]
            packet_count: 1,
        });
        let mut drivers = BTreeMap::new();
        drivers.insert(
            0,
            EndpointOwnedOneRttDriver {
                id: 0,
                connection,
                driver,
            },
        );

        let (progress, drivers) =
            endpoint.poll_taken_endpoint_one_rtt_drivers(drivers, &mut buffer, 32);

        assert_eq!(progress.sent_packets, 0);
        assert_eq!(progress.next_send_at, Some(send_at));
        assert_eq!(drivers[&0].driver.pending_transmits.len(), 1);
        assert!(!endpoint.endpoint_driver_scheduler.has_ready());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_one_rtt_driver_initiates_key_update_before_packet_limit() {
        let (client_endpoint, _server_endpoint, connection, mut driver, mut client_buffer) =
            established_client_driver();
        driver.set_key_update_packet_threshold(1);

        connection.send_datagram(b"first").unwrap();
        let mut first_progress = EndpointDriverProgress::default();
        for _ in 0..50 {
            let progress = client_endpoint
                .poll_protected_one_rtt_udp_once(&connection, &mut driver, &mut client_buffer)
                .unwrap();
            first_progress.key_updates_initiated += progress.key_updates_initiated;
            first_progress.sent_packets += progress.sent_packets;
            if first_progress.sent_packets > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(first_progress.sent_packets, 1);
        assert_eq!(first_progress.key_updates_initiated, 0);
        assert_eq!(driver.one_rtt_packets_sent_with_current_key(), 1);
        assert_eq!(driver.keys.current_one_rtt_key_phase(), Some(false));

        connection.send_datagram(b"second").unwrap();
        let mut second_progress = EndpointDriverProgress::default();
        for _ in 0..50 {
            let progress = client_endpoint
                .poll_protected_one_rtt_udp_once(&connection, &mut driver, &mut client_buffer)
                .unwrap();
            second_progress.key_updates_initiated += progress.key_updates_initiated;
            second_progress.sent_packets += progress.sent_packets;
            if second_progress.sent_packets > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(second_progress.sent_packets, 1);
        assert_eq!(second_progress.key_updates_initiated, 1);
        assert_eq!(driver.one_rtt_packets_sent_with_current_key(), 1);
        assert_eq!(driver.keys.current_one_rtt_key_phase(), Some(true));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_transmit_batch_stops_at_key_update_boundary() {
        let dst = quion_proto::cid::ConnectionId::from_slice(b"driver").unwrap();
        let mut driver = ProtectedOneRttUdpDriver::new(
            quion_proto::crypto::packet::FramePacketBuilder::new(dst),
            quion_proto::crypto::rustls::RustlsKeyStore::default(),
            6,
        );
        driver.set_key_update_packet_threshold(5);
        driver.one_rtt_packets_sent_with_current_key = 3;

        assert_eq!(driver.protected_transmit_batch_limit(32), 2);

        driver.note_key_phase_started(7);
        assert_eq!(driver.protected_transmit_batch_limit(32), 32);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn key_phase_ack_confirmation_does_not_retire_old_read_key_early() {
        let (_client_endpoint, _server_endpoint, _connection, mut driver, _client_buffer) =
            established_client_driver();
        assert!(driver.keys.initiate_one_rtt_key_update().unwrap());
        driver.note_key_phase_started(7);
        assert!(driver.keys.has_previous_one_rtt_key());

        assert!(!driver.confirm_key_phase_if_acked(None));
        assert!(!driver.confirm_key_phase_if_acked(Some(6)));
        assert!(driver.keys.has_previous_one_rtt_key());

        assert!(driver.confirm_key_phase_if_acked(Some(7)));
        assert!(driver.keys.has_previous_one_rtt_key());

        let now = web_time::Instant::now();
        driver.previous_key_discard_at = Some(now + Duration::from_millis(10));
        assert!(!driver.retire_previous_key_if_due(now));
        assert!(driver.retire_previous_key_if_due(now + Duration::from_millis(10)));
        assert!(!driver.keys.has_previous_one_rtt_key());
        assert!(!driver.retire_previous_key_if_due(now + Duration::from_millis(11)));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn subsequent_local_key_update_waits_for_current_phase_ack() {
        let (_client_endpoint, _server_endpoint, _connection, mut driver, _client_buffer) =
            established_client_driver();
        driver.set_key_update_packet_threshold(1);
        driver.record_one_rtt_packet_sent(false);
        assert!(driver.initiate_key_update_if_needed().unwrap());
        driver.note_key_phase_started(7);

        driver.record_one_rtt_packet_sent(false);
        assert!(!driver.initiate_key_update_if_needed().unwrap());
        assert_eq!(driver.keys.current_one_rtt_key_phase(), Some(true));

        assert!(driver.confirm_key_phase_if_acked(Some(7)));
        assert!(driver.initiate_key_update_if_needed().unwrap());
        assert_eq!(driver.keys.current_one_rtt_key_phase(), Some(false));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn confidentiality_limit_stops_further_packet_protection() {
        let (_client_endpoint, _server_endpoint, _connection, mut driver, _client_buffer) =
            established_client_driver();
        let limit = driver.keys.one_rtt_confidentiality_limit().unwrap();
        driver.one_rtt_packets_sent_with_current_key = limit;

        assert!(matches!(
            driver.ensure_can_protect_next_packet(),
            Err(ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::AeadLimitReached
            ))
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn peer_key_update_before_local_send_maps_to_key_update_error() {
        let (_client_endpoint, _server_endpoint, _connection, mut driver, _client_buffer) =
            established_client_driver();
        assert_eq!(driver.keys.current_one_rtt_key_phase(), Some(false));

        // A key-phase change observed while we have sent nothing in the prior
        // phase is a too-fast peer key update (RFC 9001 §6.1).
        let error = driver
            .validate_and_reset_after_peer_key_update(Some(true), 0)
            .unwrap_err();
        assert!(matches!(
            error,
            ConnectionError::TransportError(
                quion_proto::transport_error::TransportErrorCode::KeyUpdateError
            )
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn peer_key_update_after_local_send_resets_phase_counter() {
        let (_client_endpoint, _server_endpoint, _connection, mut driver, _client_buffer) =
            established_client_driver();
        driver.record_one_rtt_packet_sent(false);
        driver.record_one_rtt_packet_sent(false);
        assert_eq!(driver.one_rtt_packets_sent_with_current_key(), 2);

        // No phase change: not a peer update, never an error, counter preserved.
        assert!(
            !driver
                .validate_and_reset_after_peer_key_update(Some(false), 0)
                .unwrap()
        );
        assert_eq!(driver.one_rtt_packets_sent_with_current_key(), 2);

        // Legitimate peer update after local sending resets the phase counter.
        assert!(
            driver
                .validate_and_reset_after_peer_key_update(Some(true), 2)
                .unwrap()
        );
        assert_eq!(driver.one_rtt_packets_sent_with_current_key(), 0);
        assert!(driver.peer_update_ack_pending);

        driver.record_one_rtt_packet_sent(false);
        assert!(driver.peer_update_ack_pending);
        driver.record_one_rtt_packet_sent(true);
        assert!(!driver.peer_update_ack_pending);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn test_client_config() -> rustls::ClientConfig {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let provider = crate::config::default_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn test_server_config() -> rustls::ServerConfig {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let provider = crate::config::default_crypto_provider();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
        );
        rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .unwrap()
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn test_client_server_configs() -> (rustls::ClientConfig, rustls::ServerConfig) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let provider = crate::config::default_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
        );
        let server = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .unwrap();
        (client, server)
    }

    struct TestWaker {
        wake_count: Arc<AtomicUsize>,
    }

    impl Wake for TestWaker {
        fn wake(self: Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn initial_packet(token: Vec<u8>) -> Vec<u8> {
        let mut packet = initial_packet_with_version(quion_proto::packet::QUIC_VERSION_1, token);
        packet.resize(1200, 0);
        packet
    }

    fn test_initial_header(token: Vec<u8>) -> quion_proto::packet::LongHeader {
        quion_proto::packet::LongHeader {
            ty: quion_proto::packet::PacketType::Initial,
            version: quion_proto::packet::QUIC_VERSION_1,
            dst_cid: quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap(),
            src_cid: quion_proto::cid::ConnectionId::from_slice(b"client-scid").unwrap(),
            token,
            length: Some(quion_proto::VarInt::from_u32(1200)),
            packet_number_len: 2,
        }
    }

    fn small_initial_packet(token: Vec<u8>) -> Vec<u8> {
        initial_packet_with_version(quion_proto::packet::QUIC_VERSION_1, token)
    }

    fn initial_packet_with_version(version: u32, token: Vec<u8>) -> Vec<u8> {
        initial_packet_for_destination_with_version(
            version,
            quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap(),
            token,
        )
    }

    fn initial_packet_for_destination(
        destination: quion_proto::cid::ConnectionId,
        token: Vec<u8>,
    ) -> Vec<u8> {
        initial_packet_for_destination_with_version(
            quion_proto::packet::QUIC_VERSION_1,
            destination,
            token,
        )
    }

    fn initial_packet_for_destination_with_version(
        version: u32,
        destination: quion_proto::cid::ConnectionId,
        token: Vec<u8>,
    ) -> Vec<u8> {
        quion_proto::packet::Header::Long(quion_proto::packet::LongHeader {
            ty: quion_proto::packet::PacketType::Initial,
            version,
            dst_cid: destination,
            src_cid: quion_proto::cid::ConnectionId::from_slice(b"client-scid").unwrap(),
            token,
            length: Some(quion_proto::VarInt::from_u32(0)),
            packet_number_len: 2,
        })
        .encode()
    }

    fn poll_until_progress(endpoint: &Endpoint, recv_buffer: &mut [u8]) -> EndpointAcceptProgress {
        for _ in 0..50 {
            let progress = endpoint.poll_server_initial_udp_once(recv_buffer).unwrap();
            if progress.received_packets > 0 {
                return progress;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("endpoint did not receive packet");
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_until_connect_receive(
        endpoint: &Endpoint,
        connecting: &mut Connecting,
        recv_buffer: &mut [u8],
    ) -> EndpointConnectReceiveProgress {
        for _ in 0..50 {
            let progress = endpoint
                .poll_connect_udp_once(connecting, recv_buffer)
                .unwrap();
            if progress.received_packets > 0 {
                return progress;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("endpoint did not receive connect packet");
    }

    fn recv_retry(socket: &quion_udp::UdpSocket, recv_buffer: &mut [u8]) -> quion_udp::RecvMeta {
        for _ in 0..50 {
            if let Some(meta) = socket.recv(recv_buffer).unwrap() {
                return meta;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("client did not receive retry packet");
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_until_server_crypto_progress(
        endpoint: &Endpoint,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        recv_buffer: &mut [u8],
    ) -> ServerInitialCryptoProgress {
        for _ in 0..50 {
            let progress = endpoint
                .poll_server_initial_crypto_udp_once(config.clone(), transport_config, recv_buffer)
                .unwrap();
            if progress.initial_packets_received > 0 {
                return progress;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("server did not receive initial crypto packet");
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_until_server_udp_progress(
        endpoint: &Endpoint,
        config: Arc<rustls::ServerConfig>,
        transport_config: &quion_proto::config::TransportConfig,
        recv_buffer: &mut [u8],
    ) -> EndpointServerProgress {
        for _ in 0..50 {
            let progress = endpoint
                .poll_server_udp_once(config.clone(), transport_config, recv_buffer)
                .unwrap();
            if progress.received_packets > 0 {
                return progress;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("server did not receive packet");
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_until_client_initial_response(
        endpoint: &Endpoint,
        connecting: &mut Connecting,
        recv_buffer: &mut [u8],
    ) -> ClientInitialCryptoProgress {
        for _ in 0..50 {
            let progress = endpoint
                .poll_connect_initial_response_udp_once(connecting, recv_buffer)
                .unwrap();
            if progress.initial_packets_received > 0 {
                return progress;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("client did not receive initial response packet");
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn runtime_client_retry_publishes_qlog_event() {
        let captured = Arc::new(Mutex::new(Vec::<crate::QlogEvent>::new()));
        let mut transport = crate::config::TransportConfig::default();
        let sink = Arc::clone(&captured);
        transport.set_qlog_handler(move |event| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.clone());
        });
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(
            crate::ClientConfig::builder()
                .with_transport_config(transport)
                .build(),
        );
        let route_cid = quion_proto::cid::ConnectionId::from_slice(b"client-scid").unwrap();
        let original_dst_cid = quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap();
        let client_crypto = ClientCryptoConnection::new(
            Connection::new(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap()),
            endpoint.local_addr(),
            "127.0.0.1:4433".parse().unwrap(),
            original_dst_cid.clone(),
            route_cid.clone(),
            quion_proto::packet::QUIC_VERSION_1,
            None,
        );
        endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .client_crypto
            .insert(route_cid.clone(), client_crypto);
        let retry_src = quion_proto::cid::ConnectionId::from_slice(b"retry-scid").unwrap();
        let mut retry = quion_proto::packet::encode_retry_packet(
            quion_proto::packet::QUIC_VERSION_1,
            route_cid.clone(),
            retry_src,
            b"retry-token".to_vec(),
            &original_dst_cid,
        )
        .unwrap();
        let meta = quion_udp::RecvMeta {
            local: Some(endpoint.local_addr()),
            remote: "127.0.0.1:4433".parse().unwrap(),
            interface: None,
            ecn: None,
            segment_size: None,
            len: retry.len(),
        };

        let progress = endpoint
            .handle_client_crypto_packet(&route_cid, &mut retry, &meta)
            .unwrap();

        assert_eq!(progress.retry_packets_received, 1);
        let events = captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(events.iter().any(|event| matches!(
            event,
            crate::QlogEvent::EndpointStateUpdated {
                state: "retry_received",
                packet_type: "retry",
            }
        )));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn runtime_client_version_negotiation_publishes_qlog_event() {
        let captured = Arc::new(Mutex::new(Vec::<crate::QlogEvent>::new()));
        let mut transport = crate::config::TransportConfig::default();
        let sink = Arc::clone(&captured);
        transport.set_qlog_handler(move |event| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.clone());
        });
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(
            crate::ClientConfig::builder()
                .with_transport_config(transport)
                .build(),
        );
        let route_cid = quion_proto::cid::ConnectionId::from_slice(b"client-scid").unwrap();
        let original_dst_cid = quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap();
        let client_crypto = ClientCryptoConnection::new(
            Connection::new(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap()),
            endpoint.local_addr(),
            "127.0.0.1:4433".parse().unwrap(),
            original_dst_cid.clone(),
            route_cid.clone(),
            quion_proto::packet::VERSION_NEGOTIATION_PROBE,
            None,
        );
        endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .client_crypto
            .insert(route_cid.clone(), client_crypto);
        let mut packet = quion_proto::packet::Header::VersionNegotiation {
            dst_cid: route_cid.clone(),
            src_cid: original_dst_cid,
            versions: vec![quion_proto::packet::QUIC_VERSION_1],
        }
        .encode();
        let meta = quion_udp::RecvMeta {
            local: Some(endpoint.local_addr()),
            remote: "127.0.0.1:4433".parse().unwrap(),
            interface: None,
            ecn: None,
            segment_size: None,
            len: packet.len(),
        };

        let progress = endpoint
            .handle_client_crypto_packet(&route_cid, &mut packet, &meta)
            .unwrap();

        assert_eq!(progress.version_negotiation_packets_received, 1);
        let events = captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(events.iter().any(|event| matches!(
            event,
            crate::QlogEvent::EndpointStateUpdated {
                state: "version_negotiation_received",
                packet_type: "version_negotiation",
            }
        )));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn queued_short_connect_packet_decodes_with_route_cid_length() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let route_cid = quion_proto::cid::ConnectionId::from_slice(b"client-scid").unwrap();
        let mut client_crypto = ClientCryptoConnection::new(
            Connection::new(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap()),
            endpoint.local_addr(),
            "127.0.0.1:4433".parse().unwrap(),
            quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap(),
            route_cid.clone(),
            quion_proto::packet::QUIC_VERSION_1,
            None,
        );
        let short = quion_proto::packet::Header::Short(quion_proto::packet::ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: route_cid.clone(),
            packet_number_len: 1,
        })
        .encode();
        client_crypto.enqueue_routed_datagram(
            quion_udp::RecvMeta {
                local: Some(endpoint.local_addr()),
                remote: "127.0.0.1:4433".parse().unwrap(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: short.len(),
            },
            short,
        );
        endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .client_crypto
            .insert(route_cid.clone(), client_crypto);

        let progress = endpoint
            .poll_client_crypto_queued_once(&route_cid)
            .unwrap()
            .unwrap();

        assert_eq!(progress.received_packets, 1);
        assert_eq!(progress.dropped_packets, 1);
    }

    #[test]
    fn client_crypto_handoff_preserves_routed_datagrams() {
        let mut client_crypto = ClientCryptoConnection::new(
            Connection::new(
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:4433".parse().unwrap(),
            ),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:4433".parse().unwrap(),
            quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap(),
            quion_proto::cid::ConnectionId::from_slice(b"client-scid").unwrap(),
            quion_proto::packet::QUIC_VERSION_1,
            None,
        );
        client_crypto.enqueue_routed_datagram(
            quion_udp::RecvMeta {
                local: Some("127.0.0.1:0".parse().unwrap()),
                remote: "127.0.0.1:4433".parse().unwrap(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: 4,
            },
            b"ping".to_vec(),
        );

        let connection = client_crypto.into_connection();
        let datagram = connection.pop_routed_datagram().unwrap();

        assert_eq!(datagram.contents, b"ping");
    }

    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test]
    async fn connect_runtime_wait_observes_already_queued_datagram() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let route_cid = quion_proto::cid::ConnectionId::from_slice(b"client-scid").unwrap();
        let mut client_crypto = ClientCryptoConnection::new(
            Connection::new(endpoint.local_addr(), "127.0.0.1:4433".parse().unwrap()),
            endpoint.local_addr(),
            "127.0.0.1:4433".parse().unwrap(),
            quion_proto::cid::ConnectionId::from_slice(b"client-dcid").unwrap(),
            route_cid.clone(),
            quion_proto::packet::QUIC_VERSION_1,
            None,
        );
        client_crypto.enqueue_routed_datagram(
            quion_udp::RecvMeta {
                local: Some(endpoint.local_addr()),
                remote: "127.0.0.1:4433".parse().unwrap(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: 4,
            },
            b"ping".to_vec(),
        );
        endpoint
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .client_crypto
            .insert(route_cid.clone(), client_crypto);

        tokio::time::timeout(
            Duration::from_millis(50),
            endpoint.wait_for_connect_runtime_activity(
                &route_cid,
                None,
                Some(web_time::Instant::now() + Duration::from_secs(1)),
            ),
        )
        .await
        .expect("queued datagram must prevent the connect driver from sleeping");
    }
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[tokio::test]
    async fn native_idle_wait_has_no_periodic_polling_and_observes_queued_packets() {
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let socket = endpoint.runtime_udp_socket().unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                endpoint.wait_for_server_runtime_activity(Some(&socket), None)
            )
            .await
            .is_err()
        );
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"queued", endpoint.local_addr()).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            endpoint.wait_for_server_runtime_activity(Some(&socket), None),
        )
        .await
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_default_receive_buffer_absorbs_a_scheduled_datagram_burst() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let endpoint = Endpoint::client(address.parse().unwrap()).unwrap();
            let sender = std::net::UdpSocket::bind(address).unwrap();
            // A ready task can enqueue a congestion window before the receive
            // task runs. Preserve the burst across that scheduling interval.
            for sequence in 0..128u8 {
                sender
                    .send_to(&[sequence; 1200], endpoint.local_addr())
                    .unwrap();
            }
            let mut buffer = [0; 1500];
            let mut received = 0;
            while let Some(meta) = endpoint.socket.recv(&mut buffer).unwrap() {
                assert_eq!(meta.len, 1200);
                assert_eq!(&buffer[..meta.len], &[received as u8; 1200]);
                received += 1;
            }
            assert_eq!(
                received, 128,
                "a scheduling pause must not overflow the default receive buffer"
            );
        }
    }
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn dropped_handoff_cancels_only_connections_not_transferred_to_the_application() {
        for (preserve, deliver) in [(false, false), (true, false), (false, true)] {
            let connection = Connection::new(
                "127.0.0.1:3000".parse().unwrap(),
                "127.0.0.1:4000".parse().unwrap(),
            );
            let completion = ConnectCompletion {
                connection: connection.clone(),
                preserve: Arc::new(AtomicBool::new(preserve)),
                delivered: false,
            };
            if deliver {
                drop(completion.into_connection());
            } else {
                drop(completion);
            }
            assert_eq!(connection.is_closed(), !preserve && !deliver);
        }
        let transport = quion_proto::config::TransportConfig {
            max_idle_timeout_ms: quion_proto::VarInt::ZERO,
            ..Default::default()
        };
        assert!(connect_deadline(&transport).is_some());
    }
}
