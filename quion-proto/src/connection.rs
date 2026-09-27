use std::collections::{BTreeMap, BTreeSet, VecDeque};

use smallvec::SmallVec;
use tracing::{debug, trace, trace_span};
use web_time::{Duration, Instant};

use crate::{
    cid::ConnectionId,
    config::AckFrequencyConfig,
    congestion::CongestionController,
    crypto::{
        CryptoData, CryptoSession, EncryptionLevel,
        stream::{CryptoFrame, CryptoStreams},
    },
    ecn::EcnCodepoint,
    error::Result,
    frame::Frame,
    mtud::{MtuDiscovery, MtuDiscoveryConfig},
    qlog::{QlogEvent, encryption_level_name, frame_type_name, varint_inner},
    ranges::RangeSet,
    recovery::{
        ack::{AckTracker, GeneratedAck},
        loss::{LossDetector, LossEvent, SentPacket, TimeoutOutcome},
    },
    stats::ConnectionStats,
    streams::{
        Chunk, SendBuffer, SendFlowController, StreamId, StreamInitiator, StreamLimitKind,
        StreamMap,
    },
    timer::Deadline,
    transport_error::TransportErrorCode,
    varint::VarInt,
};

const MAX_QUEUED_DATAGRAMS: usize = 1024;
const MAX_QUEUED_DATAGRAM_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_BUFFERED_QLOG_EVENTS: usize = 4096;
const DEFAULT_MAX_ACK_DELAY: Duration = Duration::from_millis(25);
const DEFAULT_ACK_DELAY_EXPONENT: u8 = crate::recovery::ack::DEFAULT_ACK_DELAY_EXPONENT;
const MAX_REQUESTED_ACK_DELAY: Duration = Duration::from_micros(16_383_999);
const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PATH_VALIDATION_ATTEMPTS: u8 = 3;
const MAX_STREAM_COUNT: u64 = 1 << 60;
const MAX_RECYCLED_STREAM_PAYLOADS: usize = 64;
const STREAM_PACKET_OVERHEAD_BUDGET: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ApplicationClose,
    CryptoFrame {
        level: EncryptionLevel,
        offset: u64,
        data: Vec<u8>,
    },
    Datagram(bytes::Bytes),
    Stream {
        stream_id: StreamId,
        offset: u64,
        fin: bool,
        data: bytes::Bytes,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    Connected,
    Closed,
    CryptoDataReceived(CryptoData),
    CryptoFrameQueued(CryptoFrame),
    DatagramReceived {
        len: usize,
    },
    FrameReceived(Frame),
    PacketLost {
        level: EncryptionLevel,
        packet_number: u64,
    },
    ProbeRequired {
        level: EncryptionLevel,
        packets: usize,
    },
    PathValidated,
    PathValidationFailed,
    RetireConnectionIdReceived {
        sequence: VarInt,
        packet_destination_cid: ConnectionId,
    },
    StreamFrameQueued {
        stream_id: StreamId,
        offset: u64,
        len: usize,
        fin: bool,
    },
    StreamStopped {
        stream_id: StreamId,
        error_code: VarInt,
    },
    StreamFinished {
        stream_id: StreamId,
    },
    StreamReset {
        stream_id: StreamId,
        error_code: VarInt,
        final_size: VarInt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointEvent {
    ConnectionClosed,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Effects {
    pub endpoint_events: Vec<EndpointEvent>,
    pub connection_events: SmallVec<[ConnectionEvent; 1]>,
    pub crypto_frames: Vec<CryptoFrame>,
    pub ack_frames: SmallVec<[GeneratedAck; 1]>,
    pub qlog_events: Vec<QlogEvent>,
    pub wakeups: SmallVec<[Deadline; 4]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvMeta {
    pub ecn: Option<EcnCodepoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneRttReceiveContext {
    pub largest_received: Option<u64>,
    pub key_update_permitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    pub contents: Vec<u8>,
    pub ecn: Option<EcnCodepoint>,
    pub segment_size: Option<usize>,
    pub send_at: Option<Instant>,
    pub contains_ack: bool,
    pub path_probe: bool,
    pub path_response: Option<[u8; 8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSchedulerConfig {
    pub max_frame_data: usize,
}

impl Default for StreamSchedulerConfig {
    fn default() -> Self {
        Self {
            max_frame_data: 1200,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SendStreamState {
    buffer: SendBuffer,
    flow: SendFlowController,
    priority: u16,
    queued: bool,
    blocked_at: Option<u64>,
    stopped_error: Option<VarInt>,
    reliable_reset: Option<(VarInt, u64, u64)>,
    fin_acked: bool,
}

impl SendStreamState {
    fn new(max_stream_data: u64) -> Self {
        Self {
            buffer: SendBuffer::default(),
            flow: SendFlowController::new(max_stream_data),
            priority: 128,
            queued: false,
            blocked_at: None,
            stopped_error: None,
            reliable_reset: None,
            fin_acked: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathValidation {
    challenge: [u8; 8],
    deadline: Instant,
    attempts: u8,
}

#[derive(Debug)]
struct QlogBuffer {
    events: VecDeque<QlogEvent>,
    max_events: usize,
}

impl QlogBuffer {
    fn with_max_events(max_events: usize) -> Self {
        Self {
            events: VecDeque::new(),
            max_events,
        }
    }

    fn set_max_events(&mut self, max_events: usize) {
        self.max_events = max_events;
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
    }

    fn push(&mut self, event: QlogEvent) {
        if self.max_events == 0 {
            return;
        }
        if self.events.len() >= self.max_events {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn drain(&mut self) -> Vec<QlogEvent> {
        self.events.drain(..).collect()
    }

    fn len(&self) -> usize {
        self.events.len()
    }
}

impl Default for QlogBuffer {
    fn default() -> Self {
        Self::with_max_events(DEFAULT_MAX_BUFFERED_QLOG_EVENTS)
    }
}

#[derive(Debug)]
pub struct Connection {
    crypto: CryptoStreams,
    ack: AckTracker,
    recovery: LossDetector,
    congestion: CongestionController,
    mtud: MtuDiscovery,
    initial_mtu: u16,
    next_one_rtt_packet_number: u64,
    largest_acked: BTreeMap<EncryptionLevel, u64>,
    sent_crypto: BTreeMap<(EncryptionLevel, u64), Vec<CryptoFrame>>,
    sent_control: BTreeMap<(EncryptionLevel, u64), Frame>,
    sent_stream: BTreeMap<(EncryptionLevel, u64), Frame>,
    sent_stream_bytes: usize,
    recycled_stream_payloads: Vec<Vec<u8>>,
    send_streams: BTreeMap<StreamId, SendStreamState>,
    closed_send_streams: [RangeSet; 4],
    max_stream_metadata_entries: usize,
    send_flow: SendFlowController,
    recv_flow: crate::streams::RecvFlowController,
    data_blocked_at: Option<u64>,
    pending_send_streams: BTreeSet<StreamId>,
    recv_streams: StreamMap,
    stream_schedule: VecDeque<StreamId>,
    send_retransmit_streams: VecDeque<Frame>,
    send_acks: VecDeque<GeneratedAck>,
    send_control: VecDeque<Frame>,
    send_datagrams: VecDeque<bytes::Bytes>,
    send_datagrams_bytes: usize,
    recv_datagrams: VecDeque<bytes::Bytes>,
    recv_datagrams_bytes: usize,
    max_queued_datagrams: usize,
    max_receive_datagram_frame_size: u64,
    idle_send_time: Option<Instant>,
    last_ack_eliciting_sent: Option<Instant>,
    max_queued_datagram_bytes: usize,
    max_queued_control_frames: usize,
    one_rtt_ack_delay_start: Option<Instant>,
    one_rtt_ack_deadline: Option<Instant>,
    one_rtt_ack_eliciting_since_last_ack: u64,
    local_max_ack_delay: Duration,
    local_ack_delay_exponent: u8,
    local_min_ack_delay: Option<Duration>,
    ack_eliciting_threshold: u64,
    reordering_threshold: u64,
    largest_ack_frequency_sequence: Option<u64>,
    immediate_ack_requested: bool,
    ack_frequency_config: Option<AckFrequencyConfig>,
    next_ack_frequency_sequence: u64,
    peer_min_ack_delay: Option<Duration>,
    peer_max_ack_delay: Duration,
    peer_ack_delay_exponent: u8,
    in_flight_ack_frequency: Option<(u64, Duration)>,
    one_rtt_probe_packets_pending: usize,
    max_send_buffered_stream_data: usize,
    send_buffered_stream_data: usize,
    max_recv_buffered_stream_data: usize,
    ecn_enabled: bool,
    path_validation: Option<PathValidation>,
    scheduler: StreamSchedulerConfig,
    stats: ConnectionStats,
    closed: bool,
    qlog_events: QlogBuffer,
    reset_stream_at_enabled: bool,
    local_initiator: StreamInitiator,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    local_uses_zero_length_connection_id: Option<bool>,
    peer_uses_zero_length_connection_id: Option<bool>,
}

impl Default for Connection {
    fn default() -> Self {
        let congestion = CongestionController::default();
        let mut stats = ConnectionStats::default();
        stats.current_mtu = 1_200;
        stats.congestion_window = congestion.stats().congestion_window;
        stats.bytes_in_flight = congestion.stats().bytes_in_flight;
        Self {
            crypto: CryptoStreams::default(),
            ack: AckTracker::default(),
            recovery: LossDetector::default(),
            congestion,
            mtud: MtuDiscovery::new(1_200, None),
            initial_mtu: 1_200,
            next_one_rtt_packet_number: 0,
            largest_acked: BTreeMap::new(),
            sent_crypto: BTreeMap::new(),
            sent_control: BTreeMap::new(),
            sent_stream: BTreeMap::new(),
            sent_stream_bytes: 0,
            recycled_stream_payloads: Vec::new(),
            send_streams: BTreeMap::new(),
            closed_send_streams: std::array::from_fn(|_| RangeSet::default()),
            max_stream_metadata_entries: 16_384,
            send_flow: SendFlowController::new(0),
            recv_flow: crate::streams::RecvFlowController::new(10 * 1024 * 1024),
            data_blocked_at: None,
            pending_send_streams: BTreeSet::new(),
            recv_streams: StreamMap::new(1_250_000),
            stream_schedule: VecDeque::new(),
            send_retransmit_streams: VecDeque::new(),
            send_acks: VecDeque::new(),
            send_control: VecDeque::new(),
            send_datagrams: VecDeque::new(),
            send_datagrams_bytes: 0,
            recv_datagrams: VecDeque::new(),
            recv_datagrams_bytes: 0,
            max_queued_datagrams: MAX_QUEUED_DATAGRAMS,
            max_receive_datagram_frame_size: 0,
            idle_send_time: None,
            last_ack_eliciting_sent: None,
            max_queued_datagram_bytes: MAX_QUEUED_DATAGRAM_BYTES,
            max_queued_control_frames: crate::config::TransportConfig::default()
                .max_queued_control_frames,
            one_rtt_ack_delay_start: None,
            one_rtt_ack_deadline: None,
            one_rtt_ack_eliciting_since_last_ack: 0,
            local_max_ack_delay: DEFAULT_MAX_ACK_DELAY,
            local_ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
            local_min_ack_delay: None,
            ack_eliciting_threshold: 1,
            reordering_threshold: 1,
            largest_ack_frequency_sequence: None,
            immediate_ack_requested: false,
            ack_frequency_config: None,
            next_ack_frequency_sequence: 0,
            peer_min_ack_delay: None,
            peer_max_ack_delay: DEFAULT_MAX_ACK_DELAY,
            peer_ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
            in_flight_ack_frequency: None,
            one_rtt_probe_packets_pending: 0,
            max_send_buffered_stream_data: crate::config::TransportConfig::default()
                .max_send_buffered_stream_data,
            send_buffered_stream_data: 0,
            max_recv_buffered_stream_data: crate::config::TransportConfig::default()
                .max_recv_buffered_stream_data,
            ecn_enabled: true,
            path_validation: None,
            scheduler: StreamSchedulerConfig::default(),
            stats,
            closed: false,
            qlog_events: QlogBuffer::default(),
            reset_stream_at_enabled: false,
            local_initiator: StreamInitiator::Client,
            peer_max_streams_bidi: MAX_STREAM_COUNT,
            peer_max_streams_uni: MAX_STREAM_COUNT,
            local_uses_zero_length_connection_id: None,
            peer_uses_zero_length_connection_id: None,
        }
    }
}

impl Connection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_ack_delay_config(&mut self, max_ack_delay: Duration, ack_delay_exponent: u8) {
        self.local_max_ack_delay = max_ack_delay;
        self.local_ack_delay_exponent = ack_delay_exponent;
        self.set_peer_ack_delay_config(max_ack_delay, ack_delay_exponent);
    }

    /// Configures locally generated ACKs and whether ACK_FREQUENCY frames are
    /// accepted.
    pub fn set_local_ack_delay_config(
        &mut self,
        max_ack_delay: Duration,
        ack_delay_exponent: u8,
        min_ack_delay: Option<Duration>,
    ) {
        self.local_max_ack_delay = max_ack_delay;
        self.local_ack_delay_exponent = ack_delay_exponent;
        self.local_min_ack_delay = min_ack_delay;
    }

    /// Configures ACK decoding and recovery from the peer's transport
    /// parameters without changing locally generated ACKs.
    pub fn set_peer_ack_delay_config(&mut self, max_ack_delay: Duration, ack_delay_exponent: u8) {
        self.peer_max_ack_delay = max_ack_delay;
        self.peer_ack_delay_exponent = ack_delay_exponent;
        self.recovery
            .set_ack_delay_config(max_ack_delay, ack_delay_exponent);
    }

    /// Configures outgoing ACK_FREQUENCY requests.
    pub fn set_ack_frequency_config(&mut self, config: Option<AckFrequencyConfig>) {
        self.ack_frequency_config = config;
    }

    /// Applies peer ACK_FREQUENCY support learned during transport-parameter
    /// negotiation and queues the initial request when configured.
    pub fn set_peer_min_ack_delay(&mut self, min_ack_delay: Option<Duration>) {
        self.peer_min_ack_delay = min_ack_delay;
        let (Some(min_ack_delay), Some(config)) =
            (self.peer_min_ack_delay, self.ack_frequency_config.as_ref())
        else {
            return;
        };
        let requested = config
            .max_ack_delay
            .unwrap_or(self.peer_max_ack_delay)
            .clamp(min_ack_delay, MAX_REQUESTED_ACK_DELAY);
        let Ok(requested_micros) = u64::try_from(requested.as_micros()) else {
            return;
        };
        let sequence = self.next_ack_frequency_sequence;
        self.next_ack_frequency_sequence = self.next_ack_frequency_sequence.saturating_add(1);
        self.queue_control_frame_best_effort(Frame::AckFrequency {
            sequence: VarInt::new(sequence).unwrap_or(VarInt::MAX),
            ack_eliciting_threshold: config.ack_eliciting_threshold,
            requested_max_ack_delay: VarInt::new(requested_micros).unwrap_or(VarInt::MAX),
            reordering_threshold: config.reordering_threshold,
        });
    }

    /// Marks the TLS handshake as confirmed for loss recovery.
    ///
    /// Servers call this when TLS completes. Clients become confirmed after
    /// receiving `HANDSHAKE_DONE`.
    pub fn confirm_handshake(&mut self) {
        if self.recovery.is_handshake_confirmed() {
            return;
        }
        self.recovery.confirm_handshake();
        self.qlog_events.push(QlogEvent::ConnectionStateUpdated {
            state: "handshake_confirmed",
        });
    }

    pub const fn is_handshake_confirmed(&self) -> bool {
        self.recovery.is_handshake_confirmed()
    }

    pub fn set_max_ack_ranges_per_space(&mut self, max_ranges: usize) {
        self.ack.set_max_ranges_per_space(max_ranges);
    }

    pub fn set_max_crypto_buffered_data(&mut self, max_bytes: u64) {
        self.crypto.set_max_recv_buffered_data(max_bytes);
    }

    pub fn set_max_buffered_qlog_events(&mut self, max_events: usize) {
        self.qlog_events.set_max_events(max_events);
    }

    pub fn set_reset_stream_at_enabled(&mut self, enabled: bool) {
        self.reset_stream_at_enabled = enabled;
    }

    pub fn record_path_state(&mut self, state: &'static str) {
        self.qlog_events.push(QlogEvent::PathStateUpdated { state });
    }

    pub fn record_packet_protection(
        &mut self,
        operation: &'static str,
        level: EncryptionLevel,
        key_phase: Option<bool>,
        bytes: usize,
    ) {
        self.qlog_events.push(QlogEvent::PacketProtectionUpdated {
            operation,
            level: encryption_level_name(level),
            key_phase,
            bytes,
        });
    }

    pub const fn reset_stream_at_enabled(&self) -> bool {
        self.reset_stream_at_enabled
    }

    /// Selects the congestion controller before packets are sent.
    ///
    /// Replacing the controller resets its controller-specific state and uses
    /// QUIC's conservative 1,200-byte datagram baseline.
    pub fn set_congestion_algorithm(&mut self, algorithm: crate::congestion::CongestionAlgorithm) {
        self.congestion = CongestionController::new(algorithm, 1200);
        self.sync_congestion_stats();
    }

    pub const fn congestion_algorithm(&self) -> crate::congestion::CongestionAlgorithm {
        self.congestion.algorithm()
    }

    pub fn reset_path_recovery(&mut self) {
        let algorithm = self.congestion.algorithm();
        self.congestion = CongestionController::new(algorithm, 1200);
        self.recovery.reset_path_rtt();
        self.mtud.reset_path(self.initial_mtu);
        self.update_scheduler_mtu();
        self.ecn_enabled = true;
        self.stats.smoothed_rtt = None;
        self.stats.latest_rtt = None;
        self.stats.min_rtt = None;
        self.stats.rtt_variance = None;
        self.stats.ecn_disabled = false;
        self.sync_congestion_stats();
    }

    pub fn configure_mtu_discovery(
        &mut self,
        initial_mtu: u16,
        config: Option<MtuDiscoveryConfig>,
    ) {
        self.initial_mtu = initial_mtu.clamp(1_200, 65_527);
        self.mtud = MtuDiscovery::new(self.initial_mtu, config);
        self.update_scheduler_mtu();
    }

    pub fn set_peer_max_udp_payload_size(&mut self, value: u16) {
        self.mtud.set_peer_limit(value);
        self.update_scheduler_mtu();
    }

    pub const fn current_mtu(&self) -> u16 {
        self.mtud.current_mtu()
    }

    pub fn set_max_send_buffered_stream_data(&mut self, max_bytes: usize) {
        self.max_send_buffered_stream_data = max_bytes;
    }

    pub const fn send_buffered_stream_data(&self) -> usize {
        self.send_buffered_stream_data
    }

    pub fn set_max_recv_buffered_stream_data(&mut self, max_bytes: usize) {
        self.max_recv_buffered_stream_data = max_bytes;
        self.recv_streams
            .set_max_recv_buffered_stream_data(max_bytes);
    }

    pub fn set_max_recv_buffered_stream_data_per_connection(&mut self, max_bytes: usize) {
        self.recv_streams
            .set_max_recv_buffered_stream_data_per_connection(max_bytes);
        self.recv_flow
            .set_max_window(u64::try_from(max_bytes).unwrap_or(u64::MAX));
    }

    pub fn configure_receive_flow_control(
        &mut self,
        max_data: u64,
        max_stream_data_bidi_local: u64,
        max_stream_data_bidi_remote: u64,
        max_stream_data_uni: u64,
    ) {
        self.recv_flow.set_limit(max_data);
        self.recv_streams.configure_receive_stream_data_limits(
            max_stream_data_bidi_local,
            max_stream_data_bidi_remote,
            max_stream_data_uni,
        );
    }

    /// Applies the locally advertised DATAGRAM wire-size limit.
    /// Receipt is disabled by default; `None` and zero disable it explicitly.
    pub fn set_receive_datagram_frame_size(&mut self, maximum: Option<VarInt>) {
        self.max_receive_datagram_frame_size = maximum.map_or(0, VarInt::into_inner);
    }

    fn validate_datagram_size(&self, size: Option<usize>) -> Result<()> {
        if size.is_some_and(|size| size as u64 > self.max_receive_datagram_frame_size) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::ProtocolViolation,
            ));
        }
        Ok(())
    }

    pub fn set_datagram_queue_limits(&mut self, max_datagrams: usize, max_bytes: usize) {
        self.max_queued_datagrams = max_datagrams;
        self.max_queued_datagram_bytes = max_bytes;
        while self.send_datagrams.len() > self.max_queued_datagrams
            || self.send_datagrams_bytes > self.max_queued_datagram_bytes
        {
            let Some(dropped) = self.send_datagrams.pop_front() else {
                break;
            };
            self.send_datagrams_bytes = self.send_datagrams_bytes.saturating_sub(dropped.len());
            self.qlog_events.push(QlogEvent::DatagramStateUpdated {
                state: "send_dropped",
                len: dropped.len(),
            });
        }
        self.trim_received_datagram_queue();
    }

    pub fn set_max_queued_control_frames(&mut self, max_frames: usize) {
        self.max_queued_control_frames = max_frames;
        while self.send_control.len() > max_frames {
            self.send_control.pop_back();
            self.note_dropped_control_frame();
        }
    }

    pub fn queued_send_datagrams(&self) -> usize {
        self.send_datagrams.len()
    }

    pub const fn queued_send_datagram_bytes(&self) -> usize {
        self.send_datagrams_bytes
    }

    pub fn queued_recv_datagrams(&self) -> usize {
        self.recv_datagrams.len()
    }

    pub const fn queued_recv_datagram_bytes(&self) -> usize {
        self.recv_datagrams_bytes
    }

    pub const fn recv_buffered_stream_data(&self) -> usize {
        self.recv_streams.recv_buffered_stream_data()
    }

    pub fn discard_packet_space(&mut self, level: EncryptionLevel) {
        self.crypto.discard_space(level);
        self.ack.discard_space(level);
        let discarded_bytes = self.recovery.discard_space(level);
        self.largest_acked.remove(&level);
        self.congestion.discard_bytes_in_flight(discarded_bytes);
        self.sent_crypto
            .retain(|(packet_level, _), _| *packet_level != level);
        self.sent_control
            .retain(|(packet_level, _), _| *packet_level != level);
        self.sent_stream
            .retain(|(packet_level, _), _| *packet_level != level);
        self.sent_stream_bytes = self.sent_stream.values().map(frame_payload_len).sum();
        self.send_acks.retain(|ack| ack.level != level);
        self.sync_congestion_stats();
        self.qlog_events.push(QlogEvent::ConnectionStateUpdated {
            state: packet_space_discarded_state(level),
        });
    }

    pub fn reject_zero_rtt(&mut self) {
        let control = self
            .sent_control
            .iter()
            .filter_map(|((level, _), frame)| {
                (*level == EncryptionLevel::ZeroRtt).then_some(frame.clone())
            })
            .collect::<Vec<_>>();
        let mut streams = self
            .sent_stream
            .iter()
            .filter_map(|((level, _), frame)| {
                (*level == EncryptionLevel::ZeroRtt).then_some(frame.clone())
            })
            .collect::<Vec<_>>();
        streams.extend(self.send_retransmit_streams.drain(..));
        self.discard_packet_space(EncryptionLevel::ZeroRtt);
        for frame in control.into_iter().rev() {
            self.queue_control_frame_front_best_effort(frame);
        }
        streams.sort_by_key(|frame| match frame {
            Frame::Stream {
                stream_id, offset, ..
            } => (stream_id.into_inner(), offset.into_inner()),
            _ => (u64::MAX, u64::MAX),
        });
        for frame in streams.into_iter().rev() {
            let Frame::Stream {
                stream_id,
                offset,
                data,
                ..
            } = frame
            else {
                continue;
            };
            let stream_id = StreamId(stream_id);
            let data_len = data.len();
            let restored = self
                .send_streams
                .entry(stream_id)
                .or_insert_with(|| SendStreamState::new(0))
                .buffer
                .restore_frame(offset.into_inner(), data);
            if restored {
                self.send_buffered_stream_data =
                    self.send_buffered_stream_data.saturating_add(data_len);
                self.pending_send_streams.insert(stream_id);
                self.mark_stream_schedulable(stream_id);
            }
        }
        self.qlog_events.push(QlogEvent::ConnectionStateUpdated {
            state: "zero_rtt_rejected",
        });
    }

    pub fn start_path_validation(&mut self, challenge: [u8; 8], now: Instant) -> Effects {
        self.path_validation = Some(PathValidation {
            challenge,
            deadline: now + PATH_VALIDATION_TIMEOUT,
            attempts: 1,
        });
        self.queue_control_frame_best_effort(Frame::PathChallenge(challenge));
        self.qlog_events.push(QlogEvent::PathStateUpdated {
            state: "validating",
        });
        self.timer_effects(now)
    }

    /// Queues the server's confirmation that the QUIC handshake is complete.
    pub fn send_handshake_done(&mut self) -> Result<()> {
        self.queue_control_frame(Frame::HandshakeDone)
    }

    pub fn handle_event(&mut self, event: Event, _now: Instant) -> Result<Effects> {
        let mut effects = Effects::default();
        match event {
            Event::ApplicationClose => {
                self.closed = true;
                self.qlog_events
                    .push(QlogEvent::ConnectionStateUpdated { state: "closed" });
                effects.connection_events.push(ConnectionEvent::Closed);
                effects
                    .endpoint_events
                    .push(EndpointEvent::ConnectionClosed);
            }
            Event::CryptoFrame {
                level,
                offset,
                data,
            } => {
                effects
                    .connection_events
                    .push(ConnectionEvent::CryptoDataReceived(CryptoData {
                        level,
                        offset,
                        bytes: data.clone(),
                    }));
                self.crypto.insert_frame(level, offset, &data)?;
            }
            Event::Datagram(data) => {
                let len = data.len();
                self.queue_received_datagram(data);
                self.stats.datagrams_received += 1;
                self.qlog_events.push(QlogEvent::DatagramStateUpdated {
                    state: "received",
                    len,
                });
                effects
                    .connection_events
                    .push(ConnectionEvent::DatagramReceived { len });
            }
            Event::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => {
                let len = data.len();
                self.receive_stream_frame(stream_id, offset, data, fin)?;
                self.qlog_events.push(QlogEvent::StreamDataQueued {
                    stream_id: stream_id.0.into_inner(),
                    offset,
                    len,
                    fin,
                });
                effects
                    .connection_events
                    .push(ConnectionEvent::StreamFrameQueued {
                        stream_id,
                        offset,
                        len,
                        fin,
                    });
            }
        }
        Ok(effects)
    }

    pub fn recv(&mut self, packet: &[u8], _meta: RecvMeta, _now: Instant) -> Result<Effects> {
        self.stats.bytes_received += packet.len() as u64;
        self.stats.packets_received += 1;
        self.record_ecn(_meta.ecn);
        self.qlog_events.push(QlogEvent::PacketReceived {
            level: encryption_level_name(EncryptionLevel::OneRtt),
            bytes: packet.len() as u64,
        });
        self.handle_frame_payload(EncryptionLevel::OneRtt, packet, _now)
    }

    pub fn handle_frame_payload(
        &mut self,
        level: EncryptionLevel,
        mut payload: &[u8],
        now: Instant,
    ) -> Result<Effects> {
        let mut effects = Effects::default();
        while !payload.is_empty() {
            let (frame, consumed) = Frame::decode(payload)?;
            if consumed == 0 || consumed > payload.len() {
                return Err(crate::error::CodecError::MalformedFrame);
            }
            effects.extend(self.handle_frame_with_datagram_size(
                level,
                frame,
                now,
                Some(consumed),
            )?);
            payload = &payload[consumed..];
        }
        Ok(effects)
    }

    pub fn handle_frame(
        &mut self,
        level: EncryptionLevel,
        frame: Frame,
        now: Instant,
    ) -> Result<Effects> {
        let size = matches!(frame, Frame::Datagram { .. }).then(|| frame.encoded_len());
        self.handle_frame_with_datagram_size(level, frame, now, size)
    }

    fn handle_frame_with_datagram_size(
        &mut self,
        level: EncryptionLevel,
        frame: Frame,
        now: Instant,
        size: Option<usize>,
    ) -> Result<Effects> {
        if matches!(frame, Frame::Datagram { .. }) {
            self.validate_datagram_size(size)?;
        }
        let _span = trace_span!(
            "quion.proto.connection",
            action = "handle_frame",
            level = encryption_level_name(level),
            frame_type = frame_type_name(&frame)
        )
        .entered();
        if !frame_allowed_at_level(&frame, level) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::ProtocolViolation,
            ));
        }
        let dispatched_frame = frame_requires_connection_event(&frame).then(|| frame.clone());
        let mut effects = Effects::default();
        match frame {
            Frame::Padding => {}
            Frame::Ping => {}
            Frame::Ack {
                largest,
                ref ranges,
                ..
            } => {
                if !self.recovery.has_valid_ack_ranges(&frame) {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::FrameEncodingError,
                    ));
                }
                if self.recovery.acknowledges_unsent_packet(level, &frame) {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::ProtocolViolation,
                    ));
                }
                let Some(outcome) = self.recovery.try_on_ack_frame(level, &frame, now) else {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::FrameEncodingError,
                    ));
                };
                trace!(
                    largest_acked = largest.into_inner(),
                    ack_ranges = ranges.len().saturating_add(1),
                    "processing ack frame"
                );
                self.qlog_events.push(QlogEvent::AckProcessed {
                    level: encryption_level_name(level),
                    largest_acked: largest.into_inner(),
                    ack_range_count: ranges.len().saturating_add(1),
                });
                effects.extend(self.handle_ack_outcome(level, outcome, now))
            }
            Frame::Crypto { offset, data } => effects.extend(self.handle_event(
                Event::CryptoFrame {
                    level,
                    offset: offset.into_inner(),
                    data,
                },
                now,
            )?),
            Frame::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => effects.extend(self.handle_event(
                Event::Stream {
                    stream_id: StreamId(stream_id),
                    offset: offset.into_inner(),
                    fin,
                    data,
                },
                now,
            )?),
            Frame::Datagram { data } => {
                trace!(len = data.len(), "processing datagram frame");
                effects.extend(self.handle_event(Event::Datagram(data), now)?);
            }
            Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. } => {
                effects.extend(self.handle_event(Event::ApplicationClose, now)?);
            }
            Frame::MaxStreamData { stream_id, maximum } => {
                if !self.peer_can_stop_sending(StreamId(stream_id)) {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::StreamStateError,
                    ));
                }
                trace!(
                    stream_id = stream_id.into_inner(),
                    maximum = maximum.into_inner(),
                    "raising stream send limit"
                );
                self.validate_peer_send_control(StreamId(stream_id))?;
                self.increase_stream_send_limit(StreamId(stream_id), maximum.into_inner())?;
                self.qlog_events.push(QlogEvent::FlowControlUpdated {
                    scope: "stream",
                    stream_id: Some(stream_id.into_inner()),
                    maximum: maximum.into_inner(),
                });
            }
            Frame::MaxData(maximum) => {
                trace!(
                    maximum = maximum.into_inner(),
                    "raising connection send limit"
                );
                self.increase_connection_send_limit(maximum.into_inner());
                self.qlog_events.push(QlogEvent::FlowControlUpdated {
                    scope: "connection",
                    stream_id: None,
                    maximum: maximum.into_inner(),
                });
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                debug!(
                    stream_id = stream_id.into_inner(),
                    error_code = error_code.into_inner(),
                    final_size = final_size.into_inner(),
                    "received reset_stream"
                );
                self.reset_recv_stream(StreamId(stream_id), final_size.into_inner(), error_code)?;
                self.qlog_events.push(QlogEvent::StreamStateUpdated {
                    stream_id: stream_id.into_inner(),
                    state: "reset",
                    error_code: Some(varint_inner(error_code)),
                    final_size: Some(final_size.into_inner()),
                });
                effects
                    .connection_events
                    .push(ConnectionEvent::StreamReset {
                        stream_id: StreamId(stream_id),
                        error_code,
                        final_size,
                    });
            }
            Frame::ResetStreamAt {
                stream_id,
                error_code,
                final_size,
                reliable_size,
            } => {
                if !self.reset_stream_at_enabled {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::ProtocolViolation,
                    ));
                }
                self.reset_recv_stream_at(
                    StreamId(stream_id),
                    final_size.into_inner(),
                    reliable_size.into_inner(),
                    error_code,
                )?;
                self.qlog_events.push(QlogEvent::StreamStateUpdated {
                    stream_id: stream_id.into_inner(),
                    state: "reliable_reset_received",
                    error_code: Some(varint_inner(error_code)),
                    final_size: Some(final_size.into_inner()),
                });
            }
            Frame::PathChallenge(data) => {
                self.qlog_events.push(QlogEvent::PathStateUpdated {
                    state: "challenge_received",
                });
                self.queue_control_frame(Frame::PathResponse(data))
                    .map_err(map_peer_control_queue_error)?;
                self.qlog_events.push(QlogEvent::PathStateUpdated {
                    state: "response_queued",
                });
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                if !self.peer_can_stop_sending(StreamId(stream_id)) {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::StreamStateError,
                    ));
                }
                self.validate_peer_send_control(StreamId(stream_id))?;
                debug!(
                    stream_id = stream_id.into_inner(),
                    error_code = error_code.into_inner(),
                    "received stop_sending"
                );
                if self
                    .stop_send_stream(StreamId(stream_id), error_code)
                    .map_err(map_peer_control_queue_error)?
                {
                    self.qlog_events.push(QlogEvent::StreamStateUpdated {
                        stream_id: stream_id.into_inner(),
                        state: "stopped",
                        error_code: Some(varint_inner(error_code)),
                        final_size: None,
                    });
                    effects
                        .connection_events
                        .push(ConnectionEvent::StreamStopped {
                            stream_id: StreamId(stream_id),
                            error_code,
                        });
                }
            }
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                ..
            } => {
                if self.peer_uses_zero_length_connection_id == Some(true) {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::ProtocolViolation,
                    ));
                }
                if retire_prior_to > sequence {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::FrameEncodingError,
                    ));
                }
            }
            Frame::StreamDataBlocked { stream_id, .. } => {
                if !self.peer_can_send_on_stream(StreamId(stream_id)) {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::StreamStateError,
                    ));
                }
            }
            Frame::MaxStreamsBidi(maximum) => {
                if maximum.into_inner() > MAX_STREAM_COUNT {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::FrameEncodingError,
                    ));
                }
                self.peer_max_streams_bidi = self.peer_max_streams_bidi.max(maximum.into_inner());
                let streams = self
                    .pending_send_streams
                    .iter()
                    .copied()
                    .filter(|stream_id| !is_unidirectional_stream(*stream_id))
                    .collect::<Vec<_>>();
                for stream_id in streams {
                    self.mark_stream_schedulable(stream_id);
                }
            }
            Frame::MaxStreamsUni(maximum) => {
                if maximum.into_inner() > MAX_STREAM_COUNT {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::FrameEncodingError,
                    ));
                }
                self.peer_max_streams_uni = self.peer_max_streams_uni.max(maximum.into_inner());
                let streams = self
                    .pending_send_streams
                    .iter()
                    .copied()
                    .filter(|stream_id| is_unidirectional_stream(*stream_id))
                    .collect::<Vec<_>>();
                for stream_id in streams {
                    self.mark_stream_schedulable(stream_id);
                }
            }
            Frame::StreamsBlockedBidi(maximum) | Frame::StreamsBlockedUni(maximum) => {
                if maximum.into_inner() > MAX_STREAM_COUNT {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::StreamLimitError,
                    ));
                }
            }
            Frame::NewToken(_) | Frame::HandshakeDone
                if self.local_initiator == StreamInitiator::Server =>
            {
                return Err(crate::error::CodecError::Transport(
                    TransportErrorCode::ProtocolViolation,
                ));
            }
            Frame::RetireConnectionId(_)
                if self.local_uses_zero_length_connection_id == Some(true) =>
            {
                return Err(crate::error::CodecError::Transport(
                    TransportErrorCode::ProtocolViolation,
                ));
            }
            Frame::HandshakeDone => {
                self.confirm_handshake();
                self.discard_packet_space(EncryptionLevel::Handshake);
            }
            Frame::AckFrequency {
                sequence,
                ack_eliciting_threshold,
                requested_max_ack_delay,
                reordering_threshold,
            } => {
                self.stats.ack_frequency_frames_received =
                    self.stats.ack_frequency_frames_received.saturating_add(1);
                let Some(min_ack_delay) = self.local_min_ack_delay else {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::ProtocolViolation,
                    ));
                };
                if self
                    .largest_ack_frequency_sequence
                    .is_some_and(|largest| sequence.into_inner() <= largest)
                {
                    return Ok(effects);
                }
                let requested_max_ack_delay =
                    Duration::from_micros(requested_max_ack_delay.into_inner());
                if requested_max_ack_delay < min_ack_delay
                    || requested_max_ack_delay > MAX_REQUESTED_ACK_DELAY
                {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::ProtocolViolation,
                    ));
                }
                self.largest_ack_frequency_sequence = Some(sequence.into_inner());
                self.local_max_ack_delay = requested_max_ack_delay;
                self.ack_eliciting_threshold = ack_eliciting_threshold.into_inner();
                self.reordering_threshold = reordering_threshold.into_inner();
                if let Some(start) = self.one_rtt_ack_delay_start {
                    self.one_rtt_ack_deadline = Some(start + self.local_max_ack_delay);
                    if now >= start + self.local_max_ack_delay {
                        self.immediate_ack_requested = true;
                    }
                }
            }
            Frame::ImmediateAck => {
                self.stats.immediate_ack_frames_received =
                    self.stats.immediate_ack_frames_received.saturating_add(1);
                if self.local_min_ack_delay.is_none() {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::ProtocolViolation,
                    ));
                }
                self.immediate_ack_requested = true;
            }
            Frame::DataBlocked(_) | Frame::NewToken(_) | Frame::RetireConnectionId(_) => {}
            Frame::PathResponse(data) => {
                if self
                    .path_validation
                    .is_some_and(|validation| validation.challenge == data)
                {
                    self.path_validation = None;
                    self.qlog_events
                        .push(QlogEvent::PathStateUpdated { state: "validated" });
                    effects
                        .connection_events
                        .push(ConnectionEvent::PathValidated);
                } else {
                    self.qlog_events.push(QlogEvent::PathStateUpdated {
                        state: "response_received",
                    });
                }
            }
        }
        if let Some(frame) = dispatched_frame {
            effects
                .connection_events
                .push(ConnectionEvent::FrameReceived(frame));
        }
        Ok(effects)
    }

    pub fn poll_transmit(&mut self, now: Instant) -> Option<Transmit> {
        let (frame, ack_eliciting, send_at) = self.poll_frame_for_transmit(now)?;
        let contents = frame.encode();
        if ack_eliciting && !self.can_send_one_rtt(contents.len() as u64) {
            self.requeue_frame_front(frame);
            return None;
        }
        let contains_ack = matches!(frame, Frame::Ack { .. });
        let path_probe = matches!(frame, Frame::PathChallenge(_) | Frame::PathResponse(_));
        let path_response = if let Frame::PathResponse(data) = &frame {
            Some(*data)
        } else {
            None
        };
        self.commit_frame_transmit(
            EncryptionLevel::OneRtt,
            frame,
            contents.len() as u64,
            ack_eliciting,
            now,
        );
        Some(Transmit {
            contents,
            ecn: (ack_eliciting && self.ecn_enabled).then_some(EcnCodepoint::Ect0),
            segment_size: None,
            send_at: ack_eliciting.then_some(send_at).flatten(),
            contains_ack,
            path_probe,
            path_response,
        })
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn poll_protected_one_rtt_transmit(
        &mut self,
        builder: &mut crate::crypto::packet::FramePacketBuilder,
        keys: &crate::crypto::rustls::RustlsKeyStore,
        now: Instant,
    ) -> Result<Option<Transmit>> {
        Ok(self
            .poll_protected_one_rtt_transmit_inner(builder, keys, now)?
            .map(|(transmit, _)| transmit))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn poll_protected_one_rtt_transmit_inner(
        &mut self,
        builder: &mut crate::crypto::packet::FramePacketBuilder,
        keys: &crate::crypto::rustls::RustlsKeyStore,
        now: Instant,
    ) -> Result<Option<(Transmit, bool)>> {
        let mtu_probe_packet_number = builder.next_one_rtt_packet_number();
        if let Some(probe_size) = self.mtud.poll_probe(now, mtu_probe_packet_number) {
            if !self.congestion.can_send(u64::from(probe_size)) {
                self.mtud.on_probe_not_sent(mtu_probe_packet_number);
            } else {
                let packet = match builder.build_one_rtt_padded(
                    keys,
                    &[Frame::Ping],
                    usize::from(probe_size),
                ) {
                    Ok(packet) => packet,
                    Err(error) => {
                        self.mtud.on_probe_not_sent(mtu_probe_packet_number);
                        return Err(error);
                    }
                };
                self.qlog_events.push(QlogEvent::PacketSent {
                    level: encryption_level_name(EncryptionLevel::OneRtt),
                    packet_number: mtu_probe_packet_number,
                    bytes: packet.len() as u64,
                    ack_eliciting: true,
                    frame_type: frame_type_name(&Frame::Ping),
                });
                let send_at = self.congestion.send_at(now);
                self.commit_transmit(EncryptionLevel::OneRtt, packet.len() as u64, true, now);
                self.stats.mtu_probes_sent = self.stats.mtu_probes_sent.saturating_add(1);
                return Ok(Some((
                    Transmit {
                        contents: packet,
                        ecn: self.ecn_enabled.then_some(EcnCodepoint::Ect0),
                        segment_size: None,
                        send_at,
                        contains_ack: false,
                        path_probe: false,
                        path_response: None,
                    },
                    false,
                )));
            }
        }
        let Some((frame, ack_eliciting, send_at)) = self.poll_frame_for_transmit(now) else {
            return Ok(None);
        };
        if ack_eliciting && !self.can_send_one_rtt((frame.encoded_len() + 64) as u64) {
            self.requeue_frame_front(frame);
            return Ok(None);
        }
        let packet = builder.build_one_rtt(keys, core::slice::from_ref(&frame))?;
        if ack_eliciting && !self.can_send_one_rtt(packet.len() as u64) {
            self.requeue_frame_front(frame);
            return Ok(None);
        }
        let contains_ack = matches!(frame, Frame::Ack { .. });
        let path_probe = matches!(frame, Frame::PathChallenge(_) | Frame::PathResponse(_));
        let path_response = if let Frame::PathResponse(data) = &frame {
            Some(*data)
        } else {
            None
        };
        let datagram = matches!(frame, Frame::Datagram { .. });
        self.commit_frame_transmit(
            EncryptionLevel::OneRtt,
            frame,
            packet.len() as u64,
            ack_eliciting,
            now,
        );
        Ok(Some((
            Transmit {
                contents: packet,
                ecn: (ack_eliciting && self.ecn_enabled).then_some(EcnCodepoint::Ect0),
                segment_size: None,
                send_at: ack_eliciting.then_some(send_at).flatten(),
                contains_ack,
                path_probe,
                path_response,
            },
            datagram,
        )))
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn poll_protected_one_rtt_transmit_batch(
        &mut self,
        builder: &mut crate::crypto::packet::FramePacketBuilder,
        keys: &crate::crypto::rustls::RustlsKeyStore,
        now: Instant,
        max_transmits: usize,
    ) -> Result<Vec<Transmit>> {
        let mut transmits = Vec::new();
        self.poll_protected_one_rtt_transmit_batch_into(
            builder,
            keys,
            now,
            max_transmits,
            &mut transmits,
        )?;
        Ok(transmits)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn poll_protected_one_rtt_transmit_batch_into(
        &mut self,
        builder: &mut crate::crypto::packet::FramePacketBuilder,
        keys: &crate::crypto::rustls::RustlsKeyStore,
        now: Instant,
        max_transmits: usize,
        transmits: &mut Vec<Transmit>,
    ) -> Result<()> {
        transmits.clear();
        transmits.reserve(max_transmits);
        for _ in 0..max_transmits {
            let Some((transmit, datagram)) =
                self.poll_protected_one_rtt_transmit_inner(builder, keys, now)?
            else {
                break;
            };
            let pacing_blocked = transmit.send_at.is_some_and(|send_at| send_at > now);
            let full_sized = transmit.contents.len() >= self.scheduler.max_frame_data;
            transmits.push(transmit);
            // Keep latency-sensitive control frames and stream tails out of an
            // eagerly committed batch. Full-sized data packets are the case
            // where amortizing the protocol lock materially improves throughput.
            if pacing_blocked || (!full_sized && !datagram) {
                break;
            }
        }
        Ok(())
    }

    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub fn poll_protected_zero_rtt_transmit(
        &mut self,
        builder: &mut crate::crypto::packet::CryptoPacketBuilder,
        keys: &crate::crypto::rustls::RustlsKeyStore,
        now: Instant,
    ) -> Result<Option<Transmit>> {
        let send_at = self.congestion.send_at(now);
        if !self.congestion.can_send(1) {
            return Ok(None);
        }
        let frame = self
            .poll_zero_rtt_control_frame()
            .or_else(|| self.poll_datagram_frame())
            .or_else(|| self.poll_retransmit_stream_frame())
            .or_else(|| {
                self.poll_stream_frame_if_congestion_allows()
                    .map(|(frame, _)| frame)
            });
        let Some(frame) = frame else {
            return Ok(None);
        };
        let ack_eliciting = is_ack_eliciting(&frame);
        let packet = match builder.build_zero_rtt_frames(keys, core::slice::from_ref(&frame)) {
            Ok(packet) => packet,
            Err(error) => {
                self.requeue_frame_front(frame);
                return Err(error);
            }
        };
        if matches!(frame, Frame::Datagram { .. }) && packet.len() > usize::from(self.current_mtu())
        {
            self.stats.datagrams_dropped = self.stats.datagrams_dropped.saturating_add(1);
            return Ok(None);
        }
        if !self.congestion.can_send(packet.len() as u64) {
            self.requeue_frame_front(frame);
            return Ok(None);
        }
        self.commit_frame_transmit(
            EncryptionLevel::ZeroRtt,
            frame,
            packet.len() as u64,
            ack_eliciting,
            now,
        );
        Ok(Some(Transmit {
            contents: packet,
            ecn: (ack_eliciting && self.ecn_enabled).then_some(EcnCodepoint::Ect0),
            segment_size: None,
            send_at,
            contains_ack: false,
            path_probe: false,
            path_response: None,
        }))
    }

    pub fn queue_stream_data(&mut self, stream_id: StreamId, data: &[u8]) -> Result<Effects> {
        self.ensure_send_stream_capacity(stream_id)?;
        let _span = trace_span!(
            "quion.proto.connection",
            action = "queue_stream_data",
            stream_id = stream_id.0.into_inner()
        )
        .entered();
        if self.is_send_stream_finished(stream_id) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::StreamStateError,
            ));
        }
        if self.send_buffered_stream_data.saturating_add(data.len())
            > self.max_send_buffered_stream_data
        {
            return Err(crate::error::CodecError::BufferLimitExceeded);
        }
        let stream = self
            .send_streams
            .entry(stream_id)
            .or_insert_with(|| SendStreamState::new(0));
        let offset = stream.buffer.next_offset() + stream.buffer.queued_len() as u64;
        trace!(offset, len = data.len(), "queueing stream bytes");
        let written = stream.buffer.write(data)?;
        self.pending_send_streams.insert(stream_id);
        self.send_buffered_stream_data = self.send_buffered_stream_data.saturating_add(written);
        self.qlog_events.push(QlogEvent::StreamDataQueued {
            stream_id: stream_id.0.into_inner(),
            offset,
            len: data.len(),
            fin: false,
        });
        self.mark_stream_schedulable(stream_id);
        Ok(Effects::default())
    }

    pub fn available_send_credit(&self, stream_id: StreamId) -> u64 {
        let Some(stream) = self.send_streams.get(&stream_id) else {
            return 0;
        };
        let stream_reserved = stream
            .flow
            .consumed()
            .saturating_add(stream.buffer.queued_len() as u64);
        let stream_available = stream.flow.max_data().saturating_sub(stream_reserved);

        let connection_buffered = u64::try_from(self.send_buffered_stream_data).unwrap_or(u64::MAX);
        let connection_reserved = self
            .send_flow
            .consumed()
            .saturating_add(connection_buffered);
        let connection_available = self
            .send_flow
            .max_data()
            .saturating_sub(connection_reserved);

        stream_available.min(connection_available)
    }

    pub fn finish_stream(&mut self, stream_id: StreamId) -> Result<Effects> {
        self.ensure_send_stream_capacity(stream_id)?;
        let _span = trace_span!(
            "quion.proto.connection",
            action = "finish_stream",
            stream_id = stream_id.0.into_inner()
        )
        .entered();
        if self.is_send_stream_finished(stream_id) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::StreamStateError,
            ));
        }
        let stream = self
            .send_streams
            .entry(stream_id)
            .or_insert_with(|| SendStreamState::new(0));
        if stream.stopped_error.is_some() {
            return Ok(Effects::default());
        }
        stream.buffer.finish();
        self.pending_send_streams.insert(stream_id);
        debug!("marking send stream finished");
        self.qlog_events.push(QlogEvent::StreamStateUpdated {
            stream_id: stream_id.0.into_inner(),
            state: "finished",
            error_code: None,
            final_size: stream.buffer.final_offset(),
        });
        self.mark_stream_schedulable(stream_id);
        Ok(Effects::default())
    }

    pub fn reset_stream(&mut self, stream_id: StreamId, error_code: VarInt) -> Result<Effects> {
        self.ensure_send_stream_capacity(stream_id)?;
        let _span = trace_span!(
            "quion.proto.connection",
            action = "reset_stream",
            stream_id = stream_id.0.into_inner(),
            error_code = error_code.into_inner()
        )
        .entered();
        if self.is_send_stream_finished(stream_id) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::StreamStateError,
            ));
        }
        let (final_size, queued_len) = {
            let stream = self
                .send_streams
                .entry(stream_id)
                .or_insert_with(|| SendStreamState::new(0));
            if stream.stopped_error.is_some() {
                return Ok(Effects::default());
            }
            (stream.buffer.reset_final_size(), stream.buffer.queued_len())
        };
        let final_size = VarInt::new(final_size)?;
        self.queue_control_frame(Frame::ResetStream {
            stream_id: stream_id.0,
            error_code,
            final_size,
        })?;
        let Some(stream) = self.send_streams.get_mut(&stream_id) else {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::InternalError,
            ));
        };
        self.send_buffered_stream_data = self.send_buffered_stream_data.saturating_sub(queued_len);
        self.pending_send_streams.remove(&stream_id);
        stream.stopped_error = Some(error_code);
        stream.queued = false;
        stream.buffer = SendBuffer::default();
        debug!(
            final_size = final_size.into_inner(),
            "queued reset_stream control frame"
        );
        self.qlog_events.push(QlogEvent::StreamStateUpdated {
            stream_id: stream_id.0.into_inner(),
            state: "reset_sent",
            error_code: Some(varint_inner(error_code)),
            final_size: Some(final_size.into_inner()),
        });
        Ok(Effects::default())
    }

    pub fn reset_stream_at(
        &mut self,
        stream_id: StreamId,
        error_code: VarInt,
        reliable_size: VarInt,
    ) -> Result<Effects> {
        self.ensure_send_stream_capacity(stream_id)?;
        if !self.reset_stream_at_enabled {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::ProtocolViolation,
            ));
        }
        if self.is_send_stream_finished(stream_id) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::StreamStateError,
            ));
        }
        let final_size = {
            let stream = self
                .send_streams
                .entry(stream_id)
                .or_insert_with(|| SendStreamState::new(0));
            if stream.stopped_error.is_some() {
                return Ok(Effects::default());
            }
            if let Some((existing_error, existing_final, existing_reliable)) = stream.reliable_reset
            {
                if existing_error != error_code {
                    return Err(crate::error::CodecError::Transport(
                        TransportErrorCode::StreamStateError,
                    ));
                }
                if reliable_size.into_inner() >= existing_reliable {
                    return Ok(Effects::default());
                }
                existing_final
            } else {
                stream.buffer.reset_final_size()
            }
        };
        let final_size = VarInt::new(final_size)?;
        if reliable_size > final_size {
            return Err(crate::error::CodecError::ValueOutOfBounds);
        }
        self.queue_control_frame(Frame::ResetStreamAt {
            stream_id: stream_id.0,
            error_code,
            final_size,
            reliable_size,
        })?;
        let Some(stream) = self.send_streams.get_mut(&stream_id) else {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::InternalError,
            ));
        };
        let (_, discarded) = stream
            .buffer
            .prepare_reliable_reset(reliable_size.into_inner())?;
        stream.reliable_reset = Some((
            error_code,
            final_size.into_inner(),
            reliable_size.into_inner(),
        ));
        self.send_buffered_stream_data = self.send_buffered_stream_data.saturating_sub(discarded);
        self.send_retransmit_streams.retain_mut(|frame| {
            trim_stream_frame_to_reliable(frame, stream_id, reliable_size.into_inner())
        });
        self.pending_send_streams.insert(stream_id);
        self.mark_stream_schedulable(stream_id);
        self.qlog_events.push(QlogEvent::StreamStateUpdated {
            stream_id: stream_id.0.into_inner(),
            state: "reliable_reset_sent",
            error_code: Some(varint_inner(error_code)),
            final_size: Some(final_size.into_inner()),
        });
        Ok(Effects::default())
    }

    pub fn increase_stream_send_limit(
        &mut self,
        stream_id: StreamId,
        max_stream_data: u64,
    ) -> Result<()> {
        trace!(
            stream_id = stream_id.0.into_inner(),
            maximum = max_stream_data,
            "increasing stream send credit"
        );
        if self.is_send_stream_finished(stream_id) {
            return Ok(());
        }
        self.ensure_send_stream_capacity(stream_id)?;
        let stream = self
            .send_streams
            .entry(stream_id)
            .or_insert_with(|| SendStreamState::new(max_stream_data));
        stream.flow.increase_limit(max_stream_data);
        if stream
            .blocked_at
            .is_some_and(|blocked_at| stream.flow.max_data() > blocked_at)
        {
            stream.blocked_at = None;
        }
        self.qlog_events.push(QlogEvent::FlowControlUpdated {
            scope: "stream",
            stream_id: Some(stream_id.0.into_inner()),
            maximum: max_stream_data,
        });
        if self.pending_send_streams.contains(&stream_id) {
            self.mark_stream_schedulable(stream_id);
        }
        Ok(())
    }

    /// Sets a stream's scheduling priority. Lower values are transmitted
    /// first; streams with equal priority retain round-robin fairness.
    pub fn set_stream_priority(&mut self, stream_id: StreamId, priority: u16) {
        if self.is_send_stream_finished(stream_id) {
            return;
        }
        let Some(stream) = self.send_streams.get_mut(&stream_id) else {
            return;
        };
        let was_queued = stream.queued;
        stream.priority = priority;
        if was_queued {
            stream.queued = false;
            self.stream_schedule.retain(|queued| *queued != stream_id);
            self.mark_stream_schedulable(stream_id);
        }
    }

    pub fn stopped_stream_error(&self, stream_id: StreamId) -> Option<VarInt> {
        self.send_streams.get(&stream_id)?.stopped_error
    }

    pub fn stop_recv_stream(&mut self, stream_id: StreamId, error_code: VarInt) -> Result<Effects> {
        if self.recv_streams.is_recv_stream_closed(stream_id) {
            return Ok(Effects::default());
        }
        if self.recv_stream_reset_error(stream_id).is_some() {
            self.recv_streams.stop_recv_stream(stream_id)?;
            self.release_recv_credit(Instant::now());
            return Ok(Effects::default());
        }
        debug!(
            stream_id = stream_id.0.into_inner(),
            error_code = error_code.into_inner(),
            "queueing stop_sending"
        );
        self.queue_control_frame(Frame::StopSending {
            stream_id: stream_id.0,
            error_code,
        })?;
        self.recv_streams.stop_recv_stream(stream_id)?;
        self.release_recv_credit(Instant::now());
        self.qlog_events.push(QlogEvent::StreamStateUpdated {
            stream_id: stream_id.0.into_inner(),
            state: "stop_requested",
            error_code: Some(varint_inner(error_code)),
            final_size: None,
        });
        Ok(Effects::default())
    }

    pub fn increase_connection_send_limit(&mut self, max_data: u64) {
        trace!(maximum = max_data, "increasing connection send credit");
        self.send_flow.increase_limit(max_data);
        if self
            .data_blocked_at
            .is_some_and(|blocked_at| self.send_flow.max_data() > blocked_at)
        {
            self.data_blocked_at = None;
        }
        self.qlog_events.push(QlogEvent::FlowControlUpdated {
            scope: "connection",
            stream_id: None,
            maximum: max_data,
        });
        let streams = self
            .pending_send_streams
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for stream_id in streams {
            self.mark_stream_schedulable(stream_id);
        }
    }

    pub fn configure_outbound_stream_limits(
        &mut self,
        max_bidi_streams: u64,
        max_uni_streams: u64,
    ) {
        self.peer_max_streams_bidi = max_bidi_streams.min(MAX_STREAM_COUNT);
        self.peer_max_streams_uni = max_uni_streams.min(MAX_STREAM_COUNT);
        let streams = self
            .pending_send_streams
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for stream_id in streams {
            self.mark_stream_schedulable(stream_id);
        }
    }

    pub fn reset_zero_rtt_send_limits(
        &mut self,
        max_data: u64,
        max_stream_data_bidi_remote: u64,
        max_stream_data_uni: u64,
        max_streams_bidi: u64,
        max_streams_uni: u64,
    ) {
        self.send_flow.reset_limit(max_data);
        self.data_blocked_at = None;
        self.configure_outbound_stream_limits(max_streams_bidi, max_streams_uni);
        let streams = self.send_streams.keys().copied().collect::<Vec<_>>();
        for stream_id in streams {
            if self.is_locally_initiated(stream_id) {
                let maximum = if is_unidirectional_stream(stream_id) {
                    max_stream_data_uni
                } else {
                    max_stream_data_bidi_remote
                };
                if let Some(stream) = self.send_streams.get_mut(&stream_id) {
                    stream.flow.reset_limit(maximum);
                    stream.blocked_at = None;
                }
            }
            if self.pending_send_streams.contains(&stream_id) {
                self.mark_stream_schedulable(stream_id);
            }
        }
    }

    pub fn configure_inbound_stream_limits(
        &mut self,
        local_initiator: StreamInitiator,
        max_bidi_streams: u64,
        max_uni_streams: u64,
    ) {
        self.local_initiator = local_initiator;
        self.recv_streams.configure_inbound_stream_limits(
            local_initiator,
            max_bidi_streams,
            max_uni_streams,
        );
    }

    /// Records whether locally issued connection IDs are zero length.
    ///
    /// QUIC forbids issuing replacement IDs after selecting a zero-length ID.
    /// Returns `false` if a previous call selected the opposite zero-length
    /// policy.
    pub fn set_local_connection_id_length(&mut self, length: usize) -> bool {
        let uses_zero_length = length == 0;
        match self.local_uses_zero_length_connection_id {
            Some(configured) => configured == uses_zero_length,
            None => {
                self.local_uses_zero_length_connection_id = Some(uses_zero_length);
                true
            }
        }
    }

    /// Records whether the peer's initial connection ID is zero length.
    ///
    /// QUIC forbids retiring or replacing a zero-length peer connection ID.
    /// Returns `false` if a previous call selected the opposite zero-length
    /// policy.
    pub fn set_peer_connection_id_length(&mut self, length: usize) -> bool {
        let uses_zero_length = length == 0;
        match self.peer_uses_zero_length_connection_id {
            Some(configured) => configured == uses_zero_length,
            None => {
                self.peer_uses_zero_length_connection_id = Some(uses_zero_length);
                true
            }
        }
    }

    pub fn register_local_stream(&mut self, stream_id: StreamId) -> Result<()> {
        self.ensure_send_stream_capacity(stream_id)?;
        if !stream_id.is_unidirectional() {
            self.recv_streams.register_local_stream(stream_id)?;
        }
        self.send_streams
            .entry(stream_id)
            .or_insert_with(|| SendStreamState::new(0));
        Ok(())
    }

    /// Bounds metadata separately from buffered application bytes.
    pub fn set_max_stream_metadata_entries(&mut self, limit: usize) {
        self.max_stream_metadata_entries = limit;
        self.recv_streams.set_max_metadata_entries(limit);
    }

    fn ensure_send_stream_capacity(&self, stream_id: StreamId) -> Result<()> {
        if !self.is_send_stream_finished(stream_id)
            && !self.send_streams.contains_key(&stream_id)
            && self.send_streams.len()
                + self
                    .closed_send_streams
                    .iter()
                    .map(RangeSet::len)
                    .sum::<usize>()
                >= self.max_stream_metadata_entries
        {
            return Err(crate::CodecError::BufferLimitExceeded);
        }
        Ok(())
    }

    fn validate_peer_send_control(&self, stream_id: StreamId) -> Result<()> {
        if stream_id.initiator() == self.local_initiator {
            if !self.send_streams.contains_key(&stream_id)
                && !self.is_send_stream_finished(stream_id)
            {
                return Err(crate::CodecError::Transport(
                    TransportErrorCode::StreamStateError,
                ));
            }
        } else {
            self.recv_streams.validate_peer_send_control(stream_id)?;
        }
        self.ensure_send_stream_capacity(stream_id)
    }

    fn peer_can_stop_sending(&self, stream_id: StreamId) -> bool {
        self.recv_streams.peer_can_stop_sending(stream_id)
    }

    fn peer_can_send_on_stream(&self, stream_id: StreamId) -> bool {
        self.recv_streams.peer_can_send_on_stream(stream_id)
    }

    pub fn configure_stream_scheduler(&mut self, config: StreamSchedulerConfig) {
        self.scheduler = config;
    }

    pub fn send_datagram(&mut self, data: Vec<u8>) -> Result<Effects> {
        self.send_datagram_bytes(data.into())
    }

    /// Queues an unreliable DATAGRAM payload without copying shared storage.
    pub fn send_datagram_bytes(&mut self, data: bytes::Bytes) -> Result<Effects> {
        self.queue_send_datagram(data)?;
        self.stats.datagrams_sent += 1;
        self.qlog_events.push(QlogEvent::DatagramStateUpdated {
            state: "queued",
            len: self.send_datagrams.back().map_or(0, bytes::Bytes::len),
        });
        Ok(Effects::default())
    }

    pub fn queue_new_connection_id(
        &mut self,
        sequence: VarInt,
        retire_prior_to: VarInt,
        connection_id: Vec<u8>,
        reset_token: [u8; 16],
    ) -> Result<Effects> {
        if self.local_uses_zero_length_connection_id == Some(true) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::ProtocolViolation,
            ));
        }
        if !(1..=crate::cid::MAX_CONNECTION_ID_LEN).contains(&connection_id.len())
            || retire_prior_to > sequence
        {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::FrameEncodingError,
            ));
        }
        self.queue_control_frame(Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            connection_id,
            reset_token,
        })?;
        Ok(Effects::default())
    }

    pub fn queue_retire_connection_id(&mut self, sequence: VarInt) -> Result<Effects> {
        if self.peer_uses_zero_length_connection_id == Some(true) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::ProtocolViolation,
            ));
        }
        self.queue_control_frame_best_effort(Frame::RetireConnectionId(sequence));
        Ok(Effects::default())
    }

    pub fn close_application(&mut self, error_code: VarInt, reason: &[u8]) -> Result<Effects> {
        self.closed = true;
        self.qlog_events.push(QlogEvent::ConnectionStateUpdated {
            state: "application_close_sent",
        });
        self.send_control.clear();
        self.send_control.push_back(Frame::ApplicationClose {
            error_code,
            reason: reason.to_vec(),
        });
        let mut effects = Effects::default();
        effects.connection_events.push(ConnectionEvent::Closed);
        effects
            .endpoint_events
            .push(EndpointEvent::ConnectionClosed);
        Ok(effects)
    }

    pub fn close_transport(
        &mut self,
        error_code: TransportErrorCode,
        frame_type: VarInt,
        reason: &[u8],
    ) -> Result<Effects> {
        self.closed = true;
        self.qlog_events.push(QlogEvent::ConnectionStateUpdated {
            state: "transport_close_sent",
        });
        self.send_control.clear();
        self.send_control.push_back(Frame::ConnectionClose {
            error_code,
            frame_type,
            reason: reason.to_vec(),
        });
        let mut effects = Effects::default();
        effects.connection_events.push(ConnectionEvent::Closed);
        effects
            .endpoint_events
            .push(EndpointEvent::ConnectionClosed);
        Ok(effects)
    }

    pub fn abort(&mut self) -> Effects {
        self.closed = true;
        self.sent_crypto.clear();
        self.sent_control.clear();
        self.sent_stream.clear();
        self.sent_stream_bytes = 0;
        self.recycled_stream_payloads.clear();
        self.send_acks.clear();
        self.send_control.clear();
        self.send_datagrams.clear();
        self.send_datagrams_bytes = 0;
        self.recv_datagrams.clear();
        self.recv_datagrams_bytes = 0;
        self.send_streams.clear();
        self.closed_send_streams = std::array::from_fn(|_| RangeSet::default());
        self.pending_send_streams.clear();
        self.send_buffered_stream_data = 0;
        self.recv_streams.clear();
        self.stream_schedule.clear();
        self.send_retransmit_streams.clear();
        self.one_rtt_probe_packets_pending = 0;
        self.recovery = LossDetector::default();
        self.congestion = CongestionController::default();
        self.qlog_events
            .push(QlogEvent::ConnectionStateUpdated { state: "aborted" });
        self.sync_congestion_stats();

        let mut effects = Effects::default();
        effects.connection_events.push(ConnectionEvent::Closed);
        effects
            .endpoint_events
            .push(EndpointEvent::ConnectionClosed);
        effects
    }

    pub fn read_datagram(&mut self) -> Option<Vec<u8>> {
        self.read_datagram_bytes().map(|datagram| datagram.to_vec())
    }

    pub fn read_datagram_bytes(&mut self) -> Option<bytes::Bytes> {
        let datagram = self.recv_datagrams.pop_front()?;
        self.recv_datagrams_bytes = self.recv_datagrams_bytes.saturating_sub(datagram.len());
        Some(datagram)
    }

    pub fn receive_stream_frame(
        &mut self,
        stream_id: StreamId,
        offset: u64,
        data: impl Into<bytes::Bytes>,
        fin: bool,
    ) -> Result<Effects> {
        if self.recv_streams.is_recv_stream_closed(stream_id) {
            return Ok(Effects::default());
        }
        let data = data.into();
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(crate::error::CodecError::ValueOutOfBounds)?;
        let received = self.recv_streams.received_stream_data(stream_id);
        self.recv_flow
            .validate_additional(end.saturating_sub(received))?;
        let newly_accounted = self
            .recv_streams
            .receive_stream_frame(stream_id, offset, data, fin)?;
        self.recv_flow.add_received(newly_accounted)?;
        self.release_recv_credit(Instant::now());
        Ok(Effects::default())
    }

    pub fn accept_recv_stream(&mut self) -> Option<StreamId> {
        let (stream_id, limit_update) = self.recv_streams.accept_recv_stream_with_limit_update()?;
        self.stats.streams_accepted = self.stats.streams_accepted.saturating_add(1);
        self.queue_max_streams(limit_update);
        Some(stream_id)
    }

    pub fn accept_recv_stream_where(
        &mut self,
        predicate: impl Fn(StreamId) -> bool,
    ) -> Option<StreamId> {
        let (stream_id, limit_update) = self
            .recv_streams
            .accept_recv_stream_where_with_limit_update(predicate)?;
        self.stats.streams_accepted = self.stats.streams_accepted.saturating_add(1);
        self.queue_max_streams(limit_update);
        Some(stream_id)
    }

    pub fn record_stream_opened(&mut self) {
        self.stats.streams_opened = self.stats.streams_opened.saturating_add(1);
    }

    pub fn record_handshake_duration(&mut self, duration: std::time::Duration) {
        self.stats.handshake_duration = Some(duration);
    }

    pub fn queue_streams_blocked(&mut self, kind: StreamLimitKind, maximum: u64) {
        let maximum = VarInt::new(maximum).unwrap_or(VarInt::MAX);
        match kind {
            StreamLimitKind::Bidi => {
                self.queue_control_frame_best_effort(Frame::StreamsBlockedBidi(maximum));
            }
            StreamLimitKind::Uni => {
                self.queue_control_frame_best_effort(Frame::StreamsBlockedUni(maximum));
            }
        }
    }

    pub fn read_recv_stream(
        &mut self,
        stream_id: StreamId,
        max: usize,
        ordered: bool,
    ) -> Option<Chunk> {
        let now = Instant::now();
        let smoothed_rtt = self.recovery.smoothed_rtt();
        let (chunk, max_stream_data) = if ordered {
            self.recv_streams
                .read_ordered_with_flow_update_at(stream_id, max, now, smoothed_rtt)?
        } else {
            self.recv_streams.read_unordered_with_flow_update_at(
                stream_id,
                max,
                now,
                smoothed_rtt,
            )?
        };
        if let Some(maximum) = max_stream_data.and_then(|maximum| VarInt::new(maximum).ok()) {
            self.queue_control_frame_best_effort(Frame::MaxStreamData {
                stream_id: stream_id.0,
                maximum,
            });
        }
        self.release_recv_credit(now);
        Some(chunk)
    }

    fn release_recv_credit(&mut self, now: Instant) {
        let released = self.recv_streams.take_connection_release();
        if let Some(maximum) = self
            .recv_flow
            .release(released, now, self.recovery.smoothed_rtt())
            && let Ok(maximum) = VarInt::new(maximum)
        {
            self.queue_control_frame_best_effort(Frame::MaxData(maximum));
        }
    }

    pub fn is_recv_stream_finished(&self, stream_id: StreamId) -> bool {
        self.recv_streams.is_recv_stream_closed(stream_id)
            || self
                .recv_streams
                .recv_stream(stream_id)
                .is_some_and(|stream| stream.final_offset() == Some(stream.delivered()))
    }

    /// Returns whether unread bytes are buffered for a receive stream.
    ///
    /// Callers that impose a byte limit can use this to distinguish an empty
    /// FIN from additional payload without consuming buffered data.
    pub fn recv_stream_has_buffered_data(&self, stream_id: StreamId) -> bool {
        self.recv_streams
            .recv_stream(stream_id)
            .is_some_and(|stream| stream.buffered_bytes() != 0)
    }

    pub fn recv_stream_reset_error(&self, stream_id: StreamId) -> Option<VarInt> {
        self.recv_streams.recv_stream(stream_id)?.reset_error()
    }

    pub fn drain_qlog_events(&mut self) -> Vec<QlogEvent> {
        self.qlog_events.drain()
    }

    /// Clears the one-time idle timer extension after authenticated receive.
    pub fn reset_idle_send_time(&mut self) {
        self.idle_send_time = None;
    }
    /// First ack-eliciting transmission since the latest authenticated receive.
    pub fn idle_send_time(&self) -> Option<Instant> {
        self.idle_send_time
    }
    /// Latest ack-eliciting transmission, used for keep-alive scheduling.
    pub fn last_ack_eliciting_sent(&self) -> Option<Instant> {
        self.last_ack_eliciting_sent
    }
    /// Queues a congestion-controlled PING unless ack-eliciting control work exists.
    pub fn queue_keep_alive(&mut self) -> Result<()> {
        // Queued stream or DATAGRAM data may be blocked or become unsendable.
        // ACK-only work does not refresh the peer's idle timer either.
        if !self.send_control.iter().any(is_ack_eliciting) {
            self.queue_control_frame(Frame::Ping)?;
        }
        Ok(())
    }

    pub fn record_sent_packet(
        &mut self,
        level: EncryptionLevel,
        packet_number: u64,
        bytes: u64,
        ack_eliciting: bool,
        now: Instant,
    ) -> Effects {
        self.record_sent_packet_inner(SentPacket {
            level,
            packet_number,
            bytes,
            ack_eliciting,
            ecn: (ack_eliciting && self.ecn_enabled).then_some(EcnCodepoint::Ect0),
            sent_at: now,
        })
    }

    fn record_sent_packet_inner(&mut self, packet: SentPacket) -> Effects {
        let SentPacket {
            level,
            packet_number,
            bytes,
            ack_eliciting,
            ecn,
            sent_at: now,
        } = packet;
        if ack_eliciting {
            self.idle_send_time.get_or_insert(now);
            self.last_ack_eliciting_sent = Some(now);
        }
        if matches!(level, EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt) {
            self.next_one_rtt_packet_number = self
                .next_one_rtt_packet_number
                .max(packet_number.saturating_add(1));
        }
        self.recovery
            .on_packet_sent_with_ecn(level, packet_number, bytes, ack_eliciting, ecn, now);
        if ack_eliciting {
            self.congestion.on_packet_sent_at(bytes, now);
        }
        self.sync_congestion_stats();
        self.timer_effects(now)
    }

    pub fn record_sent_crypto_packet(
        &mut self,
        level: EncryptionLevel,
        packet_number: u64,
        bytes: u64,
        frames: Vec<CryptoFrame>,
        now: Instant,
    ) -> Effects {
        self.sent_crypto.insert((level, packet_number), frames);
        // Endpoint crypto flights are sent without ECN marking. Recording an
        // invented ECT(0) mark disables ECN as soon as their plain ACK arrives.
        self.record_sent_packet_inner(SentPacket {
            level,
            packet_number,
            bytes,
            ack_eliciting: true,
            ecn: None,
            sent_at: now,
        })
    }

    pub fn handle_ack_frame(
        &mut self,
        level: EncryptionLevel,
        frame: &Frame,
        now: Instant,
    ) -> Effects {
        let Some(outcome) = self.recovery.try_on_ack_frame(level, frame, now) else {
            return Effects::default();
        };
        self.handle_ack_outcome(level, outcome, now)
    }

    fn handle_ack_outcome(
        &mut self,
        level: EncryptionLevel,
        outcome: crate::recovery::loss::AckOutcome,
        now: Instant,
    ) -> Effects {
        let _span = trace_span!(
            "quion.proto.connection",
            action = "handle_ack_frame",
            level = encryption_level_name(level)
        )
        .entered();
        let mut effects = Effects::default();
        let updated_rtt = !outcome.newly_acked_packets.is_empty();
        if let Some(largest) = outcome
            .newly_acked_packets
            .iter()
            .map(|packet| packet.packet_number)
            .max()
        {
            self.largest_acked
                .entry(level)
                .and_modify(|current| *current = (*current).max(largest))
                .or_insert(largest);
        }
        trace!(
            acked_packets = outcome.acked_packet_numbers.len(),
            acked_bytes = outcome.acked_bytes,
            lost_packets = outcome.lost_packets.len(),
            ecn_ce_delta = outcome.ecn.ce_delta,
            persistent_congestion = outcome.persistent_congestion,
            "processed ack outcome"
        );
        if level == EncryptionLevel::OneRtt
            && let Some(sample) = outcome.rtt_sample
        {
            self.congestion
                .on_ack_rtt_sample(sample, outcome.largest_acked, outcome.largest_sent);
        }
        if outcome.acked_bytes > 0 {
            self.congestion
                .on_packets_acked_at(outcome.acked_bytes, now);
        }
        let previous_mtu = self.mtud.current_mtu();
        for packet in &outcome.newly_acked_packets {
            self.mtud.on_acked(
                packet.packet_number,
                packet.bytes.min(u64::from(u16::MAX)) as u16,
            );
        }
        if self.mtud.current_mtu() != previous_mtu {
            self.update_scheduler_mtu();
        }
        for packet_number in outcome.acked_packet_numbers {
            if level == EncryptionLevel::OneRtt {
                for packet_level in [EncryptionLevel::ZeroRtt, EncryptionLevel::OneRtt] {
                    self.sent_crypto.remove(&(packet_level, packet_number));
                    if let Some(frame) = self.sent_control.remove(&(packet_level, packet_number)) {
                        self.on_control_frame_acked(packet_number, &frame);
                    }
                    if let Some(frame) = self.remove_sent_stream((packet_level, packet_number)) {
                        if let Some(stream_id) = self.on_stream_frame_acked(&frame) {
                            effects
                                .connection_events
                                .push(ConnectionEvent::StreamFinished { stream_id });
                        }
                        self.recycle_acked_stream_frame(frame);
                    }
                }
            } else {
                self.sent_crypto.remove(&(level, packet_number));
                if let Some(frame) = self.sent_control.remove(&(level, packet_number)) {
                    self.on_control_frame_acked(packet_number, &frame);
                }
                if let Some(frame) = self.remove_sent_stream((level, packet_number)) {
                    if let Some(stream_id) = self.on_stream_frame_acked(&frame) {
                        effects
                            .connection_events
                            .push(ConnectionEvent::StreamFinished { stream_id });
                    }
                    self.recycle_acked_stream_frame(frame);
                }
            }
        }
        if outcome.ecn.ce_delta > 0 {
            self.congestion.on_packets_lost(0);
        }
        if outcome.ecn.validation_failed && self.ecn_enabled {
            self.ecn_enabled = false;
            self.stats.ecn_disabled = true;
            self.stats.ecn_validation_failures =
                self.stats.ecn_validation_failures.saturating_add(1);
            self.qlog_events.push(QlogEvent::RecoveryStateUpdated {
                state: "ecn_disabled",
                level: encryption_level_name(level),
                packet_count: outcome.newly_acked_packets.len(),
            });
        }
        effects.extend(self.handle_detected_losses(
            outcome.lost_packets,
            outcome.persistent_congestion,
            now,
        ));
        if updated_rtt {
            self.qlog_events.push(QlogEvent::RecoveryMetricsUpdated {
                latest_rtt_us: duration_micros(self.recovery.latest_rtt().unwrap_or_default()),
                min_rtt_us: duration_micros(self.recovery.min_rtt().unwrap_or_default()),
                smoothed_rtt_us: duration_micros(self.recovery.smoothed_rtt()),
                rtt_variance_us: duration_micros(self.recovery.rttvar()),
            });
        }
        effects.extend(self.timer_effects(now));
        effects
    }

    fn handle_detected_losses(
        &mut self,
        lost_packets: Vec<LossEvent>,
        persistent_congestion: bool,
        now: Instant,
    ) -> Effects {
        let mut effects = Effects::default();
        let probe_packet = self.mtud.in_flight_probe();
        let (probe_losses, lost_packets): (Vec<_>, Vec<_>) = lost_packets
            .into_iter()
            .partition(|packet| Some(packet.packet_number) == probe_packet);
        for probe in probe_losses {
            self.mtud.on_probe_lost(probe.packet_number);
            self.stats.mtu_probes_lost = self.stats.mtu_probes_lost.saturating_add(1);
            self.stats.packets_lost = self.stats.packets_lost.saturating_add(1);
            self.qlog_events.push(QlogEvent::PacketLost {
                level: encryption_level_name(probe.level),
                packet_number: probe.packet_number,
            });
        }
        let lost_bytes = lost_packets.iter().map(|packet| packet.bytes).sum();
        if lost_bytes > 0 {
            self.congestion.on_packets_lost(lost_bytes);
        }
        if persistent_congestion && !lost_packets.is_empty() {
            self.congestion.on_persistent_congestion();
        }
        let previous_mtu = self.mtud.current_mtu();
        let black_hole_detected = self.mtud.on_non_probe_losses(
            lost_packets.iter().map(|packet| {
                (
                    packet.packet_number,
                    packet.bytes.min(u64::from(u16::MAX)) as u16,
                )
            }),
            now,
        );
        if black_hole_detected {
            self.stats.black_holes_detected = self.stats.black_holes_detected.saturating_add(1);
        }
        if self.mtud.current_mtu() != previous_mtu {
            self.update_scheduler_mtu();
        }
        for lost in lost_packets {
            let mut retransmissions = 0u64;
            self.stats.packets_lost = self.stats.packets_lost.saturating_add(1);
            self.qlog_events.push(QlogEvent::PacketLost {
                level: encryption_level_name(lost.level),
                packet_number: lost.packet_number,
            });
            if let Some(frames) = self.sent_crypto.remove(&(lost.level, lost.packet_number)) {
                let frame_count = frames.len() as u64;
                if self.crypto.requeue_frames(lost.level, frames).is_err() {
                    effects.extend(self.abort());
                    break;
                }
                retransmissions = retransmissions.saturating_add(frame_count);
                effects.extend(self.flush_crypto_frames(lost.level, 1200));
            }
            if let Some(frame) = self.sent_control.remove(&(lost.level, lost.packet_number)) {
                self.requeue_frame_front(frame);
                retransmissions = retransmissions.saturating_add(1);
            }
            if let Some(frame) = self.remove_sent_stream((lost.level, lost.packet_number)) {
                self.requeue_frame_front(frame);
                retransmissions = retransmissions.saturating_add(1);
            }
            self.stats.retransmissions = self.stats.retransmissions.saturating_add(retransmissions);
            effects.connection_events.push(ConnectionEvent::PacketLost {
                level: lost.level,
                packet_number: lost.packet_number,
            });
        }
        self.sync_congestion_stats();
        effects
    }

    fn update_scheduler_mtu(&mut self) {
        self.stats.current_mtu = self.mtud.current_mtu();
        self.congestion
            .on_mtu_update(u64::from(self.mtud.current_mtu()));
        self.scheduler.max_frame_data = usize::from(self.mtud.current_mtu())
            .saturating_sub(STREAM_PACKET_OVERHEAD_BUDGET)
            .max(1);
    }

    pub fn pull_tls_output<S: CryptoSession>(
        &mut self,
        session: &mut S,
        level: EncryptionLevel,
        max_frame_len: usize,
    ) -> Result<Effects> {
        let mut bytes = Vec::new();
        session.write_tls(&mut bytes)?;
        if !bytes.is_empty() {
            self.crypto.push_tls(level, &bytes)?;
        }
        Ok(self.flush_crypto_frames(level, max_frame_len))
    }

    pub fn queue_crypto_bytes(
        &mut self,
        level: EncryptionLevel,
        bytes: &[u8],
        max_frame_len: usize,
    ) -> Result<Effects> {
        if !bytes.is_empty() {
            self.crypto.push_tls(level, bytes)?;
        }
        Ok(self.flush_crypto_frames(level, max_frame_len))
    }

    pub fn receive_crypto_frame<S: CryptoSession>(
        &mut self,
        session: &mut S,
        level: EncryptionLevel,
        offset: u64,
        data: &[u8],
        max_frame_len: usize,
    ) -> Result<Effects> {
        let mut effects = self.receive_crypto_frame_only(session, level, offset, data)?;
        let output = self.pull_tls_output(session, level, max_frame_len)?;
        effects.extend(output);
        Ok(effects)
    }

    pub fn receive_crypto_frame_only<S: CryptoSession>(
        &mut self,
        session: &mut S,
        level: EncryptionLevel,
        offset: u64,
        data: &[u8],
    ) -> Result<Effects> {
        self.crypto.insert_frame(level, offset, data)?;
        let mut effects = Effects::default();
        loop {
            let plaintext = self.crypto.read_tls(level, usize::MAX);
            if plaintext.is_empty() {
                break;
            }
            session.read_tls(&plaintext)?;
            effects
                .connection_events
                .push(ConnectionEvent::CryptoDataReceived(CryptoData {
                    level,
                    offset: self.crypto.space(level).recv.read_offset() - plaintext.len() as u64,
                    bytes: plaintext,
                }));
        }
        Ok(effects)
    }

    pub fn flush_crypto_frames(&mut self, level: EncryptionLevel, max_frame_len: usize) -> Effects {
        let mut effects = Effects::default();
        while let Some(frame) = self.crypto.poll_frame(level, max_frame_len) {
            effects
                .connection_events
                .push(ConnectionEvent::CryptoFrameQueued(frame.clone()));
            effects.crypto_frames.push(frame);
        }
        effects
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn handle_opened_crypto_packet<S: CryptoSession>(
        &mut self,
        session: &mut S,
        packet: crate::crypto::packet::OpenedCryptoPacket,
    ) -> Result<Effects> {
        self.validate_datagram_size(packet.max_datagram_frame_size.or_else(|| {
            packet
                .frames
                .iter()
                .filter(|frame| matches!(frame, Frame::Datagram { .. }))
                .map(Frame::encoded_len)
                .max()
        }))?;
        let mut effects = Effects::default();
        let now = Instant::now();
        let ack_eliciting = packet.frames.iter().any(is_ack_eliciting_frame);
        let previous_largest_ack_eliciting = self.ack.largest_ack_eliciting_received(packet.level);
        let is_new_packet = self.ack.record_received_packet_with_ecn(
            packet.level,
            packet.packet_number,
            ack_eliciting,
            packet.ecn,
        );
        if !is_new_packet {
            return Ok(effects);
        }
        self.qlog_events.push(QlogEvent::PacketReceived {
            level: encryption_level_name(packet.level),
            bytes: packet.consumed as u64,
        });
        for frame in packet.frames {
            match frame {
                Frame::Crypto { offset, data } => {
                    let next = self.receive_crypto_frame_only(
                        session,
                        packet.level,
                        offset.into_inner(),
                        &data,
                    )?;
                    effects.extend(next);
                }
                other => {
                    effects.extend(self.handle_frame_with_datagram_size(
                        packet.level,
                        other,
                        now,
                        None,
                    )?);
                }
            }
        }
        if let Some(ack) = self.take_or_schedule_ack(
            packet.level,
            packet.packet_number,
            previous_largest_ack_eliciting,
            ack_eliciting,
            packet.ecn == Some(EcnCodepoint::Ce),
            now,
        ) {
            self.queue_ack(ack.clone());
            effects.ack_frames.push(ack);
        }
        Ok(effects)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn handle_opened_frame_packet(
        &mut self,
        packet: crate::crypto::packet::OpenedFramePacket,
        now: Instant,
    ) -> Result<Effects> {
        self.validate_datagram_size(packet.max_datagram_frame_size.or_else(|| {
            packet
                .frames
                .iter()
                .filter(|frame| matches!(frame, Frame::Datagram { .. }))
                .map(Frame::encoded_len)
                .max()
        }))?;
        let mut effects = Effects::default();
        let packet_destination_cid = packet
            .frames
            .iter()
            .any(|frame| matches!(frame, Frame::RetireConnectionId(_)))
            .then(|| packet.header.destination_connection_id().clone());
        let ack_eliciting = packet.frames.iter().any(is_ack_eliciting_frame);
        let previous_largest_ack_eliciting = self.ack.largest_ack_eliciting_received(packet.level);
        let is_new_packet = self.ack.record_received_packet_with_ecn(
            packet.level,
            packet.packet_number,
            ack_eliciting,
            packet.ecn,
        );
        if !is_new_packet {
            return Ok(effects);
        }
        for frame in packet.frames {
            let retire_sequence = match &frame {
                Frame::RetireConnectionId(sequence) => Some(*sequence),
                _ => None,
            };
            let mut frame_effects =
                self.handle_frame_with_datagram_size(packet.level, frame, now, None)?;
            if let (Some(sequence), Some(destination_cid)) =
                (retire_sequence, packet_destination_cid.as_ref())
            {
                frame_effects.connection_events.retain(|event| {
                    !matches!(
                        event,
                        ConnectionEvent::FrameReceived(Frame::RetireConnectionId(_))
                    )
                });
                frame_effects
                    .connection_events
                    .push(ConnectionEvent::RetireConnectionIdReceived {
                        sequence,
                        packet_destination_cid: destination_cid.clone(),
                    });
            }
            effects.extend(frame_effects);
        }
        if let Some(ack) = self.take_or_schedule_ack(
            packet.level,
            packet.packet_number,
            previous_largest_ack_eliciting,
            ack_eliciting,
            packet.ecn == Some(EcnCodepoint::Ce),
            now,
        ) {
            self.queue_ack(ack.clone());
            effects.ack_frames.push(ack);
        }
        Ok(effects)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn recv_protected_one_rtt(
        &mut self,
        keys: &mut crate::crypto::rustls::RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
        meta: RecvMeta,
        now: Instant,
    ) -> Result<Effects> {
        self.recv_protected_one_rtt_with_key_update_permission(
            keys,
            packet,
            expected_dst_cid_len,
            OneRttReceiveContext {
                largest_received,
                key_update_permitted: true,
            },
            meta,
            now,
        )
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn recv_protected_one_rtt_with_key_update_permission(
        &mut self,
        keys: &mut crate::crypto::rustls::RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        receive_context: OneRttReceiveContext,
        meta: RecvMeta,
        now: Instant,
    ) -> Result<Effects> {
        self.stats.bytes_received += packet.len() as u64;
        self.stats.packets_received += 1;
        self.record_ecn(meta.ecn);
        let mut opened =
            crate::crypto::packet::FramePacketOpener::open_one_rtt_with_key_update_permission(
                keys,
                packet,
                expected_dst_cid_len,
                receive_context.largest_received,
                receive_context.key_update_permitted,
            )?;
        opened.ecn = meta.ecn;
        self.handle_opened_frame_packet(opened, now)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn recv_protected_one_rtt_owned_with_key_update_permission<O>(
        &mut self,
        keys: &mut crate::crypto::rustls::RustlsKeyStore,
        packet: O,
        expected_dst_cid_len: usize,
        receive_context: OneRttReceiveContext,
        meta: RecvMeta,
        now: Instant,
    ) -> Result<Effects>
    where
        O: AsRef<[u8]> + AsMut<[u8]> + Send + 'static,
    {
        let packet_len = packet.as_ref().len();
        self.stats.bytes_received += packet_len as u64;
        self.stats.packets_received += 1;
        self.record_ecn(meta.ecn);
        let mut opened = crate::crypto::packet::FramePacketOpener::
            open_one_rtt_owned_with_key_update_permission(
                keys,
                packet,
                expected_dst_cid_len,
                receive_context.largest_received,
                receive_context.key_update_permitted,
            )?;
        opened.ecn = meta.ecn;
        self.handle_opened_frame_packet(opened, now)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn recv_protected_one_rtt_with_session<S: CryptoSession>(
        &mut self,
        session: &mut S,
        keys: &mut crate::crypto::rustls::RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        receive_context: OneRttReceiveContext,
        meta: RecvMeta,
    ) -> Result<Effects> {
        self.stats.bytes_received += packet.len() as u64;
        self.stats.packets_received += 1;
        self.record_ecn(meta.ecn);
        let opened =
            crate::crypto::packet::FramePacketOpener::open_one_rtt_with_key_update_permission(
                keys,
                packet,
                expected_dst_cid_len,
                receive_context.largest_received,
                receive_context.key_update_permitted,
            )?;
        self.handle_opened_crypto_packet(
            session,
            crate::crypto::packet::OpenedCryptoPacket {
                level: opened.level,
                header: opened.header,
                packet_number: opened.packet_number,
                ecn: meta.ecn,
                frames: opened.frames,
                max_datagram_frame_size: opened.max_datagram_frame_size,
                consumed: opened.consumed,
            },
        )
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn recv_protected_one_rtt_owned_with_session<S, O>(
        &mut self,
        session: &mut S,
        keys: &mut crate::crypto::rustls::RustlsKeyStore,
        packet: O,
        expected_dst_cid_len: usize,
        receive_context: OneRttReceiveContext,
        meta: RecvMeta,
    ) -> Result<Effects>
    where
        S: CryptoSession,
        O: AsRef<[u8]> + AsMut<[u8]> + Send + 'static,
    {
        let packet_len = packet.as_ref().len();
        self.stats.bytes_received += packet_len as u64;
        self.stats.packets_received += 1;
        self.record_ecn(meta.ecn);
        let opened = crate::crypto::packet::FramePacketOpener::
            open_one_rtt_owned_with_key_update_permission(
                keys,
                packet,
                expected_dst_cid_len,
                receive_context.largest_received,
                receive_context.key_update_permitted,
            )?;
        self.handle_opened_crypto_packet(
            session,
            crate::crypto::packet::OpenedCryptoPacket {
                level: opened.level,
                header: opened.header,
                packet_number: opened.packet_number,
                ecn: meta.ecn,
                frames: opened.frames,
                max_datagram_frame_size: opened.max_datagram_frame_size,
                consumed: opened.consumed,
            },
        )
    }

    pub fn timeout(&self) -> Option<Instant> {
        earlier_deadline(
            earlier_deadline(self.recovery.timeout(), self.one_rtt_ack_deadline),
            self.path_validation.map(|validation| validation.deadline),
        )
    }

    pub fn on_timeout(&mut self, now: Instant) -> Result<Effects> {
        let _span = trace_span!("quion.proto.connection", action = "on_timeout").entered();
        let mut effects = Effects::default();
        if self
            .one_rtt_ack_deadline
            .is_some_and(|deadline| deadline <= now)
            && let Some(ack) = self.take_one_rtt_ack_frame(now)
        {
            self.queue_ack(ack.clone());
            effects.ack_frames.push(ack);
        }
        if self
            .path_validation
            .is_some_and(|validation| validation.deadline <= now)
            && let Some(event) = self.on_path_validation_timeout(now)
        {
            effects.connection_events.push(event);
        }
        if let Some(timeout) = self.recovery.on_timeout(now) {
            match timeout {
                TimeoutOutcome::Loss {
                    lost_packets,
                    persistent_congestion,
                } => {
                    effects.extend(self.handle_detected_losses(
                        lost_packets,
                        persistent_congestion,
                        now,
                    ));
                }
                TimeoutOutcome::Probe(probe) => {
                    debug!(
                        level = encryption_level_name(probe.level),
                        packets = probe.packets,
                        "loss detector requested probe"
                    );
                    self.stats.retransmissions += probe.packets as u64;
                    self.qlog_events.push(QlogEvent::RecoveryStateUpdated {
                        state: "probe_required",
                        level: encryption_level_name(probe.level),
                        packet_count: probe.packets,
                    });
                    let mut queued_probe_payload = false;
                    if let Some(frames) = self.oldest_sent_crypto_frames(probe.level) {
                        if self.crypto.requeue_frames(probe.level, frames).is_err() {
                            effects.extend(self.abort());
                            return Ok(effects);
                        }
                        effects.extend(self.flush_crypto_frames(probe.level, 1200));
                        queued_probe_payload = true;
                    } else if let Some(frame) = self.oldest_sent_control_frame(probe.level) {
                        self.requeue_frame_front(frame);
                        queued_probe_payload = true;
                    } else if let Some(frame) = self.oldest_sent_stream_frame(probe.level) {
                        self.requeue_frame_front(frame);
                        queued_probe_payload = true;
                    }
                    if probe.level == EncryptionLevel::OneRtt {
                        self.one_rtt_probe_packets_pending = self
                            .one_rtt_probe_packets_pending
                            .saturating_add(probe.packets);
                        let ping_count = if queued_probe_payload {
                            probe.packets.saturating_sub(1)
                        } else {
                            probe.packets
                        };
                        for _ in 0..ping_count {
                            self.queue_probe_ping_best_effort();
                        }
                    }
                    effects
                        .connection_events
                        .push(ConnectionEvent::ProbeRequired {
                            level: probe.level,
                            packets: probe.packets,
                        });
                }
            }
        }
        effects.extend(self.timer_effects(now));
        Ok(effects)
    }

    pub const fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    pub const fn flow_control_stats(&self) -> crate::stats::FlowControlStats {
        crate::stats::FlowControlStats {
            send_limit: self.send_flow.max_data(),
            send_consumed: self.send_flow.consumed(),
            receive_limit: self.recv_flow.max_data(),
            receive_received: self.recv_flow.received(),
            receive_window: self.recv_flow.window(),
        }
    }

    pub fn memory_stats(&self) -> crate::stats::ConnectionMemoryStats {
        crate::stats::ConnectionMemoryStats {
            send_stream_bytes: self.send_buffered_stream_data,
            recv_stream_bytes: self.recv_streams.recv_buffered_stream_data(),
            send_datagram_bytes: self.send_datagrams_bytes,
            recv_datagram_bytes: self.recv_datagrams_bytes,
            send_crypto_bytes: self.crypto.send_buffered_bytes(),
            recv_crypto_bytes: self.crypto.recv_buffered_bytes(),
            sent_crypto_bytes: self
                .sent_crypto
                .values()
                .flatten()
                .map(|frame| frame.bytes.len())
                .sum(),
            sent_stream_bytes: self.sent_stream_bytes,
            recycled_stream_capacity_bytes: self
                .recycled_stream_payloads
                .iter()
                .map(Vec::capacity)
                .sum(),
            sent_control_bytes: self
                .sent_control
                .values()
                .map(frame_payload_len)
                .fold(0usize, usize::saturating_add),
            retransmit_stream_bytes: self
                .send_retransmit_streams
                .iter()
                .map(frame_payload_len)
                .sum(),
            pending_control_bytes: self
                .send_control
                .iter()
                .map(frame_payload_len)
                .fold(0usize, usize::saturating_add),
            pending_control_frames: self.send_control.len(),
            pending_ack_frames: self.send_acks.len(),
            retained_ack_ranges: self.ack.retained_range_count(),
            send_stream_states: self.send_streams.len(),
            closed_send_stream_ranges: self.closed_send_streams.iter().map(RangeSet::len).sum(),
            recv_stream_states: self.recv_streams.recv_stream_count(),
            closed_recv_stream_ranges: self.recv_streams.closed_recv_stream_range_count(),
            qlog_events: self.qlog_events.len(),
            qlog_event_bytes: self
                .qlog_events
                .len()
                .saturating_mul(core::mem::size_of::<QlogEvent>()),
        }
    }

    pub fn stream_flow_control_stats(
        &self,
        stream_id: StreamId,
    ) -> crate::stats::StreamFlowControlStats {
        let send = self.send_streams.get(&stream_id);
        let receive = self.recv_streams.recv_stream(stream_id);
        crate::stats::StreamFlowControlStats {
            send_limit: send.map(|stream| stream.flow.max_data()),
            send_consumed: send.map(|stream| stream.flow.consumed()),
            receive_limit: receive.map(crate::streams::RecvStreamState::flow_limit),
            receive_received: receive.map(crate::streams::RecvStreamState::flow_received),
            receive_window: receive.map(crate::streams::RecvStreamState::flow_window),
        }
    }

    pub const fn ack_tracker(&self) -> &AckTracker {
        &self.ack
    }

    pub fn largest_acked_packet_number(&self, level: EncryptionLevel) -> Option<u64> {
        self.largest_acked.get(&level).copied()
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    #[doc(hidden)]
    pub fn has_pending_transmit(&self) -> bool {
        !self.send_acks.is_empty()
            || !self.send_control.is_empty()
            || !self.send_datagrams.is_empty()
            || !self.send_retransmit_streams.is_empty()
            || !self.stream_schedule.is_empty()
    }

    #[doc(hidden)]
    pub fn has_immediate_transmit(&self) -> bool {
        !self.send_acks.is_empty()
            || (self.can_send_one_rtt(1)
                && (!self.send_control.is_empty()
                    || !self.send_datagrams.is_empty()
                    || !self.send_retransmit_streams.is_empty()))
            || (!self.stream_schedule.is_empty()
                && self.can_send_one_rtt(self.scheduler.max_frame_data.saturating_add(32) as u64))
    }

    /// Encoded size of a queued ACK at the requested crypto level.
    pub fn crypto_ack_size(&self, level: EncryptionLevel) -> usize {
        self.send_acks
            .iter()
            .find(|ack| ack.level == level)
            .map_or(0, |ack| ack.frame.encoded_len())
    }

    /// Removes the pending ACK for an Initial or Handshake packet number
    /// space so the crypto transport can encode it at the matching encryption
    /// level.
    #[doc(hidden)]
    pub fn take_crypto_ack(&mut self, level: EncryptionLevel) -> Option<Frame> {
        if !matches!(level, EncryptionLevel::Initial | EncryptionLevel::Handshake) {
            return None;
        }
        let position = self.send_acks.iter().position(|ack| ack.level == level)?;
        self.send_acks.remove(position).map(|ack| ack.frame)
    }

    /// Minimum idle timeout derived from three probe intervals, without backoff.
    pub fn idle_timeout_floor(&self) -> std::time::Duration {
        self.recovery.idle_timeout_floor()
    }

    #[doc(hidden)]
    pub fn close_drain_duration(&self) -> std::time::Duration {
        self.recovery.close_drain_duration()
    }

    #[doc(hidden)]
    pub fn one_rtt_key_retirement_duration(&self) -> std::time::Duration {
        self.recovery.one_rtt_key_retirement_duration()
    }

    fn poll_stream_frame(&mut self) -> Option<Frame> {
        if self.stream_schedule.is_empty()
            && let Some(stream_id) = self.pending_send_streams.first().copied()
        {
            if let Some(stream) = self.send_streams.get_mut(&stream_id) {
                stream.queued = false;
            }
            self.mark_stream_schedulable(stream_id);
        }
        let scheduled = self.stream_schedule.len();
        for _ in 0..scheduled {
            let stream_id = self.stream_schedule.pop_front()?;
            if !self.stream_is_within_peer_limit(stream_id) {
                if let Some(stream) = self.send_streams.get_mut(&stream_id) {
                    stream.queued = false;
                }
                continue;
            }
            let recycled_payload = self.recycled_stream_payloads.pop().unwrap_or_default();
            let Some(stream) = self.send_streams.get_mut(&stream_id) else {
                continue;
            };
            stream.queued = false;
            if stream.stopped_error.is_some() {
                self.send_buffered_stream_data = self
                    .send_buffered_stream_data
                    .saturating_sub(stream.buffer.queued_len());
                stream.buffer = SendBuffer::default();
                continue;
            }
            let Some(chunk) = stream.buffer.poll_frame_with_connection_flow_reusing(
                &mut stream.flow,
                Some(&mut self.send_flow),
                self.scheduler.max_frame_data,
                recycled_payload,
            ) else {
                if !stream.buffer.is_empty() && self.send_flow.available() == 0 {
                    if self.data_blocked_at == Some(self.send_flow.max_data()) {
                        continue;
                    }
                    let maximum = self.send_flow.max_data();
                    self.data_blocked_at = Some(maximum);
                    self.stats.data_blocked_events =
                        self.stats.data_blocked_events.saturating_add(1);
                    trace!(maximum, "connection flow control blocked stream transmit");
                    return Some(Frame::DataBlocked(
                        VarInt::new(maximum).unwrap_or(VarInt::MAX),
                    ));
                }
                if !stream.buffer.is_empty() && stream.blocked_at != Some(stream.flow.max_data()) {
                    let maximum = stream.flow.max_data();
                    stream.blocked_at = Some(maximum);
                    self.stats.stream_data_blocked_events =
                        self.stats.stream_data_blocked_events.saturating_add(1);
                    trace!(
                        stream_id = stream_id.0.into_inner(),
                        maximum, "stream flow control blocked stream transmit"
                    );
                    return Some(Frame::StreamDataBlocked {
                        stream_id: stream_id.0,
                        maximum: VarInt::new(maximum).unwrap_or(VarInt::MAX),
                    });
                }
                continue;
            };
            self.send_buffered_stream_data = self
                .send_buffered_stream_data
                .saturating_sub(chunk.bytes.len());
            if chunk.fin {
                self.pending_send_streams.remove(&stream_id);
            }
            if !stream.buffer.is_empty()
                || (stream.buffer.final_offset() == Some(stream.buffer.next_offset()) && !chunk.fin)
            {
                self.mark_stream_schedulable(stream_id);
            }
            trace!(
                stream_id = stream_id.0.into_inner(),
                offset = chunk.offset,
                len = chunk.bytes.len(),
                fin = chunk.fin,
                "polled stream frame for transmit"
            );
            return chunk.into_stream_frame(stream_id).ok();
        }
        None
    }

    fn is_locally_initiated(&self, stream_id: StreamId) -> bool {
        let initiator_bit = stream_id.0.into_inner() & 0x01;
        initiator_bit
            == match self.local_initiator {
                StreamInitiator::Client => 0,
                StreamInitiator::Server => 1,
            }
    }

    fn stream_is_within_peer_limit(&self, stream_id: StreamId) -> bool {
        if !self.is_locally_initiated(stream_id) {
            return true;
        }
        let ordinal = stream_id.0.into_inner() / 4;
        let maximum = if is_unidirectional_stream(stream_id) {
            self.peer_max_streams_uni
        } else {
            self.peer_max_streams_bidi
        };
        ordinal < maximum
    }

    fn poll_frame_for_transmit(&mut self, now: Instant) -> Option<(Frame, bool, Option<Instant>)> {
        let send_at = self.congestion.send_at(now);
        self.poll_ack_frame()
            .map(|frame| (frame, false, send_at))
            .or_else(|| {
                if !self.can_send_one_rtt(1) {
                    return None;
                }
                self.poll_control_frame()
                    .map(|frame| {
                        let ack_eliciting = is_ack_eliciting(&frame);
                        (frame, ack_eliciting, send_at)
                    })
                    .or_else(|| {
                        self.poll_datagram_frame()
                            .map(|frame| (frame, true, send_at))
                    })
                    .or_else(|| {
                        self.poll_retransmit_stream_frame()
                            .map(|frame| (frame, true, send_at))
                    })
                    .or_else(|| {
                        self.poll_stream_frame_if_congestion_allows()
                            .map(|(frame, ack_eliciting)| (frame, ack_eliciting, send_at))
                    })
            })
    }

    fn commit_transmit(
        &mut self,
        level: EncryptionLevel,
        bytes: u64,
        ack_eliciting: bool,
        now: Instant,
    ) {
        self.stats.bytes_sent += bytes;
        self.stats.packets_sent += 1;
        let packet_number = self.next_one_rtt_packet_number;
        self.next_one_rtt_packet_number = self.next_one_rtt_packet_number.saturating_add(1);
        let _ = self.record_sent_packet(level, packet_number, bytes, ack_eliciting, now);
        if level == EncryptionLevel::OneRtt && ack_eliciting {
            self.one_rtt_probe_packets_pending =
                self.one_rtt_probe_packets_pending.saturating_sub(1);
        }
    }

    fn commit_frame_transmit(
        &mut self,
        level: EncryptionLevel,
        frame: Frame,
        bytes: u64,
        ack_eliciting: bool,
        now: Instant,
    ) {
        let packet_number = self.next_one_rtt_packet_number;
        let frame_type = frame_type_name(&frame);
        if matches!(frame, Frame::AckFrequency { .. }) {
            self.stats.ack_frequency_frames_sent =
                self.stats.ack_frequency_frames_sent.saturating_add(1);
        } else if matches!(frame, Frame::ImmediateAck) {
            self.stats.immediate_ack_frames_sent =
                self.stats.immediate_ack_frames_sent.saturating_add(1);
        }
        if let Frame::AckFrequency {
            requested_max_ack_delay,
            ..
        } = &frame
        {
            let requested = Duration::from_micros(requested_max_ack_delay.into_inner());
            self.in_flight_ack_frequency = Some((packet_number, requested));
            self.recovery
                .set_max_ack_delay(self.peer_max_ack_delay.max(requested));
        }
        if matches!(frame, Frame::Stream { .. }) {
            let frame_bytes = frame_payload_len(&frame);
            let replaced = self.sent_stream.insert((level, packet_number), frame);
            self.sent_stream_bytes = self
                .sent_stream_bytes
                .saturating_add(frame_bytes)
                .saturating_sub(replaced.as_ref().map_or(0, frame_payload_len));
        } else if is_retransmittable_control_frame(&frame) {
            self.sent_control.insert((level, packet_number), frame);
        }
        self.qlog_events.push(QlogEvent::PacketSent {
            level: encryption_level_name(level),
            packet_number,
            bytes,
            ack_eliciting,
            frame_type,
        });
        self.commit_transmit(level, bytes, ack_eliciting, now);
    }

    fn on_control_frame_acked(&mut self, packet_number: u64, frame: &Frame) {
        if let Frame::ResetStream { stream_id, .. } = frame {
            self.close_reset_send_stream(StreamId(*stream_id));
            return;
        }
        if !matches!(frame, Frame::AckFrequency { .. })
            || self
                .in_flight_ack_frequency
                .is_none_or(|(in_flight, _)| in_flight != packet_number)
        {
            return;
        }
        let Some((_, requested)) = self.in_flight_ack_frequency.take() else {
            return;
        };
        self.peer_max_ack_delay = requested;
        self.recovery
            .set_ack_delay_config(self.peer_max_ack_delay, self.peer_ack_delay_exponent);
    }

    fn close_reset_send_stream(&mut self, stream_id: StreamId) {
        self.send_streams.remove(&stream_id);
        self.pending_send_streams.remove(&stream_id);
        self.stream_schedule.retain(|queued| *queued != stream_id);
        let sent_keys = self
            .sent_stream
            .iter()
            .filter_map(|(key, frame)| {
                matches!(
                    frame,
                    Frame::Stream {
                        stream_id: sent,
                        ..
                    } if *sent == stream_id.0
                )
                .then_some(*key)
            })
            .collect::<SmallVec<[_; 8]>>();
        for key in sent_keys {
            if let Some(frame) = self.remove_sent_stream(key) {
                self.recycle_acked_stream_frame(frame);
            }
        }
        self.send_retransmit_streams.retain(|frame| {
            !matches!(
                frame,
                Frame::Stream {
                    stream_id: queued,
                    ..
                } if *queued == stream_id.0
            )
        });
        let stream_type = (stream_id.0.into_inner() & 0x03) as usize;
        let ordinal = stream_id.ordinal();
        self.closed_send_streams[stream_type].insert(ordinal, ordinal.saturating_add(1));
    }

    fn poll_stream_frame_if_congestion_allows(&mut self) -> Option<(Frame, bool)> {
        let frame_budget = self.scheduler.max_frame_data.saturating_add(32) as u64;
        if !self.can_send_one_rtt(frame_budget) {
            return None;
        }
        self.poll_stream_frame().map(|frame| (frame, true))
    }

    fn can_send_one_rtt(&self, bytes: u64) -> bool {
        self.one_rtt_probe_packets_pending != 0 || self.congestion.can_send(bytes)
    }

    fn poll_control_frame(&mut self) -> Option<Frame> {
        self.send_control.pop_front()
    }

    fn remove_sent_stream(&mut self, key: (EncryptionLevel, u64)) -> Option<Frame> {
        let frame = self.sent_stream.remove(&key)?;
        self.sent_stream_bytes = self
            .sent_stream_bytes
            .saturating_sub(frame_payload_len(&frame));
        Some(frame)
    }

    fn recycle_acked_stream_frame(&mut self, frame: Frame) {
        let Frame::Stream { data, .. } = frame else {
            return;
        };
        if self.recycled_stream_payloads.len() >= MAX_RECYCLED_STREAM_PAYLOADS {
            return;
        }
        let mut data: Vec<u8> = match data.try_into_mut() {
            Ok(data) => data.into(),
            Err(_) => return,
        };
        data.clear();
        self.recycled_stream_payloads.push(data);
    }

    fn on_stream_frame_acked(&mut self, frame: &Frame) -> Option<StreamId> {
        let Frame::Stream { stream_id, fin, .. } = frame else {
            return None;
        };
        let stream_id = StreamId(*stream_id);
        if *fin && let Some(stream) = self.send_streams.get_mut(&stream_id) {
            stream.fin_acked = true;
        }
        self.try_close_send_stream(stream_id).then_some(stream_id)
    }

    fn try_close_send_stream(&mut self, stream_id: StreamId) -> bool {
        let terminal = self.send_streams.get(&stream_id).is_some_and(|stream| {
            stream.fin_acked
                && stream.buffer.is_empty()
                && stream.buffer.final_offset().is_some()
                && !stream.queued
        });
        if !terminal || self.pending_send_streams.contains(&stream_id) {
            return false;
        }
        let has_outstanding = self
            .sent_stream
            .values()
            .chain(self.send_retransmit_streams.iter())
            .any(|frame| {
                matches!(
                    frame,
                    Frame::Stream {
                        stream_id: queued,
                        ..
                    } if *queued == stream_id.0
                )
            });
        if has_outstanding {
            return false;
        }
        self.send_streams.remove(&stream_id);
        self.stream_schedule.retain(|queued| *queued != stream_id);
        let stream_type = (stream_id.0.into_inner() & 0x03) as usize;
        let ordinal = stream_id.ordinal();
        self.closed_send_streams[stream_type].insert(ordinal, ordinal.saturating_add(1));
        true
    }

    /// Returns whether the sending side reached a terminal acknowledged state.
    pub fn is_send_stream_finished(&self, stream_id: StreamId) -> bool {
        let stream_type = (stream_id.0.into_inner() & 0x03) as usize;
        self.closed_send_streams[stream_type].contains(stream_id.ordinal())
    }

    #[cfg(feature = "zero-rtt")]
    fn poll_zero_rtt_control_frame(&mut self) -> Option<Frame> {
        let position = self
            .send_control
            .iter()
            .position(|frame| frame_allowed_at_level(frame, EncryptionLevel::ZeroRtt))?;
        self.send_control.remove(position)
    }

    fn poll_datagram_frame(&mut self) -> Option<Frame> {
        loop {
            let data = self.send_datagrams.pop_front()?;
            self.send_datagrams_bytes = self.send_datagrams_bytes.saturating_sub(data.len());
            let frame = Frame::Datagram { data };
            if frame.encoded_len().saturating_add(64) <= usize::from(self.current_mtu()) {
                return Some(frame);
            }
            self.stats.datagrams_dropped = self.stats.datagrams_dropped.saturating_add(1);
        }
    }

    fn poll_retransmit_stream_frame(&mut self) -> Option<Frame> {
        self.send_retransmit_streams.pop_front()
    }

    fn poll_ack_frame(&mut self) -> Option<Frame> {
        let position = self
            .send_acks
            .iter()
            .position(|ack| ack.level == EncryptionLevel::OneRtt)?;
        self.send_acks.remove(position).map(|ack| ack.frame)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn take_or_schedule_ack(
        &mut self,
        level: EncryptionLevel,
        packet_number: u64,
        previous_largest_ack_eliciting: Option<u64>,
        ack_eliciting: bool,
        force_immediate: bool,
        now: Instant,
    ) -> Option<GeneratedAck> {
        if !self.ack.has_pending_ack(level) {
            return None;
        }
        if matches!(level, EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt) {
            // RFC 9000 §13.2.1 requires immediate acknowledgments before the
            // handshake is confirmed. In particular, delaying the first
            // HANDSHAKE_DONE acknowledgment can add max_ack_delay to the
            // confirmation tail and postpone key retirement at the server.
            if !self.recovery.is_handshake_confirmed() {
                return self.take_one_rtt_ack_frame(now);
            }
            if ack_eliciting {
                self.one_rtt_ack_eliciting_since_last_ack =
                    self.one_rtt_ack_eliciting_since_last_ack.saturating_add(1);
            }
            let reordered = ack_eliciting
                && self.ack.requires_immediate_ack_for_reordering(
                    level,
                    packet_number,
                    previous_largest_ack_eliciting,
                    self.reordering_threshold,
                );
            if force_immediate
                || self.immediate_ack_requested
                || reordered
                || self.one_rtt_ack_eliciting_since_last_ack > self.ack_eliciting_threshold
            {
                return self.take_one_rtt_ack_frame(now);
            }
            self.schedule_one_rtt_ack(now);
            return None;
        }
        self.ack
            .take_ack_frame(level, Duration::ZERO, self.local_ack_delay_exponent)
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn schedule_one_rtt_ack(&mut self, now: Instant) {
        if self.one_rtt_ack_deadline.is_some() {
            return;
        }
        self.one_rtt_ack_delay_start = Some(now);
        self.one_rtt_ack_deadline = Some(now + self.local_max_ack_delay);
    }

    fn take_one_rtt_ack_frame(&mut self, now: Instant) -> Option<GeneratedAck> {
        let delay = self
            .one_rtt_ack_delay_start
            .map_or(Duration::ZERO, |start| now.saturating_duration_since(start));
        let ack = self.ack.take_ack_frame(
            EncryptionLevel::OneRtt,
            delay,
            self.local_ack_delay_exponent,
        );
        if ack.is_some() {
            self.one_rtt_ack_delay_start = None;
            self.one_rtt_ack_deadline = None;
            self.one_rtt_ack_eliciting_since_last_ack = 0;
            self.immediate_ack_requested = false;
        }
        ack
    }

    fn requeue_frame_front(&mut self, frame: Frame) {
        match frame {
            Frame::Datagram { data } => {
                self.send_datagrams_bytes = self.send_datagrams_bytes.saturating_add(data.len());
                self.send_datagrams.push_front(data);
            }
            Frame::Stream { stream_id, .. } => {
                let stream_id = StreamId(stream_id);
                let reliable_size = self
                    .send_streams
                    .get(&stream_id)
                    .and_then(|stream| stream.reliable_reset)
                    .map(|(_, _, reliable_size)| reliable_size);
                let mut frame = frame;
                if reliable_size.is_none_or(|reliable_size| {
                    trim_stream_frame_to_reliable(&mut frame, stream_id, reliable_size)
                }) {
                    self.send_retransmit_streams.push_front(frame);
                }
            }
            Frame::Ack { .. } => self.queue_ack_front(GeneratedAck {
                level: EncryptionLevel::OneRtt,
                frame,
            }),
            other => self.queue_control_frame_front_best_effort(other),
        }
    }

    fn queue_ack(&mut self, ack: GeneratedAck) {
        self.send_acks.retain(|queued| queued.level != ack.level);
        self.send_acks.push_back(ack);
    }

    fn queue_ack_front(&mut self, ack: GeneratedAck) {
        self.send_acks.retain(|queued| queued.level != ack.level);
        self.send_acks.push_front(ack);
    }

    fn queue_control_frame(&mut self, frame: Frame) -> Result<()> {
        self.coalesce_control_frame(&frame);
        if self.send_control.len() >= self.max_queued_control_frames {
            self.note_dropped_control_frame();
            return Err(crate::error::CodecError::BufferLimitExceeded);
        }
        self.send_control.push_back(frame);
        Ok(())
    }

    fn queue_control_frame_best_effort(&mut self, frame: Frame) {
        let _ = self.queue_control_frame(frame);
    }

    fn queue_probe_ping_best_effort(&mut self) {
        if self.send_control.len() >= self.max_queued_control_frames {
            self.note_dropped_control_frame();
            return;
        }
        self.send_control.push_back(Frame::Ping);
    }

    fn queue_control_frame_front_best_effort(&mut self, frame: Frame) {
        self.coalesce_control_frame(&frame);
        if self.max_queued_control_frames == 0 {
            self.note_dropped_control_frame();
            return;
        }
        if self.send_control.len() >= self.max_queued_control_frames {
            self.send_control.pop_back();
            self.note_dropped_control_frame();
        }
        self.send_control.push_front(frame);
    }

    fn coalesce_control_frame(&mut self, frame: &Frame) {
        self.send_control
            .retain(|queued| !control_frame_supersedes(frame, queued));
    }

    fn note_dropped_control_frame(&mut self) {
        self.stats.control_frames_dropped = self.stats.control_frames_dropped.saturating_add(1);
    }

    fn queue_send_datagram(&mut self, data: bytes::Bytes) -> Result<()> {
        if self.max_queued_datagrams == 0 || data.len() > self.max_queued_datagram_bytes {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::FlowControlError,
            ));
        }
        if self.send_datagrams.len() >= self.max_queued_datagrams
            || self.send_datagrams_bytes.saturating_add(data.len()) > self.max_queued_datagram_bytes
        {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::FlowControlError,
            ));
        }
        self.send_datagrams_bytes = self.send_datagrams_bytes.saturating_add(data.len());
        self.send_datagrams.push_back(data);
        Ok(())
    }

    fn queue_received_datagram(&mut self, data: bytes::Bytes) {
        if self.max_queued_datagrams == 0 || data.len() > self.max_queued_datagram_bytes {
            self.record_datagram_drop(data.len());
            return;
        }
        while self.recv_datagrams.len() >= self.max_queued_datagrams
            || self.recv_datagrams_bytes.saturating_add(data.len()) > self.max_queued_datagram_bytes
        {
            let Some(dropped) = self.recv_datagrams.pop_front() else {
                self.record_datagram_drop(data.len());
                return;
            };
            self.recv_datagrams_bytes = self.recv_datagrams_bytes.saturating_sub(dropped.len());
            self.record_datagram_drop(dropped.len());
        }
        self.recv_datagrams_bytes = self.recv_datagrams_bytes.saturating_add(data.len());
        self.recv_datagrams.push_back(data);
    }

    fn trim_received_datagram_queue(&mut self) {
        while self.recv_datagrams.len() > self.max_queued_datagrams
            || self.recv_datagrams_bytes > self.max_queued_datagram_bytes
        {
            let Some(dropped) = self.recv_datagrams.pop_front() else {
                break;
            };
            self.recv_datagrams_bytes = self.recv_datagrams_bytes.saturating_sub(dropped.len());
            self.record_datagram_drop(dropped.len());
        }
    }

    fn record_datagram_drop(&mut self, len: usize) {
        self.stats.datagrams_dropped = self.stats.datagrams_dropped.saturating_add(1);
        self.qlog_events.push(QlogEvent::DatagramStateUpdated {
            state: "dropped",
            len,
        });
    }

    fn mark_stream_schedulable(&mut self, stream_id: StreamId) {
        if !self.pending_send_streams.contains(&stream_id) {
            return;
        }
        if let Some(stream) = self.send_streams.get_mut(&stream_id)
            && !stream.queued
        {
            stream.queued = true;
            let priority = stream.priority;
            let insertion_index = self
                .stream_schedule
                .iter()
                .position(|queued| {
                    self.send_streams
                        .get(queued)
                        .is_some_and(|stream| stream.priority > priority)
                })
                .unwrap_or(self.stream_schedule.len());
            self.stream_schedule.insert(insertion_index, stream_id);
        }
    }

    fn stop_send_stream(&mut self, stream_id: StreamId, error_code: VarInt) -> Result<bool> {
        if self.is_send_stream_finished(stream_id) {
            return Ok(false);
        }
        let (final_size, queued_len) = {
            let stream = self
                .send_streams
                .entry(stream_id)
                .or_insert_with(|| SendStreamState::new(0));
            if stream.stopped_error.is_some() {
                return Ok(false);
            }
            (
                VarInt::new(stream.buffer.reset_final_size()).unwrap_or(VarInt::MAX),
                stream.buffer.queued_len(),
            )
        };
        self.queue_control_frame(Frame::ResetStream {
            stream_id: stream_id.0,
            error_code,
            final_size,
        })?;
        let Some(stream) = self.send_streams.get_mut(&stream_id) else {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::InternalError,
            ));
        };
        self.send_buffered_stream_data = self.send_buffered_stream_data.saturating_sub(queued_len);
        self.pending_send_streams.remove(&stream_id);
        stream.stopped_error = Some(error_code);
        stream.queued = false;
        stream.buffer = SendBuffer::default();
        self.qlog_events.push(QlogEvent::StreamStateUpdated {
            stream_id: stream_id.0.into_inner(),
            state: "reset_sent",
            error_code: Some(varint_inner(error_code)),
            final_size: Some(final_size.into_inner()),
        });
        Ok(true)
    }

    fn reset_recv_stream(
        &mut self,
        stream_id: StreamId,
        final_size: u64,
        error_code: VarInt,
    ) -> Result<()> {
        if self.recv_streams.is_recv_stream_closed(stream_id) {
            return Ok(());
        }
        let received = self.recv_streams.received_stream_data(stream_id);
        let newly_accounted = final_size.saturating_sub(received);
        self.recv_flow.validate_additional(newly_accounted)?;
        let newly_accounted = self
            .recv_streams
            .reset_stream(stream_id, final_size, error_code)?;
        // The preflight above guarantees this cannot fail. Keep the update in
        // one place so RESET_STREAM and STREAM consume identical connection
        // flow-control credit.
        self.recv_flow.add_received(newly_accounted)?;
        self.release_recv_credit(Instant::now());
        Ok(())
    }

    fn reset_recv_stream_at(
        &mut self,
        stream_id: StreamId,
        final_size: u64,
        reliable_size: u64,
        error_code: VarInt,
    ) -> Result<()> {
        if self.recv_streams.is_recv_stream_closed(stream_id) {
            return Ok(());
        }
        if !self.peer_can_send_on_stream(stream_id) {
            return Err(crate::error::CodecError::Transport(
                TransportErrorCode::StreamStateError,
            ));
        }
        let received = self.recv_streams.received_stream_data(stream_id);
        self.recv_flow
            .validate_additional(final_size.saturating_sub(received))?;
        let newly_accounted =
            self.recv_streams
                .reset_stream_at(stream_id, final_size, reliable_size, error_code)?;
        self.recv_flow.add_received(newly_accounted)?;
        self.release_recv_credit(Instant::now());
        Ok(())
    }

    fn queue_max_streams(&mut self, limit_update: Option<(StreamLimitKind, u64)>) {
        let Some((kind, maximum)) = limit_update else {
            return;
        };
        let maximum = VarInt::new(maximum).unwrap_or(VarInt::MAX);
        match kind {
            StreamLimitKind::Bidi => {
                self.queue_control_frame_best_effort(Frame::MaxStreamsBidi(maximum));
            }
            StreamLimitKind::Uni => {
                self.queue_control_frame_best_effort(Frame::MaxStreamsUni(maximum));
            }
        }
    }

    fn timer_effects(&self, now: Instant) -> Effects {
        let mut effects = Effects::default();
        if let Some(at) = self.recovery.timeout() {
            effects.wakeups.push(Deadline {
                timer: self.recovery.timer(),
                at,
            });
        }
        if let Some(at) = self.one_rtt_ack_deadline {
            effects.wakeups.push(Deadline {
                timer: crate::timer::Timer::AckDelay,
                at,
            });
        }
        if let Some(validation) = self.path_validation {
            effects.wakeups.push(Deadline {
                timer: crate::timer::Timer::PathValidation,
                at: validation.deadline,
            });
        }
        if let Some(at) = self.congestion.next_send_at(now) {
            effects.wakeups.push(Deadline {
                timer: crate::timer::Timer::Pacing,
                at,
            });
        }
        effects
    }

    fn on_path_validation_timeout(&mut self, now: Instant) -> Option<ConnectionEvent> {
        let validation = self.path_validation.as_mut()?;
        if validation.attempts < MAX_PATH_VALIDATION_ATTEMPTS {
            validation.attempts += 1;
            validation.deadline = now + PATH_VALIDATION_TIMEOUT;
            let challenge = validation.challenge;
            self.queue_control_frame_best_effort(Frame::PathChallenge(challenge));
            self.qlog_events.push(QlogEvent::PathStateUpdated {
                state: "challenge_retransmitted",
            });
            None
        } else {
            self.path_validation = None;
            self.qlog_events.push(QlogEvent::PathStateUpdated {
                state: "validation_failed",
            });
            Some(ConnectionEvent::PathValidationFailed)
        }
    }

    fn oldest_sent_crypto_frames(&self, level: EncryptionLevel) -> Option<Vec<CryptoFrame>> {
        self.sent_crypto
            .iter()
            .filter(|((packet_level, _), _)| *packet_level == level)
            .min_by_key(|((_, packet_number), _)| *packet_number)
            .map(|(_, frames)| frames.clone())
    }

    fn oldest_sent_control_frame(&self, level: EncryptionLevel) -> Option<Frame> {
        self.sent_control
            .iter()
            .filter(|((packet_level, _), _)| *packet_level == level)
            .min_by_key(|((_, packet_number), _)| *packet_number)
            .map(|(_, frame)| frame.clone())
    }

    fn oldest_sent_stream_frame(&self, level: EncryptionLevel) -> Option<Frame> {
        self.sent_stream
            .iter()
            .filter(|((packet_level, _), _)| *packet_level == level)
            .min_by_key(|((_, packet_number), _)| *packet_number)
            .map(|(_, frame)| frame.clone())
    }

    fn sync_congestion_stats(&mut self) {
        self.stats.bytes_in_flight = self.congestion.stats().bytes_in_flight;
        self.stats.congestion_window = self.congestion.stats().congestion_window;
        self.stats.smoothed_rtt = Some(self.recovery.smoothed_rtt());
        self.stats.latest_rtt = self.recovery.latest_rtt();
        self.stats.min_rtt = self.recovery.min_rtt();
        self.stats.rtt_variance = self.recovery.latest_rtt().map(|_| self.recovery.rttvar());
        self.congestion
            .set_smoothed_rtt(self.recovery.smoothed_rtt());
    }

    fn record_ecn(&mut self, ecn: Option<EcnCodepoint>) {
        match ecn {
            Some(EcnCodepoint::Ect0) => {
                self.stats.ecn_ect0_packets = self.stats.ecn_ect0_packets.saturating_add(1);
            }
            Some(EcnCodepoint::Ect1) => {
                self.stats.ecn_ect1_packets = self.stats.ecn_ect1_packets.saturating_add(1);
            }
            Some(EcnCodepoint::Ce) => {
                self.stats.ecn_ce_packets = self.stats.ecn_ce_packets.saturating_add(1);
            }
            None => {}
        }
    }
}

fn frame_payload_len(frame: &Frame) -> usize {
    match frame {
        Frame::Crypto { data, .. } | Frame::NewToken(data) => data.len(),
        Frame::Stream { data, .. } | Frame::Datagram { data } => data.len(),
        Frame::ConnectionClose { reason, .. } | Frame::ApplicationClose { reason, .. } => {
            reason.len()
        }
        Frame::NewConnectionId { connection_id, .. } => connection_id.len(),
        _ => 0,
    }
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

const fn is_unidirectional_stream(stream_id: StreamId) -> bool {
    stream_id.0.into_inner() & 0x02 != 0
}

fn trim_stream_frame_to_reliable(
    frame: &mut Frame,
    target_stream: StreamId,
    reliable_size: u64,
) -> bool {
    let Frame::Stream {
        stream_id,
        offset,
        fin,
        data,
    } = frame
    else {
        return true;
    };
    if *stream_id != target_stream.0 {
        return true;
    }
    let offset = offset.into_inner();
    if offset >= reliable_size {
        return false;
    }
    let keep = usize::try_from(reliable_size - offset)
        .unwrap_or(usize::MAX)
        .min(data.len());
    data.truncate(keep);
    *fin = false;
    true
}

fn is_ack_eliciting(frame: &Frame) -> bool {
    !matches!(frame, Frame::Padding | Frame::Ack { .. })
}

fn frame_allowed_at_level(frame: &Frame, level: EncryptionLevel) -> bool {
    match level {
        EncryptionLevel::Initial | EncryptionLevel::Handshake => matches!(
            frame,
            Frame::Padding
                | Frame::Ping
                | Frame::Ack { .. }
                | Frame::Crypto { .. }
                | Frame::ConnectionClose { .. }
        ),
        EncryptionLevel::ZeroRtt => !matches!(
            frame,
            Frame::Ack { .. }
                | Frame::Crypto { .. }
                | Frame::NewToken(_)
                | Frame::RetireConnectionId(_)
                | Frame::PathResponse(_)
                | Frame::HandshakeDone
                | Frame::AckFrequency { .. }
                | Frame::ImmediateAck
        ),
        EncryptionLevel::OneRtt => true,
    }
}

fn frame_requires_connection_event(frame: &Frame) -> bool {
    matches!(
        frame,
        Frame::ConnectionClose { .. }
            | Frame::ApplicationClose { .. }
            | Frame::PathChallenge(_)
            | Frame::MaxStreamData { .. }
            | Frame::MaxData(_)
            | Frame::MaxStreamsBidi(_)
            | Frame::MaxStreamsUni(_)
            | Frame::NewConnectionId { .. }
            | Frame::RetireConnectionId(_)
    )
}

fn is_retransmittable_control_frame(frame: &Frame) -> bool {
    matches!(
        frame,
        Frame::ResetStream { .. }
            | Frame::ResetStreamAt { .. }
            | Frame::StopSending { .. }
            | Frame::MaxData(_)
            | Frame::MaxStreamData { .. }
            | Frame::MaxStreamsBidi(_)
            | Frame::MaxStreamsUni(_)
            | Frame::DataBlocked(_)
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlockedBidi(_)
            | Frame::StreamsBlockedUni(_)
            | Frame::NewConnectionId { .. }
            | Frame::RetireConnectionId(_)
            | Frame::PathChallenge(_)
            | Frame::ConnectionClose { .. }
            | Frame::ApplicationClose { .. }
            | Frame::HandshakeDone
            | Frame::AckFrequency { .. }
    )
}

fn control_frame_supersedes(new: &Frame, queued: &Frame) -> bool {
    match (new, queued) {
        (Frame::Ping, Frame::Ping) | (Frame::HandshakeDone, Frame::HandshakeDone) => true,
        (
            Frame::AckFrequency {
                sequence: new_sequence,
                ..
            },
            Frame::AckFrequency {
                sequence: old_sequence,
                ..
            },
        ) => new_sequence >= old_sequence,
        (Frame::MaxData(new), Frame::MaxData(old))
        | (Frame::MaxStreamsBidi(new), Frame::MaxStreamsBidi(old))
        | (Frame::MaxStreamsUni(new), Frame::MaxStreamsUni(old)) => new >= old,
        (
            Frame::MaxStreamData {
                stream_id: new_stream,
                maximum: new_maximum,
            },
            Frame::MaxStreamData {
                stream_id: old_stream,
                maximum: old_maximum,
            },
        ) => new_stream == old_stream && new_maximum >= old_maximum,
        (Frame::DataBlocked(_), Frame::DataBlocked(_))
        | (Frame::StreamsBlockedBidi(_), Frame::StreamsBlockedBidi(_))
        | (Frame::StreamsBlockedUni(_), Frame::StreamsBlockedUni(_)) => true,
        (
            Frame::StreamDataBlocked {
                stream_id: new_stream,
                ..
            },
            Frame::StreamDataBlocked {
                stream_id: old_stream,
                ..
            },
        )
        | (
            Frame::ResetStream {
                stream_id: new_stream,
                ..
            },
            Frame::ResetStream {
                stream_id: old_stream,
                ..
            },
        )
        | (
            Frame::ResetStreamAt {
                stream_id: new_stream,
                ..
            },
            Frame::ResetStreamAt {
                stream_id: old_stream,
                ..
            },
        )
        | (
            Frame::StopSending {
                stream_id: new_stream,
                ..
            },
            Frame::StopSending {
                stream_id: old_stream,
                ..
            },
        ) => new_stream == old_stream,
        (
            Frame::NewConnectionId {
                sequence: new_sequence,
                ..
            },
            Frame::NewConnectionId {
                sequence: old_sequence,
                ..
            },
        ) => new_sequence == old_sequence,
        (Frame::RetireConnectionId(new), Frame::RetireConnectionId(old)) => new == old,
        (Frame::PathChallenge(new), Frame::PathChallenge(old))
        | (Frame::PathResponse(new), Frame::PathResponse(old)) => new == old,
        _ => false,
    }
}

fn map_peer_control_queue_error(error: crate::error::CodecError) -> crate::error::CodecError {
    match error {
        crate::error::CodecError::BufferLimitExceeded => {
            crate::error::CodecError::Transport(TransportErrorCode::InternalError)
        }
        other => other,
    }
}

fn packet_space_discarded_state(level: EncryptionLevel) -> &'static str {
    match level {
        EncryptionLevel::Initial => "initial_space_discarded",
        EncryptionLevel::ZeroRtt => "zero_rtt_space_discarded",
        EncryptionLevel::Handshake => "handshake_space_discarded",
        EncryptionLevel::OneRtt => "one_rtt_space_discarded",
    }
}

fn earlier_deadline(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn is_ack_eliciting_frame(frame: &Frame) -> bool {
    is_ack_eliciting(frame)
}

impl Effects {
    pub fn extend(&mut self, other: Self) {
        extend_vec(&mut self.endpoint_events, other.endpoint_events);
        self.connection_events.extend(other.connection_events);
        extend_vec(&mut self.crypto_frames, other.crypto_frames);
        self.ack_frames.extend(other.ack_frames);
        extend_vec(&mut self.qlog_events, other.qlog_events);
        self.wakeups.extend(other.wakeups);
    }
}

fn extend_vec<T>(target: &mut Vec<T>, mut source: Vec<T>) {
    if target.is_empty() {
        *target = source;
    } else {
        target.append(&mut source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CodecError;

    #[derive(Debug, Default)]
    struct FakeCryptoSession {
        outbound: Vec<u8>,
        inbound: Vec<u8>,
        fail_reads: bool,
    }

    impl CryptoSession for FakeCryptoSession {
        fn write_tls(&mut self, out: &mut Vec<u8>) -> Result<()> {
            out.extend_from_slice(&self.outbound);
            self.outbound.clear();
            Ok(())
        }

        fn read_tls(&mut self, input: &[u8]) -> Result<()> {
            if self.fail_reads {
                return Err(CodecError::Crypto("read failed".into()));
            }
            self.inbound.extend_from_slice(input);
            Ok(())
        }

        fn is_handshaking(&self) -> bool {
            true
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    fn opened_one_rtt_packet(
        packet_number: u64,
        ecn: Option<EcnCodepoint>,
        frames: Vec<Frame>,
    ) -> crate::crypto::packet::OpenedFramePacket {
        crate::crypto::packet::OpenedFramePacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::OneRtt,
            header: crate::packet::Header::Short(crate::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: crate::cid::ConnectionId::EMPTY,
                packet_number_len: 2,
            }),
            packet_number,
            consumed: 0,
            ecn,
            frames: frames.into(),
        }
    }

    #[test]
    fn pulls_tls_output_into_crypto_frames() {
        let mut conn = Connection::new();
        let mut session = FakeCryptoSession {
            outbound: b"client hello".to_vec(),
            ..FakeCryptoSession::default()
        };

        let effects = conn
            .pull_tls_output(&mut session, EncryptionLevel::Initial, 6)
            .unwrap();

        assert_eq!(effects.crypto_frames.len(), 2);
        assert_eq!(effects.crypto_frames[0].offset, 0);
        assert_eq!(effects.crypto_frames[0].bytes, b"client");
        assert_eq!(effects.crypto_frames[1].offset, 6);
        assert_eq!(effects.crypto_frames[1].bytes, b" hello");
    }

    #[test]
    fn receives_reordered_crypto_frames_into_tls() {
        let mut conn = Connection::new();
        let mut session = FakeCryptoSession::default();

        let effects = conn
            .receive_crypto_frame(&mut session, EncryptionLevel::Initial, 6, b" hello", 1200)
            .unwrap();
        assert!(effects.connection_events.is_empty());
        assert!(session.inbound.is_empty());

        let effects = conn
            .receive_crypto_frame(&mut session, EncryptionLevel::Initial, 0, b"client", 1200)
            .unwrap();
        assert_eq!(session.inbound, b"client hello");
        assert_eq!(
            effects.connection_events[0],
            ConnectionEvent::CryptoDataReceived(CryptoData {
                level: EncryptionLevel::Initial,
                offset: 0,
                bytes: b"client hello".to_vec()
            })
        );
    }

    #[test]
    fn duplicate_crypto_frames_are_delivered_to_tls_once() {
        let mut conn = Connection::new();
        let mut session = FakeCryptoSession::default();

        conn.receive_crypto_frame(
            &mut session,
            EncryptionLevel::Handshake,
            0,
            b"server hello",
            1200,
        )
        .unwrap();
        let duplicate = conn
            .receive_crypto_frame(
                &mut session,
                EncryptionLevel::Handshake,
                0,
                b"server hello",
                1200,
            )
            .unwrap();

        assert_eq!(session.inbound, b"server hello");
        assert!(duplicate.connection_events.is_empty());
    }

    #[test]
    fn receive_crypto_frame_propagates_tls_errors() {
        let mut conn = Connection::new();
        let mut session = FakeCryptoSession {
            fail_reads: true,
            ..FakeCryptoSession::default()
        };

        let err = conn
            .receive_crypto_frame(&mut session, EncryptionLevel::Initial, 0, b"bad", 1200)
            .unwrap_err();
        assert_eq!(err, CodecError::Crypto("read failed".into()));
    }

    #[test]
    fn schedules_stream_frames_with_flow_control() {
        let mut conn = Connection::new();
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        conn.configure_stream_scheduler(StreamSchedulerConfig { max_frame_data: 8 });
        conn.increase_connection_send_limit(11);
        conn.queue_stream_data(stream_id, b"hello world").unwrap();
        let blocked = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&blocked.contents).unwrap();
        assert_eq!(consumed, blocked.contents.len());
        assert_eq!(
            frame,
            Frame::StreamDataBlocked {
                stream_id: stream_id.0,
                maximum: crate::VarInt::ZERO,
            }
        );

        conn.increase_stream_send_limit(stream_id, 5).unwrap();
        let first = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&first.contents).unwrap();
        assert_eq!(consumed, first.contents.len());
        assert_eq!(
            frame,
            Frame::Stream {
                stream_id: stream_id.0,
                offset: crate::VarInt::ZERO,
                fin: false,
                data: b"hello".to_vec().into(),
            }
        );
        let blocked = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&blocked.contents).unwrap();
        assert_eq!(consumed, blocked.contents.len());
        assert_eq!(
            frame,
            Frame::StreamDataBlocked {
                stream_id: stream_id.0,
                maximum: crate::VarInt::from_u32(5),
            }
        );

        conn.increase_stream_send_limit(stream_id, 11).unwrap();
        conn.finish_stream(stream_id).unwrap();
        let second = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&second.contents).unwrap();
        assert_eq!(consumed, second.contents.len());
        assert_eq!(
            frame,
            Frame::Stream {
                stream_id: stream_id.0,
                offset: crate::VarInt::from_u32(5),
                fin: true,
                data: b" world".to_vec().into(),
            }
        );
        assert!(conn.poll_transmit(web_time::Instant::now()).is_none());
        assert_eq!(conn.stats().packets_sent, 4);
    }

    #[test]
    fn stream_send_emits_blocked_when_credit_is_exhausted() {
        let mut conn = Connection::new();
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        conn.increase_connection_send_limit(7);
        conn.queue_stream_data(stream_id, b"blocked").unwrap();

        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::StreamDataBlocked {
                stream_id: stream_id.0,
                maximum: crate::VarInt::ZERO,
            }
        );
        assert_eq!(conn.stats().stream_data_blocked_events, 1);
        assert!(conn.poll_transmit(web_time::Instant::now()).is_none());

        conn.increase_stream_send_limit(stream_id, 7).unwrap();
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::Stream {
                stream_id: stream_id.0,
                offset: crate::VarInt::ZERO,
                fin: false,
                data: b"blocked".to_vec().into(),
            }
        );
    }

    #[test]
    fn stream_send_buffer_limit_rejects_excess_queued_data() {
        let mut conn = Connection::new();
        conn.set_max_send_buffered_stream_data(4);
        conn.increase_connection_send_limit(16);
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        conn.increase_stream_send_limit(stream_id, 16).unwrap();

        conn.queue_stream_data(stream_id, b"1234").unwrap();
        assert_eq!(conn.send_buffered_stream_data(), 4);

        assert_eq!(
            conn.queue_stream_data(stream_id, b"5"),
            Err(crate::error::CodecError::BufferLimitExceeded)
        );
        assert_eq!(conn.send_buffered_stream_data(), 4);
        conn.reset_stream(stream_id, VarInt::ZERO).unwrap();
        assert_eq!(conn.send_buffered_stream_data(), 0);
    }

    #[test]
    fn stream_send_buffer_accounting_releases_on_packetization_and_abort() {
        let mut conn = Connection::new();
        conn.increase_connection_send_limit(16);
        let stream_id = StreamId(VarInt::ZERO);
        conn.increase_stream_send_limit(stream_id, 16).unwrap();

        conn.queue_stream_data(stream_id, b"1234").unwrap();
        assert_eq!(conn.send_buffered_stream_data(), 4);
        let _ = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert_eq!(conn.send_buffered_stream_data(), 0);

        conn.queue_stream_data(stream_id, b"56").unwrap();
        assert_eq!(conn.send_buffered_stream_data(), 2);
        conn.abort();
        assert_eq!(conn.send_buffered_stream_data(), 0);
    }

    #[test]
    fn acknowledged_stream_payload_buffer_is_bounded_and_reused() {
        let mut conn = Connection::new();
        conn.configure_stream_scheduler(StreamSchedulerConfig {
            max_frame_data: 100,
        });
        conn.increase_connection_send_limit(200);
        let stream_id = StreamId(VarInt::ZERO);
        conn.increase_stream_send_limit(stream_id, 200).unwrap();
        let now = web_time::Instant::now();

        conn.queue_stream_data(stream_id, &[1; 100]).unwrap();
        conn.poll_transmit(now).unwrap();
        let ack = Frame::Ack {
            largest: VarInt::ZERO,
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(
            EncryptionLevel::OneRtt,
            &ack,
            now + Duration::from_millis(1),
        );

        assert_eq!(conn.recycled_stream_payloads.len(), 1);
        assert!(conn.memory_stats().recycled_stream_capacity_bytes >= 100);

        conn.queue_stream_data(stream_id, &[2; 100]).unwrap();
        conn.poll_transmit(now + Duration::from_millis(2)).unwrap();

        assert!(conn.recycled_stream_payloads.is_empty());
        assert_eq!(conn.memory_stats().recycled_stream_capacity_bytes, 0);
    }

    #[test]
    fn acknowledged_finished_send_streams_are_reclaimed_into_compact_ranges() {
        let mut conn = Connection::new();
        conn.increase_connection_send_limit(64);
        let now = web_time::Instant::now();

        for (packet_number, raw_stream_id) in [(0, 0), (1, 4)] {
            let stream_id = StreamId(VarInt::from_u32(raw_stream_id));
            conn.increase_stream_send_limit(stream_id, 32).unwrap();
            conn.queue_stream_data(stream_id, b"done").unwrap();
            conn.finish_stream(stream_id).unwrap();
            conn.poll_transmit(now + Duration::from_millis(u64::from(packet_number)))
                .unwrap();
            let ack = Frame::Ack {
                largest: VarInt::from_u32(packet_number),
                delay: VarInt::ZERO,
                first_range: VarInt::ZERO,
                ranges: Default::default(),
                ecn: None,
            };
            let effects = conn.handle_ack_frame(
                EncryptionLevel::OneRtt,
                &ack,
                now + Duration::from_millis(u64::from(packet_number) + 1),
            );
            assert!(
                effects
                    .connection_events
                    .contains(&ConnectionEvent::StreamFinished { stream_id })
            );
        }

        let reset = StreamId(VarInt::from_u32(8));
        conn.increase_stream_send_limit(reset, 32).unwrap();
        conn.reset_stream(reset, VarInt::from_u32(7)).unwrap();
        conn.poll_transmit(now + Duration::from_millis(3)).unwrap();
        let ack = Frame::Ack {
            largest: VarInt::from_u32(2),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(
            EncryptionLevel::OneRtt,
            &ack,
            now + Duration::from_millis(4),
        );

        let memory = conn.memory_stats();
        assert_eq!(memory.send_stream_states, 0);
        assert_eq!(memory.closed_send_stream_ranges, 1);

        let closed = StreamId(VarInt::ZERO);
        conn.increase_stream_send_limit(closed, 64).unwrap();
        assert_eq!(conn.memory_stats().send_stream_states, 0);
        assert_eq!(
            conn.queue_stream_data(closed, b"late"),
            Err(crate::error::CodecError::Transport(
                TransportErrorCode::StreamStateError
            ))
        );
        assert!(!conn.stop_send_stream(closed, VarInt::ZERO).unwrap());
        assert_eq!(conn.memory_stats().send_stream_states, 0);
    }

    #[test]
    fn reading_stream_data_refreshes_stream_receive_window() {
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        conn.configure_receive_flow_control(10, 10, 10, 10);
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        conn.receive_stream_frame(stream_id, 0, b"hello".to_vec(), false)
            .unwrap();

        let chunk = conn.read_recv_stream(stream_id, 4, true).unwrap();
        assert_eq!(chunk.bytes.as_ref(), b"hell");
        assert!(conn.poll_transmit(web_time::Instant::now()).is_none());

        let chunk = conn.read_recv_stream(stream_id, 1, true).unwrap();
        assert_eq!(chunk.bytes.as_ref(), b"o");

        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::MaxStreamData {
                stream_id: stream_id.0,
                maximum: crate::VarInt::from_u32(15),
            }
        );
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(frame, Frame::MaxData(crate::VarInt::from_u32(15)));
    }

    #[test]
    fn stream_send_emits_data_blocked_when_connection_credit_is_exhausted() {
        let mut conn = Connection::new();
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        conn.increase_stream_send_limit(stream_id, 7).unwrap();
        conn.queue_stream_data(stream_id, b"blocked").unwrap();

        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(frame, Frame::DataBlocked(crate::VarInt::ZERO));
        assert_eq!(conn.stats().data_blocked_events, 1);
        assert!(conn.poll_transmit(web_time::Instant::now()).is_none());

        conn.increase_connection_send_limit(7);
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::Stream {
                stream_id: stream_id.0,
                offset: crate::VarInt::ZERO,
                fin: false,
                data: b"blocked".to_vec().into(),
            }
        );
    }

    #[test]
    fn connection_credit_update_reschedules_only_blocked_streams() {
        let mut conn = Connection::new();
        let completed = StreamId(crate::VarInt::from_u32(0));
        let blocked = StreamId(crate::VarInt::from_u32(4));
        conn.increase_connection_send_limit(4);
        conn.increase_stream_send_limit(completed, 4).unwrap();
        conn.increase_stream_send_limit(blocked, 4).unwrap();
        conn.queue_stream_data(completed, b"done").unwrap();
        conn.finish_stream(completed).unwrap();
        conn.queue_stream_data(blocked, b"more").unwrap();

        let first = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert!(matches!(
            Frame::decode(&first.contents).unwrap().0,
            Frame::Stream { stream_id, fin: true, .. } if stream_id == completed.0
        ));
        let second = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert_eq!(
            Frame::decode(&second.contents).unwrap().0,
            Frame::DataBlocked(crate::VarInt::from_u32(4))
        );
        assert!(conn.stream_schedule.is_empty());

        conn.increase_connection_send_limit(8);
        assert_eq!(
            conn.stream_schedule.iter().copied().collect::<Vec<_>>(),
            vec![blocked]
        );
    }

    #[test]
    fn stream_credit_updates_do_not_reschedule_completed_streams() {
        let mut conn = Connection::new();
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        conn.increase_connection_send_limit(16);
        conn.increase_stream_send_limit(stream_id, 8).unwrap();
        conn.queue_stream_data(stream_id, b"complete").unwrap();
        conn.finish_stream(stream_id).unwrap();

        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert!(matches!(
            Frame::decode(&transmit.contents).unwrap().0,
            Frame::Stream {
                stream_id: id,
                fin: true,
                ..
            } if id == stream_id.0
        ));
        assert!(conn.pending_send_streams.is_empty());
        assert!(conn.stream_schedule.is_empty());

        conn.increase_stream_send_limit(stream_id, 16).unwrap();
        conn.configure_outbound_stream_limits(16, 16);
        conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::MaxStreamsBidi(crate::VarInt::from_u32(16)),
            web_time::Instant::now(),
        )
        .unwrap();

        assert!(conn.stream_schedule.is_empty());
        assert!(conn.poll_transmit(web_time::Instant::now()).is_none());
    }

    #[test]
    fn pending_stream_index_repairs_a_missing_scheduler_entry() {
        let mut conn = Connection::new();
        let stream_id = StreamId(crate::VarInt::ZERO);
        conn.increase_connection_send_limit(4);
        conn.increase_stream_send_limit(stream_id, 4).unwrap();
        conn.queue_stream_data(stream_id, b"done").unwrap();
        conn.finish_stream(stream_id).unwrap();
        conn.stream_schedule.clear();

        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert!(matches!(
            Frame::decode(&transmit.contents).unwrap().0,
            Frame::Stream { stream_id: id, fin: true, .. } if id == stream_id.0
        ));
        assert!(conn.pending_send_streams.is_empty());
    }

    #[test]
    fn stream_scheduler_round_robins_ready_streams() {
        let mut conn = Connection::new();
        conn.configure_stream_scheduler(StreamSchedulerConfig { max_frame_data: 3 });
        let a = StreamId(crate::VarInt::from_u32(0));
        let b = StreamId(crate::VarInt::from_u32(4));
        conn.increase_connection_send_limit(12);
        conn.increase_stream_send_limit(a, 6).unwrap();
        conn.increase_stream_send_limit(b, 6).unwrap();
        conn.queue_stream_data(a, b"abcdef").unwrap();
        conn.queue_stream_data(b, b"uvwxyz").unwrap();

        let frames = (0..4)
            .map(|_| {
                let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
                Frame::decode(&transmit.contents).unwrap().0
            })
            .collect::<Vec<_>>();

        assert_eq!(
            frames,
            vec![
                Frame::Stream {
                    stream_id: a.0,
                    offset: crate::VarInt::ZERO,
                    fin: false,
                    data: b"abc".to_vec().into(),
                },
                Frame::Stream {
                    stream_id: b.0,
                    offset: crate::VarInt::ZERO,
                    fin: false,
                    data: b"uvw".to_vec().into(),
                },
                Frame::Stream {
                    stream_id: a.0,
                    offset: crate::VarInt::from_u32(3),
                    fin: false,
                    data: b"def".to_vec().into(),
                },
                Frame::Stream {
                    stream_id: b.0,
                    offset: crate::VarInt::from_u32(3),
                    fin: false,
                    data: b"xyz".to_vec().into(),
                },
            ]
        );
    }

    #[test]
    fn stream_scheduler_prefers_lower_priority_values() {
        let mut conn = Connection::new();
        conn.configure_stream_scheduler(StreamSchedulerConfig { max_frame_data: 3 });
        let low = StreamId(crate::VarInt::from_u32(0));
        let high = StreamId(crate::VarInt::from_u32(4));
        conn.increase_connection_send_limit(7);
        conn.increase_stream_send_limit(low, 3).unwrap();
        conn.increase_stream_send_limit(high, 4).unwrap();
        conn.queue_stream_data(low, b"low").unwrap();
        conn.queue_stream_data(high, b"high").unwrap();
        conn.set_stream_priority(low, 200);
        conn.set_stream_priority(high, 10);

        let first = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let second = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let third = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert!(matches!(
            Frame::decode(&first.contents).unwrap().0,
            Frame::Stream { stream_id, data, .. }
                if stream_id == high.0 && data.as_ref() == b"hig"
        ));
        assert!(matches!(
            Frame::decode(&second.contents).unwrap().0,
            Frame::Stream { stream_id, data, .. }
                if stream_id == high.0 && data.as_ref() == b"h"
        ));
        assert!(matches!(
            Frame::decode(&third.contents).unwrap().0,
            Frame::Stream { stream_id, data, .. }
                if stream_id == low.0 && data.as_ref() == b"low"
        ));
    }

    #[test]
    fn sent_packet_records_loss_timer_and_ack_loss_events() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let effects = conn.record_sent_packet(EncryptionLevel::Initial, 0, 1200, true, now);
        assert_eq!(effects.wakeups.len(), 1);
        assert_eq!(conn.stats().bytes_in_flight, 1200);
        assert_eq!(conn.timeout(), Some(effects.wakeups[0].at));

        let ack = Frame::Ack {
            largest: crate::VarInt::from_u32(1),
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        let effects = conn.handle_ack_frame(
            EncryptionLevel::Initial,
            &ack,
            now + web_time::Duration::from_secs(1),
        );

        assert_eq!(
            effects.connection_events.as_slice(),
            &[ConnectionEvent::PacketLost {
                level: EncryptionLevel::Initial,
                packet_number: 0,
            }]
        );
        assert_eq!(conn.stats().packets_lost, 1);
        assert_eq!(conn.stats().bytes_in_flight, 0);
    }

    #[test]
    fn rejects_frames_forbidden_at_packet_encryption_level() {
        let now = web_time::Instant::now();
        let cases = [
            (
                EncryptionLevel::Initial,
                Frame::Stream {
                    stream_id: VarInt::ZERO,
                    offset: VarInt::ZERO,
                    fin: false,
                    data: bytes::Bytes::new(),
                },
            ),
            (
                EncryptionLevel::Handshake,
                Frame::Datagram {
                    data: Vec::new().into(),
                },
            ),
            (
                EncryptionLevel::ZeroRtt,
                Frame::Ack {
                    largest: VarInt::ZERO,
                    delay: VarInt::ZERO,
                    first_range: VarInt::ZERO,
                    ranges: Default::default(),
                    ecn: None,
                },
            ),
            (EncryptionLevel::ZeroRtt, Frame::HandshakeDone),
        ];

        for (level, frame) in cases {
            let error = Connection::new()
                .handle_frame(level, frame, now)
                .unwrap_err();
            assert_eq!(
                error,
                crate::error::CodecError::Transport(TransportErrorCode::ProtocolViolation)
            );
        }
    }

    #[test]
    fn rejects_server_only_frames_received_by_server() {
        let now = web_time::Instant::now();
        for frame in [Frame::NewToken(vec![1]), Frame::HandshakeDone] {
            let mut conn = Connection::new();
            conn.configure_inbound_stream_limits(StreamInitiator::Server, 0, 0);
            let error = conn
                .handle_frame(EncryptionLevel::OneRtt, frame, now)
                .unwrap_err();
            assert_eq!(
                error,
                crate::error::CodecError::Transport(TransportErrorCode::ProtocolViolation)
            );
        }
    }

    #[test]
    fn client_confirms_handshake_and_discards_handshake_space_on_handshake_done() {
        let now = web_time::Instant::now();
        let mut conn = Connection::new();
        conn.record_sent_packet(EncryptionLevel::Handshake, 0, 1200, true, now);
        conn.record_sent_packet(EncryptionLevel::OneRtt, 0, 800, true, now);

        assert!(!conn.is_handshake_confirmed());
        assert_eq!(conn.stats().bytes_in_flight, 2000);

        conn.handle_frame(EncryptionLevel::OneRtt, Frame::HandshakeDone, now)
            .unwrap();

        assert!(conn.is_handshake_confirmed());
        assert_eq!(conn.stats().bytes_in_flight, 800);
    }

    #[test]
    fn zero_length_connection_id_policy_rejects_cid_lifecycle_frames() {
        let now = web_time::Instant::now();

        let mut local_zero = Connection::new();
        assert!(local_zero.set_local_connection_id_length(0));
        assert!(!local_zero.set_local_connection_id_length(8));
        assert_eq!(
            local_zero
                .handle_frame(
                    EncryptionLevel::OneRtt,
                    Frame::RetireConnectionId(VarInt::ZERO),
                    now,
                )
                .unwrap_err(),
            crate::error::CodecError::Transport(TransportErrorCode::ProtocolViolation)
        );
        assert_eq!(
            local_zero
                .queue_new_connection_id(
                    VarInt::from_u32(1),
                    VarInt::ZERO,
                    b"localcid".to_vec(),
                    [1; 16],
                )
                .unwrap_err(),
            crate::error::CodecError::Transport(TransportErrorCode::ProtocolViolation)
        );

        let mut peer_zero = Connection::new();
        assert!(peer_zero.set_peer_connection_id_length(0));
        assert!(!peer_zero.set_peer_connection_id_length(8));
        assert_eq!(
            peer_zero
                .handle_frame(
                    EncryptionLevel::OneRtt,
                    Frame::NewConnectionId {
                        sequence: VarInt::from_u32(1),
                        retire_prior_to: VarInt::ZERO,
                        connection_id: b"peercid1".to_vec(),
                        reset_token: [2; 16],
                    },
                    now,
                )
                .unwrap_err(),
            crate::error::CodecError::Transport(TransportErrorCode::ProtocolViolation)
        );
        assert_eq!(
            peer_zero
                .queue_retire_connection_id(VarInt::ZERO)
                .unwrap_err(),
            crate::error::CodecError::Transport(TransportErrorCode::ProtocolViolation)
        );
    }

    #[test]
    fn rejects_stream_count_frames_above_quic_limit() {
        let now = web_time::Instant::now();
        let invalid = VarInt::new(MAX_STREAM_COUNT + 1).unwrap();
        let cases = [
            (
                Frame::MaxStreamsBidi(invalid),
                TransportErrorCode::FrameEncodingError,
            ),
            (
                Frame::MaxStreamsUni(invalid),
                TransportErrorCode::FrameEncodingError,
            ),
            (
                Frame::StreamsBlockedBidi(invalid),
                TransportErrorCode::StreamLimitError,
            ),
            (
                Frame::StreamsBlockedUni(invalid),
                TransportErrorCode::StreamLimitError,
            ),
        ];

        for (frame, expected) in cases {
            let error = Connection::new()
                .handle_frame(EncryptionLevel::OneRtt, frame, now)
                .unwrap_err();
            assert_eq!(error, crate::error::CodecError::Transport(expected));
        }
    }

    #[test]
    fn pto_timeout_emits_probe_request() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let effects = conn.record_sent_packet(EncryptionLevel::Handshake, 0, 1200, true, now);
        let timeout = effects.wakeups[0].at;

        assert!(conn.on_timeout(now).unwrap().connection_events.is_empty());
        let effects = conn.on_timeout(timeout).unwrap();

        assert_eq!(
            effects.connection_events.as_slice(),
            &[ConnectionEvent::ProbeRequired {
                level: EncryptionLevel::Handshake,
                packets: 2,
            }]
        );
        assert_eq!(conn.stats().retransmissions, 2);
    }

    #[test]
    fn one_rtt_pto_without_retransmittable_payload_queues_ping_probes() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let effects = conn.record_sent_packet(EncryptionLevel::OneRtt, 0, 1200, true, now);
        let timeout = effects.wakeups[0].at;

        let effects = conn.on_timeout(timeout).unwrap();

        assert!(
            effects
                .connection_events
                .contains(&ConnectionEvent::ProbeRequired {
                    level: EncryptionLevel::OneRtt,
                    packets: 2,
                })
        );
        for _ in 0..2 {
            let transmit = conn.poll_transmit(timeout).unwrap();
            assert_eq!(Frame::decode(&transmit.contents).unwrap().0, Frame::Ping);
        }
    }

    #[test]
    fn lost_crypto_packet_requeues_frames_for_retransmission() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let frame = CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 0,
            bytes: b"client hello".to_vec(),
        };
        conn.record_sent_crypto_packet(EncryptionLevel::Initial, 0, 1200, vec![frame.clone()], now);
        let ack = Frame::Ack {
            largest: crate::VarInt::from_u32(1),
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        let effects = conn.handle_ack_frame(
            EncryptionLevel::Initial,
            &ack,
            now + web_time::Duration::from_secs(1),
        );

        assert!(
            effects
                .connection_events
                .contains(&ConnectionEvent::PacketLost {
                    level: EncryptionLevel::Initial,
                    packet_number: 0,
                })
        );
        assert_eq!(effects.crypto_frames, vec![frame]);
        assert_eq!(conn.stats().retransmissions, 1);
    }

    #[test]
    fn externally_recorded_one_rtt_packet_advances_transmit_packet_number() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_crypto_packet(EncryptionLevel::OneRtt, 7, 1200, Vec::new(), now);

        assert_eq!(conn.next_one_rtt_packet_number, 8);
    }

    #[test]
    fn one_rtt_ack_confirms_zero_rtt_packet_in_shared_application_space() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_packet(EncryptionLevel::ZeroRtt, 3, 700, true, now);
        assert_eq!(conn.next_one_rtt_packet_number, 4);
        assert_eq!(conn.stats().bytes_in_flight, 700);
        let ack = Frame::Ack {
            largest: crate::VarInt::from_u32(3),
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert_eq!(conn.stats().bytes_in_flight, 0);
        assert_eq!(
            conn.largest_acked_packet_number(EncryptionLevel::OneRtt),
            Some(3)
        );
    }

    #[test]
    fn discard_packet_space_removes_crypto_ack_and_loss_state() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let initial_frame = CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 0,
            bytes: b"client hello".to_vec(),
        };
        conn.record_sent_crypto_packet(EncryptionLevel::Initial, 0, 1200, vec![initial_frame], now);
        conn.record_sent_packet(EncryptionLevel::OneRtt, 0, 800, true, now);
        assert_eq!(conn.stats().bytes_in_flight, 2000);

        conn.discard_packet_space(EncryptionLevel::Initial);

        assert_eq!(conn.stats().bytes_in_flight, 800);
        assert_eq!(
            conn.ack_tracker()
                .largest_received(EncryptionLevel::Initial),
            None
        );
        let effects = conn
            .on_timeout(now + web_time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            effects.connection_events.as_slice(),
            &[ConnectionEvent::ProbeRequired {
                level: EncryptionLevel::OneRtt,
                packets: 2,
            }]
        );
        assert!(effects.crypto_frames.is_empty());
    }

    #[test]
    fn pto_requeues_oldest_crypto_frames_as_probe_payload() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let frame = CryptoFrame {
            level: EncryptionLevel::Handshake,
            offset: 12,
            bytes: b"server flight".to_vec(),
        };
        let effects = conn.record_sent_crypto_packet(
            EncryptionLevel::Handshake,
            3,
            1200,
            vec![frame.clone()],
            now,
        );
        let timeout = effects.wakeups[0].at;

        let effects = conn.on_timeout(timeout).unwrap();

        assert!(
            effects
                .connection_events
                .contains(&ConnectionEvent::ProbeRequired {
                    level: EncryptionLevel::Handshake,
                    packets: 2,
                })
        );
        assert_eq!(effects.crypto_frames, vec![frame]);
    }

    #[test]
    fn mismatched_stored_crypto_level_aborts_without_panicking() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let frame = CryptoFrame {
            level: EncryptionLevel::Handshake,
            offset: 0,
            bytes: b"invalid stored flight".to_vec(),
        };
        let effects =
            conn.record_sent_crypto_packet(EncryptionLevel::Initial, 0, 1200, vec![frame], now);
        let timeout = effects.wakeups[0].at;

        let effects = conn.on_timeout(timeout).unwrap();

        assert!(conn.is_closed());
        assert!(effects.connection_events.contains(&ConnectionEvent::Closed));
        assert!(effects.crypto_frames.is_empty());
    }

    #[test]
    fn receive_stream_frame_accepts_and_reads_ordered_data() {
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        conn.receive_stream_frame(stream_id, 6, b"world".to_vec(), true)
            .unwrap();
        assert_eq!(conn.accept_recv_stream(), Some(stream_id));
        assert_eq!(conn.accept_recv_stream(), None);
        assert!(conn.read_recv_stream(stream_id, 64, true).is_none());

        conn.receive_stream_frame(stream_id, 0, b"hello ".to_vec(), false)
            .unwrap();
        let chunk = conn.read_recv_stream(stream_id, 64, true).unwrap();

        assert_eq!(chunk.offset, 0);
        assert_eq!(chunk.bytes.as_ref(), b"hello ");
        assert!(!chunk.fin);
        let chunk = conn.read_recv_stream(stream_id, 64, true).unwrap();
        assert_eq!(chunk.offset, 6);
        assert_eq!(chunk.bytes.as_ref(), b"world");
        assert!(chunk.fin);
    }

    #[test]
    fn receive_stream_frame_respects_configured_buffer_limit() {
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        conn.set_max_recv_buffered_stream_data(4);
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        conn.receive_stream_frame(stream_id, 0, b"abcd".to_vec(), false)
            .unwrap();

        let err = conn
            .receive_stream_frame(stream_id, 4, b"e".to_vec(), false)
            .unwrap_err();
        assert_eq!(
            err,
            crate::error::CodecError::Transport(TransportErrorCode::FlowControlError)
        );
    }

    #[test]
    fn configured_receive_flow_control_uses_role_specific_stream_limits() {
        let mut conn = Connection::new();
        conn.register_local_stream(StreamId(VarInt::ZERO)).unwrap();
        conn.configure_receive_flow_control(16, 1, 2, 3);

        conn.receive_stream_frame(StreamId(VarInt::ZERO), 0, vec![1], false)
            .unwrap();
        assert_eq!(
            conn.receive_stream_frame(StreamId(VarInt::ZERO), 1, vec![2], false),
            Err(crate::error::CodecError::Transport(
                TransportErrorCode::FlowControlError
            ))
        );

        conn.receive_stream_frame(StreamId(VarInt::from_u32(1)), 0, vec![1; 2], false)
            .unwrap();
        assert_eq!(
            conn.receive_stream_frame(StreamId(VarInt::from_u32(1)), 2, vec![2], false),
            Err(crate::error::CodecError::Transport(
                TransportErrorCode::FlowControlError
            ))
        );

        conn.receive_stream_frame(StreamId(VarInt::from_u32(3)), 0, vec![1; 3], false)
            .unwrap();
        assert_eq!(
            conn.receive_stream_frame(StreamId(VarInt::from_u32(3)), 3, vec![2], false),
            Err(crate::error::CodecError::Transport(
                TransportErrorCode::FlowControlError
            ))
        );
    }

    #[test]
    fn accepting_peer_initiated_stream_refreshes_stream_limit() {
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Client, 1, 1);
        let stream_id = StreamId(crate::VarInt::from_u32(1));
        conn.receive_stream_frame(stream_id, 0, b"hello".to_vec(), false)
            .unwrap();

        assert_eq!(conn.accept_recv_stream(), Some(stream_id));
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(frame, Frame::MaxStreamsBidi(crate::VarInt::from_u32(2)));
    }

    #[test]
    fn datagrams_queue_for_transmit_and_receive() {
        let mut conn = Connection::new();
        conn.send_datagram(b"hello".to_vec()).unwrap();
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert_eq!(transmit.send_at, None);
        assert_eq!(transmit.ecn, Some(EcnCodepoint::Ect0));
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::Datagram {
                data: b"hello".to_vec().into(),
            }
        );
        assert_eq!(conn.stats().datagrams_sent, 1);

        conn.handle_event(
            Event::Datagram(b"world".to_vec().into()),
            web_time::Instant::now(),
        )
        .unwrap();
        assert_eq!(conn.read_datagram(), Some(b"world".to_vec()));
        assert_eq!(conn.read_datagram(), None);
        assert_eq!(conn.stats().datagrams_received, 1);
    }

    #[test]
    fn shared_datagram_payload_reaches_packetization_without_copying() {
        let mut conn = Connection::new();
        let payload = bytes::Bytes::from_static(b"shared-datagram");
        let payload_pointer = payload.as_ptr();

        conn.send_datagram_bytes(payload.clone()).unwrap();
        let Frame::Datagram { data } = conn.poll_datagram_frame().unwrap() else {
            panic!("queued DATAGRAM produced a different frame");
        };

        assert_eq!(data.as_ptr(), payload_pointer);
        assert_eq!(data, payload);
    }

    #[test]
    fn shared_received_datagram_payload_reaches_reader_without_copying() {
        let mut conn = Connection::new();
        let payload = bytes::Bytes::from_static(b"shared-received-datagram");
        let payload_pointer = payload.as_ptr();

        conn.handle_event(Event::Datagram(payload.clone()), web_time::Instant::now())
            .unwrap();
        let received = conn.read_datagram_bytes().unwrap();

        assert_eq!(received.as_ptr(), payload_pointer);
        assert_eq!(received, payload);
    }

    #[test]
    fn send_datagram_queue_is_bounded() {
        let mut conn = Connection::new();
        for _ in 0..MAX_QUEUED_DATAGRAMS {
            conn.send_datagram(vec![0]).unwrap();
        }

        let err = conn.send_datagram(vec![0]).unwrap_err();

        assert_eq!(
            err,
            crate::error::CodecError::Transport(TransportErrorCode::FlowControlError)
        );
    }

    #[test]
    fn received_datagram_queue_drops_oldest_when_bounded() {
        let mut conn = Connection::new();
        for i in 0..=MAX_QUEUED_DATAGRAMS {
            conn.handle_event(
                Event::Datagram(vec![(i % u8::MAX as usize) as u8].into()),
                web_time::Instant::now(),
            )
            .unwrap();
        }

        assert_eq!(conn.read_datagram(), Some(vec![1]));
        assert_eq!(conn.stats().datagrams_dropped, 1);
    }

    #[test]
    fn oversized_received_datagram_is_dropped_and_counted() {
        let mut conn = Connection::new();
        conn.handle_event(
            Event::Datagram(vec![0; MAX_QUEUED_DATAGRAM_BYTES + 1].into()),
            web_time::Instant::now(),
        )
        .unwrap();

        assert_eq!(conn.read_datagram(), None);
        assert_eq!(conn.stats().datagrams_dropped, 1);
    }

    #[test]
    fn configured_datagram_queue_limits_apply_to_send_and_receive() {
        let mut conn = Connection::new();
        conn.set_datagram_queue_limits(2, 3);
        conn.send_datagram(b"aa".to_vec()).unwrap();
        assert_eq!(
            conn.send_datagram(b"bb".to_vec()),
            Err(crate::error::CodecError::Transport(
                TransportErrorCode::FlowControlError
            ))
        );

        conn.handle_event(
            Event::Datagram(b"aa".to_vec().into()),
            web_time::Instant::now(),
        )
        .unwrap();
        conn.handle_event(
            Event::Datagram(b"bb".to_vec().into()),
            web_time::Instant::now(),
        )
        .unwrap();
        assert_eq!(conn.read_datagram(), Some(b"bb".to_vec()));
        assert_eq!(conn.read_datagram(), None);
        assert_eq!(conn.stats().datagrams_dropped, 1);
    }

    #[test]
    fn control_queue_coalesces_superseded_and_duplicate_frames() {
        let mut conn = Connection::new();
        conn.set_max_queued_control_frames(2);

        conn.queue_control_frame(Frame::MaxData(VarInt::from_u32(10)))
            .unwrap();
        conn.queue_control_frame(Frame::MaxData(VarInt::from_u32(20)))
            .unwrap();
        conn.queue_control_frame(Frame::PathResponse([1; 8]))
            .unwrap();
        conn.queue_control_frame(Frame::PathResponse([1; 8]))
            .unwrap();

        assert_eq!(conn.send_control.len(), 2);
        assert_eq!(conn.send_control[0], Frame::MaxData(VarInt::from_u32(20)));
        assert_eq!(conn.send_control[1], Frame::PathResponse([1; 8]));
        assert_eq!(conn.stats().control_frames_dropped, 0);
    }

    #[test]
    fn control_queue_limit_reports_backpressure_and_counts_drop() {
        let mut conn = Connection::new();
        conn.set_max_queued_control_frames(1);
        conn.queue_control_frame(Frame::PathResponse([1; 8]))
            .unwrap();

        assert_eq!(
            conn.queue_control_frame(Frame::PathResponse([2; 8])),
            Err(CodecError::BufferLimitExceeded)
        );
        assert_eq!(conn.send_control.len(), 1);
        assert_eq!(conn.stats().control_frames_dropped, 1);
    }

    #[test]
    fn peer_control_queue_overload_maps_to_internal_error() {
        let mut conn = Connection::new();
        conn.set_max_queued_control_frames(0);

        assert_eq!(
            conn.handle_frame(
                EncryptionLevel::OneRtt,
                Frame::PathChallenge([1; 8]),
                web_time::Instant::now(),
            ),
            Err(CodecError::Transport(TransportErrorCode::InternalError))
        );
        assert_eq!(conn.stats().control_frames_dropped, 1);
    }

    #[test]
    fn ack_queue_retains_only_latest_frame_per_packet_space() {
        let mut conn = Connection::new();
        let ack = |level, largest| GeneratedAck {
            level,
            frame: Frame::Ack {
                largest: VarInt::from_u32(largest),
                delay: VarInt::ZERO,
                first_range: VarInt::ZERO,
                ranges: Default::default(),
                ecn: None,
            },
        };

        conn.queue_ack(ack(EncryptionLevel::Initial, 1));
        conn.queue_ack(ack(EncryptionLevel::Handshake, 2));
        conn.queue_ack(ack(EncryptionLevel::OneRtt, 3));
        conn.queue_ack(ack(EncryptionLevel::OneRtt, 4));

        assert_eq!(conn.send_acks.len(), 3);
        assert!(conn.send_acks.iter().any(|queued| {
            queued.level == EncryptionLevel::OneRtt
                && matches!(
                    queued.frame,
                    Frame::Ack {
                        largest,
                        ..
                    } if largest == VarInt::from_u32(4)
                )
        }));
    }

    #[test]
    fn zero_datagram_queue_limit_has_stable_backpressure_and_drop_behavior() {
        let mut conn = Connection::new();
        conn.set_datagram_queue_limits(0, 0);

        assert_eq!(
            conn.send_datagram(Vec::new()),
            Err(crate::error::CodecError::Transport(
                TransportErrorCode::FlowControlError
            ))
        );
        conn.handle_event(Event::Datagram(Vec::new().into()), web_time::Instant::now())
            .unwrap();
        assert_eq!(conn.read_datagram(), None);
        assert_eq!(conn.stats().datagrams_dropped, 1);
    }

    #[test]
    fn qlog_events_capture_stream_flow_and_close() {
        let mut conn = Connection::new();
        let stream_id = StreamId(VarInt::ZERO);

        conn.increase_connection_send_limit(16);
        conn.increase_stream_send_limit(stream_id, 16).unwrap();
        conn.queue_stream_data(stream_id, b"ping").unwrap();
        conn.finish_stream(stream_id).unwrap();
        let _ = conn.poll_transmit(web_time::Instant::now()).unwrap();
        conn.close_application(VarInt::from_u32(7), b"bye").unwrap();

        let events = conn.drain_qlog_events();

        assert!(events.iter().any(|event| matches!(
            event,
            QlogEvent::FlowControlUpdated {
                scope: "connection",
                maximum: 16,
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            QlogEvent::StreamDataQueued {
                stream_id: 0,
                len: 4,
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            QlogEvent::PacketSent {
                frame_type: "stream",
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            QlogEvent::ConnectionStateUpdated {
                state: "application_close_sent"
            }
        )));
    }

    #[test]
    fn proto_qlog_buffer_is_bounded_and_keeps_newest_events() {
        let mut conn = Connection::new();
        conn.set_max_buffered_qlog_events(2);
        conn.increase_connection_send_limit(1);
        conn.increase_connection_send_limit(2);
        conn.increase_connection_send_limit(3);

        let events = conn.drain_qlog_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events.as_slice(),
            [
                QlogEvent::FlowControlUpdated { maximum: 2, .. },
                QlogEvent::FlowControlUpdated { maximum: 3, .. }
            ]
        ));

        conn.set_max_buffered_qlog_events(0);
        conn.increase_connection_send_limit(4);
        assert!(conn.drain_qlog_events().is_empty());
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_events_serialize_to_json() {
        let event = QlogEvent::PacketSent {
            level: "1rtt",
            packet_number: 4,
            bytes: 1200,
            ack_eliciting: true,
            frame_type: "stream",
        };

        let json = event.to_json().unwrap();

        assert!(json.contains("\"packet_number\":4"));
        assert!(json.contains("\"frame_type\":\"stream\""));
    }

    #[test]
    fn path_challenge_queues_path_response() {
        let mut conn = Connection::new();
        let challenge = [7; 8];
        conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::PathChallenge(challenge),
            web_time::Instant::now(),
        )
        .unwrap();

        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(frame, Frame::PathResponse(challenge));
        let events = conn.drain_qlog_events();
        assert!(events.iter().any(|event| matches!(
            event,
            QlogEvent::PathStateUpdated {
                state: "challenge_received"
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            QlogEvent::PathStateUpdated {
                state: "response_queued"
            }
        )));
    }

    #[test]
    fn path_validation_queues_challenge_and_arms_deadline() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let challenge = [9; 8];

        let effects = conn.start_path_validation(challenge, now);

        assert_eq!(conn.timeout(), Some(now + PATH_VALIDATION_TIMEOUT));
        assert!(effects.wakeups.iter().any(|deadline| {
            deadline.timer == crate::timer::Timer::PathValidation
                && deadline.at == now + PATH_VALIDATION_TIMEOUT
        }));
        let transmit = conn.poll_transmit(now).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(frame, Frame::PathChallenge(challenge));
    }

    #[test]
    fn path_validation_success_clears_deadline() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let challenge = [3; 8];
        conn.start_path_validation(challenge, now);
        let _ = conn.poll_transmit(now).unwrap();

        let effects = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::PathResponse(challenge),
                now + Duration::from_millis(1),
            )
            .unwrap();

        assert!(
            effects
                .connection_events
                .contains(&ConnectionEvent::PathValidated)
        );
        assert!(
            !conn
                .timer_effects(now)
                .wakeups
                .iter()
                .any(|deadline| deadline.timer == crate::timer::Timer::PathValidation)
        );
        let events = conn.drain_qlog_events();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, QlogEvent::PathStateUpdated { state: "validated" }))
        );
    }

    #[test]
    fn path_validation_retransmits_until_attempt_limit() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let challenge = [5; 8];
        conn.start_path_validation(challenge, now);
        let _ = conn.poll_transmit(now).unwrap();

        let first_timeout = now + PATH_VALIDATION_TIMEOUT;
        let effects = conn.on_timeout(first_timeout).unwrap();
        assert!(
            !effects
                .connection_events
                .contains(&ConnectionEvent::PathValidationFailed)
        );
        assert_eq!(
            effects
                .wakeups
                .iter()
                .find(|deadline| deadline.timer == crate::timer::Timer::PathValidation)
                .map(|deadline| deadline.at),
            Some(first_timeout + PATH_VALIDATION_TIMEOUT)
        );
        let retransmit = conn.poll_transmit(first_timeout).unwrap();
        let (frame, consumed) = Frame::decode(&retransmit.contents).unwrap();
        assert_eq!(consumed, retransmit.contents.len());
        assert_eq!(frame, Frame::PathChallenge(challenge));

        let second_timeout = first_timeout + PATH_VALIDATION_TIMEOUT;
        let _ = conn.on_timeout(second_timeout).unwrap();
        let _ = conn.poll_transmit(second_timeout).unwrap();

        let third_timeout = second_timeout + PATH_VALIDATION_TIMEOUT;
        let effects = conn.on_timeout(third_timeout).unwrap();
        assert!(
            effects
                .connection_events
                .contains(&ConnectionEvent::PathValidationFailed)
        );
        assert!(
            !effects
                .wakeups
                .iter()
                .any(|deadline| deadline.timer == crate::timer::Timer::PathValidation)
        );
        let events = conn.drain_qlog_events();
        assert!(events.iter().any(|event| matches!(
            event,
            QlogEvent::PathStateUpdated {
                state: "validation_failed"
            }
        )));
    }

    #[test]
    fn queue_new_connection_id_emits_control_frame() {
        let mut conn = Connection::new();
        conn.queue_new_connection_id(
            VarInt::from_u32(1),
            VarInt::ZERO,
            b"altcid01".to_vec(),
            [9; 16],
        )
        .unwrap();

        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::NewConnectionId {
                sequence: VarInt::from_u32(1),
                retire_prior_to: VarInt::ZERO,
                connection_id: b"altcid01".to_vec(),
                reset_token: [9; 16],
            }
        );
    }

    #[test]
    fn rejects_new_connection_id_with_retire_prior_to_after_sequence() {
        let mut conn = Connection::new();
        let error = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::NewConnectionId {
                    sequence: VarInt::from_u32(1),
                    retire_prior_to: VarInt::from_u32(2),
                    connection_id: b"peer-cid".to_vec(),
                    reset_token: [0; 16],
                },
                Instant::now(),
            )
            .unwrap_err();

        assert_eq!(
            error.transport_code(),
            TransportErrorCode::FrameEncodingError
        );
    }

    #[test]
    fn rejects_invalid_outgoing_new_connection_id() {
        let mut conn = Connection::new();
        let error = conn
            .queue_new_connection_id(VarInt::ZERO, VarInt::ZERO, Vec::new(), [0; 16])
            .unwrap_err();
        assert_eq!(
            error.transport_code(),
            TransportErrorCode::FrameEncodingError
        );

        let error = conn
            .queue_new_connection_id(
                VarInt::from_u32(1),
                VarInt::from_u32(2),
                b"peer-cid".to_vec(),
                [0; 16],
            )
            .unwrap_err();
        assert_eq!(
            error.transport_code(),
            TransportErrorCode::FrameEncodingError
        );
    }

    #[test]
    fn application_close_queues_close_frame() {
        let mut conn = Connection::new();
        let effects = conn
            .close_application(VarInt::from_u32(42), b"done")
            .unwrap();

        assert!(conn.is_closed());
        assert_eq!(
            effects.connection_events.as_slice(),
            &[ConnectionEvent::Closed]
        );
        assert_eq!(conn.memory_stats().pending_control_bytes, 4);
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert_eq!(conn.memory_stats().pending_control_bytes, 0);
        assert_eq!(conn.memory_stats().sent_control_bytes, 4);
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::ApplicationClose {
                error_code: VarInt::from_u32(42),
                reason: b"done".to_vec(),
            }
        );
    }

    #[test]
    fn tracks_largest_actually_acked_packet_per_space() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_packet(EncryptionLevel::OneRtt, 7, 1200, true, now);
        let unsent_ack = Frame::Ack {
            largest: VarInt::from_u32(8),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(EncryptionLevel::OneRtt, &unsent_ack, now);
        assert_eq!(
            conn.largest_acked_packet_number(EncryptionLevel::OneRtt),
            None
        );

        let sent_ack = Frame::Ack {
            largest: VarInt::from_u32(7),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(EncryptionLevel::OneRtt, &sent_ack, now);

        assert_eq!(
            conn.largest_acked_packet_number(EncryptionLevel::OneRtt),
            Some(7)
        );
        conn.discard_packet_space(EncryptionLevel::OneRtt);
        assert_eq!(
            conn.largest_acked_packet_number(EncryptionLevel::OneRtt),
            None
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_mtu_probe_ack_raises_current_mtu() {
        use crate::{
            crypto::{packet::FramePacketBuilder, rustls::tests::one_rtt_test_keys},
            mtud::MtuDiscoveryConfig,
        };

        let now = web_time::Instant::now();
        let (keys, _) = one_rtt_test_keys();
        let mut connection = Connection::new();
        connection.configure_mtu_discovery(1_200, Some(MtuDiscoveryConfig::default()));
        let mut builder =
            FramePacketBuilder::new(crate::cid::ConnectionId::from_slice(b"peer-cid").unwrap());

        let probe = connection
            .poll_protected_one_rtt_transmit(&mut builder, &keys, now)
            .unwrap()
            .unwrap();
        assert!(probe.contents.len() > 1_200);
        let probe_size = probe.contents.len() as u16;
        let ack = Frame::Ack {
            largest: VarInt::ZERO,
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        connection.handle_ack_frame(
            EncryptionLevel::OneRtt,
            &ack,
            now + Duration::from_millis(1),
        );

        assert_eq!(connection.current_mtu(), probe_size);
        assert_eq!(connection.stats().current_mtu, probe_size);
        assert_eq!(connection.stats().mtu_probes_sent, 1);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn sparse_ack_protected_packet_fits_minimum_mtu() {
        use crate::crypto::{packet::FramePacketBuilder, rustls::tests::one_rtt_test_keys};
        let now = web_time::Instant::now();
        let (keys, _) = one_rtt_test_keys();
        let mut connection = Connection::new();
        for number in 0..256u64 {
            connection
                .ack
                .record_received_packet(EncryptionLevel::OneRtt, number << 32, true);
        }
        let ack = connection
            .ack
            .take_ack_frame(EncryptionLevel::OneRtt, Duration::ZERO, 3)
            .unwrap();
        connection.queue_ack(ack);
        let mut builder =
            FramePacketBuilder::new(crate::cid::ConnectionId::from_slice(&[7; 20]).unwrap());
        let packet = connection
            .poll_protected_one_rtt_transmit(&mut builder, &keys, now)
            .unwrap()
            .unwrap();
        assert!(packet.contains_ack);
        assert!(packet.contents.len() <= 1200);
    }

    #[test]
    fn ack_for_unsent_packet_is_a_protocol_violation() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_packet(EncryptionLevel::OneRtt, 7, 1200, true, now);
        let ack = Frame::Ack {
            largest: VarInt::from_u32(8),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        let error = conn
            .handle_frame(EncryptionLevel::OneRtt, ack, now)
            .unwrap_err();

        assert_eq!(
            error,
            crate::error::CodecError::Transport(TransportErrorCode::ProtocolViolation)
        );
    }

    #[test]
    fn ack_for_sent_non_ack_eliciting_packet_is_valid() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_packet(EncryptionLevel::OneRtt, 7, 64, false, now);
        assert_eq!(conn.stats().bytes_in_flight, 0);

        conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::Ack {
                largest: VarInt::from_u32(7),
                delay: VarInt::ZERO,
                first_range: VarInt::ZERO,
                ranges: Default::default(),
                ecn: None,
            },
            now,
        )
        .unwrap();

        assert_eq!(
            conn.largest_acked_packet_number(EncryptionLevel::OneRtt),
            Some(7)
        );
        assert_eq!(conn.stats().bytes_in_flight, 0);
    }

    #[test]
    fn malformed_ack_range_is_a_frame_encoding_error() {
        let mut conn = Connection::new();
        let error = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::Ack {
                    largest: VarInt::ZERO,
                    delay: VarInt::ZERO,
                    first_range: VarInt::from_u32(1),
                    ranges: Default::default(),
                    ecn: None,
                },
                web_time::Instant::now(),
            )
            .unwrap_err();

        assert_eq!(
            error,
            crate::error::CodecError::Transport(TransportErrorCode::FrameEncodingError)
        );
    }

    #[test]
    fn lost_application_close_frame_is_requeued_for_retransmission() {
        let mut conn = Connection::new();
        let sent_at = web_time::Instant::now() - web_time::Duration::from_millis(20);
        conn.close_application(VarInt::from_u32(42), b"done")
            .unwrap();
        let _ = conn.poll_transmit(sent_at).unwrap();
        let ack = Frame::Ack {
            largest: VarInt::from_u32(3),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        let effects =
            conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, web_time::Instant::now());

        assert!(effects.connection_events.iter().any(|event| matches!(
            event,
            ConnectionEvent::PacketLost {
                level: EncryptionLevel::OneRtt,
                packet_number: 0
            }
        )));
        assert_eq!(conn.stats().retransmissions, 1);
        let retransmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&retransmit.contents).unwrap();
        assert_eq!(consumed, retransmit.contents.len());
        assert_eq!(
            frame,
            Frame::ApplicationClose {
                error_code: VarInt::from_u32(42),
                reason: b"done".to_vec(),
            }
        );
    }

    #[test]
    fn time_threshold_timeout_requeues_lost_control_frame() {
        let now = web_time::Instant::now();
        let mut conn = Connection::new();
        conn.recovery
            .set_smoothed_rtt(web_time::Duration::from_millis(100));
        conn.close_application(VarInt::from_u32(42), b"done")
            .unwrap();
        let _ = conn.poll_transmit(now).unwrap();

        conn.send_control.push_back(Frame::Ping);
        let _ = conn
            .poll_transmit(now + web_time::Duration::from_millis(10))
            .unwrap();
        let ack = Frame::Ack {
            largest: VarInt::from_u32(1),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        let ack_effects = conn.handle_ack_frame(
            EncryptionLevel::OneRtt,
            &ack,
            now + web_time::Duration::from_millis(11),
        );
        assert!(ack_effects.connection_events.is_empty());

        let loss_deadline = conn.timeout().unwrap();
        let effects = conn.on_timeout(loss_deadline).unwrap();
        assert!(effects.connection_events.iter().any(|event| matches!(
            event,
            ConnectionEvent::PacketLost {
                level: EncryptionLevel::OneRtt,
                packet_number: 0
            }
        )));
        let retransmit = conn.poll_transmit(loss_deadline).unwrap();
        let (frame, consumed) = Frame::decode(&retransmit.contents).unwrap();
        assert_eq!(consumed, retransmit.contents.len());
        assert!(matches!(
            frame,
            Frame::ApplicationClose {
                error_code,
                reason
            } if error_code == VarInt::from_u32(42) && reason == b"done"
        ));
    }

    #[test]
    fn lost_reset_stream_is_requeued_for_retransmission() {
        let mut conn = Connection::new();
        let stream_id = StreamId(VarInt::from_u32(0));
        let sent_at = web_time::Instant::now() - web_time::Duration::from_millis(20);
        conn.queue_stream_data(stream_id, b"hello").unwrap();
        conn.reset_stream(stream_id, VarInt::from_u32(42)).unwrap();
        let sent = conn.poll_transmit(sent_at).unwrap();
        let (frame, consumed) = Frame::decode(&sent.contents).unwrap();
        assert_eq!(consumed, sent.contents.len());
        assert_eq!(
            frame,
            Frame::ResetStream {
                stream_id: stream_id.0,
                error_code: VarInt::from_u32(42),
                final_size: VarInt::from_u32(5),
            }
        );

        let ack = Frame::Ack {
            largest: VarInt::from_u32(3),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, web_time::Instant::now());
        assert_eq!(conn.stats().retransmissions, 1);

        let retransmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&retransmit.contents).unwrap();
        assert_eq!(consumed, retransmit.contents.len());
        assert_eq!(
            frame,
            Frame::ResetStream {
                stream_id: stream_id.0,
                error_code: VarInt::from_u32(42),
                final_size: VarInt::from_u32(5),
            }
        );
    }

    #[test]
    fn reliable_reset_keeps_required_unsent_prefix() {
        let mut conn = Connection::new();
        conn.set_reset_stream_at_enabled(true);
        conn.increase_connection_send_limit(1024);
        let stream_id = StreamId(VarInt::ZERO);
        conn.increase_stream_send_limit(stream_id, 1024).unwrap();
        conn.queue_stream_data(stream_id, b"header-payload")
            .unwrap();
        conn.reset_stream_at(stream_id, VarInt::from_u32(42), VarInt::from_u32(6))
            .unwrap();

        let first = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, _) = Frame::decode(&first.contents).unwrap();
        assert_eq!(
            frame,
            Frame::ResetStreamAt {
                stream_id: VarInt::ZERO,
                error_code: VarInt::from_u32(42),
                final_size: VarInt::from_u32(14),
                reliable_size: VarInt::from_u32(6),
            }
        );

        let second = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, _) = Frame::decode(&second.contents).unwrap();
        assert!(matches!(
            frame,
            Frame::Stream {
                stream_id: VarInt::ZERO,
                offset: VarInt::ZERO,
                fin: false,
                data,
            } if data.as_ref() == b"header"
        ));
    }

    #[test]
    fn received_reliable_reset_delivers_prefix_before_error() {
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        conn.set_reset_stream_at_enabled(true);
        let stream_id = StreamId(VarInt::ZERO);
        let now = web_time::Instant::now();
        conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::ResetStreamAt {
                stream_id: stream_id.0,
                error_code: VarInt::from_u32(42),
                final_size: VarInt::from_u32(10),
                reliable_size: VarInt::from_u32(6),
            },
            now,
        )
        .unwrap();
        assert_eq!(conn.recv_stream_reset_error(stream_id), None);

        conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::Stream {
                stream_id: stream_id.0,
                offset: VarInt::ZERO,
                fin: false,
                data: b"header".to_vec().into(),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            conn.read_recv_stream(stream_id, 64, true)
                .unwrap()
                .bytes
                .as_ref(),
            b"header"
        );
        assert_eq!(
            conn.recv_stream_reset_error(stream_id),
            Some(VarInt::from_u32(42))
        );
    }

    #[test]
    fn lost_stop_sending_is_requeued_for_retransmission() {
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        let stream_id = StreamId(VarInt::from_u32(0));
        let sent_at = web_time::Instant::now() - web_time::Duration::from_millis(20);
        conn.receive_stream_frame(stream_id, 0, b"hello".to_vec(), false)
            .unwrap();
        conn.stop_recv_stream(stream_id, VarInt::from_u32(9))
            .unwrap();
        let sent = conn.poll_transmit(sent_at).unwrap();
        let (frame, consumed) = Frame::decode(&sent.contents).unwrap();
        assert_eq!(consumed, sent.contents.len());
        assert_eq!(
            frame,
            Frame::StopSending {
                stream_id: stream_id.0,
                error_code: VarInt::from_u32(9),
            }
        );

        let ack = Frame::Ack {
            largest: VarInt::from_u32(3),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, web_time::Instant::now());

        let retransmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&retransmit.contents).unwrap();
        assert_eq!(consumed, retransmit.contents.len());
        assert_eq!(
            frame,
            Frame::StopSending {
                stream_id: stream_id.0,
                error_code: VarInt::from_u32(9),
            }
        );
    }

    #[test]
    fn rejects_stop_sending_on_peer_initiated_unidirectional_stream() {
        let mut conn = Connection::new();

        let err = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::StopSending {
                    // The default local initiator is the client, so stream 3
                    // is a server-initiated unidirectional stream. The peer
                    // has no receive direction on which to stop local data.
                    stream_id: VarInt::from_u32(3),
                    error_code: VarInt::from_u32(42),
                },
                web_time::Instant::now(),
            )
            .unwrap_err();

        assert_eq!(
            err,
            crate::error::CodecError::Transport(TransportErrorCode::StreamStateError)
        );
    }

    #[test]
    fn rejects_max_stream_data_on_peer_initiated_unidirectional_stream() {
        let mut conn = Connection::new();

        let err = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::MaxStreamData {
                    stream_id: VarInt::from_u32(3),
                    maximum: VarInt::from_u32(1024),
                },
                web_time::Instant::now(),
            )
            .unwrap_err();

        assert_eq!(
            err,
            crate::error::CodecError::Transport(TransportErrorCode::StreamStateError)
        );
    }

    #[test]
    fn rejects_stream_data_blocked_on_locally_initiated_unidirectional_stream() {
        let mut conn = Connection::new();

        let err = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::StreamDataBlocked {
                    // The default local initiator is the client, so stream 2
                    // is locally initiated and has no peer send direction.
                    stream_id: VarInt::from_u32(2),
                    maximum: VarInt::from_u32(1024),
                },
                web_time::Instant::now(),
            )
            .unwrap_err();

        assert_eq!(
            err,
            crate::error::CodecError::Transport(TransportErrorCode::StreamStateError)
        );
    }

    #[test]
    fn lost_stream_frame_is_requeued_with_original_offset_and_data() {
        let mut conn = Connection::new();
        let stream_id = StreamId(VarInt::from_u32(0));
        let sent_at = web_time::Instant::now() - web_time::Duration::from_millis(20);
        conn.increase_connection_send_limit(5);
        conn.increase_stream_send_limit(stream_id, 5).unwrap();
        conn.queue_stream_data(stream_id, b"hello").unwrap();
        let sent = conn.poll_transmit(sent_at).unwrap();
        let (frame, consumed) = Frame::decode(&sent.contents).unwrap();
        assert_eq!(consumed, sent.contents.len());
        assert_eq!(
            frame,
            Frame::Stream {
                stream_id: stream_id.0,
                offset: VarInt::ZERO,
                fin: false,
                data: b"hello".to_vec().into(),
            }
        );

        let ack = Frame::Ack {
            largest: VarInt::from_u32(3),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, web_time::Instant::now());

        let retransmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&retransmit.contents).unwrap();
        assert_eq!(consumed, retransmit.contents.len());
        assert_eq!(
            frame,
            Frame::Stream {
                stream_id: stream_id.0,
                offset: VarInt::ZERO,
                fin: false,
                data: b"hello".to_vec().into(),
            }
        );
    }

    #[test]
    fn pto_requeues_application_close_frame_as_probe() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.close_application(VarInt::from_u32(7), b"bye").unwrap();
        let _ = conn.poll_transmit(now).unwrap();
        let timeout = conn.timeout().expect("close frame should arm PTO");

        let effects = conn.on_timeout(timeout).unwrap();

        assert!(effects.connection_events.iter().any(|event| matches!(
            event,
            ConnectionEvent::ProbeRequired {
                level: EncryptionLevel::OneRtt,
                packets: 2
            }
        )));
        let retransmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&retransmit.contents).unwrap();
        assert_eq!(consumed, retransmit.contents.len());
        assert_eq!(
            frame,
            Frame::ApplicationClose {
                error_code: VarInt::from_u32(7),
                reason: b"bye".to_vec(),
            }
        );
    }

    #[test]
    fn pto_queues_stream_retransmission_and_ping_probe() {
        let mut conn = Connection::new();
        let stream_id = StreamId(VarInt::ZERO);
        let now = web_time::Instant::now();
        conn.increase_connection_send_limit(5);
        conn.increase_stream_send_limit(stream_id, 5).unwrap();
        conn.queue_stream_data(stream_id, b"hello").unwrap();
        let _ = conn.poll_transmit(now).unwrap();
        let timeout = conn.timeout().expect("stream frame should arm PTO");

        let effects = conn.on_timeout(timeout).unwrap();
        assert!(effects.connection_events.iter().any(|event| matches!(
            event,
            ConnectionEvent::ProbeRequired {
                level: EncryptionLevel::OneRtt,
                packets: 2
            }
        )));

        let first = Frame::decode(&conn.poll_transmit(timeout).unwrap().contents)
            .unwrap()
            .0;
        let second = Frame::decode(&conn.poll_transmit(timeout).unwrap().contents)
            .unwrap()
            .0;
        let frames = [first, second];
        assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
        assert!(frames.iter().any(|frame| matches!(
            frame,
            Frame::Stream { stream_id: id, data, .. }
                if *id == stream_id.0 && data.as_ref() == b"hello"
        )));
    }

    #[test]
    fn pto_probe_bypasses_exhausted_congestion_window() {
        let mut conn = Connection::new();
        let stream_id = StreamId(VarInt::ZERO);
        let now = web_time::Instant::now();
        conn.increase_connection_send_limit(5);
        conn.increase_stream_send_limit(stream_id, 5).unwrap();
        conn.queue_stream_data(stream_id, b"hello").unwrap();
        let _ = conn.poll_transmit(now).unwrap();
        for packet_number in 1..=10 {
            conn.record_sent_packet(EncryptionLevel::OneRtt, packet_number, 1_200, true, now);
        }
        assert!(!conn.congestion.can_send(1));

        let timeout = conn.timeout().expect("in-flight data should arm PTO");
        let effects = conn.on_timeout(timeout).unwrap();
        assert!(effects.connection_events.iter().any(|event| matches!(
            event,
            ConnectionEvent::ProbeRequired {
                level: EncryptionLevel::OneRtt,
                ..
            }
        )));

        let probe = conn
            .poll_transmit(timeout)
            .expect("PTO probe must bypass the congestion window");
        assert!(!probe.contents.is_empty());
        assert_eq!(conn.one_rtt_probe_packets_pending, 1);
    }

    #[test]
    fn abort_clears_pending_close_and_timers() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.close_application(VarInt::from_u32(7), b"bye").unwrap();
        let _ = conn.poll_transmit(now).unwrap();

        let effects = conn.abort();

        assert!(conn.is_closed());
        assert!(!conn.has_pending_transmit());
        assert!(conn.timeout().is_none());
        assert_eq!(conn.stats().bytes_in_flight, 0);
        assert_eq!(
            effects.connection_events.as_slice(),
            &[ConnectionEvent::Closed]
        );
    }

    #[test]
    fn transport_close_queues_close_frame() {
        let mut conn = Connection::new();
        let effects = conn
            .close_transport(
                TransportErrorCode::ProtocolViolation,
                VarInt::from_u32(0x1a),
                b"bad path",
            )
            .unwrap();

        assert!(conn.is_closed());
        assert_eq!(
            effects.connection_events.as_slice(),
            &[ConnectionEvent::Closed]
        );
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::ConnectionClose {
                error_code: TransportErrorCode::ProtocolViolation,
                frame_type: VarInt::from_u32(0x1a),
                reason: b"bad path".to_vec(),
            }
        );
    }

    #[test]
    fn peer_application_close_reports_received_close_frame() {
        let mut conn = Connection::new();

        let effects = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::ApplicationClose {
                    error_code: VarInt::from_u32(42),
                    reason: b"done".to_vec(),
                },
                web_time::Instant::now(),
            )
            .unwrap();

        assert_eq!(
            effects.connection_events.as_slice(),
            &[
                ConnectionEvent::Closed,
                ConnectionEvent::FrameReceived(Frame::ApplicationClose {
                    error_code: VarInt::from_u32(42),
                    reason: b"done".to_vec(),
                }),
            ]
        );
    }

    #[test]
    fn peer_transport_close_reports_received_close_frame() {
        let mut conn = Connection::new();

        let effects = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::ConnectionClose {
                    error_code: TransportErrorCode::ProtocolViolation,
                    frame_type: VarInt::from_u32(0x1a),
                    reason: b"bad path".to_vec(),
                },
                web_time::Instant::now(),
            )
            .unwrap();

        assert_eq!(
            effects.connection_events.as_slice(),
            &[
                ConnectionEvent::Closed,
                ConnectionEvent::FrameReceived(Frame::ConnectionClose {
                    error_code: TransportErrorCode::ProtocolViolation,
                    frame_type: VarInt::from_u32(0x1a),
                    reason: b"bad path".to_vec(),
                }),
            ]
        );
    }

    #[test]
    fn reset_stream_final_size_consumes_connection_flow_control_credit() {
        let mut conn = Connection::new();
        let stream_id = StreamId(VarInt::ZERO);
        conn.recv_flow = crate::streams::RecvFlowController::new(5);

        let err = conn
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::ResetStream {
                    stream_id: stream_id.0,
                    error_code: VarInt::from_u32(1),
                    final_size: VarInt::from_u32(6),
                },
                web_time::Instant::now(),
            )
            .unwrap_err();

        assert_eq!(
            err,
            crate::error::CodecError::Transport(TransportErrorCode::FlowControlError)
        );
        assert!(conn.recv_streams.recv_stream(stream_id).is_none());
        assert_eq!(conn.recv_flow.received(), 0);
    }

    #[test]
    fn reset_stream_accounts_only_new_bytes_after_received_data() {
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        let stream_id = StreamId(VarInt::ZERO);
        conn.recv_flow = crate::streams::RecvFlowController::new(5);
        conn.receive_stream_frame(stream_id, 0, b"abc".to_vec(), false)
            .unwrap();

        conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::ResetStream {
                stream_id: stream_id.0,
                error_code: VarInt::from_u32(1),
                final_size: VarInt::from_u32(5),
            },
            web_time::Instant::now(),
        )
        .unwrap();

        assert_eq!(conn.recv_flow.received(), 5);
        assert_eq!(
            conn.recv_streams
                .recv_stream(stream_id)
                .unwrap()
                .reset_error(),
            Some(VarInt::from_u32(1))
        );
    }

    #[test]
    fn stream_fin_final_offset_consumes_connection_flow_control_credit() {
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        let stream_id = StreamId(VarInt::ZERO);
        conn.recv_flow = crate::streams::RecvFlowController::new(5);

        conn.receive_stream_frame(stream_id, 5, Vec::new(), true)
            .unwrap();

        assert_eq!(conn.recv_flow.received(), 5);
        assert_eq!(
            conn.recv_streams
                .recv_stream(stream_id)
                .unwrap()
                .final_offset(),
            Some(5)
        );
    }

    #[test]
    fn stream_high_offset_cannot_exceed_connection_flow_control_credit() {
        let mut conn = Connection::new();
        let stream_id = StreamId(VarInt::ZERO);
        conn.recv_flow = crate::streams::RecvFlowController::new(5);

        let err = conn
            .receive_stream_frame(stream_id, 5, b"x".to_vec(), false)
            .unwrap_err();

        assert_eq!(
            err,
            crate::error::CodecError::Transport(TransportErrorCode::FlowControlError)
        );
        assert!(conn.recv_streams.recv_stream(stream_id).is_none());
        assert_eq!(conn.recv_flow.received(), 0);
    }

    #[test]
    fn pacing_deadline_is_attached_after_the_initial_burst() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.congestion.on_packets_acked_at(12_000, now);
        for _ in 0..16 {
            conn.send_datagram(vec![0; 1_100]).unwrap();
        }

        let mut immediate = 0;
        let mut paced = None;
        for _ in 0..16 {
            let Some(transmit) = conn.poll_transmit(now) else {
                break;
            };
            if transmit.send_at.is_some() {
                paced = Some(transmit);
                break;
            }
            immediate += 1;
        }

        assert!(immediate >= 10);
        assert!(
            paced.is_some_and(|transmit| transmit.send_at.is_some_and(|send_at| send_at > now))
        );
    }

    #[test]
    fn ack_ecn_ce_mark_reacts_as_congestion_signal() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_packet(EncryptionLevel::OneRtt, 1, 1200, true, now);
        let cwnd = conn.stats().congestion_window;
        let ack = Frame::Ack {
            largest: crate::VarInt::from_u32(1),
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: Some((
                crate::VarInt::ZERO,
                crate::VarInt::ZERO,
                crate::VarInt::from_u32(1),
            )),
        };

        conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert!(conn.stats().congestion_window < cwnd);
    }

    #[test]
    fn congestion_window_blocks_and_releases_ack_eliciting_transmits() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let cwnd = conn.stats().congestion_window;
        conn.record_sent_packet(EncryptionLevel::OneRtt, 10, cwnd, true, now);
        assert_eq!(conn.stats().bytes_in_flight, cwnd);

        conn.send_datagram(b"blocked".to_vec()).unwrap();
        assert!(conn.poll_transmit(now).is_none());

        let ack = Frame::Ack {
            largest: crate::VarInt::from_u32(10),
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        let transmit = conn.poll_transmit(now).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::Datagram {
                data: b"blocked".to_vec().into(),
            }
        );
        assert!(conn.stats().bytes_in_flight > 0);
        assert!(conn.stats().congestion_window > cwnd);
    }

    #[test]
    fn persistent_congestion_reduces_connection_window_to_minimum() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_packet(
            EncryptionLevel::OneRtt,
            1,
            1200,
            true,
            now - web_time::Duration::from_millis(3000),
        );
        conn.record_sent_packet(
            EncryptionLevel::OneRtt,
            2,
            1200,
            true,
            now - web_time::Duration::from_millis(500),
        );
        conn.record_sent_packet(EncryptionLevel::OneRtt, 3, 1200, true, now);

        let ack = Frame::Ack {
            largest: crate::VarInt::from_u32(3),
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        let effects = conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert_eq!(effects.connection_events.len(), 2);
        assert_eq!(conn.stats().congestion_window, 2400);
        assert_eq!(conn.stats().bytes_in_flight, 0);
    }

    #[test]
    fn recv_dispatches_plain_frame_payloads() {
        let mut conn = Connection::new();
        conn.set_receive_datagram_frame_size(Some(VarInt::from_u32(1200)));
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        let now = web_time::Instant::now();
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        let payload = [
            Frame::Datagram {
                data: b"dgram".to_vec().into(),
            }
            .encode(),
            Frame::Stream {
                stream_id: stream_id.0,
                offset: crate::VarInt::ZERO,
                fin: true,
                data: b"stream".to_vec().into(),
            }
            .encode(),
        ]
        .concat();

        let effects = conn
            .recv(
                &payload,
                RecvMeta {
                    ecn: Some(EcnCodepoint::Ect1),
                },
                now,
            )
            .unwrap();

        assert_eq!(conn.stats().bytes_received, payload.len() as u64);
        assert_eq!(conn.stats().packets_received, 1);
        assert_eq!(conn.stats().ecn_ect1_packets, 1);
        assert_eq!(conn.read_datagram(), Some(b"dgram".to_vec()));
        assert_eq!(conn.accept_recv_stream(), Some(stream_id));
        assert_eq!(conn.stats().streams_accepted, 1);
        assert_eq!(
            conn.read_recv_stream(stream_id, 64, true)
                .unwrap()
                .bytes
                .as_ref(),
            b"stream"
        );
        assert!(
            effects
                .connection_events
                .iter()
                .any(|event| matches!(event, ConnectionEvent::DatagramReceived { len: 5 }))
        );
        assert!(
            !effects
                .connection_events
                .iter()
                .any(|event| matches!(event, ConnectionEvent::FrameReceived(_)))
        );
    }

    #[test]
    fn frame_dispatch_handles_ack_and_close() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_packet(EncryptionLevel::OneRtt, 0, 100, true, now);
        let payload = [
            Frame::Ack {
                largest: crate::VarInt::ZERO,
                delay: crate::VarInt::ZERO,
                first_range: crate::VarInt::ZERO,
                ranges: Default::default(),
                ecn: None,
            }
            .encode(),
            Frame::ApplicationClose {
                error_code: crate::VarInt::from_u32(42),
                reason: b"done".to_vec(),
            }
            .encode(),
        ]
        .concat();

        let effects = conn
            .handle_frame_payload(EncryptionLevel::OneRtt, &payload, now)
            .unwrap();

        assert_eq!(conn.stats().bytes_in_flight, 0);
        assert!(conn.is_closed());
        assert!(effects.connection_events.contains(&ConnectionEvent::Closed));
    }

    #[test]
    fn ack_updates_rtt_stats() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let sent_at = now - web_time::Duration::from_millis(25);
        conn.record_sent_packet(EncryptionLevel::OneRtt, 3, 1200, true, sent_at);

        let ack = Frame::Ack {
            largest: crate::VarInt::from_u32(3),
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert_eq!(
            conn.stats().latest_rtt,
            Some(core::time::Duration::from_millis(25))
        );
        assert_eq!(
            conn.stats().min_rtt,
            Some(core::time::Duration::from_millis(25))
        );
        assert_eq!(
            conn.stats().smoothed_rtt,
            Some(core::time::Duration::from_millis(25))
        );
        assert_eq!(
            conn.stats().rtt_variance,
            Some(core::time::Duration::from_micros(12_500))
        );
        assert!(conn.drain_qlog_events().iter().any(|event| matches!(
            event,
            QlogEvent::RecoveryMetricsUpdated {
                latest_rtt_us: 25_000,
                min_rtt_us: 25_000,
                smoothed_rtt_us: 25_000,
                rtt_variance_us: 12_500,
            }
        )));
    }

    #[test]
    fn ecn_validation_does_not_expect_markings_on_crypto_flights() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.record_sent_crypto_packet(EncryptionLevel::Initial, 0, 1200, Vec::new(), now);
        let ack = Frame::Ack {
            largest: crate::VarInt::ZERO,
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(EncryptionLevel::Initial, &ack, now);
        assert!(!conn.stats().ecn_disabled);
        assert_eq!(conn.stats().ecn_validation_failures, 0);
    }

    #[test]
    fn ecn_validation_failure_disables_future_packet_marking() {
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        conn.send_datagram(b"first".to_vec()).unwrap();

        let first = conn.poll_transmit(now).unwrap();
        assert_eq!(first.ecn, Some(EcnCodepoint::Ect0));

        let ack = Frame::Ack {
            largest: crate::VarInt::ZERO,
            delay: crate::VarInt::ZERO,
            first_range: crate::VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        conn.handle_ack_frame(
            EncryptionLevel::OneRtt,
            &ack,
            now + web_time::Duration::from_millis(1),
        );

        assert!(conn.stats().ecn_disabled);
        assert_eq!(conn.stats().ecn_validation_failures, 1);
        assert!(conn.drain_qlog_events().iter().any(|event| matches!(
            event,
            QlogEvent::RecoveryStateUpdated {
                state: "ecn_disabled",
                level: "1rtt",
                packet_count: 1,
            }
        )));

        conn.send_datagram(b"second".to_vec()).unwrap();
        let second = conn
            .poll_transmit(now + web_time::Duration::from_millis(2))
            .unwrap();
        assert_eq!(second.ecn, None);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn handles_opened_crypto_packet_into_tls() {
        let mut conn = Connection::new();
        let mut session = FakeCryptoSession::default();
        let packet = crate::crypto::packet::OpenedCryptoPacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::Initial,
            header: crate::packet::Header::VersionNegotiation {
                dst_cid: crate::cid::ConnectionId::EMPTY,
                src_cid: crate::cid::ConnectionId::EMPTY,
                versions: Vec::new(),
            },
            packet_number: 0,
            consumed: 123,
            ecn: None,
            frames: vec![
                Frame::Crypto {
                    offset: crate::VarInt::from_u32(6),
                    data: b" hello".to_vec(),
                },
                Frame::Crypto {
                    offset: crate::VarInt::ZERO,
                    data: b"client".to_vec(),
                },
            ]
            .into(),
        };

        let effects = conn
            .handle_opened_crypto_packet(&mut session, packet)
            .unwrap();

        assert_eq!(session.inbound, b"client hello");
        assert_eq!(effects.connection_events.len(), 1);
        assert_eq!(effects.ack_frames.len(), 1);
        assert_eq!(effects.ack_frames[0].level, EncryptionLevel::Initial);
        assert!(conn.drain_qlog_events().iter().any(|event| matches!(
            event,
            QlogEvent::PacketReceived {
                level: "initial",
                bytes: 123,
            }
        )));
        let frame = conn
            .take_crypto_ack(EncryptionLevel::Initial)
            .expect("Initial ACK should remain available to the crypto transport");
        assert!(matches!(frame, Frame::Ack { .. }));
        assert!(conn.poll_transmit(web_time::Instant::now()).is_none());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn handles_opened_frame_packet_through_common_dispatch() {
        let mut conn = Connection::new();
        conn.set_receive_datagram_frame_size(Some(VarInt::from_u32(1200)));
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        conn.confirm_handshake();
        let stream_id = StreamId(crate::VarInt::from_u32(0));
        let packet = crate::crypto::packet::OpenedFramePacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::OneRtt,
            header: crate::packet::Header::Short(crate::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: crate::cid::ConnectionId::EMPTY,
                packet_number_len: 2,
            }),
            packet_number: 0,
            consumed: 0,
            ecn: None,
            frames: vec![
                Frame::Datagram {
                    data: b"dgram".to_vec().into(),
                },
                Frame::Stream {
                    stream_id: stream_id.0,
                    offset: crate::VarInt::ZERO,
                    fin: true,
                    data: b"stream".to_vec().into(),
                },
            ]
            .into(),
        };

        let effects = conn
            .handle_opened_frame_packet(packet, web_time::Instant::now())
            .unwrap();

        assert!(effects.ack_frames.is_empty());
        assert_eq!(conn.read_datagram(), Some(b"dgram".to_vec()));
        assert_eq!(conn.accept_recv_stream(), Some(stream_id));
        assert_eq!(
            conn.read_recv_stream(stream_id, 64, true)
                .unwrap()
                .bytes
                .as_ref(),
            b"stream"
        );
        let timeout = conn.timeout().expect("1-RTT ACK delay should arm timer");
        let effects = conn.on_timeout(timeout).unwrap();
        assert_eq!(effects.ack_frames.len(), 1);
        let transmit = conn.poll_transmit(timeout).unwrap();
        let (frame, _) = Frame::decode(&transmit.contents).unwrap();
        assert!(matches!(frame, Frame::Ack { .. }));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn opened_packet_preserves_destination_cid_for_retirement_validation() {
        let mut conn = Connection::new();
        let destination_cid = crate::cid::ConnectionId::from_slice(b"localcid").unwrap();
        let packet = crate::crypto::packet::OpenedFramePacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::OneRtt,
            header: crate::packet::Header::Short(crate::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: destination_cid.clone(),
                packet_number_len: 2,
            }),
            packet_number: 7,
            consumed: 0,
            ecn: None,
            frames: vec![Frame::RetireConnectionId(crate::VarInt::from_u32(3))].into(),
        };

        let effects = conn
            .handle_opened_frame_packet(packet, web_time::Instant::now())
            .unwrap();

        assert!(effects.connection_events.iter().any(|event| matches!(
            event,
            ConnectionEvent::RetireConnectionIdReceived {
                sequence,
                packet_destination_cid,
            } if *sequence == crate::VarInt::from_u32(3)
                && packet_destination_cid == &destination_cid
        )));
        assert!(!effects.connection_events.iter().any(|event| matches!(
            event,
            ConnectionEvent::FrameReceived(Frame::RetireConnectionId(_))
        )));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn duplicate_opened_frame_packet_is_not_dispatched_twice() {
        let mut conn = Connection::new();
        conn.set_receive_datagram_frame_size(Some(VarInt::from_u32(1200)));
        let packet = crate::crypto::packet::OpenedFramePacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::OneRtt,
            header: crate::packet::Header::Short(crate::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: crate::cid::ConnectionId::EMPTY,
                packet_number_len: 2,
            }),
            packet_number: 7,
            consumed: 0,
            ecn: None,
            frames: vec![Frame::Datagram {
                data: b"dgram".to_vec().into(),
            }]
            .into(),
        };

        conn.handle_opened_frame_packet(packet.clone(), web_time::Instant::now())
            .unwrap();
        let effects = conn
            .handle_opened_frame_packet(packet, web_time::Instant::now())
            .unwrap();

        assert!(effects.connection_events.is_empty());
        assert_eq!(conn.read_datagram(), Some(b"dgram".to_vec()));
        assert_eq!(conn.read_datagram(), None);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn opened_frame_packet_queues_ack_with_ecn_counters() {
        let mut conn = Connection::new();
        conn.confirm_handshake();
        let packet = crate::crypto::packet::OpenedFramePacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::OneRtt,
            header: crate::packet::Header::Short(crate::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: crate::cid::ConnectionId::EMPTY,
                packet_number_len: 2,
            }),
            packet_number: 9,
            consumed: 0,
            ecn: Some(EcnCodepoint::Ce),
            frames: vec![Frame::Ping].into(),
        };

        let effects = conn
            .handle_opened_frame_packet(packet, web_time::Instant::now())
            .unwrap();

        assert_eq!(effects.ack_frames.len(), 1);
        assert!(matches!(
            effects.ack_frames[0].frame,
            Frame::Ack {
                ecn: Some((crate::VarInt::ZERO, crate::VarInt::ZERO, ce)),
                ..
            } if ce == crate::VarInt::from_u32(1)
        ));
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, _) = Frame::decode(&transmit.contents).unwrap();
        assert!(matches!(
            frame,
            Frame::Ack {
                ecn: Some((crate::VarInt::ZERO, crate::VarInt::ZERO, ce)),
                ..
            } if ce == crate::VarInt::from_u32(1)
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn second_one_rtt_ack_eliciting_packet_queues_ack_immediately() {
        let mut conn = Connection::new();
        conn.confirm_handshake();
        let packet = |packet_number| crate::crypto::packet::OpenedFramePacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::OneRtt,
            header: crate::packet::Header::Short(crate::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: crate::cid::ConnectionId::EMPTY,
                packet_number_len: 2,
            }),
            packet_number,
            consumed: 0,
            ecn: None,
            frames: vec![Frame::Ping].into(),
        };
        let now = web_time::Instant::now();

        let first = conn.handle_opened_frame_packet(packet(1), now).unwrap();
        let second = conn.handle_opened_frame_packet(packet(2), now).unwrap();

        assert!(first.ack_frames.is_empty());
        assert_eq!(second.ack_frames.len(), 1);
        assert!(conn.timeout().is_none_or(|deadline| deadline > now));
        assert!(matches!(
            conn.poll_transmit(now).map(|transmit| Frame::decode(&transmit.contents).unwrap().0),
            Some(Frame::Ack { largest, .. }) if largest == crate::VarInt::from_u32(2)
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn ack_frequency_updates_threshold_and_delay_for_containing_packet() {
        let mut conn = Connection::new();
        conn.confirm_handshake();
        conn.set_local_ack_delay_config(
            Duration::from_millis(25),
            3,
            Some(Duration::from_millis(1)),
        );
        let now = web_time::Instant::now();
        let frequency = Frame::AckFrequency {
            sequence: crate::VarInt::ZERO,
            ack_eliciting_threshold: crate::VarInt::from_u32(3),
            requested_max_ack_delay: crate::VarInt::from_u32(10_000),
            reordering_threshold: crate::VarInt::ZERO,
        };

        let first = conn
            .handle_opened_frame_packet(opened_one_rtt_packet(0, None, vec![frequency]), now)
            .unwrap();
        let second = conn
            .handle_opened_frame_packet(opened_one_rtt_packet(1, None, vec![Frame::Ping]), now)
            .unwrap();
        let third = conn
            .handle_opened_frame_packet(opened_one_rtt_packet(2, None, vec![Frame::Ping]), now)
            .unwrap();
        let fourth = conn
            .handle_opened_frame_packet(opened_one_rtt_packet(3, None, vec![Frame::Ping]), now)
            .unwrap();

        assert!(first.ack_frames.is_empty());
        assert!(second.ack_frames.is_empty());
        assert!(third.ack_frames.is_empty());
        assert_eq!(fourth.ack_frames.len(), 1);
        assert!(conn.one_rtt_ack_deadline.is_none());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn immediate_ack_and_reordering_override_ack_frequency_threshold() {
        let mut conn = Connection::new();
        conn.confirm_handshake();
        conn.set_local_ack_delay_config(
            Duration::from_millis(25),
            3,
            Some(Duration::from_millis(1)),
        );
        let now = web_time::Instant::now();
        conn.handle_opened_frame_packet(
            opened_one_rtt_packet(
                0,
                None,
                vec![Frame::AckFrequency {
                    sequence: crate::VarInt::ZERO,
                    ack_eliciting_threshold: crate::VarInt::from_u32(20),
                    requested_max_ack_delay: crate::VarInt::from_u32(25_000),
                    reordering_threshold: crate::VarInt::from_u32(1),
                }],
            ),
            now,
        )
        .unwrap();

        let reordered = conn
            .handle_opened_frame_packet(opened_one_rtt_packet(2, None, vec![Frame::Ping]), now)
            .unwrap();
        assert_eq!(reordered.ack_frames.len(), 1);

        let immediate = conn
            .handle_opened_frame_packet(
                opened_one_rtt_packet(3, None, vec![Frame::ImmediateAck]),
                now,
            )
            .unwrap();
        assert_eq!(immediate.ack_frames.len(), 1);
    }

    #[test]
    fn ack_frequency_requires_negotiation_and_valid_requested_delay() {
        let now = web_time::Instant::now();
        let frame = |sequence, delay| Frame::AckFrequency {
            sequence: crate::VarInt::from_u32(sequence),
            ack_eliciting_threshold: crate::VarInt::from_u32(10),
            requested_max_ack_delay: crate::VarInt::from_u32(delay),
            reordering_threshold: crate::VarInt::from_u32(2),
        };
        let mut unsupported = Connection::new();
        assert_eq!(
            unsupported.handle_frame(EncryptionLevel::OneRtt, frame(0, 25_000), now),
            Err(CodecError::Transport(TransportErrorCode::ProtocolViolation))
        );
        assert_eq!(
            unsupported.handle_frame(EncryptionLevel::ZeroRtt, frame(0, 25_000), now),
            Err(CodecError::Transport(TransportErrorCode::ProtocolViolation))
        );

        let mut conn = Connection::new();
        conn.set_local_ack_delay_config(
            Duration::from_millis(25),
            3,
            Some(Duration::from_millis(1)),
        );
        assert_eq!(
            conn.handle_frame(EncryptionLevel::OneRtt, frame(0, 999), now),
            Err(CodecError::Transport(TransportErrorCode::ProtocolViolation))
        );
        conn.handle_frame(EncryptionLevel::OneRtt, frame(1, 25_000), now)
            .unwrap();
        // Stale frames are ignored before validating their requested delay.
        conn.handle_frame(EncryptionLevel::OneRtt, frame(0, 999), now)
            .unwrap();
        assert_eq!(
            conn.handle_frame(EncryptionLevel::OneRtt, frame(2, 16_384_000), now),
            Err(CodecError::Transport(TransportErrorCode::ProtocolViolation))
        );
    }

    #[test]
    fn peer_ack_frequency_support_queues_retransmittable_request() {
        let mut conn = Connection::new();
        conn.set_ack_frequency_config(Some(AckFrequencyConfig {
            ack_eliciting_threshold: crate::VarInt::from_u32(9),
            max_ack_delay: Some(Duration::from_millis(10)),
            reordering_threshold: crate::VarInt::from_u32(2),
        }));
        conn.set_peer_ack_delay_config(Duration::from_millis(25), 3);
        conn.set_peer_min_ack_delay(Some(Duration::from_millis(1)));

        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        let (frame, consumed) = Frame::decode(&transmit.contents).unwrap();
        assert_eq!(consumed, transmit.contents.len());
        assert_eq!(
            frame,
            Frame::AckFrequency {
                sequence: crate::VarInt::ZERO,
                ack_eliciting_threshold: crate::VarInt::from_u32(9),
                requested_max_ack_delay: crate::VarInt::from_u32(10_000),
                reordering_threshold: crate::VarInt::from_u32(2),
            }
        );
        assert_eq!(conn.sent_control.len(), 1);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn accepted_zero_rtt_is_acknowledged_only_at_one_rtt() {
        let mut conn = Connection::new();
        let mut session = FakeCryptoSession::default();
        let packet = crate::crypto::packet::OpenedCryptoPacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::ZeroRtt,
            header: crate::packet::Header::Long(crate::packet::LongHeader {
                ty: crate::packet::PacketType::ZeroRtt,
                version: 1,
                dst_cid: crate::cid::ConnectionId::EMPTY,
                src_cid: crate::cid::ConnectionId::EMPTY,
                token: Vec::new(),
                length: Some(crate::VarInt::ZERO),
                packet_number_len: 1,
            }),
            packet_number: 5,
            consumed: 0,
            ecn: None,
            frames: vec![Frame::Ping].into(),
        };

        let effects = conn
            .handle_opened_crypto_packet(&mut session, packet)
            .unwrap();

        assert_eq!(effects.ack_frames.len(), 1);
        assert_eq!(effects.ack_frames[0].level, EncryptionLevel::OneRtt);
        assert!(matches!(
            effects.ack_frames[0].frame,
            Frame::Ack { largest, .. } if largest.into_inner() == 5
        ));
        conn.discard_packet_space(EncryptionLevel::ZeroRtt);
        assert!(conn.poll_transmit(web_time::Instant::now()).is_some());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn one_rtt_ack_delay_uses_configured_transport_values() {
        let mut conn = Connection::new();
        conn.confirm_handshake();
        conn.set_ack_delay_config(Duration::from_millis(10), 0);
        let now = web_time::Instant::now();
        let packet = crate::crypto::packet::OpenedFramePacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::OneRtt,
            header: crate::packet::Header::Short(crate::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: crate::cid::ConnectionId::EMPTY,
                packet_number_len: 2,
            }),
            packet_number: 0,
            consumed: 0,
            ecn: None,
            frames: vec![Frame::Ping].into(),
        };

        let effects = conn.handle_opened_frame_packet(packet, now).unwrap();

        assert!(effects.ack_frames.is_empty());
        assert_eq!(conn.timeout(), Some(now + Duration::from_millis(10)));
        let effects = conn.on_timeout(now + Duration::from_millis(10)).unwrap();
        assert!(matches!(
            effects.ack_frames[0].frame,
            Frame::Ack { delay, .. } if delay == crate::VarInt::from_u32(10_000)
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn one_rtt_ack_is_immediate_before_handshake_confirmation() {
        let mut conn = Connection::new();
        conn.set_ack_delay_config(Duration::from_millis(25), 3);
        let now = web_time::Instant::now();
        let packet = crate::crypto::packet::OpenedFramePacket {
            max_datagram_frame_size: None,
            level: EncryptionLevel::OneRtt,
            header: crate::packet::Header::Short(crate::packet::ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: crate::cid::ConnectionId::EMPTY,
                packet_number_len: 2,
            }),
            packet_number: 12,
            consumed: 0,
            ecn: None,
            frames: vec![Frame::Ping].into(),
        };

        let effects = conn.handle_opened_frame_packet(packet, now).unwrap();

        assert_eq!(effects.ack_frames.len(), 1);
        assert!(matches!(
            effects.ack_frames[0].frame,
            Frame::Ack { largest, delay, .. }
                if largest == crate::VarInt::from_u32(12) && delay == crate::VarInt::ZERO
        ));
        assert!(conn.one_rtt_ack_deadline.is_none());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_one_rtt_transmit_builds_wire_packet() {
        use crate::{
            cid::ConnectionId,
            crypto::{packet::FramePacketBuilder, rustls::tests::one_rtt_test_keys},
        };

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let mut builder = FramePacketBuilder::new(dst);
        let expected_dst_cid_len = builder.dst_cid_len();
        let mut conn = Connection::new();
        conn.send_datagram(b"wire".to_vec()).unwrap();

        let transmit = conn
            .poll_protected_one_rtt_transmit(&mut builder, &client_keys, web_time::Instant::now())
            .unwrap()
            .unwrap();

        assert_eq!(conn.stats().bytes_sent, transmit.contents.len() as u64);
        assert_eq!(transmit.ecn, Some(EcnCodepoint::Ect0));
        let mut packet = transmit.contents;
        let opened = crate::crypto::packet::FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut packet,
            expected_dst_cid_len,
            None,
        )
        .unwrap();
        assert_eq!(
            opened.frames.as_slice(),
            &[Frame::Datagram {
                data: b"wire".to_vec().into(),
            }]
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn unauthenticated_one_rtt_packet_is_discarded_without_poisoning_the_connection() {
        use crate::{
            cid::ConnectionId,
            crypto::{packet::FramePacketBuilder, rustls::tests::one_rtt_test_keys},
        };

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let mut builder =
            FramePacketBuilder::new(ConnectionId::from_slice(b"server-dcid").unwrap());
        let expected_dst_cid_len = builder.dst_cid_len();
        let mut conn = Connection::new();
        let now = web_time::Instant::now();
        let frames = [Frame::Ping];
        let mut corrupt = builder.build_one_rtt(&client_keys, &frames).unwrap();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;

        let error = conn
            .recv_protected_one_rtt(
                &mut server_keys,
                &mut corrupt,
                expected_dst_cid_len,
                None,
                RecvMeta { ecn: None },
                now,
            )
            .unwrap_err();
        assert_eq!(error, crate::CodecError::PacketDiscard);
        assert_eq!(server_keys.one_rtt_integrity_failures(), 1);
        assert!(!conn.is_closed());

        let mut valid = builder.build_one_rtt(&client_keys, &frames).unwrap();
        conn.recv_protected_one_rtt(
            &mut server_keys,
            &mut valid,
            expected_dst_cid_len,
            None,
            RecvMeta { ecn: None },
            now + web_time::Duration::from_millis(1),
        )
        .unwrap();
        assert_eq!(server_keys.one_rtt_integrity_failures(), 1);
        assert!(!conn.is_closed());
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_one_rtt_transmit_batch_amortizes_full_sized_stream_packets() {
        use crate::{
            cid::ConnectionId,
            crypto::{packet::FramePacketBuilder, rustls::tests::one_rtt_test_keys},
        };

        let (client_keys, _server_keys) = one_rtt_test_keys();
        let mut builder =
            FramePacketBuilder::new(ConnectionId::from_slice(b"server-dcid").unwrap());
        let mut conn = Connection::new();
        let stream_id = StreamId(crate::VarInt::ZERO);
        conn.increase_connection_send_limit(4_800);
        conn.increase_stream_send_limit(stream_id, 4_800).unwrap();
        conn.queue_stream_data(stream_id, &vec![0x5a; 4_800])
            .unwrap();

        let transmits = conn
            .poll_protected_one_rtt_transmit_batch(
                &mut builder,
                &client_keys,
                web_time::Instant::now(),
                4,
            )
            .unwrap();

        assert_eq!(transmits.len(), 4);
        assert!(
            transmits
                .iter()
                .all(|transmit| transmit.contents.len() >= 1_200)
        );
        assert_eq!(builder.next_one_rtt_packet_number(), 4);
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_one_rtt_transmit_batch_amortizes_queued_datagrams() {
        use crate::{
            cid::ConnectionId,
            crypto::{packet::FramePacketBuilder, rustls::tests::one_rtt_test_keys},
        };

        let (client_keys, _server_keys) = one_rtt_test_keys();
        let mut builder =
            FramePacketBuilder::new(ConnectionId::from_slice(b"server-dcid").unwrap());
        let mut conn = Connection::new();
        conn.send_datagram(b"latency-sensitive".to_vec()).unwrap();
        conn.send_datagram(vec![0x5a; 1_100]).unwrap();

        let transmits = conn
            .poll_protected_one_rtt_transmit_batch(
                &mut builder,
                &client_keys,
                web_time::Instant::now(),
                8,
            )
            .unwrap();

        assert_eq!(transmits.len(), 2);
        assert!(transmits[0].contents.len() < 1_200);
        assert_eq!(builder.next_one_rtt_packet_number(), 2);
        assert!(!conn.has_pending_transmit());
    }

    #[test]
    fn keep_alive_without_crypto_preserves_padding_and_queues_one_ping() {
        let mut conn = Connection::new();
        conn.send_control.push_back(Frame::Padding);
        conn.queue_keep_alive().unwrap();
        conn.queue_keep_alive().unwrap();
        assert_eq!(conn.send_control.len(), 2);
        assert!(matches!(conn.send_control.front(), Some(Frame::Padding)));
        assert!(matches!(conn.send_control.back(), Some(Frame::Ping)));
    }

    #[test]
    fn keep_alive_is_not_suppressed_by_pending_application_data() {
        let mut conn = Connection::new();
        conn.send_datagram(vec![0; 1300]).unwrap();
        conn.queue_keep_alive().unwrap();
        conn.queue_keep_alive().unwrap();
        assert_eq!(conn.send_control.len(), 1);
        assert!(matches!(conn.send_control.front(), Some(Frame::Ping)));
    }

    #[test]
    fn received_datagrams_enforce_actual_wire_limit() {
        let now = Instant::now();
        let mut conn = Connection::new();
        conn.set_receive_datagram_frame_size(None);
        assert_eq!(
            conn.handle_frame_payload(EncryptionLevel::OneRtt, &[0x30], now)
                .unwrap_err()
                .transport_code(),
            TransportErrorCode::ProtocolViolation
        );
        conn.set_receive_datagram_frame_size(Some(VarInt::from_u32(2)));
        conn.handle_frame_payload(EncryptionLevel::OneRtt, &[0x30, 7], now)
            .unwrap();
        conn.handle_frame_payload(EncryptionLevel::OneRtt, &[0x31, 0], now)
            .unwrap();
        assert!(
            conn.handle_frame_payload(EncryptionLevel::OneRtt, &[0x31, 1, 7], now)
                .is_err()
        );
        // A two-byte Length of zero is legal, but makes the wire frame too large.
        assert!(
            conn.handle_frame_payload(EncryptionLevel::OneRtt, &[0x31, 0x40, 0], now)
                .is_err()
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn protected_datagram_limit_and_mtu_shrink_are_enforced() {
        use crate::crypto::{
            packet::{FramePacketBuilder, FramePacketOpener},
            rustls::tests::one_rtt_test_keys,
        };
        let (client, mut server) = one_rtt_test_keys();
        let mut builder = FramePacketBuilder::new(crate::cid::ConnectionId::EMPTY);
        let packet = builder
            .build_one_rtt(
                &client,
                &[Frame::Datagram {
                    data: vec![7; 8].into(),
                }],
            )
            .unwrap();
        let mut bytes = packet;
        let opened = FramePacketOpener::open_one_rtt(&mut server, &mut bytes, 0, None).unwrap();
        assert_eq!(opened.max_datagram_frame_size, Some(10));
        let mut conn = Connection::new();
        conn.set_receive_datagram_frame_size(Some(VarInt::from_u32(9)));
        assert_eq!(
            conn.handle_opened_frame_packet(opened, Instant::now())
                .unwrap_err()
                .transport_code(),
            TransportErrorCode::ProtocolViolation
        );
        conn.configure_mtu_discovery(1500, None);
        conn.send_datagram(vec![0; 1300]).unwrap();
        conn.configure_mtu_discovery(1200, None);
        assert!(conn.poll_datagram_frame().is_none());
        assert_eq!(conn.queued_send_datagram_bytes(), 0);
        assert_eq!(conn.stats().datagrams_dropped, 1);
    }

    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    #[test]
    fn protected_zero_rtt_stream_is_requeued_after_rejection() {
        use crate::{
            cid::ConnectionId,
            crypto::{
                packet::{CryptoPacketBuilder, CryptoPacketOpener, FramePacketBuilder},
                rustls::tests::zero_rtt_test_keys,
            },
        };

        let (client_keys, mut server_keys) = zero_rtt_test_keys();
        let destination = ConnectionId::from_slice(b"server-dcid").unwrap();
        let mut zero_rtt_builder =
            CryptoPacketBuilder::new(destination.clone(), ConnectionId::EMPTY);
        let stream_id = StreamId(crate::VarInt::ZERO);
        let mut conn = Connection::new();
        conn.increase_connection_send_limit(64);
        conn.increase_stream_send_limit(stream_id, 64).unwrap();
        conn.queue_stream_data(stream_id, b"early-stream").unwrap();

        let transmit = conn
            .poll_protected_zero_rtt_transmit(
                &mut zero_rtt_builder,
                &client_keys,
                web_time::Instant::now(),
            )
            .unwrap()
            .unwrap();
        let mut packet = transmit.contents;
        let opened = CryptoPacketOpener::open_zero_rtt(&server_keys, &mut packet, None).unwrap();
        assert_eq!(opened.level, EncryptionLevel::ZeroRtt);
        assert!(matches!(
            opened.frames.as_slice(),
            [Frame::Stream {
                stream_id: id,
                data,
                ..
            }] if *id == stream_id.0 && data.as_ref() == b"early-stream"
        ));

        conn.reject_zero_rtt();
        conn.reset_zero_rtt_send_limits(4, 4, 0, 1, 0);
        let mut one_rtt_builder = FramePacketBuilder::with_next_one_rtt_packet_number(
            destination,
            zero_rtt_builder
                .next_packet_number(EncryptionLevel::OneRtt)
                .unwrap(),
        );
        let retransmit = conn
            .poll_protected_one_rtt_transmit(
                &mut one_rtt_builder,
                &client_keys,
                web_time::Instant::now() + web_time::Duration::from_millis(1),
            )
            .unwrap()
            .unwrap();
        let opened = crate::crypto::packet::FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut retransmit.contents.clone(),
            one_rtt_builder.dst_cid_len(),
            None,
        )
        .unwrap();
        assert!(matches!(
            opened.frames.as_slice(),
            [Frame::Stream {
                stream_id: id,
                data,
                ..
            }] if *id == stream_id.0 && data.as_ref() == b"earl"
        ));
    }

    #[test]
    fn outbound_stream_scheduler_waits_for_peer_stream_credit() {
        let stream_id = StreamId(crate::VarInt::from_u32(6));
        let mut conn = Connection::new();
        conn.configure_outbound_stream_limits(0, 1);
        conn.increase_connection_send_limit(64);
        conn.increase_stream_send_limit(stream_id, 64).unwrap();
        conn.queue_stream_data(stream_id, b"second-uni").unwrap();

        assert!(conn.poll_transmit(web_time::Instant::now()).is_none());

        conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::MaxStreamsUni(crate::VarInt::from_u32(2)),
            web_time::Instant::now(),
        )
        .unwrap();
        let transmit = conn.poll_transmit(web_time::Instant::now()).unwrap();
        assert!(matches!(
            Frame::decode(&transmit.contents).unwrap().0,
            Frame::Stream {
                stream_id: id,
                data,
                ..
            } if id == stream_id.0 && data.as_ref() == b"second-uni"
        ));
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn recv_protected_one_rtt_opens_and_dispatches_wire_packet() {
        use crate::{
            cid::ConnectionId,
            crypto::{packet::FramePacketBuilder, rustls::tests::one_rtt_test_keys},
        };

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let stream_id = StreamId(crate::VarInt::ZERO);
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let mut builder = FramePacketBuilder::new(dst);
        let expected_dst_cid_len = builder.dst_cid_len();
        let mut packet = builder
            .build_one_rtt(
                &client_keys,
                &[Frame::Stream {
                    stream_id: stream_id.0,
                    offset: crate::VarInt::ZERO,
                    fin: true,
                    data: b"wire stream".to_vec().into(),
                }],
            )
            .unwrap();
        let packet_len = packet.len();
        let mut conn = Connection::new();
        conn.configure_inbound_stream_limits(StreamInitiator::Server, 100, 100);
        conn.confirm_handshake();

        let effects = conn
            .recv_protected_one_rtt(
                &mut server_keys,
                &mut packet,
                expected_dst_cid_len,
                None,
                RecvMeta {
                    ecn: Some(EcnCodepoint::Ce),
                },
                web_time::Instant::now(),
            )
            .unwrap();

        assert_eq!(conn.stats().bytes_received, packet_len as u64);
        assert_eq!(conn.stats().packets_received, 1);
        assert_eq!(conn.accept_recv_stream(), Some(stream_id));
        assert_eq!(
            conn.read_recv_stream(stream_id, 64, true)
                .unwrap()
                .bytes
                .as_ref(),
            b"wire stream"
        );
        assert_eq!(effects.ack_frames.len(), 1);
        assert!(matches!(
            effects.ack_frames[0].frame,
            Frame::Ack {
                ecn: Some((crate::VarInt::ZERO, crate::VarInt::ZERO, ce)),
                ..
            } if ce == crate::VarInt::from_u32(1)
        ));
    }
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn authenticated_stream_input_rejects_unopened_ids_and_bounds_metadata() {
        use crate::{
            cid::ConnectionId,
            crypto::{packet::FramePacketBuilder, rustls::tests::one_rtt_test_keys},
        };
        for local_id in [false, true] {
            let (client_keys, mut server_keys) = one_rtt_test_keys();
            let mut conn = Connection::new();
            conn.configure_inbound_stream_limits(StreamInitiator::Server, 1000, 1000);
            conn.set_max_stream_metadata_entries(8);
            let mut builder =
                FramePacketBuilder::new(ConnectionId::from_slice(b"servercid").unwrap());
            for ordinal in 0..9 {
                let mut packet = builder
                    .build_one_rtt(
                        &client_keys,
                        &[Frame::Stream {
                            stream_id: VarInt::from_u32(ordinal * 4 + u32::from(local_id)),
                            offset: VarInt::ZERO,
                            fin: false,
                            data: bytes::Bytes::new(),
                        }],
                    )
                    .unwrap();
                let result = conn.recv_protected_one_rtt(
                    &mut server_keys,
                    &mut packet,
                    builder.dst_cid_len(),
                    None,
                    RecvMeta { ecn: None },
                    Instant::now(),
                );
                if local_id {
                    assert_eq!(
                        result.unwrap_err(),
                        crate::CodecError::Transport(TransportErrorCode::StreamStateError)
                    );
                    assert_eq!(conn.memory_stats().recv_stream_states, 0);
                    break;
                } else if ordinal == 8 {
                    assert_eq!(result.unwrap_err(), crate::CodecError::BufferLimitExceeded);
                    assert_eq!(conn.memory_stats().recv_stream_states, 8);
                } else {
                    result.unwrap();
                }
            }
        }
    }
}
