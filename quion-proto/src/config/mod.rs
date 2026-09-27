use crate::{congestion::CongestionAlgorithm, mtud::MtuDiscoveryConfig, varint::VarInt};

/// Policy requested from peers through the ACK_FREQUENCY extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrequencyConfig {
    /// Number of ACK-eliciting packets a peer may receive without immediately
    /// acknowledging them.
    pub ack_eliciting_threshold: VarInt,
    /// Requested maximum ACK delay. `None` retains the peer's advertised
    /// maximum while still applying the packet and reordering thresholds.
    pub max_ack_delay: Option<core::time::Duration>,
    /// Packet reordering threshold that causes an immediate acknowledgment.
    pub reordering_threshold: VarInt,
}

impl AckFrequencyConfig {
    /// Sets the number of ACK-eliciting packets the peer may receive before it
    /// must acknowledge them.
    pub fn ack_eliciting_threshold(&mut self, value: VarInt) -> &mut Self {
        self.ack_eliciting_threshold = value;
        self
    }

    /// Sets the requested maximum ACK delay.
    pub fn max_ack_delay(&mut self, value: Option<core::time::Duration>) -> &mut Self {
        self.max_ack_delay = value;
        self
    }

    /// Sets the reordering threshold that requests an immediate ACK.
    pub fn reordering_threshold(&mut self, value: VarInt) -> &mut Self {
        self.reordering_threshold = value;
        self
    }
}

impl Default for AckFrequencyConfig {
    fn default() -> Self {
        Self {
            ack_eliciting_threshold: VarInt::from_u32(1),
            max_ack_delay: None,
            reordering_threshold: VarInt::from_u32(2),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Congestion controller used for newly created connections.
    pub congestion_algorithm: CongestionAlgorithm,
    /// Initial maximum UDP payload size used on a path.
    ///
    /// Values above 1,200 bytes are suitable when the deployment already
    /// knows that the path supports them. DPLPMTUD can otherwise discover a
    /// larger value and restore the 1,200-byte base after a black hole.
    pub initial_mtu: u16,
    /// Datagram Packetization Layer PMTU discovery configuration.
    ///
    /// `None` fixes the UDP payload size to `initial_mtu`.
    pub mtu_discovery: Option<MtuDiscoveryConfig>,
    pub initial_max_data: VarInt,
    pub initial_max_stream_data_bidi_local: VarInt,
    pub initial_max_stream_data_bidi_remote: VarInt,
    pub initial_max_stream_data_uni: VarInt,
    pub initial_max_streams_bidi: VarInt,
    pub initial_max_streams_uni: VarInt,
    pub max_idle_timeout_ms: VarInt,
    /// Optional local keep-alive interval; never sent as a transport parameter.
    pub keep_alive_interval: Option<core::time::Duration>,
    /// Minimum ACK delay in microseconds advertised for ACK_FREQUENCY.
    ///
    /// `None` disables negotiation of the extension.
    pub min_ack_delay: Option<VarInt>,
    /// ACK behavior requested from peers that advertise ACK_FREQUENCY.
    ///
    /// `None` disables sending ACK_FREQUENCY frames while retaining support
    /// for peer requests when `min_ack_delay` is advertised.
    pub ack_frequency_config: Option<AckFrequencyConfig>,
    /// Maximum number of peer-issued connection IDs this endpoint will retain.
    /// RFC 9000 requires this transport parameter to be at least two.
    pub active_connection_id_limit: VarInt,
    pub max_datagram_frame_size: Option<VarInt>,
    /// Advertise support for QUIC stream resets with partial delivery.
    pub reset_stream_at: bool,
    /// Maximum number of application DATAGRAM payloads queued in either
    /// direction per connection.
    pub max_queued_datagrams: usize,
    /// Maximum application DATAGRAM payload bytes queued in either direction
    /// per connection.
    pub max_queued_datagram_bytes: usize,
    /// Maximum number of pending control frames per connection.
    ///
    /// Superseded flow-control updates and duplicate idempotent frames are
    /// coalesced before this limit is applied.
    pub max_queued_control_frames: usize,
    /// Maximum disjoint received packet ranges retained per packet number
    /// space for ACK generation.
    /// Values below one are clamped to one when applied to a connection.
    /// Generated ACK frames also have an independent wire-size limit.
    pub max_ack_ranges_per_space: usize,
    /// Maximum CRYPTO bytes buffered ahead of the TLS read offset in each
    /// packet number space.
    pub max_crypto_buffered_data: u64,
    /// Maximum queued stream send data across all streams in one connection.
    pub max_send_buffered_stream_data: usize,
    /// Maximum metadata entries per stream direction, including terminal ranges.
    pub max_stream_metadata_entries: usize,
    /// Maximum received stream data buffered per stream before the
    /// application reads it.
    pub max_recv_buffered_stream_data: usize,
    /// Maximum received stream data buffered across all streams in one
    /// connection before the application reads it.
    pub max_recv_buffered_stream_data_per_connection: usize,
    /// Advertise that peer-initiated active connection migration is disabled.
    pub disable_active_migration: bool,
    /// Length used for newly generated connection IDs. Zero selects the
    /// high-level endpoint default.
    pub connection_id_length: u8,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            congestion_algorithm: CongestionAlgorithm::NewReno,
            initial_mtu: 1200,
            mtu_discovery: Some(MtuDiscoveryConfig::default()),
            initial_max_data: VarInt::from_u32(10 * 1024 * 1024),
            initial_max_stream_data_bidi_local: VarInt::from_u32(1_250_000),
            initial_max_stream_data_bidi_remote: VarInt::from_u32(1_250_000),
            initial_max_stream_data_uni: VarInt::from_u32(1_250_000),
            initial_max_streams_bidi: VarInt::from_u32(100),
            initial_max_streams_uni: VarInt::from_u32(100),
            max_idle_timeout_ms: VarInt::from_u32(30_000),
            keep_alive_interval: None,
            min_ack_delay: Some(VarInt::from_u32(1_000)),
            ack_frequency_config: None,
            active_connection_id_limit: VarInt::from_u32(2),
            max_datagram_frame_size: None,
            reset_stream_at: false,
            max_queued_datagrams: 1024,
            max_queued_datagram_bytes: 4 * 1024 * 1024,
            max_queued_control_frames: 4096,
            max_ack_ranges_per_space: crate::recovery::ack::MAX_ACK_RANGES,
            max_crypto_buffered_data: crate::crypto::stream::DEFAULT_MAX_CRYPTO_BUFFER,
            max_send_buffered_stream_data: 16 * 1024 * 1024,
            max_stream_metadata_entries: 16_384,
            max_recv_buffered_stream_data: 16 * 1024 * 1024,
            max_recv_buffered_stream_data_per_connection: 16 * 1024 * 1024,
            disable_active_migration: true,
            connection_id_length: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EndpointConfig {
    pub transport: TransportConfig,
    pub connection_id_length: u8,
}
