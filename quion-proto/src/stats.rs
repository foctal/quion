use core::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowControlStats {
    pub send_limit: u64,
    pub send_consumed: u64,
    pub receive_limit: u64,
    pub receive_received: u64,
    pub receive_window: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamFlowControlStats {
    pub send_limit: Option<u64>,
    pub send_consumed: Option<u64>,
    pub receive_limit: Option<u64>,
    pub receive_received: Option<u64>,
    pub receive_window: Option<u64>,
}

/// Payload-oriented memory retained by one sans-I/O connection.
///
/// The byte fields count application or CRYPTO payloads, while the count
/// fields expose bounded protocol metadata. Allocator and collection overhead
/// is intentionally excluded so snapshots remain portable across platforms.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionMemoryStats {
    pub send_stream_bytes: usize,
    pub recv_stream_bytes: usize,
    pub send_datagram_bytes: usize,
    pub recv_datagram_bytes: usize,
    pub send_crypto_bytes: usize,
    pub recv_crypto_bytes: usize,
    pub sent_crypto_bytes: usize,
    pub sent_stream_bytes: usize,
    pub recycled_stream_capacity_bytes: usize,
    pub sent_control_bytes: usize,
    pub retransmit_stream_bytes: usize,
    pub pending_control_bytes: usize,
    pub pending_control_frames: usize,
    pub pending_ack_frames: usize,
    pub retained_ack_ranges: usize,
    pub send_stream_states: usize,
    pub closed_send_stream_ranges: usize,
    pub recv_stream_states: usize,
    pub closed_recv_stream_ranges: usize,
    pub qlog_events: usize,
    pub qlog_event_bytes: usize,
}

impl ConnectionMemoryStats {
    pub const fn payload_bytes(self) -> usize {
        self.send_stream_bytes
            .saturating_add(self.recv_stream_bytes)
            .saturating_add(self.send_datagram_bytes)
            .saturating_add(self.recv_datagram_bytes)
            .saturating_add(self.send_crypto_bytes)
            .saturating_add(self.recv_crypto_bytes)
            .saturating_add(self.sent_crypto_bytes)
            .saturating_add(self.sent_stream_bytes)
            .saturating_add(self.recycled_stream_capacity_bytes)
            .saturating_add(self.sent_control_bytes)
            .saturating_add(self.retransmit_stream_bytes)
            .saturating_add(self.pending_control_bytes)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub retransmissions: u64,
    pub current_mtu: u16,
    pub mtu_probes_sent: u64,
    pub mtu_probes_lost: u64,
    pub black_holes_detected: u64,
    pub smoothed_rtt: Option<Duration>,
    pub latest_rtt: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub rtt_variance: Option<Duration>,
    pub congestion_window: u64,
    pub bytes_in_flight: u64,
    pub ecn_ect0_packets: u64,
    pub ecn_ect1_packets: u64,
    pub ecn_ce_packets: u64,
    pub ecn_validation_failures: u64,
    pub ecn_disabled: bool,
    pub streams_opened: u64,
    pub streams_accepted: u64,
    pub data_blocked_events: u64,
    pub stream_data_blocked_events: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub datagrams_dropped: u64,
    pub control_frames_dropped: u64,
    pub ack_frequency_frames_sent: u64,
    pub ack_frequency_frames_received: u64,
    pub immediate_ack_frames_sent: u64,
    pub immediate_ack_frames_received: u64,
    pub handshake_duration: Option<Duration>,
    pub migrations: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointStats {
    pub accepted_connections: u64,
    pub opened_connections: u64,
    pub closed_connections: u64,
    pub rejected_connections: u64,
    pub packets_received: u64,
    pub packets_sent: u64,
    pub dropped_packets: u64,
}
