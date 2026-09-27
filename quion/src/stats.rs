/// Stable aggregate counters for one connection.
pub type ConnectionStats = quion_proto::stats::ConnectionStats;
/// Stable aggregate counters for one endpoint.
pub type EndpointStats = quion_proto::stats::EndpointStats;
/// Connection-level flow-control snapshot.
pub type FlowControlStats = quion_proto::stats::FlowControlStats;
/// Stream-level flow-control snapshot.
pub type StreamFlowControlStats = quion_proto::stats::StreamFlowControlStats;

/// Stable per-stream statistics snapshot.
pub type StreamStats = StreamFlowControlStats;

/// Stable per-path statistics snapshot.
pub type PathStats = crate::PathDiagnostics;

/// Stable congestion and recovery snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CongestionStats {
    /// Smoothed round-trip time.
    pub smoothed_rtt: Option<std::time::Duration>,
    /// Latest round-trip sample.
    pub latest_rtt: Option<std::time::Duration>,
    /// Minimum observed round-trip time.
    pub min_rtt: Option<std::time::Duration>,
    /// RTT variation estimate.
    pub rtt_variance: Option<std::time::Duration>,
    /// Current congestion window in bytes.
    pub congestion_window: u64,
    /// Ack-eliciting bytes currently in flight.
    pub bytes_in_flight: u64,
    /// Packets declared lost.
    pub packets_lost: u64,
    /// Frames retransmitted after loss or PTO.
    pub retransmissions: u64,
}

impl From<&ConnectionStats> for CongestionStats {
    fn from(stats: &ConnectionStats) -> Self {
        Self {
            smoothed_rtt: stats.smoothed_rtt,
            latest_rtt: stats.latest_rtt,
            min_rtt: stats.min_rtt,
            rtt_variance: stats.rtt_variance,
            congestion_window: stats.congestion_window,
            bytes_in_flight: stats.bytes_in_flight,
            packets_lost: stats.packets_lost,
            retransmissions: stats.retransmissions,
        }
    }
}
