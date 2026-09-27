use crate::{ConnectionStats, EndpointStats, FlowControlStats};

/// Portable retained-memory accounting snapshot for one connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionMemoryDiagnostics {
    /// Payload and bounded metadata retained by the sans-I/O core.
    pub protocol: quion_proto::stats::ConnectionMemoryStats,
    /// UDP payload bytes awaiting connection-level packet processing.
    pub routed_datagram_bytes: usize,
    /// Accounted bytes retained by connection-ID keys, values, and indexes.
    pub connection_id_bytes: usize,
    /// Number of qlog events retained for manual draining.
    pub qlog_events: usize,
    /// Accounted bytes retained by buffered qlog events.
    pub qlog_bytes: usize,
}

impl ConnectionMemoryDiagnostics {
    /// Returns retained payload, connection-ID, and qlog bytes.
    pub const fn payload_bytes(self) -> usize {
        self.protocol
            .payload_bytes()
            .saturating_add(self.routed_datagram_bytes)
            .saturating_add(self.connection_id_bytes)
            .saturating_add(self.qlog_bytes)
    }
}

/// Payload-oriented memory retained by an endpoint and its connections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndpointMemoryDiagnostics {
    /// Payload bytes currently reserved against the enforced shared budget.
    pub reserved_payload_bytes: usize,
    /// Configured shared endpoint payload-memory ceiling.
    pub max_payload_bytes: usize,
    /// Payload bytes retained by registered connections.
    pub connection_payload_bytes: usize,
    /// Payload bytes retained while client or server handshakes are pending.
    pub pending_handshake_payload_bytes: usize,
    /// Routed UDP bytes reserved by the shared endpoint budget.
    pub routed_datagram_bytes: usize,
    /// Accounted bytes in endpoint CID routes, reset tokens, and indexes.
    pub connection_id_route_bytes: usize,
}

impl EndpointMemoryDiagnostics {
    /// Returns all endpoint-accounted payload and connection-ID bytes.
    pub const fn payload_bytes(self) -> usize {
        self.connection_payload_bytes
            .saturating_add(self.pending_handshake_payload_bytes)
            .saturating_add(self.routed_datagram_bytes)
            .saturating_add(self.connection_id_route_bytes)
    }

    /// Returns remaining capacity in the enforced shared payload budget.
    pub const fn available_payload_bytes(self) -> usize {
        self.max_payload_bytes
            .saturating_sub(self.reserved_payload_bytes)
    }
}

/// Path-validation lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathValidationStatus {
    /// The path is awaiting a matching PATH_RESPONSE.
    Validating,
    /// The path has been authenticated and validated.
    Validated,
}

/// Stable counters and state for one network path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDiagnostics {
    /// Local UDP address used by the path.
    pub local_address: std::net::SocketAddr,
    /// Peer UDP address used by the path.
    pub remote_address: std::net::SocketAddr,
    /// Current validation state.
    pub validation: PathValidationStatus,
    /// Packets sent on the path.
    pub packets_sent: u64,
    /// UDP payload bytes sent on the path.
    pub bytes_sent: u64,
    /// Authenticated packets received on the path.
    pub packets_received: u64,
    /// Authenticated UDP payload bytes received on the path.
    pub bytes_received: u64,
    /// Smoothed RTT snapshot, when measured.
    pub smoothed_rtt: Option<std::time::Duration>,
    /// Congestion window snapshot, when the path has recovery state.
    pub congestion_window: Option<u64>,
    /// Current discovered UDP payload size, when the path has recovery state.
    pub current_mtu: Option<u16>,
    /// Whether ECN validation has failed on the path.
    pub ecn_disabled: bool,
    /// Whether anti-amplification currently prevents sends.
    pub amplification_limited: bool,
}

/// Stable, non-invasive diagnostics for a connection.
///
/// This snapshot intentionally exposes counts and lifecycle flags instead of
/// protocol-internal maps, packet number spaces, or key state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDiagnostics {
    /// Current connection counters.
    pub stats: ConnectionStats,
    /// Current connection-level send and receive flow-control state.
    pub flow_control: FlowControlStats,
    /// Active and validating network paths owned by the connection.
    pub paths: Vec<PathDiagnostics>,
    /// Number of authenticated peer address changes detected.
    pub peer_address_changes: u64,
    /// Whether the connection has reached the established state.
    pub is_established: bool,
    /// Whether the connection has entered a terminal closed state.
    pub is_closed: bool,
    /// Number of endpoint-routed UDP datagrams waiting for connection-level
    /// processing.
    pub routed_datagrams_queued: usize,
    /// Total payload bytes held by endpoint-routed UDP datagrams.
    pub routed_datagram_bytes: usize,
    /// Total unread STREAM payload bytes buffered by the connection.
    pub recv_stream_bytes_buffered: usize,
    /// Total application STREAM payload bytes waiting to be packetized.
    pub send_stream_bytes_buffered: usize,
    /// Number of application DATAGRAM payloads waiting to be sent.
    pub send_datagrams_queued: usize,
    /// Total payload bytes held by the DATAGRAM send queue.
    pub send_datagram_bytes: usize,
    /// Number of received application DATAGRAM payloads waiting to be read.
    pub recv_datagrams_queued: usize,
    /// Total payload bytes held by the DATAGRAM receive queue.
    pub recv_datagram_bytes: usize,
    /// Number of qlog events retained for manual draining.
    pub qlog_events_buffered: usize,
    /// Unified payload-oriented memory accounting.
    pub memory: ConnectionMemoryDiagnostics,
}

/// Stable, non-invasive diagnostics for an endpoint.
///
/// This snapshot reports queue and registry sizes without exposing route
/// tables, connection IDs, token material, packet keys, or task handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDiagnostics {
    /// Current endpoint counters.
    pub stats: EndpointStats,
    /// Whether the endpoint has been closed.
    pub is_closed: bool,
    /// Number of established or handshaking connections registered for
    /// endpoint routing.
    pub active_connections: usize,
    /// Number of accepted server connections waiting for `Endpoint::accept`.
    pub pending_incoming_connections: usize,
    /// Number of server-side Initial/Handshake exchanges still in progress.
    pub pending_server_handshakes: usize,
    /// Number of client-side Initial/Handshake exchanges still in progress.
    pub pending_client_handshakes: usize,
    /// Number of remote addresses retaining anti-amplification or path state.
    pub tracked_paths: usize,
    /// Configured upper bound for retained remote path state.
    pub max_tracked_paths: usize,
    /// Routed UDP payload bytes reserved across all endpoint connections.
    pub routed_datagram_bytes: usize,
    /// Configured endpoint-wide routed UDP payload limit.
    pub max_routed_datagram_bytes: usize,
    /// Number of CID route aliases retained by the endpoint.
    pub connection_id_routes: usize,
    /// Unified payload-oriented memory accounting across the endpoint.
    pub memory: EndpointMemoryDiagnostics,
}
