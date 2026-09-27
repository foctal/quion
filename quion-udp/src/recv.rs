//! Received datagram metadata.

use std::net::SocketAddr;

use crate::EcnCodepoint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvMeta {
    pub local: Option<SocketAddr>,
    pub remote: SocketAddr,
    /// Operating-system interface index, when packet-info metadata is
    /// available.
    pub interface: Option<u32>,
    pub ecn: Option<EcnCodepoint>,
    /// UDP GRO segment size when one receive contains multiple datagrams.
    pub segment_size: Option<usize>,
    pub len: usize,
}
