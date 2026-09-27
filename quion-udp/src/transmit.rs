//! Outgoing datagram metadata.

use std::net::SocketAddr;

use web_time::Instant;

use crate::EcnCodepoint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    pub destination: SocketAddr,
    pub source: Option<SocketAddr>,
    pub ecn: Option<EcnCodepoint>,
    pub contents: Vec<u8>,
    pub segment_size: Option<usize>,
    pub send_at: Option<Instant>,
}
