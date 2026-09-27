use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Unknown,
    Validating,
    Validated,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: PathState,
}
