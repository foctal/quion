use std::sync::Arc;

use crate::error::Result;

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub mod initial;
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub mod packet;
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub mod rustls;
pub mod stream;

pub trait CryptoProvider: Send + Sync + 'static {
    type ClientConfig: Send + Sync + 'static;
    type ServerConfig: Send + Sync + 'static;
    type Session: CryptoSession;

    fn start_client(
        &self,
        config: Arc<Self::ClientConfig>,
        server_name: &str,
    ) -> Result<Self::Session>;

    fn start_server(&self, config: Arc<Self::ServerConfig>) -> Result<Self::Session>;
}

pub trait CryptoSession: Send + 'static {
    fn write_tls(&mut self, out: &mut Vec<u8>) -> Result<()>;
    fn read_tls(&mut self, input: &[u8]) -> Result<()>;
    fn is_handshaking(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncryptionLevel {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoData {
    pub level: EncryptionLevel,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoEvent {
    HandshakeData(CryptoData),
    HandshakeComplete,
    KeyUpdate,
}
