use thiserror::Error;

use quion_proto::{VarInt, transport_error::TransportErrorCode};

/// Result type used by connection operations.
pub type Result<T> = std::result::Result<T, ConnectionError>;

/// Stable connection-level failures exposed by the high-level API.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConnectionError {
    /// Version negotiation did not select a supported QUIC version.
    #[error("QUIC version mismatch")]
    VersionMismatch,
    /// The peer or local protocol engine reported a transport error.
    #[error("transport error: {0:?}")]
    TransportError(TransportErrorCode),
    /// The peer closed the connection with an application error.
    #[error("application closed: code={code}, reason={reason}")]
    ApplicationClosed {
        /// Peer-supplied application error code.
        code: VarInt,
        /// Peer-supplied UTF-8-lossy close reason.
        reason: String,
    },
    /// The local endpoint or connection was closed.
    #[error("connection was locally closed")]
    LocallyClosed,
    /// A handshake or connection idle deadline expired.
    #[error("connection timed out")]
    TimedOut,
    /// A valid stateless reset terminated the connection.
    #[error("connection was reset")]
    Reset,
    /// UDP socket I/O failed.
    #[error("udp error: {0}")]
    Udp(String),
    /// The selected async runtime failed.
    #[error("runtime error: {0}")]
    Runtime(String),
    /// The peer has not granted another bidirectional stream.
    #[error("peer bidirectional stream limit reached")]
    BidirectionalStreamLimitReached,
    /// The peer has not granted another unidirectional stream.
    #[error("peer unidirectional stream limit reached")]
    UnidirectionalStreamLimitReached,
    /// The peer did not negotiate QUIC DATAGRAM support.
    #[error("peer did not negotiate QUIC DATAGRAM support")]
    DatagramUnsupported,
    /// A DATAGRAM exceeds the peer's negotiated maximum.
    #[error("datagram is too large: maximum payload is {maximum} bytes")]
    DatagramTooLarge {
        /// Largest DATAGRAM frame size accepted by the peer.
        maximum: u64,
    },
    /// The requested operation is unavailable in this build or state.
    #[error("operation is not implemented yet")]
    Unsupported,
    /// The endpoint-wide retained-payload budget is exhausted.
    #[error("endpoint memory limit reached")]
    EndpointMemoryLimitReached,
    /// A generated connection ID or reset token conflicts with an existing route.
    #[error("connection ID routing collision")]
    ConnectionIdCollision,
}

/// Errors produced while writing or finishing a stream.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WriteError {
    /// The peer stopped the stream with this application error code.
    #[error("stream was stopped: {0}")]
    Stopped(VarInt),
    /// The configured send-buffer budget would be exceeded.
    #[error("stream send buffer limit exceeded")]
    BufferTooLarge,
    /// The endpoint-wide retained-payload budget is exhausted.
    #[error("endpoint memory limit reached")]
    EndpointMemoryLimitReached,
    /// RESET_STREAM_AT was not negotiated.
    #[error("peer did not negotiate RESET_STREAM_AT support")]
    ResetStreamAtUnsupported,
    /// The connection became unavailable.
    #[error("connection lost: {0}")]
    ConnectionLost(ConnectionError),
    /// Data written in 0-RTT was rejected.
    #[error("0-RTT data was rejected")]
    ZeroRttRejected,
}

/// Errors produced when queueing an unreliable DATAGRAM.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SendDatagramError {
    /// The peer did not negotiate DATAGRAM support.
    #[error("peer did not negotiate QUIC DATAGRAM support")]
    Unsupported,
    /// The payload exceeds the peer's maximum.
    #[error("datagram is too large: maximum payload is {maximum} bytes")]
    TooLarge {
        /// Current payload limit imposed by the peer and the path MTU.
        maximum: u64,
    },
    /// The configured DATAGRAM queue budget is exhausted.
    #[error("datagram send queue is full")]
    Blocked,
    /// The endpoint-wide retained-payload budget is exhausted.
    #[error("endpoint memory limit reached")]
    EndpointMemoryLimitReached,
    /// The connection became unavailable.
    #[error("connection lost: {0}")]
    ConnectionLost(ConnectionError),
}

/// TLS or transport configuration failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The requested configuration is unavailable in this build.
    #[error("the requested configuration is unavailable with the enabled features")]
    Unsupported,
    /// Reading a configuration file failed.
    #[error("failed to access {path}: {kind:?}")]
    Io {
        /// File that could not be read.
        path: std::path::PathBuf,
        /// Portable I/O error category.
        kind: std::io::ErrorKind,
    },
    /// The platform did not provide any usable trust anchors.
    #[error("no native root certificates were available")]
    NoNativeRoots,
    /// A certificate file did not contain a usable certificate.
    #[error("invalid certificate data in {path}")]
    InvalidCertificate {
        /// Invalid certificate file.
        path: std::path::PathBuf,
    },
    /// A private-key file did not contain a supported key.
    #[error("invalid private key data in {path}")]
    InvalidPrivateKey {
        /// Invalid private-key file.
        path: std::path::PathBuf,
    },
    /// rustls rejected the supplied configuration.
    #[error("invalid TLS configuration: {0}")]
    TlsConfiguration(String),
}

/// Endpoint construction failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EndpointError {
    /// Creating the requested local UDP endpoint failed, including socket setup.
    #[error("failed to bind the UDP endpoint: {kind:?}")]
    Bind {
        /// Portable I/O error category.
        kind: std::io::ErrorKind,
    },
    /// Querying the bound local address failed.
    #[error("failed to query the UDP endpoint address: {kind:?}")]
    LocalAddress {
        /// Portable I/O error category.
        kind: std::io::ErrorKind,
    },
}

/// Errors produced while reading a stream.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReadError {
    /// The peer reset the stream with this application error code.
    #[error("stream was reset: {0}")]
    Reset(VarInt),
    /// FIN arrived before an exact-length read completed.
    #[error("stream finished before the requested bytes were available")]
    FinishedEarly,
    /// `read_to_end` exceeded its caller-provided limit.
    #[error("stream exceeded read_to_end limit of {0} bytes")]
    TooLong(usize),
    /// Ordered and unordered reads were mixed on one stream.
    #[error("cannot mix ordered and unordered reads on the same stream handle")]
    IllegalOrderedState,
    /// The connection became unavailable.
    #[error("connection lost: {0}")]
    ConnectionLost(ConnectionError),
}
