#![deny(unsafe_code)]
#![deny(missing_docs)]

//! QUIC transport with a sans-I/O protocol core and an async API.
//!
//! # Example
//!
//! ```no_run
//! use quion::{ClientConfig, Endpoint};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let client_config = ClientConfig::builder()
//!     .with_root_certificates_from_pem_file("quion-echo-cert.pem")?
//!     .with_alpn_protocols([b"quion-echo".to_vec()])
//!     .build();
//!
//! let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
//! endpoint.set_default_client_config(client_config);
//!
//! let connection = endpoint
//!     .connect("127.0.0.1:4445".parse()?, "localhost")?
//!     .await?;
//!
//! assert_eq!(connection.alpn_protocol(), Some(b"quion-echo".to_vec()));
//! let (mut send, _) = connection.open_bi().await?;
//! send.write_all(b"ping").await?;
//! send.finish()?;
//! # Ok(())
//! # }
//! ```

mod config;
mod connection;
mod diagnostics;
mod endpoint;
mod error;
mod incoming;
mod qlog;
mod recv_stream;
mod runtime;
mod send_stream;
mod stats;

pub use config::{
    ClientConfig, ClientConfigBuilder, EndpointConfig, ServerConfig, ServerConfigBuilder,
    TransportConfig,
};
#[cfg(feature = "zero-rtt")]
pub use connection::ZeroRttStatus;
pub use connection::{
    AcceptBi, AcceptUni, BiStream, Closed, Connection, NegotiatedTransport, OpenBi, OpenUni,
    ReadDatagram, ReadDatagramBytes,
};
pub use diagnostics::{
    ConnectionDiagnostics, ConnectionMemoryDiagnostics, EndpointDiagnostics,
    EndpointMemoryDiagnostics, PathDiagnostics, PathValidationStatus,
};
#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
pub use endpoint::EndpointServerUdpDriverHandle;
#[cfg(all(
    feature = "zero-rtt",
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
pub use endpoint::ZeroRttAccepted;
pub use endpoint::{Accept, Connecting, Endpoint};
pub use error::{
    ConfigError, ConnectionError, EndpointError, ReadError, Result, SendDatagramError, WriteError,
};
pub use incoming::Incoming;
pub use qlog::{QlogEvent, QlogHandler};
pub use quion_proto::VarInt;
pub use quion_proto::config::AckFrequencyConfig;
pub use quion_proto::congestion::CongestionAlgorithm;
pub use quion_proto::mtud::MtuDiscoveryConfig;
pub use quion_proto::streams::StreamId;
pub use recv_stream::{Chunk, RecvStream};
#[cfg(feature = "runtime-tokio")]
pub use runtime::TokioRuntime;
pub use runtime::{Runtime, RuntimeFuture};
pub use send_stream::{SendStream, StreamPriority};
pub use stats::{
    CongestionStats, ConnectionStats, EndpointStats, FlowControlStats, PathStats,
    StreamFlowControlStats, StreamStats,
};

/// Whether this build provides the RESET_STREAM_AT transport extension.
///
/// Applications must still enable it in [`TransportConfig`] and verify that
/// the peer negotiated it through [`NegotiatedTransport::reset_stream_at`].
pub const RESET_STREAM_AT_SUPPORTED: bool = true;
