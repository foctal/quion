#![deny(unsafe_code)]

//! Sans-IO QUIC protocol core for quion.
//!
//! This crate owns protocol parsing, deterministic state transitions, timers,
//! recovery primitives, and transport data structures. It intentionally performs
//! no socket I/O and has no runtime dependency.

pub mod buffers;
pub mod cid;
pub mod coding;
pub mod config;
pub mod congestion;
pub mod connection;
pub mod crypto;
pub mod ecn;
pub mod endpoint;
pub mod error;
pub mod ext;
pub mod frame;
pub mod mtud;
pub mod packet;
pub mod path;
pub mod qlog;
pub mod ranges;
pub mod recovery;
pub mod stats;
pub mod streams;
pub mod timer;
pub mod token;
pub mod transport_error;
pub mod transport_parameters;
pub mod varint;

pub use error::{CodecError, Result};
pub use varint::VarInt;
