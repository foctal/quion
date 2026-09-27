use thiserror::Error;

use crate::transport_error::TransportErrorCode;

pub type Result<T> = core::result::Result<T, CodecError>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodecError {
    #[error("input ended unexpectedly")]
    UnexpectedEnd,
    #[error("integer encoding is invalid")]
    InvalidInteger,
    #[error("integer value is not minimally encoded")]
    NonMinimalInteger,
    #[error("packet header is malformed")]
    MalformedPacket,
    #[error("unauthenticated packet must be discarded")]
    PacketDiscard,
    #[error("frame is malformed")]
    MalformedFrame,
    #[error("transport parameter is malformed")]
    MalformedTransportParameter,
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("value exceeds QUIC bounds")]
    ValueOutOfBounds,
    #[error("local buffer limit exceeded")]
    BufferLimitExceeded,
    #[error("duplicate transport parameter {0}")]
    DuplicateTransportParameter(u64),
    #[error("transport error {0:?}")]
    Transport(TransportErrorCode),
}

impl CodecError {
    pub fn transport_code(&self) -> TransportErrorCode {
        match self {
            Self::UnexpectedEnd
            | Self::InvalidInteger
            | Self::NonMinimalInteger
            | Self::MalformedPacket
            | Self::MalformedFrame
            | Self::Crypto(_)
            | Self::BufferLimitExceeded
            | Self::ValueOutOfBounds => TransportErrorCode::FrameEncodingError,
            Self::PacketDiscard => TransportErrorCode::InternalError,
            Self::MalformedTransportParameter | Self::DuplicateTransportParameter(_) => {
                TransportErrorCode::TransportParameterError
            }
            Self::Transport(code) => *code,
        }
    }
}
