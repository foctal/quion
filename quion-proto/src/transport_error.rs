#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum TransportErrorCode {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    CryptoError(u16),
    Unknown(u64),
}

impl From<u64> for TransportErrorCode {
    fn from(value: u64) -> Self {
        match value {
            0x00 => Self::NoError,
            0x01 => Self::InternalError,
            0x02 => Self::ConnectionRefused,
            0x03 => Self::FlowControlError,
            0x04 => Self::StreamLimitError,
            0x05 => Self::StreamStateError,
            0x06 => Self::FinalSizeError,
            0x07 => Self::FrameEncodingError,
            0x08 => Self::TransportParameterError,
            0x09 => Self::ConnectionIdLimitError,
            0x0a => Self::ProtocolViolation,
            0x0b => Self::InvalidToken,
            0x0c => Self::ApplicationError,
            0x0d => Self::CryptoBufferExceeded,
            0x0e => Self::KeyUpdateError,
            0x0f => Self::AeadLimitReached,
            0x10 => Self::NoViablePath,
            0x0100..=0x01ff => Self::CryptoError((value - 0x0100) as u16),
            other => Self::Unknown(other),
        }
    }
}
