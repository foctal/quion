use bytes::Bytes;
use smallvec::SmallVec;

use crate::{
    coding::{Reader, Writer},
    error::{CodecError, Result},
    transport_error::TransportErrorCode,
    varint::VarInt,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    pub gap: VarInt,
    pub range: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding,
    Ping,
    Ack {
        largest: VarInt,
        delay: VarInt,
        first_range: VarInt,
        ranges: SmallVec<[AckRange; 4]>,
        ecn: Option<(VarInt, VarInt, VarInt)>,
    },
    ResetStream {
        stream_id: VarInt,
        error_code: VarInt,
        final_size: VarInt,
    },
    ResetStreamAt {
        stream_id: VarInt,
        error_code: VarInt,
        final_size: VarInt,
        reliable_size: VarInt,
    },
    StopSending {
        stream_id: VarInt,
        error_code: VarInt,
    },
    Crypto {
        offset: VarInt,
        data: Vec<u8>,
    },
    NewToken(Vec<u8>),
    Stream {
        stream_id: VarInt,
        offset: VarInt,
        fin: bool,
        data: Bytes,
    },
    MaxData(VarInt),
    MaxStreamData {
        stream_id: VarInt,
        maximum: VarInt,
    },
    MaxStreamsBidi(VarInt),
    MaxStreamsUni(VarInt),
    DataBlocked(VarInt),
    StreamDataBlocked {
        stream_id: VarInt,
        maximum: VarInt,
    },
    StreamsBlockedBidi(VarInt),
    StreamsBlockedUni(VarInt),
    NewConnectionId {
        sequence: VarInt,
        retire_prior_to: VarInt,
        connection_id: Vec<u8>,
        reset_token: [u8; 16],
    },
    RetireConnectionId(VarInt),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose {
        error_code: TransportErrorCode,
        frame_type: VarInt,
        reason: Vec<u8>,
    },
    ApplicationClose {
        error_code: VarInt,
        reason: Vec<u8>,
    },
    HandshakeDone,
    /// Requests updated acknowledgment behavior from a peer that advertised
    /// the ACK_FREQUENCY extension.
    AckFrequency {
        sequence: VarInt,
        ack_eliciting_threshold: VarInt,
        requested_max_ack_delay: VarInt,
        reordering_threshold: VarInt,
    },
    /// Requests an acknowledgment as soon as practical.
    ImmediateAck,
    Datagram {
        data: Bytes,
    },
}

impl Frame {
    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        Self::decode_inner(input, None)
    }

    /// Decodes a frame while retaining payload fields as zero-copy slices of
    /// the supplied shared packet storage.
    pub fn decode_bytes(input: Bytes) -> Result<(Self, usize)> {
        Self::decode_inner(&input, Some(&input))
    }

    fn decode_inner(input: &[u8], owner: Option<&Bytes>) -> Result<(Self, usize)> {
        let mut r = Reader::new(input);
        let ty = r
            .get_var_minimal()
            .map_err(|error| match error {
                CodecError::NonMinimalInteger => {
                    CodecError::Transport(TransportErrorCode::ProtocolViolation)
                }
                other => other,
            })?
            .into_inner();
        let frame = match ty {
            0x00 => Self::Padding,
            0x01 => Self::Ping,
            0x02 | 0x03 => {
                let largest = r.get_var()?;
                let delay = r.get_var()?;
                let count = r.get_var()?.into_inner();
                let first_range = r.get_var()?;
                let minimum_trailing_bytes = if ty == 0x03 { 3 } else { 0 };
                let maximum_encodable_ranges =
                    r.remaining().saturating_sub(minimum_trailing_bytes) / 2;
                if count > maximum_encodable_ranges as u64 {
                    return Err(CodecError::UnexpectedEnd);
                }
                let mut ranges = SmallVec::with_capacity(count as usize);
                for _ in 0..count {
                    ranges.push(AckRange {
                        gap: r.get_var()?,
                        range: r.get_var()?,
                    });
                }
                let ecn = if ty == 0x03 {
                    Some((r.get_var()?, r.get_var()?, r.get_var()?))
                } else {
                    None
                };
                Self::Ack {
                    largest,
                    delay,
                    first_range,
                    ranges,
                    ecn,
                }
            }
            0x04 => Self::ResetStream {
                stream_id: r.get_var()?,
                error_code: r.get_var()?,
                final_size: r.get_var()?,
            },
            0x05 => Self::StopSending {
                stream_id: r.get_var()?,
                error_code: r.get_var()?,
            },
            0x06 => {
                let offset = r.get_var()?;
                let len = r.get_var()?.into_inner() as usize;
                Self::Crypto {
                    offset,
                    data: r.get_bytes(len)?.to_vec(),
                }
            }
            0x07 => {
                let len = r.get_var()?.into_inner() as usize;
                if len == 0 {
                    return Err(CodecError::Transport(
                        TransportErrorCode::FrameEncodingError,
                    ));
                }
                Self::NewToken(r.get_bytes(len)?.to_vec())
            }
            0x08..=0x0f => {
                let stream_id = r.get_var()?;
                let offset = if ty & 0x04 != 0 {
                    r.get_var()?
                } else {
                    VarInt::ZERO
                };
                let data_len = if ty & 0x02 != 0 {
                    r.get_var()?.into_inner() as usize
                } else {
                    r.remaining()
                };
                Self::Stream {
                    stream_id,
                    offset,
                    fin: ty & 0x01 != 0,
                    data: read_shared_bytes(&mut r, data_len, owner)?,
                }
            }
            0x10 => Self::MaxData(r.get_var()?),
            0x11 => Self::MaxStreamData {
                stream_id: r.get_var()?,
                maximum: r.get_var()?,
            },
            0x12 => Self::MaxStreamsBidi(r.get_var()?),
            0x13 => Self::MaxStreamsUni(r.get_var()?),
            0x14 => Self::DataBlocked(r.get_var()?),
            0x15 => Self::StreamDataBlocked {
                stream_id: r.get_var()?,
                maximum: r.get_var()?,
            },
            0x16 => Self::StreamsBlockedBidi(r.get_var()?),
            0x17 => Self::StreamsBlockedUni(r.get_var()?),
            0x18 => {
                let sequence = r.get_var()?;
                let retire_prior_to = r.get_var()?;
                let len = usize::from(r.get_u8()?);
                if !(1..=20).contains(&len) {
                    return Err(CodecError::MalformedFrame);
                }
                let connection_id = r.get_bytes(len)?.to_vec();
                let token: [u8; 16] = r
                    .get_bytes(16)?
                    .try_into()
                    .map_err(|_| CodecError::MalformedFrame)?;
                Self::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    connection_id,
                    reset_token: token,
                }
            }
            0x19 => Self::RetireConnectionId(r.get_var()?),
            0x1a => Self::PathChallenge(read_path_data(&mut r)?),
            0x1b => Self::PathResponse(read_path_data(&mut r)?),
            0x1c => {
                let error_code = TransportErrorCode::from(r.get_var()?.into_inner());
                let frame_type = r.get_var()?;
                let len = r.get_var()?.into_inner() as usize;
                Self::ConnectionClose {
                    error_code,
                    frame_type,
                    reason: r.get_bytes(len)?.to_vec(),
                }
            }
            0x1d => {
                let error_code = r.get_var()?;
                let len = r.get_var()?.into_inner() as usize;
                Self::ApplicationClose {
                    error_code,
                    reason: r.get_bytes(len)?.to_vec(),
                }
            }
            0x1e => Self::HandshakeDone,
            0x1f => Self::ImmediateAck,
            0x24 => {
                let stream_id = r.get_var()?;
                let error_code = r.get_var()?;
                let final_size = r.get_var()?;
                let reliable_size = r.get_var()?;
                if reliable_size > final_size {
                    return Err(CodecError::Transport(
                        TransportErrorCode::FrameEncodingError,
                    ));
                }
                Self::ResetStreamAt {
                    stream_id,
                    error_code,
                    final_size,
                    reliable_size,
                }
            }
            0x30 | 0x31 => {
                let data_len = if ty == 0x31 {
                    r.get_var()?.into_inner() as usize
                } else {
                    r.remaining()
                };
                Self::Datagram {
                    data: read_shared_bytes(&mut r, data_len, owner)?,
                }
            }
            0xaf => Self::AckFrequency {
                sequence: r.get_var()?,
                ack_eliciting_threshold: r.get_var()?,
                requested_max_ack_delay: r.get_var()?,
                reordering_threshold: r.get_var()?,
            },
            _ => {
                return Err(CodecError::Transport(
                    TransportErrorCode::FrameEncodingError,
                ));
            }
        };

        Ok((frame, r.consumed()))
    }

    /// Returns the exact number of bytes produced by [`Self::encode`].
    ///
    /// Packet scheduling uses this to enforce congestion limits without
    /// allocating and encoding a frame twice.
    pub fn encoded_len(&self) -> usize {
        let var_len = |value: VarInt| value.encoded_len();
        let bytes_len = |len: usize| {
            VarInt::new(len as u64)
                .unwrap_or(VarInt::MAX)
                .encoded_len()
                .saturating_add(len)
        };
        match self {
            Self::Padding | Self::Ping | Self::HandshakeDone | Self::ImmediateAck => 1,
            Self::Ack {
                largest,
                delay,
                first_range,
                ranges,
                ecn,
            } => 1usize
                .saturating_add(var_len(*largest))
                .saturating_add(var_len(*delay))
                .saturating_add(
                    VarInt::new(ranges.len() as u64)
                        .unwrap_or(VarInt::MAX)
                        .encoded_len(),
                )
                .saturating_add(var_len(*first_range))
                .saturating_add(
                    ranges
                        .iter()
                        .map(|range| var_len(range.gap).saturating_add(var_len(range.range)))
                        .fold(0usize, usize::saturating_add),
                )
                .saturating_add(ecn.map_or(0, |(ect0, ect1, ce)| {
                    var_len(ect0)
                        .saturating_add(var_len(ect1))
                        .saturating_add(var_len(ce))
                })),
            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => 1usize
                .saturating_add(var_len(*stream_id))
                .saturating_add(var_len(*error_code))
                .saturating_add(var_len(*final_size)),
            Self::ResetStreamAt {
                stream_id,
                error_code,
                final_size,
                reliable_size,
            } => 1usize
                .saturating_add(var_len(*stream_id))
                .saturating_add(var_len(*error_code))
                .saturating_add(var_len(*final_size))
                .saturating_add(var_len(*reliable_size)),
            Self::StopSending {
                stream_id,
                error_code,
            } => 1usize
                .saturating_add(var_len(*stream_id))
                .saturating_add(var_len(*error_code)),
            Self::Crypto { offset, data } => 1usize
                .saturating_add(var_len(*offset))
                .saturating_add(bytes_len(data.len())),
            Self::NewToken(data) => 1usize.saturating_add(bytes_len(data.len())),
            Self::Datagram { data } => 1usize.saturating_add(bytes_len(data.len())),
            Self::Stream {
                stream_id,
                offset,
                data,
                ..
            } => 1usize
                .saturating_add(var_len(*stream_id))
                .saturating_add(if offset.into_inner() != 0 {
                    var_len(*offset)
                } else {
                    0
                })
                .saturating_add(bytes_len(data.len())),
            Self::MaxData(value)
            | Self::MaxStreamsBidi(value)
            | Self::MaxStreamsUni(value)
            | Self::DataBlocked(value)
            | Self::StreamsBlockedBidi(value)
            | Self::StreamsBlockedUni(value)
            | Self::RetireConnectionId(value) => 1usize.saturating_add(var_len(*value)),
            Self::MaxStreamData { stream_id, maximum }
            | Self::StreamDataBlocked { stream_id, maximum } => 1usize
                .saturating_add(var_len(*stream_id))
                .saturating_add(var_len(*maximum)),
            Self::NewConnectionId {
                sequence,
                retire_prior_to,
                connection_id,
                ..
            } => 1usize
                .saturating_add(var_len(*sequence))
                .saturating_add(var_len(*retire_prior_to))
                .saturating_add(1)
                .saturating_add(connection_id.len())
                .saturating_add(16),
            Self::PathChallenge(_) | Self::PathResponse(_) => 9,
            Self::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => 1usize
                .saturating_add(
                    VarInt::new(error_code_value(*error_code))
                        .unwrap_or(VarInt::MAX)
                        .encoded_len(),
                )
                .saturating_add(var_len(*frame_type))
                .saturating_add(bytes_len(reason.len())),
            Self::ApplicationClose { error_code, reason } => 1usize
                .saturating_add(var_len(*error_code))
                .saturating_add(bytes_len(reason.len())),
            Self::AckFrequency {
                sequence,
                ack_eliciting_threshold,
                requested_max_ack_delay,
                reordering_threshold,
            } => VarInt::from_u32(0xaf)
                .encoded_len()
                .saturating_add(var_len(*sequence))
                .saturating_add(var_len(*ack_eliciting_threshold))
                .saturating_add(var_len(*requested_max_ack_delay))
                .saturating_add(var_len(*reordering_threshold)),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.encoded_len());
        self.encode_into_writer(&mut w);
        w.into_vec()
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn append_encoded_to(&self, output: &mut Vec<u8>) {
        output.reserve(self.encoded_len());
        let mut w = Writer::from_vec(std::mem::take(output));
        self.encode_into_writer(&mut w);
        *output = w.into_vec();
    }

    fn encode_into_writer(&self, w: &mut Writer) {
        match self {
            Self::Padding => w.put_var(VarInt::ZERO),
            Self::Ping => w.put_var(VarInt::from_u32(0x01)),
            Self::Ack {
                largest,
                delay,
                first_range,
                ranges,
                ecn,
            } => {
                w.put_var(VarInt::from_u32(if ecn.is_some() { 0x03 } else { 0x02 }));
                w.put_var(*largest);
                w.put_var(*delay);
                w.put_var(VarInt::new(ranges.len() as u64).unwrap_or(VarInt::MAX));
                w.put_var(*first_range);
                for range in ranges {
                    w.put_var(range.gap);
                    w.put_var(range.range);
                }
                if let Some((ect0, ect1, ce)) = ecn {
                    w.put_var(*ect0);
                    w.put_var(*ect1);
                    w.put_var(*ce);
                }
            }
            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                w.put_var(VarInt::from_u32(0x04));
                w.put_var(*stream_id);
                w.put_var(*error_code);
                w.put_var(*final_size);
            }
            Self::ResetStreamAt {
                stream_id,
                error_code,
                final_size,
                reliable_size,
            } => {
                w.put_var(VarInt::from_u32(0x24));
                w.put_var(*stream_id);
                w.put_var(*error_code);
                w.put_var(*final_size);
                w.put_var(*reliable_size);
            }
            Self::StopSending {
                stream_id,
                error_code,
            } => {
                w.put_var(VarInt::from_u32(0x05));
                w.put_var(*stream_id);
                w.put_var(*error_code);
            }
            Self::Crypto { offset, data } => {
                w.put_var(VarInt::from_u32(0x06));
                w.put_var(*offset);
                w.put_var(VarInt::new(data.len() as u64).unwrap_or(VarInt::MAX));
                w.put_bytes(data);
            }
            Self::NewToken(data) => {
                w.put_var(VarInt::from_u32(0x07));
                w.put_var(VarInt::new(data.len() as u64).unwrap_or(VarInt::MAX));
                w.put_bytes(data);
            }
            Self::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => {
                let mut ty = 0x0a;
                if offset.into_inner() != 0 {
                    ty |= 0x04;
                }
                if *fin {
                    ty |= 0x01;
                }
                w.put_var(VarInt::from_u32(ty));
                w.put_var(*stream_id);
                if offset.into_inner() != 0 {
                    w.put_var(*offset);
                }
                w.put_var(VarInt::new(data.len() as u64).unwrap_or(VarInt::MAX));
                w.put_bytes(data);
            }
            Self::MaxData(value) => {
                w.put_var(VarInt::from_u32(0x10));
                w.put_var(*value);
            }
            Self::MaxStreamData { stream_id, maximum } => {
                w.put_var(VarInt::from_u32(0x11));
                w.put_var(*stream_id);
                w.put_var(*maximum);
            }
            Self::MaxStreamsBidi(value) => {
                w.put_var(VarInt::from_u32(0x12));
                w.put_var(*value);
            }
            Self::MaxStreamsUni(value) => {
                w.put_var(VarInt::from_u32(0x13));
                w.put_var(*value);
            }
            Self::DataBlocked(value) => {
                w.put_var(VarInt::from_u32(0x14));
                w.put_var(*value);
            }
            Self::StreamDataBlocked { stream_id, maximum } => {
                w.put_var(VarInt::from_u32(0x15));
                w.put_var(*stream_id);
                w.put_var(*maximum);
            }
            Self::StreamsBlockedBidi(value) => {
                w.put_var(VarInt::from_u32(0x16));
                w.put_var(*value);
            }
            Self::StreamsBlockedUni(value) => {
                w.put_var(VarInt::from_u32(0x17));
                w.put_var(*value);
            }
            Self::NewConnectionId {
                sequence,
                retire_prior_to,
                connection_id,
                reset_token,
            } => {
                w.put_var(VarInt::from_u32(0x18));
                w.put_var(*sequence);
                w.put_var(*retire_prior_to);
                w.put_u8(connection_id.len() as u8);
                w.put_bytes(connection_id);
                w.put_bytes(reset_token);
            }
            Self::RetireConnectionId(sequence) => {
                w.put_var(VarInt::from_u32(0x19));
                w.put_var(*sequence);
            }
            Self::PathChallenge(data) => {
                w.put_var(VarInt::from_u32(0x1a));
                w.put_bytes(data);
            }
            Self::PathResponse(data) => {
                w.put_var(VarInt::from_u32(0x1b));
                w.put_bytes(data);
            }
            Self::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                w.put_var(VarInt::from_u32(0x1c));
                w.put_var(VarInt::new(error_code_value(*error_code)).unwrap_or(VarInt::MAX));
                w.put_var(*frame_type);
                w.put_var(VarInt::new(reason.len() as u64).unwrap_or(VarInt::MAX));
                w.put_bytes(reason);
            }
            Self::ApplicationClose { error_code, reason } => {
                w.put_var(VarInt::from_u32(0x1d));
                w.put_var(*error_code);
                w.put_var(VarInt::new(reason.len() as u64).unwrap_or(VarInt::MAX));
                w.put_bytes(reason);
            }
            Self::HandshakeDone => w.put_var(VarInt::from_u32(0x1e)),
            Self::ImmediateAck => w.put_var(VarInt::from_u32(0x1f)),
            Self::AckFrequency {
                sequence,
                ack_eliciting_threshold,
                requested_max_ack_delay,
                reordering_threshold,
            } => {
                w.put_var(VarInt::from_u32(0xaf));
                w.put_var(*sequence);
                w.put_var(*ack_eliciting_threshold);
                w.put_var(*requested_max_ack_delay);
                w.put_var(*reordering_threshold);
            }
            Self::Datagram { data } => {
                w.put_var(VarInt::from_u32(0x31));
                w.put_var(VarInt::new(data.len() as u64).unwrap_or(VarInt::MAX));
                w.put_bytes(data);
            }
        }
    }
}

fn read_shared_bytes(reader: &mut Reader<'_>, len: usize, owner: Option<&Bytes>) -> Result<Bytes> {
    let start = reader.consumed();
    let bytes = reader.get_bytes(len)?;
    Ok(owner.map_or_else(
        || Bytes::copy_from_slice(bytes),
        |owner| owner.slice(start..start + len),
    ))
}

fn read_path_data(r: &mut Reader<'_>) -> Result<[u8; 8]> {
    r.get_bytes(8)?
        .try_into()
        .map_err(|_| CodecError::MalformedFrame)
}

const fn error_code_value(code: TransportErrorCode) -> u64 {
    match code {
        TransportErrorCode::NoError => 0x00,
        TransportErrorCode::InternalError => 0x01,
        TransportErrorCode::ConnectionRefused => 0x02,
        TransportErrorCode::FlowControlError => 0x03,
        TransportErrorCode::StreamLimitError => 0x04,
        TransportErrorCode::StreamStateError => 0x05,
        TransportErrorCode::FinalSizeError => 0x06,
        TransportErrorCode::FrameEncodingError => 0x07,
        TransportErrorCode::TransportParameterError => 0x08,
        TransportErrorCode::ConnectionIdLimitError => 0x09,
        TransportErrorCode::ProtocolViolation => 0x0a,
        TransportErrorCode::InvalidToken => 0x0b,
        TransportErrorCode::ApplicationError => 0x0c,
        TransportErrorCode::CryptoBufferExceeded => 0x0d,
        TransportErrorCode::KeyUpdateError => 0x0e,
        TransportErrorCode::AeadLimitReached => 0x0f,
        TransportErrorCode::NoViablePath => 0x10,
        TransportErrorCode::CryptoError(value) => 0x0100 + value as u64,
        TransportErrorCode::Unknown(value) => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn stream_frame_roundtrip() {
        let frame = Frame::Stream {
            stream_id: VarInt::from_u32(4),
            offset: VarInt::from_u32(9),
            fin: true,
            data: b"hello".to_vec().into(),
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), frame.encoded_len());
        let (decoded, consumed) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn close_frame_roundtrip() {
        let frame = Frame::ConnectionClose {
            error_code: TransportErrorCode::ProtocolViolation,
            frame_type: VarInt::from_u32(0x06),
            reason: b"bad crypto".to_vec(),
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), frame.encoded_len());
        let (decoded, consumed) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn reset_stream_at_roundtrip() {
        let frame = Frame::ResetStreamAt {
            stream_id: VarInt::from_u32(12),
            error_code: VarInt::from_u32(42),
            final_size: VarInt::from_u32(128),
            reliable_size: VarInt::from_u32(16),
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), frame.encoded_len());
        let (decoded, consumed) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn ack_frequency_and_immediate_ack_roundtrip() {
        let frequency = Frame::AckFrequency {
            sequence: VarInt::from_u32(7),
            ack_eliciting_threshold: VarInt::from_u32(10),
            requested_max_ack_delay: VarInt::from_u32(25_000),
            reordering_threshold: VarInt::from_u32(2),
        };
        for frame in [frequency, Frame::ImmediateAck] {
            let encoded = frame.encode();
            assert_eq!(encoded.len(), frame.encoded_len());
            assert_eq!(Frame::decode(&encoded), Ok((frame, encoded.len())));
        }
    }

    #[test]
    fn reset_stream_at_rejects_reliable_size_above_final_size() {
        let encoded = [
            0x24, // frame type
            0x00, // stream ID
            0x00, // error code
            0x01, // final size
            0x02, // reliable size
        ];
        assert_eq!(
            Frame::decode(&encoded),
            Err(CodecError::Transport(
                TransportErrorCode::FrameEncodingError
            ))
        );
    }

    #[test]
    fn accepts_non_minimal_encoding_for_frame_fields() {
        let encoded = [
            0x10, // MAX_DATA frame type
            0x40, 0x00, // non-minimal encoding of maximum 0
        ];

        assert_eq!(
            Frame::decode(&encoded),
            Ok((Frame::MaxData(VarInt::ZERO), encoded.len()))
        );
    }

    #[test]
    fn rejects_non_minimal_frame_type_as_protocol_violation() {
        let encoded = [0x40, 0x01]; // non-minimal encoding of PING

        assert_eq!(
            Frame::decode(&encoded),
            Err(CodecError::Transport(TransportErrorCode::ProtocolViolation))
        );
    }

    #[test]
    fn rejects_empty_new_token() {
        let error = Frame::decode(&[0x07, 0x00]).unwrap_err();
        assert_eq!(
            error,
            CodecError::Transport(TransportErrorCode::FrameEncodingError)
        );
    }

    #[test]
    fn rejects_impossible_ack_range_count_before_range_parsing() {
        let encoded = [
            0x02, // ACK frame type
            0x00, // largest acknowledged
            0x00, // ACK delay
            0x40, 0x00, // declared ACK range count 0
            0x00, // first ACK range
        ];
        let mut impossible = encoded.to_vec();
        impossible[3..5].copy_from_slice(&[0x7f, 0xff]); // 16,383 ranges

        assert_eq!(Frame::decode(&impossible), Err(CodecError::UnexpectedEnd));
    }

    #[test]
    fn ack_ecn_feasibility_reserves_trailing_counters() {
        let encoded = [
            0x03, // ACK_ECN frame type
            0x00, // largest acknowledged
            0x00, // ACK delay
            0x01, // one additional range
            0x00, // first ACK range
            0x00, 0x00, // gap and ACK range
            0x00, 0x00, 0x00, // ECN counters
        ];
        assert!(matches!(
            Frame::decode(&encoded),
            Ok((Frame::Ack { ranges, ecn: Some(_), .. }, consumed))
                if ranges.len() == 1 && consumed == encoded.len()
        ));

        assert_eq!(
            Frame::decode(&encoded[..encoded.len() - 1]),
            Err(CodecError::UnexpectedEnd)
        );
    }

    proptest! {
        #[test]
        fn bounded_frames_roundtrip(
            selector in 0u8..12,
            a in 0u32..16_384,
            b in 0u32..16_384,
            data in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let frame = match selector {
                0 => Frame::Ping,
                1 => Frame::Crypto {
                    offset: VarInt::from_u32(a),
                    data,
                },
                2 => Frame::Stream {
                    stream_id: VarInt::from_u32(a),
                    offset: VarInt::from_u32(b),
                    fin: a & 1 == 0,
                    data: data.into(),
                },
                3 => Frame::MaxData(VarInt::from_u32(a)),
                4 => Frame::MaxStreamData {
                    stream_id: VarInt::from_u32(a),
                    maximum: VarInt::from_u32(b),
                },
                5 => Frame::DataBlocked(VarInt::from_u32(a)),
                6 => Frame::StreamDataBlocked {
                    stream_id: VarInt::from_u32(a),
                    maximum: VarInt::from_u32(b),
                },
                7 => Frame::RetireConnectionId(VarInt::from_u32(a)),
                8 => Frame::PathChallenge(fixed_8(&data)),
                9 => Frame::PathResponse(fixed_8(&data)),
                10 => Frame::ApplicationClose {
                    error_code: VarInt::from_u32(a),
                    reason: data,
                },
                _ => Frame::Datagram { data: data.into() },
            };

            let encoded = frame.encode();
            prop_assert_eq!(encoded.len(), frame.encoded_len());
            let (decoded, consumed) = Frame::decode(&encoded).unwrap();
            prop_assert_eq!(decoded, frame);
            prop_assert_eq!(consumed, encoded.len());
        }
    }

    fn fixed_8(data: &[u8]) -> [u8; 8] {
        let mut out = [0; 8];
        let len = data.len().min(8);
        out[..len].copy_from_slice(&data[..len]);
        out
    }
}
