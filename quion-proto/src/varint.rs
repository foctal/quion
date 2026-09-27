use core::fmt;

use crate::error::{CodecError, Result};

pub const MAX_VARINT: u64 = (1 << 62) - 1;

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

impl VarInt {
    pub const MAX: Self = Self(MAX_VARINT);
    pub const ZERO: Self = Self(0);

    pub const fn into_inner(self) -> u64 {
        self.0
    }

    pub const fn from_u32(value: u32) -> Self {
        Self(value as u64)
    }

    pub fn new(value: u64) -> Result<Self> {
        if value <= MAX_VARINT {
            Ok(Self(value))
        } else {
            Err(CodecError::ValueOutOfBounds)
        }
    }

    pub fn encoded_len(self) -> usize {
        match self.0 {
            0..=63 => 1,
            64..=16_383 => 2,
            16_384..=1_073_741_823 => 4,
            _ => 8,
        }
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        match self.encoded_len() {
            1 => out.push(self.0 as u8),
            2 => out.extend_from_slice(&((self.0 as u16) | 0x4000).to_be_bytes()),
            4 => out.extend_from_slice(&((self.0 as u32) | 0x8000_0000).to_be_bytes()),
            8 => out.extend_from_slice(&(self.0 | 0xc000_0000_0000_0000).to_be_bytes()),
            _ => unreachable!(),
        }
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        let first = *input.first().ok_or(CodecError::UnexpectedEnd)?;
        let len = 1usize << (first >> 6);
        if input.len() < len {
            return Err(CodecError::UnexpectedEnd);
        }

        let value = match len {
            1 => u64::from(first & 0x3f),
            2 => u64::from(u16::from_be_bytes([input[0], input[1]]) & 0x3fff),
            4 => u64::from(
                u32::from_be_bytes([input[0], input[1], input[2], input[3]]) & 0x3fff_ffff,
            ),
            8 => {
                u64::from_be_bytes([
                    input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
                ]) & 0x3fff_ffff_ffff_ffff
            }
            _ => return Err(CodecError::InvalidInteger),
        };

        Ok((Self::new(value)?, len))
    }

    /// Decodes a variable-length integer and requires its shortest encoding.
    ///
    /// QUIC permits longer encodings for ordinary integer fields. This stricter
    /// operation is intended for fields such as Frame Type that explicitly
    /// require the shortest representation.
    pub fn decode_minimal(input: &[u8]) -> Result<(Self, usize)> {
        let (value, consumed) = Self::decode(input)?;
        if value.encoded_len() != consumed {
            return Err(CodecError::NonMinimalInteger);
        }
        Ok((value, consumed))
    }
}

impl TryFrom<u64> for VarInt {
    type Error = CodecError;

    fn try_from(value: u64) -> Result<Self> {
        Self::new(value)
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl fmt::Debug for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrips_boundary_values() {
        for value in [
            0,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            MAX_VARINT,
        ] {
            let var = VarInt::new(value).unwrap();
            let mut encoded = Vec::new();
            var.encode(&mut encoded);
            let (decoded, consumed) = VarInt::decode(&encoded).unwrap();
            assert_eq!(decoded, var);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn accepts_non_minimal_encoding() {
        assert_eq!(VarInt::decode(&[0x40, 0x00]), Ok((VarInt::ZERO, 2)));
    }

    #[test]
    fn minimal_decoder_rejects_non_minimal_encoding() {
        assert_eq!(
            VarInt::decode_minimal(&[0x40, 0x00]),
            Err(CodecError::NonMinimalInteger)
        );
    }

    proptest! {
        #[test]
        fn proptest_roundtrips(value in 0u64..=MAX_VARINT) {
            let var = VarInt::new(value).unwrap();
            let mut encoded = Vec::new();
            var.encode(&mut encoded);
            let (decoded, consumed) = VarInt::decode(&encoded).unwrap();
            prop_assert_eq!(decoded, var);
            prop_assert_eq!(consumed, encoded.len());
        }
    }
}
