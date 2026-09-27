use crate::{
    cid::ConnectionId,
    coding::{Reader, Writer},
    error::{CodecError, Result},
    varint::VarInt,
};

pub const QUIC_VERSION_1: u32 = 0x0000_0001;
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;
/// Reserved version used only to probe a peer's Version Negotiation behavior.
pub const VERSION_NEGOTIATION_PROBE: u32 = 0x0a0a_0a0a;
pub const RETRY_INTEGRITY_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl PacketType {
    fn from_long_header_bits(bits: u8) -> Result<Self> {
        match bits & 0x30 {
            0x00 => Ok(Self::Initial),
            0x10 => Ok(Self::ZeroRtt),
            0x20 => Ok(Self::Handshake),
            0x30 => Ok(Self::Retry),
            _ => Err(CodecError::MalformedPacket),
        }
    }

    const fn bits(self) -> u8 {
        match self {
            Self::Initial => 0x00,
            Self::ZeroRtt => 0x10,
            Self::Handshake => 0x20,
            Self::Retry => 0x30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    pub ty: PacketType,
    pub version: u32,
    pub dst_cid: ConnectionId,
    pub src_cid: ConnectionId,
    pub token: Vec<u8>,
    pub length: Option<VarInt>,
    pub packet_number_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    pub spin: bool,
    pub key_phase: bool,
    pub dst_cid: ConnectionId,
    pub packet_number_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Long(LongHeader),
    Short(ShortHeader),
    VersionNegotiation {
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        versions: Vec<u32>,
    },
}

impl Header {
    /// Returns the Destination Connection ID carried by this packet header.
    pub fn destination_connection_id(&self) -> &ConnectionId {
        match self {
            Self::Long(header) => &header.dst_cid,
            Self::Short(header) => &header.dst_cid,
            Self::VersionNegotiation { dst_cid, .. } => dst_cid,
        }
    }

    pub fn decode(input: &[u8], expected_dst_cid_len: usize) -> Result<(Self, usize)> {
        let mut r = Reader::new(input);
        let first = r.get_u8()?;
        if first & 0x80 == 0 {
            let dst_cid = ConnectionId::decode_fixed(r.get_bytes(expected_dst_cid_len)?)?;
            let packet_number_len = usize::from(first & 0x03) + 1;
            return Ok((
                Self::Short(ShortHeader {
                    spin: first & 0x20 != 0,
                    key_phase: first & 0x04 != 0,
                    dst_cid,
                    packet_number_len,
                }),
                r.consumed(),
            ));
        }

        let version = r.get_u32()?;
        // Version Negotiation randomizes all seven unused low bits.
        if version != 0 && first & 0x40 == 0 {
            return Err(CodecError::MalformedPacket);
        }
        let dst_len = usize::from(r.get_u8()?);
        let dst_cid = ConnectionId::decode_fixed(r.get_bytes(dst_len)?)?;
        let src_len = usize::from(r.get_u8()?);
        let src_cid = ConnectionId::decode_fixed(r.get_bytes(src_len)?)?;

        if version == 0 {
            let mut versions = Vec::new();
            while !r.is_empty() {
                versions.push(r.get_u32()?);
            }
            return Ok((
                Self::VersionNegotiation {
                    dst_cid,
                    src_cid,
                    versions,
                },
                r.consumed(),
            ));
        }

        let ty = PacketType::from_long_header_bits(first)?;
        let packet_number_len = usize::from(first & 0x03) + 1;
        let (token, length) = match ty {
            PacketType::Initial => {
                let token_len = r.get_var()?.into_inner() as usize;
                let token = r.get_bytes(token_len)?.to_vec();
                let length = r.get_var()?;
                (token, Some(length))
            }
            PacketType::ZeroRtt | PacketType::Handshake => (Vec::new(), Some(r.get_var()?)),
            PacketType::Retry => (r.get_bytes(r.remaining())?.to_vec(), None),
        };

        Ok((
            Self::Long(LongHeader {
                ty,
                version,
                dst_cid,
                src_cid,
                token,
                length,
                packet_number_len,
            }),
            r.consumed(),
        ))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        self.encode_into_writer(&mut w);
        w.into_vec()
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn append_encoded_to(&self, output: &mut Vec<u8>) {
        let mut w = Writer::from_vec(std::mem::take(output));
        self.encode_into_writer(&mut w);
        *output = w.into_vec();
    }

    fn encode_into_writer(&self, w: &mut Writer) {
        match self {
            Self::Short(header) => {
                let pn_bits = (header.packet_number_len.saturating_sub(1) & 0x03) as u8;
                let mut first = 0x40 | pn_bits;
                if header.spin {
                    first |= 0x20;
                }
                if header.key_phase {
                    first |= 0x04;
                }
                w.put_u8(first);
                w.put_bytes(header.dst_cid.as_bytes());
            }
            Self::Long(header) => {
                let pn_bits = (header.packet_number_len.saturating_sub(1) & 0x03) as u8;
                w.put_u8(0xc0 | header.ty.bits() | pn_bits);
                w.put_u32(header.version);
                w.put_u8(header.dst_cid.len() as u8);
                w.put_bytes(header.dst_cid.as_bytes());
                w.put_u8(header.src_cid.len() as u8);
                w.put_bytes(header.src_cid.as_bytes());
                match header.ty {
                    PacketType::Initial => {
                        w.put_var(VarInt::new(header.token.len() as u64).unwrap_or(VarInt::MAX));
                        w.put_bytes(&header.token);
                        w.put_var(header.length.unwrap_or(VarInt::ZERO));
                    }
                    PacketType::ZeroRtt | PacketType::Handshake => {
                        w.put_var(header.length.unwrap_or(VarInt::ZERO));
                    }
                    PacketType::Retry => w.put_bytes(&header.token),
                }
            }
            Self::VersionNegotiation {
                dst_cid,
                src_cid,
                versions,
            } => {
                w.put_u8(0xc0);
                w.put_u32(0);
                w.put_u8(dst_cid.len() as u8);
                w.put_bytes(dst_cid.as_bytes());
                w.put_u8(src_cid.len() as u8);
                w.put_bytes(src_cid.as_bytes());
                for version in versions {
                    w.put_u32(*version);
                }
            }
        }
    }
}

pub fn encode_retry_packet(
    version: u32,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    token: Vec<u8>,
    original_dst_cid: &ConnectionId,
) -> Result<Vec<u8>> {
    let header = Header::Long(LongHeader {
        ty: PacketType::Retry,
        version,
        dst_cid,
        src_cid,
        token,
        length: None,
        packet_number_len: 0,
    });
    let mut packet = header.encode();
    let tag = retry_integrity_tag(original_dst_cid, &packet)?;
    packet.extend_from_slice(&tag);
    Ok(packet)
}

pub fn decode_retry_packet(
    packet: &[u8],
    original_dst_cid: &ConnectionId,
) -> Result<(LongHeader, Vec<u8>)> {
    if packet.len() < RETRY_INTEGRITY_TAG_LEN {
        return Err(CodecError::MalformedPacket);
    }
    let packet_without_tag = &packet[..packet.len() - RETRY_INTEGRITY_TAG_LEN];
    let expected_tag = retry_integrity_tag(original_dst_cid, packet_without_tag)?;
    let actual_tag = &packet[packet.len() - RETRY_INTEGRITY_TAG_LEN..];
    if actual_tag != expected_tag.as_slice() {
        return Err(CodecError::MalformedPacket);
    }
    let (header, consumed) = Header::decode(packet_without_tag, 0)?;
    if consumed != packet_without_tag.len() {
        return Err(CodecError::MalformedPacket);
    }
    let Header::Long(header) = header else {
        return Err(CodecError::MalformedPacket);
    };
    if header.ty != PacketType::Retry {
        return Err(CodecError::MalformedPacket);
    }
    Ok((header, actual_tag.to_vec()))
}

fn retry_integrity_tag(original_dst_cid: &ConnectionId, retry_packet: &[u8]) -> Result<[u8; 16]> {
    use aes_gcm::{
        Aes128Gcm, Nonce,
        aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
    };

    const KEY: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const NONCE: [u8; 12] = [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ];

    let mut pseudo_packet = Vec::with_capacity(1 + original_dst_cid.len() + retry_packet.len());
    pseudo_packet.push(original_dst_cid.len() as u8);
    pseudo_packet.extend_from_slice(original_dst_cid.as_bytes());
    pseudo_packet.extend_from_slice(retry_packet);

    let key = Aes128Gcm::new(GenericArray::from_slice(&KEY));
    let mut payload = Vec::new();
    let tag = key
        .encrypt_in_place_detached(
            Nonce::from_slice(&NONCE),
            pseudo_packet.as_slice(),
            &mut payload,
        )
        .map_err(|_| CodecError::Crypto("failed to generate retry integrity tag".into()))?;
    let mut out = [0u8; RETRY_INTEGRITY_TAG_LEN];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

pub fn decode_packet_number(truncated: u64, len: usize, largest_received: Option<u64>) -> u64 {
    let expected = largest_received.map_or(0, |largest| largest + 1);
    let pn_nbits = len * 8;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let candidate = (expected & !pn_mask) | truncated;

    if candidate + pn_hwin <= expected && candidate < (1 << 62) - pn_win {
        candidate + pn_win
    } else if candidate > expected + pn_hwin && candidate >= pn_win {
        candidate - pn_win
    } else {
        candidate
    }
}

pub fn packet_number_len(packet_number: u64, least_unacked: u64) -> usize {
    let num_unacked = packet_number.saturating_sub(least_unacked) + 1;
    if num_unacked <= (1 << 7) {
        1
    } else if num_unacked <= (1 << 15) {
        2
    } else if num_unacked <= (1 << 23) {
        3
    } else {
        4
    }
}

pub fn encode_packet_number(packet_number: u64, len: usize, out: &mut Vec<u8>) -> Result<()> {
    if !(1..=4).contains(&len) {
        return Err(CodecError::ValueOutOfBounds);
    }
    let bytes = packet_number.to_be_bytes();
    out.extend_from_slice(&bytes[8 - len..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_negotiation_accepts_every_unused_bit_pattern() {
        let expected = super::Header::VersionNegotiation {
            dst_cid: crate::cid::ConnectionId::EMPTY,
            src_cid: crate::cid::ConnectionId::EMPTY,
            versions: vec![super::QUIC_VERSION_1],
        };
        let mut bytes = expected.encode();
        for unused in 0..128 {
            bytes[0] = 0x80 | unused;
            assert_eq!(super::Header::decode(&bytes, 0).unwrap().0, expected);
        }
        bytes[1..5].copy_from_slice(&super::QUIC_VERSION_1.to_be_bytes());
        bytes[0] = 0x80;
        assert!(super::Header::decode(&bytes, 0).is_err());
    }

    use super::*;
    use proptest::prelude::*;

    #[test]
    fn long_initial_roundtrip() {
        let header = Header::Long(LongHeader {
            ty: PacketType::Initial,
            version: QUIC_VERSION_1,
            dst_cid: ConnectionId::from_slice(b"destination").unwrap(),
            src_cid: ConnectionId::from_slice(b"source").unwrap(),
            token: b"token".to_vec(),
            length: Some(VarInt::from_u32(42)),
            packet_number_len: 2,
        });
        let encoded = header.encode();
        let (decoded, consumed) = Header::decode(&encoded, 0).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn retry_packet_roundtrip_preserves_token_and_tag() {
        let original_dst_cid = ConnectionId::from_slice(b"orig-dst").unwrap();
        let dst_cid = ConnectionId::from_slice(b"client").unwrap();
        let src_cid = ConnectionId::from_slice(b"server").unwrap();
        let packet = encode_retry_packet(
            QUIC_VERSION_1,
            dst_cid.clone(),
            src_cid.clone(),
            b"retry-token".to_vec(),
            &original_dst_cid,
        )
        .unwrap();

        let (header, _tag) = decode_retry_packet(&packet, &original_dst_cid).unwrap();
        assert_eq!(header.ty, PacketType::Retry);
        assert_eq!(header.version, QUIC_VERSION_1);
        assert_eq!(header.dst_cid, dst_cid);
        assert_eq!(header.src_cid, src_cid);
        assert_eq!(header.token, b"retry-token");
    }

    #[test]
    fn retry_packet_rejects_invalid_integrity_tag() {
        let original_dst_cid = ConnectionId::from_slice(b"orig-dst").unwrap();
        let packet = encode_retry_packet(
            QUIC_VERSION_1,
            ConnectionId::from_slice(b"client").unwrap(),
            ConnectionId::from_slice(b"server").unwrap(),
            b"retry-token".to_vec(),
            &original_dst_cid,
        )
        .unwrap();
        let mut tampered = packet;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        assert!(decode_retry_packet(&tampered, &original_dst_cid).is_err());
    }

    #[test]
    fn packet_number_decode_matches_rfc_example() {
        assert_eq!(
            decode_packet_number(0x9b32, 2, Some(0xa82f30ea)),
            0xa82f9b32
        );
    }

    #[test]
    fn encodes_packet_number_suffix() {
        let mut out = Vec::new();
        encode_packet_number(0x1234_5678, 3, &mut out).unwrap();
        assert_eq!(out, [0x34, 0x56, 0x78]);
    }

    #[test]
    fn packet_number_decode_uses_largest_received_reference() {
        assert_eq!(decode_packet_number(0x44, 1, Some(0xff)), 0x144);
        assert_eq!(decode_packet_number(0xfe, 1, Some(0x100)), 0xfe);
    }

    proptest! {
        #[test]
        fn packet_number_suffix_roundtrips(
            packet_number in 0u64..(1 << 32),
            least_unacked in 0u64..(1 << 32),
        ) {
            let least_unacked = least_unacked.min(packet_number);
            let len = packet_number_len(packet_number, least_unacked);
            let mut encoded = Vec::new();
            encode_packet_number(packet_number, len, &mut encoded).unwrap();
            let truncated = encoded
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
            let largest_received = least_unacked.checked_sub(1);
            let decoded = decode_packet_number(truncated, len, largest_received);
            prop_assert_eq!(decoded, packet_number);
        }
    }
}
