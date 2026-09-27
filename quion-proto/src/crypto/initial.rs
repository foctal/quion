use ring::{aead, aead::quic, hkdf};

use crate::{
    cid::ConnectionId,
    coding::Reader,
    error::{CodecError, Result},
    packet::{
        Header, LongHeader, PacketType, QUIC_VERSION_1, QUIC_VERSION_2, VERSION_NEGOTIATION_PROBE,
        decode_packet_number, encode_packet_number,
    },
    varint::VarInt,
};

const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

const AES_128_KEY_LEN: usize = 16;
const QUIC_IV_LEN: usize = 12;
const HEADER_PROTECTION_KEY_LEN: usize = 16;
const HEADER_PROTECTION_SAMPLE_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketKey {
    key: [u8; AES_128_KEY_LEN],
    iv: [u8; QUIC_IV_LEN],
    header_protection_key: [u8; HEADER_PROTECTION_KEY_LEN],
}

impl PacketKey {
    pub const fn key(&self) -> &[u8; AES_128_KEY_LEN] {
        &self.key
    }

    pub const fn iv(&self) -> &[u8; QUIC_IV_LEN] {
        &self.iv
    }

    pub const fn header_protection_key(&self) -> &[u8; HEADER_PROTECTION_KEY_LEN] {
        &self.header_protection_key
    }

    pub fn nonce(&self, packet_number: u64) -> [u8; QUIC_IV_LEN] {
        let mut nonce = self.iv;
        let pn = packet_number.to_be_bytes();
        for (dst, src) in nonce[4..].iter_mut().zip(pn) {
            *dst ^= src;
        }
        nonce
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialKeys {
    pub client: PacketKey,
    pub server: PacketKey,
}

impl InitialKeys {
    pub fn derive(version: u32, destination_connection_id: &ConnectionId) -> Result<Self> {
        let salt = initial_salt(version)?;
        let initial_secret =
            hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(destination_connection_id.as_bytes());
        let client_initial_secret = hkdf_expand_label(&initial_secret, b"client in", 32)?;
        let server_initial_secret = hkdf_expand_label(&initial_secret, b"server in", 32)?;

        Ok(Self {
            client: derive_packet_key(&client_initial_secret)?,
            server: derive_packet_key(&server_initial_secret)?,
        })
    }
}

fn initial_salt(version: u32) -> Result<&'static [u8]> {
    match version {
        QUIC_VERSION_1 | VERSION_NEGOTIATION_PROBE => Ok(&INITIAL_SALT_V1),
        QUIC_VERSION_2 => Ok(&INITIAL_SALT_V2),
        _ => Err(CodecError::MalformedPacket),
    }
}

fn derive_packet_key(secret: &[u8]) -> Result<PacketKey> {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let key = array_from_vec(hkdf_expand_label(&prk, b"quic key", AES_128_KEY_LEN)?)?;
    let iv = array_from_vec(hkdf_expand_label(&prk, b"quic iv", QUIC_IV_LEN)?)?;
    let header_protection_key = array_from_vec(hkdf_expand_label(
        &prk,
        b"quic hp",
        HEADER_PROTECTION_KEY_LEN,
    )?)?;

    Ok(PacketKey {
        key,
        iv,
        header_protection_key,
    })
}

fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((b"tls13 ".len() + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);

    let binding = [&info[..]];
    let okm = prk
        .expand(&binding, HkdfLen(len))
        .map_err(|_| CodecError::ValueOutOfBounds)?;
    let mut out = vec![0; len];
    okm.fill(&mut out)
        .map_err(|_| CodecError::ValueOutOfBounds)?;
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn array_from_vec<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| CodecError::ValueOutOfBounds)
}

pub struct InitialPacketProtector {
    sealing_key: aead::LessSafeKey,
    opening_key: aead::LessSafeKey,
    sealing_header_key: quic::HeaderProtectionKey,
    opening_header_key: quic::HeaderProtectionKey,
    sealing_iv: [u8; QUIC_IV_LEN],
    opening_iv: [u8; QUIC_IV_LEN],
}

impl InitialPacketProtector {
    pub fn new(keys: &InitialKeys, side: super::Side) -> Result<Self> {
        let (sealing, opening) = match side {
            super::Side::Client => (&keys.client, &keys.server),
            super::Side::Server => (&keys.server, &keys.client),
        };
        Ok(Self {
            sealing_key: less_safe_key(sealing.key())?,
            opening_key: less_safe_key(opening.key())?,
            sealing_header_key: header_protection_key(sealing.header_protection_key())?,
            opening_header_key: header_protection_key(opening.header_protection_key())?,
            sealing_iv: *sealing.iv(),
            opening_iv: *opening.iv(),
        })
    }

    pub fn seal(&self, packet_number: u64, header: &[u8], payload: &mut Vec<u8>) -> Result<()> {
        let nonce = nonce_from_iv(self.sealing_iv, packet_number);
        self.sealing_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(header),
                payload,
            )
            .map_err(|_| {
                CodecError::Transport(crate::transport_error::TransportErrorCode::InternalError)
            })
    }

    pub fn open<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        let nonce = nonce_from_iv(self.opening_iv, packet_number);
        self.opening_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(header),
                payload,
            )
            .map_err(|_| CodecError::Crypto("initial packet authentication failed".into()))
    }

    pub fn sealing_header_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        header_mask(&self.sealing_header_key, sample)
    }

    pub fn opening_header_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        header_mask(&self.opening_header_key, sample)
    }

    pub fn protect_header(
        &self,
        header: &mut [u8],
        packet_number_offset: usize,
        packet_number_len: usize,
        sample: &[u8],
    ) -> Result<()> {
        let mask = self.sealing_header_mask(sample)?;
        apply_header_mask(header, packet_number_offset, packet_number_len, mask)
    }

    pub fn unprotect_header(
        &self,
        header: &mut [u8],
        packet_number_offset: usize,
        packet_number_len: usize,
        sample: &[u8],
    ) -> Result<()> {
        let mask = self.opening_header_mask(sample)?;
        apply_header_mask(header, packet_number_offset, packet_number_len, mask)
    }

    pub fn protect_initial_packet(
        &self,
        mut header: LongHeader,
        packet_number: u64,
        plaintext_payload: &[u8],
    ) -> Result<Vec<u8>> {
        if header.ty != PacketType::Initial {
            return Err(CodecError::MalformedPacket);
        }

        let packet_number_len = header.packet_number_len;
        let ciphertext_len = plaintext_payload.len() + aead::AES_128_GCM.tag_len();
        header.length = Some(VarInt::new((packet_number_len + ciphertext_len) as u64)?);

        let mut packet = Header::Long(header).encode();
        let packet_number_offset = packet.len();
        encode_packet_number(packet_number, packet_number_len, &mut packet)?;
        let header_len = packet.len();

        let mut encrypted_payload = plaintext_payload.to_vec();
        self.seal(packet_number, &packet, &mut encrypted_payload)?;
        packet.extend_from_slice(&encrypted_payload);

        let sample = header_protection_sample(&packet, packet_number_offset)?;
        self.protect_header(
            &mut packet[..header_len],
            packet_number_offset,
            packet_number_len,
            &sample,
        )?;

        Ok(packet)
    }

    pub fn open_initial_packet<'a>(
        &self,
        packet: &'a mut [u8],
        largest_received: Option<u64>,
    ) -> Result<OpenedInitialPacket<'a>> {
        let packet_number_offset = long_header_packet_number_offset(packet)?;
        let sample = header_protection_sample(packet, packet_number_offset)?;

        let mask = self.opening_header_mask(&sample)?;
        apply_first_byte_mask(packet, mask)?;
        let packet_number_len = usize::from(packet[0] & 0x03) + 1;
        apply_packet_number_mask(packet, packet_number_offset, packet_number_len, mask)?;

        let packet_number_end = packet_number_offset + packet_number_len;
        let truncated_packet_number = packet[packet_number_offset..packet_number_end]
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        let packet_number =
            decode_packet_number(truncated_packet_number, packet_number_len, largest_received);

        let (header, consumed) = Header::decode(packet, 0)?;
        if consumed != packet_number_offset {
            return Err(CodecError::MalformedPacket);
        }

        // The long-header Length field bounds this packet's packet number and
        // ciphertext, so any trailing bytes belong to a coalesced packet rather
        // than to this one (RFC 9000 §12.2).
        let Header::Long(ref long) = header else {
            return Err(CodecError::MalformedPacket);
        };
        let length = long.length.ok_or(CodecError::MalformedPacket)?.into_inner() as usize;
        if length < packet_number_len {
            return Err(CodecError::MalformedPacket);
        }
        let packet_end = packet_number_offset
            .checked_add(length)
            .ok_or(CodecError::MalformedPacket)?;
        if packet_end > packet.len() {
            return Err(CodecError::UnexpectedEnd);
        }

        let (header_bytes, rest) = packet.split_at_mut(packet_number_end);
        let ciphertext = rest
            .get_mut(..packet_end - packet_number_end)
            .ok_or(CodecError::UnexpectedEnd)?;
        let plaintext = self.open(packet_number, header_bytes, ciphertext)?;

        Ok(OpenedInitialPacket {
            header,
            packet_number,
            payload: plaintext,
            consumed: packet_end,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OpenedInitialPacket<'a> {
    pub header: Header,
    pub packet_number: u64,
    pub payload: &'a mut [u8],
    /// Total length of this packet within the datagram, i.e. the offset at which
    /// a coalesced following packet would begin.
    pub consumed: usize,
}

fn less_safe_key(key: &[u8; AES_128_KEY_LEN]) -> Result<aead::LessSafeKey> {
    let unbound =
        aead::UnboundKey::new(&aead::AES_128_GCM, key).map_err(|_| CodecError::ValueOutOfBounds)?;
    Ok(aead::LessSafeKey::new(unbound))
}

fn header_protection_key(
    key: &[u8; HEADER_PROTECTION_KEY_LEN],
) -> Result<quic::HeaderProtectionKey> {
    quic::HeaderProtectionKey::new(&quic::AES_128, key).map_err(|_| CodecError::ValueOutOfBounds)
}

fn header_mask(key: &quic::HeaderProtectionKey, sample: &[u8]) -> Result<[u8; 5]> {
    if sample.len() != HEADER_PROTECTION_SAMPLE_LEN {
        return Err(CodecError::ValueOutOfBounds);
    }
    key.new_mask(sample)
        .map_err(|_| CodecError::ValueOutOfBounds)
}

pub fn apply_header_mask(
    header: &mut [u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    mask: [u8; 5],
) -> Result<()> {
    if !(1..=4).contains(&packet_number_len) {
        return Err(CodecError::ValueOutOfBounds);
    }
    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or(CodecError::ValueOutOfBounds)?;
    if header.is_empty() || packet_number_end > header.len() {
        return Err(CodecError::UnexpectedEnd);
    }

    apply_first_byte_mask(header, mask)?;
    apply_packet_number_mask(header, packet_number_offset, packet_number_len, mask)?;

    Ok(())
}

fn apply_first_byte_mask(header: &mut [u8], mask: [u8; 5]) -> Result<()> {
    let first = header.first_mut().ok_or(CodecError::UnexpectedEnd)?;
    let first_mask = if *first & 0x80 != 0 { 0x0f } else { 0x1f };
    *first ^= mask[0] & first_mask;
    Ok(())
}

fn apply_packet_number_mask(
    header: &mut [u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    mask: [u8; 5],
) -> Result<()> {
    if !(1..=4).contains(&packet_number_len) {
        return Err(CodecError::ValueOutOfBounds);
    }
    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or(CodecError::ValueOutOfBounds)?;
    if packet_number_end > header.len() {
        return Err(CodecError::UnexpectedEnd);
    }

    for (byte, mask_byte) in header[packet_number_offset..packet_number_end]
        .iter_mut()
        .zip(mask[1..].iter())
    {
        *byte ^= *mask_byte;
    }
    Ok(())
}

fn header_protection_sample(packet: &[u8], packet_number_offset: usize) -> Result<[u8; 16]> {
    let sample_offset = packet_number_offset
        .checked_add(4)
        .ok_or(CodecError::ValueOutOfBounds)?;
    packet
        .get(sample_offset..sample_offset + HEADER_PROTECTION_SAMPLE_LEN)
        .ok_or(CodecError::UnexpectedEnd)?
        .try_into()
        .map_err(|_| CodecError::UnexpectedEnd)
}

fn long_header_packet_number_offset(packet: &[u8]) -> Result<usize> {
    let mut r = Reader::new(packet);
    let first = r.get_u8()?;
    if first & 0x80 == 0 || first & 0x40 == 0 {
        return Err(CodecError::MalformedPacket);
    }
    let version = r.get_u32()?;
    if version == 0 {
        return Err(CodecError::MalformedPacket);
    }
    let dst_len = usize::from(r.get_u8()?);
    r.get_bytes(dst_len)?;
    let src_len = usize::from(r.get_u8()?);
    r.get_bytes(src_len)?;

    let ty_bits = first & 0x30;
    match ty_bits {
        0x00 => {
            let token_len = r.get_var()?.into_inner() as usize;
            r.get_bytes(token_len)?;
            r.get_var()?;
            Ok(r.consumed())
        }
        0x10 | 0x20 => {
            r.get_var()?;
            Ok(r.consumed())
        }
        _ => Err(CodecError::MalformedPacket),
    }
}

fn nonce_from_iv(mut iv: [u8; QUIC_IV_LEN], packet_number: u64) -> [u8; QUIC_IV_LEN] {
    let pn = packet_number.to_be_bytes();
    for (dst, src) in iv[4..].iter_mut().zip(pn) {
        *dst ^= src;
    }
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_rfc9001_initial_keys() {
        let dcid = ConnectionId::from_slice(&hex("8394c8f03e515708")).unwrap();
        let keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();

        assert_eq!(
            keys.client.key(),
            &hex_array("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(keys.client.iv(), &hex_array("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(
            keys.client.header_protection_key(),
            &hex_array("9f50449e04a0e810283a1e9933adedd2")
        );
        assert_eq!(
            keys.server.key(),
            &hex_array("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(keys.server.iv(), &hex_array("0ac1493ca1905853b0bba03e"));
        assert_eq!(
            keys.server.header_protection_key(),
            &hex_array("c206b8d9b9f0f37644430b490eeaa314")
        );
    }

    #[test]
    fn reserved_version_probe_uses_v1_initial_keys() {
        let dcid = ConnectionId::from_slice(b"version-probe").unwrap();

        assert_eq!(
            InitialKeys::derive(VERSION_NEGOTIATION_PROBE, &dcid).unwrap(),
            InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap()
        );
    }

    #[test]
    fn initial_protector_roundtrips_payload() {
        let dcid = ConnectionId::from_slice(b"roundtrip").unwrap();
        let keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();
        let client = InitialPacketProtector::new(&keys, super::super::Side::Client).unwrap();
        let server = InitialPacketProtector::new(&keys, super::super::Side::Server).unwrap();
        let header = b"header";
        let mut payload = b"crypto payload".to_vec();

        client.seal(7, header, &mut payload).unwrap();
        let opened = server.open(7, header, &mut payload).unwrap();
        assert_eq!(opened, b"crypto payload");
    }

    #[test]
    fn generates_rfc9001_header_protection_mask() {
        let dcid = ConnectionId::from_slice(&hex("8394c8f03e515708")).unwrap();
        let keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();
        let client = InitialPacketProtector::new(&keys, super::super::Side::Client).unwrap();
        let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");

        assert_eq!(
            client.sealing_header_mask(&sample).unwrap(),
            hex_array("437b9aec36")
        );
    }

    #[test]
    fn header_protection_is_reversible() {
        let dcid = ConnectionId::from_slice(b"roundtrip").unwrap();
        let keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();
        let client = InitialPacketProtector::new(&keys, super::super::Side::Client).unwrap();
        let server = InitialPacketProtector::new(&keys, super::super::Side::Server).unwrap();
        let sample = [7; HEADER_PROTECTION_SAMPLE_LEN];
        let mut header = vec![0xc3, 0, 0, 0, 1, 0x12, 0x34, 0x56, 0x78];
        let original = header.clone();
        let packet_number_offset = 5;
        let packet_number_len = 4;

        client
            .protect_header(
                &mut header,
                packet_number_offset,
                packet_number_len,
                &sample,
            )
            .unwrap();
        assert_ne!(header, original);
        server
            .unprotect_header(
                &mut header,
                packet_number_offset,
                packet_number_len,
                &sample,
            )
            .unwrap();
        assert_eq!(header, original);
    }

    #[test]
    fn initial_packet_protection_roundtrips() {
        let dcid = ConnectionId::from_slice(&hex("8394c8f03e515708")).unwrap();
        let scid = ConnectionId::from_slice(b"server").unwrap();
        let keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();
        let client = InitialPacketProtector::new(&keys, super::super::Side::Client).unwrap();
        let server = InitialPacketProtector::new(&keys, super::super::Side::Server).unwrap();
        let header = LongHeader {
            ty: PacketType::Initial,
            version: QUIC_VERSION_1,
            dst_cid: dcid,
            src_cid: scid,
            token: Vec::new(),
            length: None,
            packet_number_len: 2,
        };

        let mut packet = client
            .protect_initial_packet(header, 0x1234, b"client hello bytes")
            .unwrap();
        let opened = server.open_initial_packet(&mut packet, None).unwrap();

        assert_eq!(opened.packet_number, 0x1234);
        assert_eq!(opened.payload, b"client hello bytes");
        match opened.header {
            Header::Long(header) => {
                assert_eq!(header.ty, PacketType::Initial);
                assert_eq!(
                    header.length,
                    Some(VarInt::new(2 + b"client hello bytes".len() as u64 + 16).unwrap())
                );
            }
            _ => panic!("expected long header"),
        }
    }

    fn hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        input
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| {
                let hi = nybble(chunk[0]);
                let lo = nybble(chunk[1]);
                (hi << 4) | lo
            })
            .collect()
    }

    fn hex_array<const N: usize>(input: &str) -> [u8; N] {
        hex(input).try_into().ok().unwrap()
    }

    fn nybble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex"),
        }
    }
}
