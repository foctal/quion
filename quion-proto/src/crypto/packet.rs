use bytes::Bytes;
use smallvec::SmallVec;
use tracing::trace_span;

use crate::{
    buffers::BufferPool,
    cid::ConnectionId,
    crypto::{
        EncryptionLevel, initial::InitialPacketProtector, rustls::RustlsKeyStore,
        stream::CryptoFrame,
    },
    ecn::EcnCodepoint,
    error::{CodecError, Result},
    frame::Frame,
    packet::{Header, LongHeader, PacketType, QUIC_VERSION_1, ShortHeader},
    transport_error::TransportErrorCode,
};

#[derive(Debug, Clone)]
pub struct CryptoPacketBuilder {
    version: u32,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    initial_token: Vec<u8>,
    packet_number_len: usize,
    next_initial_packet_number: u64,
    next_handshake_packet_number: u64,
    next_one_rtt_packet_number: u64,
}

impl CryptoPacketBuilder {
    pub fn new(dst_cid: ConnectionId, src_cid: ConnectionId) -> Self {
        Self {
            version: QUIC_VERSION_1,
            dst_cid,
            src_cid,
            initial_token: Vec::new(),
            packet_number_len: 2,
            next_initial_packet_number: 0,
            next_handshake_packet_number: 0,
            next_one_rtt_packet_number: 0,
        }
    }

    pub fn dst_cid_len(&self) -> usize {
        self.dst_cid.len()
    }

    pub fn set_destination_connection_id(&mut self, dst_cid: ConnectionId) {
        self.dst_cid = dst_cid;
    }

    pub fn set_version(&mut self, version: u32) {
        self.version = version;
    }

    pub fn set_source_connection_id(&mut self, src_cid: ConnectionId) {
        self.src_cid = src_cid;
    }

    pub fn set_initial_token(&mut self, token: impl Into<Vec<u8>>) {
        self.initial_token = token.into();
    }

    pub fn next_packet_number(&self, level: EncryptionLevel) -> Option<u64> {
        Some(match level {
            EncryptionLevel::Initial => self.next_initial_packet_number,
            EncryptionLevel::Handshake => self.next_handshake_packet_number,
            EncryptionLevel::OneRtt | EncryptionLevel::ZeroRtt => self.next_one_rtt_packet_number,
        })
    }

    /// Conservative plaintext budget including CID, token, length, packet
    /// number, and AEAD tag overhead for a packet constrained to `maximum`.
    pub fn max_payload_len(&self, level: EncryptionLevel, maximum: usize) -> usize {
        let overhead = match level {
            EncryptionLevel::Initial | EncryptionLevel::Handshake | EncryptionLevel::ZeroRtt => {
                let ty = if level == EncryptionLevel::Initial {
                    PacketType::Initial
                } else if level == EncryptionLevel::Handshake {
                    PacketType::Handshake
                } else {
                    PacketType::ZeroRtt
                };
                let mut header = self.long_header(ty);
                header.length =
                    Some(crate::VarInt::new(maximum as u64).unwrap_or(crate::VarInt::MAX));
                Header::Long(header).encode().len() + self.packet_number_len + 16
            }
            EncryptionLevel::OneRtt => 1 + self.dst_cid.len() + self.packet_number_len + 16,
        };
        maximum.saturating_sub(overhead)
    }

    pub fn build_initial(
        &mut self,
        protector: &InitialPacketProtector,
        frames: &[CryptoFrame],
    ) -> Result<Vec<u8>> {
        let payload = encode_crypto_frames(EncryptionLevel::Initial, frames)?;
        self.build_initial_payload(protector, &payload)
    }

    pub fn build_initial_frames(
        &mut self,
        protector: &InitialPacketProtector,
        frames: &[Frame],
    ) -> Result<Vec<u8>> {
        self.build_initial_payload(protector, &encode_frames(frames))
    }

    fn build_initial_payload(
        &mut self,
        protector: &InitialPacketProtector,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let packet_number = self.next_initial_packet_number;
        let _span = trace_span!(
            "quion.packet.protect",
            level = "initial",
            packet_number,
            payload_bytes = payload.len()
        )
        .entered();
        self.next_initial_packet_number += 1;
        protector.protect_initial_packet(
            self.long_header(PacketType::Initial),
            packet_number,
            payload,
        )
    }

    pub fn build_initial_padded(
        &mut self,
        protector: &InitialPacketProtector,
        frames: &[CryptoFrame],
        min_packet_len: usize,
    ) -> Result<Vec<u8>> {
        self.build_initial_payload_padded(
            protector,
            encode_crypto_frames(EncryptionLevel::Initial, frames)?,
            min_packet_len,
        )
    }

    /// Encodes arbitrary Initial frames with authenticated padding to the requested size.
    pub fn build_initial_frames_padded(
        &mut self,
        protector: &InitialPacketProtector,
        frames: &[Frame],
        min_packet_len: usize,
    ) -> Result<Vec<u8>> {
        self.build_initial_payload_padded(protector, encode_frames(frames), min_packet_len)
    }

    fn build_initial_payload_padded(
        &mut self,
        protector: &InitialPacketProtector,
        mut payload: Vec<u8>,
        min_packet_len: usize,
    ) -> Result<Vec<u8>> {
        let packet_number = self.next_initial_packet_number;
        let mut packet = protector.protect_initial_packet(
            self.long_header(PacketType::Initial),
            packet_number,
            &payload,
        )?;
        if packet.len() < min_packet_len {
            payload.extend(std::iter::repeat_n(0, min_packet_len - packet.len()));
            packet = protector.protect_initial_packet(
                self.long_header(PacketType::Initial),
                packet_number,
                &payload,
            )?;
            // Padding can widen the encoded Length field. Remove that extra
            // byte overhead so the packet still fits an exactly 1,200-byte path.
            if packet.len() > min_packet_len {
                payload.truncate(payload.len() - (packet.len() - min_packet_len));
                packet = protector.protect_initial_packet(
                    self.long_header(PacketType::Initial),
                    packet_number,
                    &payload,
                )?;
            }
        }
        self.next_initial_packet_number += 1;
        Ok(packet)
    }

    pub fn build_handshake(
        &mut self,
        keys: &RustlsKeyStore,
        frames: &[CryptoFrame],
    ) -> Result<Vec<u8>> {
        let payload = encode_crypto_frames(EncryptionLevel::Handshake, frames)?;
        self.build_handshake_payload(keys, &payload)
    }

    pub fn build_handshake_frames(
        &mut self,
        keys: &RustlsKeyStore,
        frames: &[Frame],
    ) -> Result<Vec<u8>> {
        self.build_handshake_payload(keys, &encode_frames(frames))
    }

    fn build_handshake_payload(
        &mut self,
        keys: &RustlsKeyStore,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let packet_number = self.next_handshake_packet_number;
        let _span = trace_span!(
            "quion.packet.protect",
            level = "handshake",
            packet_number,
            payload_bytes = payload.len()
        )
        .entered();
        self.next_handshake_packet_number += 1;
        let keys = keys
            .get(EncryptionLevel::Handshake)
            .ok_or_else(|| CodecError::Crypto("missing handshake keys".into()))?;
        keys.protect_long_packet(
            self.long_header(PacketType::Handshake),
            packet_number,
            payload,
        )
    }

    #[cfg(feature = "zero-rtt")]
    pub fn build_zero_rtt_frames(
        &mut self,
        keys: &RustlsKeyStore,
        frames: &[Frame],
    ) -> Result<Vec<u8>> {
        let packet_number = self.next_one_rtt_packet_number;
        self.next_one_rtt_packet_number += 1;
        let keys = keys
            .get(EncryptionLevel::ZeroRtt)
            .ok_or_else(|| CodecError::Crypto("missing 0-RTT keys".into()))?;
        keys.protect_long_packet(
            self.long_header(PacketType::ZeroRtt),
            packet_number,
            &encode_frames(frames),
        )
    }

    pub fn build_one_rtt(
        &mut self,
        keys: &RustlsKeyStore,
        frames: &[CryptoFrame],
    ) -> Result<Vec<u8>> {
        let payload = encode_crypto_frames(EncryptionLevel::OneRtt, frames)?;
        self.build_one_rtt_payload(keys, &payload)
    }

    /// Protects arbitrary frames in the next 1-RTT packet.
    pub fn build_one_rtt_frames(
        &mut self,
        keys: &RustlsKeyStore,
        frames: &[Frame],
    ) -> Result<Vec<u8>> {
        self.build_one_rtt_payload(keys, &encode_frames(frames))
    }

    fn build_one_rtt_payload(&mut self, keys: &RustlsKeyStore, payload: &[u8]) -> Result<Vec<u8>> {
        let packet_number = self.next_one_rtt_packet_number;
        let _span = trace_span!(
            "quion.packet.protect",
            level = "1rtt",
            packet_number,
            payload_bytes = payload.len()
        )
        .entered();
        self.next_one_rtt_packet_number += 1;
        keys.protect_one_rtt_short_packet(self.short_header(keys)?, packet_number, payload)
    }

    fn long_header(&self, ty: PacketType) -> LongHeader {
        LongHeader {
            ty,
            version: self.version,
            dst_cid: self.dst_cid.clone(),
            src_cid: self.src_cid.clone(),
            token: if ty == PacketType::Initial {
                self.initial_token.clone()
            } else {
                Vec::new()
            },
            length: None,
            packet_number_len: self.packet_number_len,
        }
    }

    fn short_header(&self, keys: &RustlsKeyStore) -> Result<ShortHeader> {
        Ok(ShortHeader {
            spin: false,
            key_phase: keys
                .current_one_rtt_key_phase()
                .ok_or_else(|| CodecError::Crypto("missing 1-RTT keys".into()))?,
            dst_cid: self.dst_cid.clone(),
            packet_number_len: self.packet_number_len,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedCryptoPacket {
    pub level: EncryptionLevel,
    pub header: Header,
    pub packet_number: u64,
    pub ecn: Option<EcnCodepoint>,
    pub frames: SmallVec<[Frame; 2]>,
    /// Largest received DATAGRAM wire size, preserving omitted/nonminimal lengths.
    pub max_datagram_frame_size: Option<usize>,
    /// Total length of this packet within the datagram; the offset at which a
    /// coalesced following packet would begin (RFC 9000 §12.2).
    pub consumed: usize,
}

pub struct CryptoPacketOpener;

impl CryptoPacketOpener {
    pub fn open_initial(
        protector: &InitialPacketProtector,
        packet: &mut [u8],
        largest_received: Option<u64>,
    ) -> Result<OpenedCryptoPacket> {
        let _span = trace_span!(
            "quion.packet.open",
            level = "initial",
            packet_bytes = packet.len()
        )
        .entered();
        let opened = protector
            .open_initial_packet(packet, largest_received)
            .map_err(map_long_header_open_error)?;
        let consumed = opened.consumed;
        let (frames, max_datagram_frame_size) = decode_frames(opened.payload)?;
        Ok(OpenedCryptoPacket {
            level: EncryptionLevel::Initial,
            header: opened.header,
            packet_number: opened.packet_number,
            ecn: None,
            frames,
            max_datagram_frame_size,
            consumed,
        })
    }

    pub fn open_handshake(
        keys: &RustlsKeyStore,
        packet: &mut [u8],
        largest_received: Option<u64>,
    ) -> Result<OpenedCryptoPacket> {
        let _span = trace_span!(
            "quion.packet.open",
            level = "handshake",
            packet_bytes = packet.len()
        )
        .entered();
        let keys = keys
            .get(EncryptionLevel::Handshake)
            .ok_or(CodecError::PacketDiscard)?;
        let opened = keys
            .open_long_packet(packet, largest_received)
            .map_err(map_long_header_open_error)?;
        let consumed = opened.consumed;
        let (frames, max_datagram_frame_size) = decode_frames(opened.payload)?;
        Ok(OpenedCryptoPacket {
            level: EncryptionLevel::Handshake,
            header: opened.header,
            packet_number: opened.packet_number,
            ecn: None,
            frames,
            max_datagram_frame_size,
            consumed,
        })
    }

    #[cfg(feature = "zero-rtt")]
    pub fn open_zero_rtt(
        keys: &RustlsKeyStore,
        packet: &mut [u8],
        largest_received: Option<u64>,
    ) -> Result<OpenedCryptoPacket> {
        let keys = keys
            .get(EncryptionLevel::ZeroRtt)
            .ok_or(CodecError::PacketDiscard)?;
        let opened = keys
            .open_long_packet(packet, largest_received)
            .map_err(map_long_header_open_error)?;
        let consumed = opened.consumed;
        let (frames, max_datagram_frame_size) = decode_frames(opened.payload)?;
        Ok(OpenedCryptoPacket {
            level: EncryptionLevel::ZeroRtt,
            header: opened.header,
            packet_number: opened.packet_number,
            ecn: None,
            frames,
            max_datagram_frame_size,
            consumed,
        })
    }

    pub fn open_one_rtt(
        keys: &mut RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
    ) -> Result<OpenedCryptoPacket> {
        let _span = trace_span!(
            "quion.packet.open",
            level = "1rtt",
            packet_bytes = packet.len()
        )
        .entered();
        let opened = keys
            .open_one_rtt_short_packet(packet, expected_dst_cid_len, largest_received)
            .map_err(map_one_rtt_open_error)?;
        let consumed = opened.consumed;
        let (frames, max_datagram_frame_size) = decode_frames(opened.payload)?;
        Ok(OpenedCryptoPacket {
            level: EncryptionLevel::OneRtt,
            header: opened.header,
            packet_number: opened.packet_number,
            ecn: None,
            frames,
            max_datagram_frame_size,
            consumed,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FramePacketBuilder {
    dst_cid: ConnectionId,
    packet_number_len: usize,
    next_one_rtt_packet_number: u64,
    packet_pool: BufferPool,
}

impl FramePacketBuilder {
    pub fn new(dst_cid: ConnectionId) -> Self {
        Self::with_next_one_rtt_packet_number(dst_cid, 0)
    }

    /// Creates a 1-RTT builder that continues an existing application-data
    /// packet-number space.
    pub fn with_next_one_rtt_packet_number(
        dst_cid: ConnectionId,
        next_one_rtt_packet_number: u64,
    ) -> Self {
        Self {
            dst_cid,
            packet_number_len: 2,
            next_one_rtt_packet_number,
            packet_pool: BufferPool::new(2_048, 32),
        }
    }

    pub fn dst_cid_len(&self) -> usize {
        self.dst_cid.len()
    }

    pub const fn next_one_rtt_packet_number(&self) -> u64 {
        self.next_one_rtt_packet_number
    }

    pub fn set_destination_connection_id(&mut self, dst_cid: ConnectionId) {
        self.dst_cid = dst_cid;
    }

    pub fn build_one_rtt(&mut self, keys: &RustlsKeyStore, frames: &[Frame]) -> Result<Vec<u8>> {
        let payload_len = frames
            .iter()
            .map(Frame::encoded_len)
            .fold(0usize, usize::saturating_add);
        self.build_one_rtt_with_payload_len(keys, frames, payload_len)
    }

    /// Builds a protected 1-RTT packet with PADDING to an exact UDP payload
    /// size, as required for DPLPMTUD probes.
    pub fn build_one_rtt_padded(
        &mut self,
        keys: &RustlsKeyStore,
        frames: &[Frame],
        packet_size: usize,
    ) -> Result<Vec<u8>> {
        let frame_payload_len = frames
            .iter()
            .map(Frame::encoded_len)
            .fold(0usize, usize::saturating_add);
        let tag_len = keys
            .one_rtt_tag_len()
            .ok_or_else(|| CodecError::Crypto("missing local 1-RTT packet key".into()))?;
        let packet_overhead = 1usize
            .saturating_add(self.dst_cid.len())
            .saturating_add(self.packet_number_len)
            .saturating_add(tag_len);
        let payload_len = packet_size
            .checked_sub(packet_overhead)
            .filter(|payload_len| *payload_len >= frame_payload_len)
            .ok_or(CodecError::ValueOutOfBounds)?;
        self.build_one_rtt_with_payload_len(keys, frames, payload_len)
    }

    fn build_one_rtt_with_payload_len(
        &mut self,
        keys: &RustlsKeyStore,
        frames: &[Frame],
        payload_len: usize,
    ) -> Result<Vec<u8>> {
        let frame_payload_len = frames
            .iter()
            .map(Frame::encoded_len)
            .fold(0usize, usize::saturating_add);
        let packet_number = self.next_one_rtt_packet_number;
        let _span = trace_span!(
            "quion.packet.protect",
            level = "1rtt",
            packet_number,
            payload_bytes = payload_len
        )
        .entered();
        self.next_one_rtt_packet_number += 1;
        let packet = self.packet_pool.acquire();
        keys.protect_one_rtt_short_packet_with_payload_in(
            packet,
            self.short_header(keys)?,
            packet_number,
            payload_len,
            |packet| {
                for frame in frames {
                    frame.append_encoded_to(packet);
                }
                packet.resize(
                    packet
                        .len()
                        .saturating_add(payload_len.saturating_sub(frame_payload_len)),
                    0,
                );
            },
        )
    }

    pub fn recycle_packet(&mut self, packet: Vec<u8>) {
        self.packet_pool.release(packet);
    }

    fn short_header(&self, keys: &RustlsKeyStore) -> Result<ShortHeader> {
        Ok(ShortHeader {
            spin: false,
            key_phase: keys
                .current_one_rtt_key_phase()
                .ok_or_else(|| CodecError::Crypto("missing 1-RTT keys".into()))?,
            dst_cid: self.dst_cid.clone(),
            packet_number_len: self.packet_number_len,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFramePacket {
    pub level: EncryptionLevel,
    pub header: Header,
    pub packet_number: u64,
    pub ecn: Option<EcnCodepoint>,
    pub frames: SmallVec<[Frame; 2]>,
    /// Largest received DATAGRAM wire size, preserving omitted/nonminimal lengths.
    pub max_datagram_frame_size: Option<usize>,
    /// Total length of this packet within the datagram. Short-header packets run
    /// to the end of the datagram, so this is always the datagram length.
    pub consumed: usize,
}

pub struct FramePacketOpener;

impl FramePacketOpener {
    pub fn open_one_rtt(
        keys: &mut RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
    ) -> Result<OpenedFramePacket> {
        let _span = trace_span!(
            "quion.packet.open",
            level = "1rtt",
            packet_bytes = packet.len()
        )
        .entered();
        let opened = keys
            .open_one_rtt_short_packet(packet, expected_dst_cid_len, largest_received)
            .map_err(map_one_rtt_open_error)?;
        let consumed = opened.consumed;
        let (frames, max_datagram_frame_size) = decode_frames(opened.payload)?;
        Ok(OpenedFramePacket {
            level: EncryptionLevel::OneRtt,
            header: opened.header,
            packet_number: opened.packet_number,
            ecn: None,
            frames,
            max_datagram_frame_size,
            consumed,
        })
    }

    pub fn open_one_rtt_with_key_update_permission(
        keys: &mut RustlsKeyStore,
        packet: &mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
        key_update_permitted: bool,
    ) -> Result<OpenedFramePacket> {
        let _span = trace_span!(
            "quion.packet.open",
            level = "1rtt",
            packet_bytes = packet.len(),
            key_update_permitted
        )
        .entered();
        let opened = keys
            .open_one_rtt_short_packet_with_key_update_permission(
                packet,
                expected_dst_cid_len,
                largest_received,
                key_update_permitted,
            )
            .map_err(map_one_rtt_open_error)?;
        let consumed = opened.consumed;
        let (frames, max_datagram_frame_size) = decode_frames(opened.payload)?;
        Ok(OpenedFramePacket {
            level: EncryptionLevel::OneRtt,
            header: opened.header,
            packet_number: opened.packet_number,
            ecn: None,
            frames,
            max_datagram_frame_size,
            consumed,
        })
    }

    /// Opens an owned 1-RTT packet and retains STREAM and DATAGRAM payloads as
    /// zero-copy slices of its decrypted backing storage.
    pub fn open_one_rtt_owned_with_key_update_permission<O>(
        keys: &mut RustlsKeyStore,
        mut packet: O,
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
        key_update_permitted: bool,
    ) -> Result<OpenedFramePacket>
    where
        O: AsRef<[u8]> + AsMut<[u8]> + Send + 'static,
    {
        let base = packet.as_ref().as_ptr() as usize;
        let (header, packet_number, payload_range, consumed) = {
            let opened = keys
                .open_one_rtt_short_packet_with_key_update_permission(
                    packet.as_mut(),
                    expected_dst_cid_len,
                    largest_received,
                    key_update_permitted,
                )
                .map_err(map_one_rtt_open_error)?;
            let payload_start = (opened.payload.as_ptr() as usize)
                .checked_sub(base)
                .ok_or(CodecError::MalformedPacket)?;
            let payload_end = payload_start
                .checked_add(opened.payload.len())
                .ok_or(CodecError::MalformedPacket)?;
            (
                opened.header,
                opened.packet_number,
                payload_start..payload_end,
                opened.consumed,
            )
        };
        let packet = Bytes::from_owner(packet);
        if payload_range.end > packet.len() {
            return Err(CodecError::MalformedPacket);
        }
        let payload = packet.slice(payload_range);
        let (frames, max_datagram_frame_size) = decode_frames_bytes(payload)?;
        Ok(OpenedFramePacket {
            level: EncryptionLevel::OneRtt,
            header,
            packet_number,
            ecn: None,
            frames,
            max_datagram_frame_size,
            consumed,
        })
    }
}

fn map_one_rtt_open_error(error: CodecError) -> CodecError {
    match error {
        CodecError::UnexpectedEnd
        | CodecError::InvalidInteger
        | CodecError::NonMinimalInteger
        | CodecError::MalformedPacket
        | CodecError::ValueOutOfBounds => CodecError::PacketDiscard,
        other => other,
    }
}

fn map_long_header_open_error(error: CodecError) -> CodecError {
    match error {
        CodecError::UnexpectedEnd
        | CodecError::InvalidInteger
        | CodecError::NonMinimalInteger
        | CodecError::MalformedPacket
        | CodecError::Crypto(_)
        | CodecError::ValueOutOfBounds => CodecError::PacketDiscard,
        other => other,
    }
}

fn encode_crypto_frames(level: EncryptionLevel, frames: &[CryptoFrame]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for frame in frames {
        if frame.level != level {
            return Err(CodecError::MalformedFrame);
        }
        frame.clone().into_frame()?.encode().append_to(&mut payload);
    }
    Ok(payload)
}

fn encode_frames(frames: &[Frame]) -> Vec<u8> {
    let capacity = frames
        .iter()
        .map(Frame::encoded_len)
        .fold(0usize, usize::saturating_add);
    let mut payload = Vec::with_capacity(capacity);
    for frame in frames {
        frame.append_encoded_to(&mut payload);
    }
    payload
}

fn decode_frames(mut payload: &[u8]) -> Result<(SmallVec<[Frame; 2]>, Option<usize>)> {
    if payload.is_empty() {
        return Err(CodecError::Transport(TransportErrorCode::ProtocolViolation));
    }
    let mut frames = SmallVec::new();
    let mut max_datagram: Option<usize> = None;
    while !payload.is_empty() {
        let (frame, consumed) = Frame::decode(payload)?;
        if consumed == 0 || consumed > payload.len() {
            return Err(CodecError::MalformedFrame);
        }
        if matches!(frame, Frame::Datagram { .. }) {
            max_datagram = Some(max_datagram.map_or(consumed, |size| size.max(consumed)));
        }
        frames.push(frame);
        payload = &payload[consumed..];
    }
    Ok((frames, max_datagram))
}

fn decode_frames_bytes(mut payload: Bytes) -> Result<(SmallVec<[Frame; 2]>, Option<usize>)> {
    if payload.is_empty() {
        return Err(CodecError::Transport(TransportErrorCode::ProtocolViolation));
    }
    let mut frames = SmallVec::new();
    let mut max_datagram: Option<usize> = None;
    while !payload.is_empty() {
        let (frame, consumed) = Frame::decode_bytes(payload.clone())?;
        if consumed == 0 || consumed > payload.len() {
            return Err(CodecError::MalformedFrame);
        }
        if matches!(frame, Frame::Datagram { .. }) {
            max_datagram = Some(max_datagram.map_or(consumed, |size| size.max(consumed)));
        }
        frames.push(frame);
        payload = payload.slice(consumed..);
    }
    Ok((frames, max_datagram))
}

trait AppendTo {
    fn append_to(self, out: &mut Vec<u8>);
}

impl AppendTo for Vec<u8> {
    fn append_to(mut self, out: &mut Vec<u8>) {
        out.append(&mut self);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn datagram_wire_metadata_preserves_length_encodings() {
        for (wire, expected) in [
            (&[0x30, 7][..], 2),
            (&[0x31, 0][..], 2),
            (&[0x31, 0x40, 0][..], 3),
            (&[0x31, 1, 7, 0x30, 8][..], 3),
        ] {
            let (borrowed, actual) = super::decode_frames(wire).unwrap();
            let (owned, owned_actual) = super::decode_frames_bytes(wire.to_vec().into()).unwrap();
            assert_eq!(actual, Some(expected));
            assert_eq!(owned_actual, actual);
            assert_eq!(borrowed, owned);
        }
    }

    use super::*;
    use crate::crypto::{Side, initial::InitialKeys};

    #[test]
    fn initial_packet_builder_and_opener_roundtrip_crypto_frames() {
        let dst = ConnectionId::from_slice(b"destination").unwrap();
        let src = ConnectionId::from_slice(b"source").unwrap();
        let keys = InitialKeys::derive(QUIC_VERSION_1, &dst).unwrap();
        let client = InitialPacketProtector::new(&keys, Side::Client).unwrap();
        let server = InitialPacketProtector::new(&keys, Side::Server).unwrap();
        let mut builder = CryptoPacketBuilder::new(dst, src);
        let frames = vec![
            CryptoFrame {
                level: EncryptionLevel::Initial,
                offset: 0,
                bytes: b"client".to_vec(),
            },
            CryptoFrame {
                level: EncryptionLevel::Initial,
                offset: 6,
                bytes: b" hello".to_vec(),
            },
        ];

        let mut packet = builder.build_initial(&client, &frames).unwrap();
        let opened = CryptoPacketOpener::open_initial(&server, &mut packet, None).unwrap();

        assert_eq!(opened.level, EncryptionLevel::Initial);
        assert_eq!(opened.packet_number, 0);
        assert_eq!(
            opened.frames.as_slice(),
            &[
                Frame::Crypto {
                    offset: crate::VarInt::ZERO,
                    data: b"client".to_vec(),
                },
                Frame::Crypto {
                    offset: crate::VarInt::from_u32(6),
                    data: b" hello".to_vec(),
                },
            ]
        );
        match opened.header {
            Header::Long(header) => assert_eq!(header.ty, PacketType::Initial),
            _ => panic!("expected long header"),
        }
    }

    #[test]
    fn initial_packet_builder_supports_token_and_padding() {
        let dst = ConnectionId::from_slice(b"destination").unwrap();
        let src = ConnectionId::from_slice(b"source").unwrap();
        let keys = InitialKeys::derive(QUIC_VERSION_1, &dst).unwrap();
        let client = InitialPacketProtector::new(&keys, Side::Client).unwrap();
        let server = InitialPacketProtector::new(&keys, Side::Server).unwrap();
        let frames = [CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 0,
            bytes: b"client hello".to_vec(),
        }];
        let mut builder = CryptoPacketBuilder::new(dst, src);
        builder.set_initial_token(b"retry-token".to_vec());

        let mut packet = builder
            .build_initial_padded(&client, &frames, 1200)
            .unwrap();

        assert_eq!(packet.len(), 1200);
        let opened = CryptoPacketOpener::open_initial(&server, &mut packet, None).unwrap();
        let Header::Long(header) = opened.header else {
            panic!("expected initial header");
        };
        assert_eq!(header.token, b"retry-token");
        assert_eq!(
            opened.frames.first(),
            Some(&Frame::Crypto {
                offset: crate::VarInt::ZERO,
                data: b"client hello".to_vec(),
            })
        );
        assert!(
            opened.frames[1..]
                .iter()
                .all(|frame| matches!(frame, Frame::Padding))
        );
    }

    #[test]
    fn initial_frame_builder_roundtrips_transport_close() {
        let dst = ConnectionId::from_slice(b"destination").unwrap();
        let src = ConnectionId::from_slice(b"source").unwrap();
        let keys = InitialKeys::derive(QUIC_VERSION_1, &dst).unwrap();
        let client = InitialPacketProtector::new(&keys, Side::Client).unwrap();
        let server = InitialPacketProtector::new(&keys, Side::Server).unwrap();
        let mut builder = CryptoPacketBuilder::new(dst, src);
        let frame = Frame::ConnectionClose {
            error_code: TransportErrorCode::FrameEncodingError,
            frame_type: crate::VarInt::ZERO,
            reason: b"malformed authenticated packet".to_vec(),
        };

        let mut packet = builder
            .build_initial_frames(&client, std::slice::from_ref(&frame))
            .unwrap();
        let opened = CryptoPacketOpener::open_initial(&server, &mut packet, None).unwrap();

        assert_eq!(opened.frames.as_slice(), &[frame]);
    }

    #[test]
    fn frame_packet_builder_and_opener_roundtrip_one_rtt_frames() {
        use crate::crypto::rustls::tests::one_rtt_test_keys;

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let mut builder = FramePacketBuilder::new(dst);
        let frames = vec![
            Frame::Ping,
            Frame::Datagram {
                data: b"hello".to_vec().into(),
            },
            Frame::Stream {
                stream_id: crate::VarInt::ZERO,
                offset: crate::VarInt::ZERO,
                fin: true,
                data: b"stream".to_vec().into(),
            },
        ];

        let expected_dst_cid_len = builder.dst_cid_len();
        let mut packet = builder.build_one_rtt(&client_keys, &frames).unwrap();
        let opened = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut packet,
            expected_dst_cid_len,
            None,
        )
        .unwrap();

        assert_eq!(opened.level, EncryptionLevel::OneRtt);
        assert_eq!(opened.packet_number, 0);
        assert_eq!(opened.frames.as_slice(), frames.as_slice());
    }

    #[test]
    fn owned_frame_packet_opener_retains_stream_and_datagram_packet_storage() {
        use crate::crypto::rustls::tests::one_rtt_test_keys;

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let mut builder = FramePacketBuilder::new(dst);
        let expected_dst_cid_len = builder.dst_cid_len();
        let frames = [
            Frame::Stream {
                stream_id: crate::VarInt::ZERO,
                offset: crate::VarInt::ZERO,
                fin: false,
                data: Bytes::from_static(b"stream payload"),
            },
            Frame::Datagram {
                data: Bytes::from_static(b"datagram payload"),
            },
        ];
        let packet = builder.build_one_rtt(&client_keys, &frames).unwrap();
        let allocation_start = packet.as_ptr() as usize;
        let allocation_end = allocation_start + packet.len();

        let opened = FramePacketOpener::open_one_rtt_owned_with_key_update_permission(
            &mut server_keys,
            packet,
            expected_dst_cid_len,
            None,
            true,
        )
        .unwrap();

        for frame in &opened.frames {
            let data = match frame {
                Frame::Stream { data, .. } | Frame::Datagram { data } => data,
                other => panic!("unexpected frame: {other:?}"),
            };
            let start = data.as_ptr() as usize;
            assert!(start >= allocation_start);
            assert!(start + data.len() <= allocation_end);
        }
    }

    #[test]
    fn frame_packet_builder_pads_mtu_probe_to_exact_size() {
        use crate::crypto::rustls::tests::one_rtt_test_keys;

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let mut builder = FramePacketBuilder::new(dst);
        let expected_dst_cid_len = builder.dst_cid_len();
        let mut packet = builder
            .build_one_rtt_padded(&client_keys, &[Frame::Ping], 1_452)
            .unwrap();

        assert_eq!(packet.len(), 1_452);
        let opened = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut packet,
            expected_dst_cid_len,
            None,
        )
        .unwrap();
        assert_eq!(opened.frames.first(), Some(&Frame::Ping));
        assert!(
            opened.frames[1..]
                .iter()
                .all(|frame| matches!(frame, Frame::Padding))
        );
    }

    #[test]
    fn crypto_packet_builder_roundtrips_one_rtt_transport_close() {
        use crate::crypto::rustls::tests::one_rtt_test_keys;

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let src = ConnectionId::from_slice(b"client-scid").unwrap();
        let expected_dst_cid_len = dst.len();
        let mut builder = CryptoPacketBuilder::new(dst, src);
        let frame = Frame::ConnectionClose {
            error_code: TransportErrorCode::StreamStateError,
            frame_type: crate::VarInt::ZERO,
            reason: b"authenticated packet violation".to_vec(),
        };

        let mut packet = builder
            .build_one_rtt_frames(&client_keys, std::slice::from_ref(&frame))
            .unwrap();
        let opened = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut packet,
            expected_dst_cid_len,
            None,
        )
        .unwrap();

        assert_eq!(opened.packet_number, 0);
        assert_eq!(opened.frames.as_slice(), &[frame]);
        assert_eq!(builder.next_packet_number(EncryptionLevel::OneRtt), Some(1));
    }

    #[test]
    fn frame_packet_builder_pads_small_payload_for_header_protection() {
        use crate::crypto::rustls::tests::one_rtt_test_keys;

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let mut builder = FramePacketBuilder::new(dst);
        let expected_dst_cid_len = builder.dst_cid_len();
        let mut packet = builder
            .build_one_rtt(&client_keys, &[Frame::HandshakeDone])
            .unwrap();

        let opened = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut packet,
            expected_dst_cid_len,
            None,
        )
        .unwrap();

        assert_eq!(opened.frames.first(), Some(&Frame::HandshakeDone));
        assert!(
            opened.frames[1..]
                .iter()
                .all(|frame| matches!(frame, Frame::Padding))
        );
    }

    #[test]
    fn empty_one_rtt_payload_is_a_protocol_violation() {
        assert_eq!(
            decode_frames(&[]).unwrap_err(),
            CodecError::Transport(TransportErrorCode::ProtocolViolation)
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn open_initial_respects_length_and_supports_coalesced_handshake() {
        use crate::crypto::rustls::tests::one_rtt_test_keys;

        let (client_keys, server_keys) = one_rtt_test_keys();
        let dcid = ConnectionId::from_slice(b"client-dcid").unwrap();
        let scid = ConnectionId::from_slice(b"server-scid").unwrap();
        let initial_keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();
        let client_initial = InitialPacketProtector::new(&initial_keys, Side::Client).unwrap();
        let server_initial = InitialPacketProtector::new(&initial_keys, Side::Server).unwrap();

        let mut builder = CryptoPacketBuilder::new(dcid, scid);
        let initial_frames = [CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 0,
            bytes: b"initial-crypto".to_vec(),
        }];
        let handshake_frames = [CryptoFrame {
            level: EncryptionLevel::Handshake,
            offset: 0,
            bytes: b"handshake-crypto".to_vec(),
        }];
        let initial_packet = builder
            .build_initial(&client_initial, &initial_frames)
            .unwrap();
        let handshake_packet = builder
            .build_handshake(&client_keys, &handshake_frames)
            .unwrap();

        // Coalesce Initial + Handshake into a single datagram (RFC 9000 §12.2).
        let mut datagram = initial_packet.clone();
        datagram.extend_from_slice(&handshake_packet);

        let opened_initial =
            CryptoPacketOpener::open_initial(&server_initial, &mut datagram, None).unwrap();
        assert_eq!(opened_initial.level, EncryptionLevel::Initial);
        // The Length field must bound consumption to the Initial packet alone.
        assert_eq!(opened_initial.consumed, initial_packet.len());
        assert_eq!(
            opened_initial.frames.as_slice(),
            &[Frame::Crypto {
                offset: crate::VarInt::ZERO,
                data: b"initial-crypto".to_vec(),
            }]
        );

        // The coalesced Handshake packet opens independently from the remainder.
        let opened_handshake = CryptoPacketOpener::open_handshake(
            &server_keys,
            &mut datagram[opened_initial.consumed..],
            None,
        )
        .unwrap();
        assert_eq!(opened_handshake.level, EncryptionLevel::Handshake);
        assert_eq!(
            opened_handshake.frames.as_slice(),
            &[Frame::Crypto {
                offset: crate::VarInt::ZERO,
                data: b"handshake-crypto".to_vec(),
            }]
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn handshake_frame_builder_roundtrips_transport_close() {
        use crate::crypto::rustls::tests::one_rtt_test_keys;

        let (client_keys, server_keys) = one_rtt_test_keys();
        let dcid = ConnectionId::from_slice(b"client-dcid").unwrap();
        let scid = ConnectionId::from_slice(b"server-scid").unwrap();
        let mut builder = CryptoPacketBuilder::new(dcid, scid);
        let frame = Frame::ConnectionClose {
            error_code: TransportErrorCode::ProtocolViolation,
            frame_type: crate::VarInt::ZERO,
            reason: b"forbidden handshake frame".to_vec(),
        };

        let mut packet = builder
            .build_handshake_frames(&client_keys, std::slice::from_ref(&frame))
            .unwrap();
        let opened = CryptoPacketOpener::open_handshake(&server_keys, &mut packet, None).unwrap();

        assert_eq!(opened.frames.as_slice(), &[frame]);
    }

    #[test]
    fn open_initial_rejects_length_overrunning_datagram() {
        let dcid = ConnectionId::from_slice(b"client-dcid").unwrap();
        let scid = ConnectionId::from_slice(b"server-scid").unwrap();
        let initial_keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();
        let client_initial = InitialPacketProtector::new(&initial_keys, Side::Client).unwrap();
        let server_initial = InitialPacketProtector::new(&initial_keys, Side::Server).unwrap();

        let mut builder = CryptoPacketBuilder::new(dcid, scid);
        let frames = [CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 0,
            bytes: b"initial-crypto-payload".to_vec(),
        }];
        let packet = builder.build_initial(&client_initial, &frames).unwrap();

        // Truncating the datagram makes the encoded Length overrun the buffer:
        // opening must fail cleanly rather than panic.
        let mut truncated = packet[..packet.len() - 5].to_vec();
        assert_eq!(
            CryptoPacketOpener::open_initial(&server_initial, &mut truncated, None).unwrap_err(),
            CodecError::PacketDiscard
        );
    }

    #[test]
    fn unauthenticated_initial_packet_is_a_silent_discard() {
        let dcid = ConnectionId::from_slice(b"client-dcid").unwrap();
        let scid = ConnectionId::from_slice(b"server-scid").unwrap();
        let initial_keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();
        let client_initial = InitialPacketProtector::new(&initial_keys, Side::Client).unwrap();
        let server_initial = InitialPacketProtector::new(&initial_keys, Side::Server).unwrap();
        let mut builder = CryptoPacketBuilder::new(dcid, scid);
        let frames = [CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 0,
            bytes: b"initial-crypto-payload".to_vec(),
        }];
        let mut packet = builder.build_initial(&client_initial, &frames).unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        assert_eq!(
            CryptoPacketOpener::open_initial(&server_initial, &mut packet, None).unwrap_err(),
            CodecError::PacketDiscard
        );
    }

    #[test]
    fn malformed_authenticated_initial_frame_is_not_a_silent_discard() {
        let dcid = ConnectionId::from_slice(b"client-dcid").unwrap();
        let scid = ConnectionId::from_slice(b"server-scid").unwrap();
        let initial_keys = InitialKeys::derive(QUIC_VERSION_1, &dcid).unwrap();
        let client_initial = InitialPacketProtector::new(&initial_keys, Side::Client).unwrap();
        let server_initial = InitialPacketProtector::new(&initial_keys, Side::Server).unwrap();
        let builder = CryptoPacketBuilder::new(dcid, scid);
        let malformed_close = [0x1d, 0x2a, 0x04, b'b', b'a'];
        let mut packet = client_initial
            .protect_initial_packet(
                builder.long_header(PacketType::Initial),
                0,
                &malformed_close,
            )
            .unwrap();

        let error =
            CryptoPacketOpener::open_initial(&server_initial, &mut packet, None).unwrap_err();

        assert_ne!(error, CodecError::PacketDiscard);
        assert_eq!(
            error.transport_code(),
            TransportErrorCode::FrameEncodingError
        );
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    #[test]
    fn unauthenticated_handshake_packet_is_a_silent_discard() {
        use crate::crypto::rustls::tests::one_rtt_test_keys;

        let (client_keys, server_keys) = one_rtt_test_keys();
        let dcid = ConnectionId::from_slice(b"client-dcid").unwrap();
        let scid = ConnectionId::from_slice(b"server-scid").unwrap();
        let mut builder = CryptoPacketBuilder::new(dcid, scid);
        let frames = [CryptoFrame {
            level: EncryptionLevel::Handshake,
            offset: 0,
            bytes: b"handshake-crypto-payload".to_vec(),
        }];
        let mut packet = builder.build_handshake(&client_keys, &frames).unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        assert_eq!(
            CryptoPacketOpener::open_handshake(&server_keys, &mut packet, None).unwrap_err(),
            CodecError::PacketDiscard
        );
    }

    #[test]
    fn handshake_packet_without_keys_is_a_silent_discard() {
        let mut packet = vec![0xc0; 64];

        assert_eq!(
            CryptoPacketOpener::open_handshake(&RustlsKeyStore::default(), &mut packet, None)
                .unwrap_err(),
            CodecError::PacketDiscard
        );
    }
}
