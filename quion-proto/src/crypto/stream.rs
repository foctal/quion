use std::collections::{BTreeMap, VecDeque};

use crate::{
    crypto::EncryptionLevel,
    error::{CodecError, Result},
    frame::Frame,
    transport_error::TransportErrorCode,
    varint::VarInt,
};

/// Maximum number of out-of-order CRYPTO bytes buffered per encryption level.
///
/// CRYPTO frames are exempt from QUIC flow control (RFC 9000 §7.5), so a peer
/// that sends CRYPTO frames at ever-increasing offsets without filling the gap
/// could otherwise force unbounded buffering. RFC 9000 §7.5 allows an endpoint
/// to bound the amount of buffered crypto data and close the connection with
/// `CRYPTO_BUFFER_EXCEEDED` when the limit is exceeded. The default is generous
/// enough for large certificate chains while keeping memory bounded.
pub const DEFAULT_MAX_CRYPTO_BUFFER: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoFrame {
    pub level: EncryptionLevel,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl CryptoFrame {
    pub fn into_frame(self) -> Result<Frame> {
        Ok(Frame::Crypto {
            offset: VarInt::new(self.offset)?,
            data: self.bytes,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CryptoSendBuffer {
    level: EncryptionLevel,
    next_offset: u64,
    pending: VecDeque<CryptoFrame>,
}

impl CryptoSendBuffer {
    pub const fn new(level: EncryptionLevel) -> Self {
        Self {
            level,
            next_offset: 0,
            pending: VecDeque::new(),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<CryptoFrame>> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let offset = self.next_offset;
        self.next_offset = self
            .next_offset
            .checked_add(bytes.len() as u64)
            .ok_or(CodecError::ValueOutOfBounds)?;
        let frame = CryptoFrame {
            level: self.level,
            offset,
            bytes: bytes.to_vec(),
        };
        self.pending.push_back(frame.clone());
        Ok(Some(frame))
    }

    pub fn poll_frame(&mut self, max_len: usize) -> Option<CryptoFrame> {
        if max_len == 0 {
            return None;
        }
        let mut frame = self.pending.pop_front()?;
        if frame.bytes.len() <= max_len {
            return Some(frame);
        }

        let rest = frame.bytes.split_off(max_len);
        let rest_offset = frame.offset + frame.bytes.len() as u64;
        self.pending.push_front(CryptoFrame {
            level: self.level,
            offset: rest_offset,
            bytes: rest,
        });
        Some(frame)
    }

    pub fn requeue_front(&mut self, mut frames: Vec<CryptoFrame>) {
        while let Some(frame) = frames.pop() {
            self.pending.push_front(frame);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.pending.iter().map(|frame| frame.bytes.len()).sum()
    }

    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }
}

impl Default for CryptoSendBuffer {
    fn default() -> Self {
        Self::new(EncryptionLevel::Initial)
    }
}

#[derive(Debug, Clone)]
pub struct CryptoRecvBuffer {
    level: EncryptionLevel,
    read_offset: u64,
    ranges: BTreeMap<u64, Vec<u8>>,
    max_buffer: u64,
}

impl CryptoRecvBuffer {
    pub const fn new(level: EncryptionLevel) -> Self {
        Self::with_max_buffer(level, DEFAULT_MAX_CRYPTO_BUFFER)
    }

    pub const fn with_max_buffer(level: EncryptionLevel, max_buffer: u64) -> Self {
        Self {
            level,
            read_offset: 0,
            ranges: BTreeMap::new(),
            max_buffer,
        }
    }

    pub fn set_max_buffer(&mut self, max_buffer: u64) {
        self.max_buffer = max_buffer;
    }

    pub fn insert(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(CodecError::ValueOutOfBounds)?;
        if end <= self.read_offset {
            return Ok(());
        }

        // RFC 9000 §7.5: bound buffered crypto data. Any byte beyond
        // `read_offset + max_buffer` would require buffering more than the
        // allowed window, so reject it with CRYPTO_BUFFER_EXCEEDED rather than
        // growing the buffer unboundedly for a stalled or malicious peer.
        let limit = self.read_offset.saturating_add(self.max_buffer);
        if end > limit {
            return Err(CodecError::Transport(
                TransportErrorCode::CryptoBufferExceeded,
            ));
        }

        let trim = self.read_offset.saturating_sub(offset) as usize;
        let mut start = offset + trim as u64;
        let mut data = bytes[trim..].to_vec();
        let mut merged_end = start + data.len() as u64;

        let overlapping: Vec<_> = self
            .ranges
            .range(..=merged_end)
            .filter_map(|(&existing_start, existing)| {
                let existing_end = existing_start + existing.len() as u64;
                if existing_end < start || existing_start > merged_end {
                    None
                } else {
                    Some((existing_start, existing.clone()))
                }
            })
            .collect();

        for (existing_start, existing) in overlapping {
            self.ranges.remove(&existing_start);
            let existing_end = existing_start + existing.len() as u64;
            let new_start = start.min(existing_start);
            let new_end = merged_end.max(existing_end);
            let mut merged = vec![0; (new_end - new_start) as usize];

            let data_offset = (start - new_start) as usize;
            merged[data_offset..data_offset + data.len()].copy_from_slice(&data);
            let existing_offset = (existing_start - new_start) as usize;
            merged[existing_offset..existing_offset + existing.len()].copy_from_slice(&existing);

            start = new_start;
            merged_end = new_end;
            data = merged;
        }

        self.ranges.insert(start, data);
        Ok(())
    }

    pub fn insert_frame(&mut self, frame: &Frame) -> Result<bool> {
        match frame {
            Frame::Crypto { offset, data } => {
                self.insert(offset.into_inner(), data)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn read_contiguous(&mut self, max_len: usize) -> Vec<u8> {
        if max_len == 0 {
            return Vec::new();
        }

        let Some(mut data) = self.ranges.remove(&self.read_offset) else {
            return Vec::new();
        };

        if data.len() > max_len {
            let rest = data.split_off(max_len);
            let rest_offset = self.read_offset + data.len() as u64;
            self.ranges.insert(rest_offset, rest);
        }

        self.read_offset += data.len() as u64;
        data
    }

    pub fn read_all_contiguous(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let chunk = self.read_contiguous(usize::MAX);
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        out
    }

    pub const fn read_offset(&self) -> u64 {
        self.read_offset
    }

    pub const fn level(&self) -> EncryptionLevel {
        self.level
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.ranges.values().map(Vec::len).sum()
    }
}

impl Default for CryptoRecvBuffer {
    fn default() -> Self {
        Self::new(EncryptionLevel::Initial)
    }
}

#[derive(Debug, Clone)]
pub struct CryptoSpace {
    pub level: EncryptionLevel,
    pub send: CryptoSendBuffer,
    pub recv: CryptoRecvBuffer,
}

impl CryptoSpace {
    pub fn new(level: EncryptionLevel) -> Self {
        Self {
            level,
            send: CryptoSendBuffer::new(level),
            recv: CryptoRecvBuffer::new(level),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CryptoStreams {
    initial: CryptoSpace,
    zero_rtt: CryptoSpace,
    handshake: CryptoSpace,
    one_rtt: CryptoSpace,
}

impl CryptoStreams {
    pub fn new() -> Self {
        Self {
            initial: CryptoSpace::new(EncryptionLevel::Initial),
            zero_rtt: CryptoSpace::new(EncryptionLevel::ZeroRtt),
            handshake: CryptoSpace::new(EncryptionLevel::Handshake),
            one_rtt: CryptoSpace::new(EncryptionLevel::OneRtt),
        }
    }

    pub fn space(&self, level: EncryptionLevel) -> &CryptoSpace {
        match level {
            EncryptionLevel::Initial => &self.initial,
            EncryptionLevel::ZeroRtt => &self.zero_rtt,
            EncryptionLevel::Handshake => &self.handshake,
            EncryptionLevel::OneRtt => &self.one_rtt,
        }
    }

    pub fn space_mut(&mut self, level: EncryptionLevel) -> &mut CryptoSpace {
        match level {
            EncryptionLevel::Initial => &mut self.initial,
            EncryptionLevel::ZeroRtt => &mut self.zero_rtt,
            EncryptionLevel::Handshake => &mut self.handshake,
            EncryptionLevel::OneRtt => &mut self.one_rtt,
        }
    }

    pub fn set_max_recv_buffered_data(&mut self, max_buffer: u64) {
        for level in [
            EncryptionLevel::Initial,
            EncryptionLevel::ZeroRtt,
            EncryptionLevel::Handshake,
            EncryptionLevel::OneRtt,
        ] {
            self.space_mut(level).recv.set_max_buffer(max_buffer);
        }
    }

    pub fn push_tls(
        &mut self,
        level: EncryptionLevel,
        bytes: &[u8],
    ) -> Result<Option<CryptoFrame>> {
        self.space_mut(level).send.push(bytes)
    }

    pub fn poll_frame(&mut self, level: EncryptionLevel, max_len: usize) -> Option<CryptoFrame> {
        self.space_mut(level).send.poll_frame(max_len)
    }

    pub fn requeue_frames(
        &mut self,
        level: EncryptionLevel,
        frames: Vec<CryptoFrame>,
    ) -> Result<()> {
        if frames.iter().any(|frame| frame.level != level) {
            return Err(CodecError::MalformedFrame);
        }
        self.space_mut(level).send.requeue_front(frames);
        Ok(())
    }

    pub fn insert_frame(
        &mut self,
        level: EncryptionLevel,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        self.space_mut(level).recv.insert(offset, bytes)
    }

    pub fn read_tls(&mut self, level: EncryptionLevel, max_len: usize) -> Vec<u8> {
        self.space_mut(level).recv.read_contiguous(max_len)
    }

    pub fn discard_space(&mut self, level: EncryptionLevel) {
        *self.space_mut(level) = CryptoSpace::new(level);
    }

    pub fn send_buffered_bytes(&self) -> usize {
        [
            EncryptionLevel::Initial,
            EncryptionLevel::ZeroRtt,
            EncryptionLevel::Handshake,
            EncryptionLevel::OneRtt,
        ]
        .into_iter()
        .map(|level| self.space(level).send.buffered_bytes())
        .sum()
    }

    pub fn recv_buffered_bytes(&self) -> usize {
        [
            EncryptionLevel::Initial,
            EncryptionLevel::ZeroRtt,
            EncryptionLevel::Handshake,
            EncryptionLevel::OneRtt,
        ]
        .into_iter()
        .map(|level| self.space(level).recv.buffered_bytes())
        .sum()
    }
}

impl Default for CryptoStreams {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_buffer_splits_crypto_frames() {
        let mut send = CryptoSendBuffer::default();
        send.push(b"abcdef").unwrap();

        let first = send.poll_frame(2).unwrap();
        let second = send.poll_frame(3).unwrap();
        let third = send.poll_frame(10).unwrap();

        assert_eq!(first.offset, 0);
        assert_eq!(first.level, EncryptionLevel::Initial);
        assert_eq!(first.bytes, b"ab");
        assert_eq!(second.offset, 2);
        assert_eq!(second.bytes, b"cde");
        assert_eq!(third.offset, 5);
        assert_eq!(third.bytes, b"f");
        assert!(send.is_empty());
    }

    #[test]
    fn send_buffer_requeues_retransmission_frames_at_front() {
        let mut send = CryptoSendBuffer::default();
        send.push(b"fresh").unwrap();
        send.requeue_front(vec![CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 9,
            bytes: b"lost".to_vec(),
        }]);

        let first = send.poll_frame(64).unwrap();
        let second = send.poll_frame(64).unwrap();

        assert_eq!(first.offset, 9);
        assert_eq!(first.bytes, b"lost");
        assert_eq!(second.offset, 0);
        assert_eq!(second.bytes, b"fresh");
    }

    #[test]
    fn recv_buffer_delivers_reordered_crypto_data() {
        let mut recv = CryptoRecvBuffer::default();
        recv.insert(5, b" world").unwrap();
        assert!(recv.read_all_contiguous().is_empty());

        recv.insert(0, b"hello").unwrap();
        assert_eq!(recv.read_all_contiguous(), b"hello world");
        assert_eq!(recv.read_offset(), 11);
    }

    #[test]
    fn recv_buffer_trims_duplicate_prefix() {
        let mut recv = CryptoRecvBuffer::default();
        recv.insert(0, b"hello").unwrap();
        assert_eq!(recv.read_contiguous(5), b"hello");

        recv.insert(3, b"lo world").unwrap();
        assert_eq!(recv.read_all_contiguous(), b" world");
        assert_eq!(recv.read_offset(), 11);
    }

    #[test]
    fn recv_buffer_merges_overlapping_ranges() {
        let mut recv = CryptoRecvBuffer::default();
        recv.insert(3, b"def").unwrap();
        recv.insert(0, b"abcde").unwrap();

        assert_eq!(recv.read_all_contiguous(), b"abcdef");
        assert!(recv.is_empty());
    }

    #[test]
    fn recv_buffer_rejects_data_beyond_buffer_limit() {
        let mut recv = CryptoRecvBuffer::with_max_buffer(EncryptionLevel::Initial, 16);
        // A gap that stays within the window is buffered.
        recv.insert(8, b"abcd").unwrap();
        // Data whose end exceeds read_offset + max_buffer is rejected.
        let err = recv.insert(16, b"toofar").unwrap_err();
        assert_eq!(
            err,
            CodecError::Transport(TransportErrorCode::CryptoBufferExceeded)
        );
    }

    #[test]
    fn recv_buffer_limit_advances_with_reads() {
        let mut recv = CryptoRecvBuffer::with_max_buffer(EncryptionLevel::Initial, 16);
        recv.insert(0, b"0123456789").unwrap();
        assert_eq!(recv.read_contiguous(10).len(), 10);
        // After reading, the window slides forward so higher offsets fit.
        recv.insert(20, b"abcd").unwrap();
        assert_eq!(recv.read_offset(), 10);
    }

    #[test]
    fn crypto_frame_converts_to_wire_frame() {
        let frame = CryptoFrame {
            level: EncryptionLevel::Initial,
            offset: 9,
            bytes: b"tls".to_vec(),
        }
        .into_frame()
        .unwrap();

        assert_eq!(
            frame,
            Frame::Crypto {
                offset: VarInt::from_u32(9),
                data: b"tls".to_vec()
            }
        );
    }

    #[test]
    fn crypto_streams_keep_levels_independent() {
        let mut streams = CryptoStreams::new();
        streams
            .push_tls(EncryptionLevel::Initial, b"initial")
            .unwrap();
        streams
            .push_tls(EncryptionLevel::Handshake, b"handshake")
            .unwrap();

        let initial = streams.poll_frame(EncryptionLevel::Initial, 64).unwrap();
        let handshake = streams.poll_frame(EncryptionLevel::Handshake, 64).unwrap();

        assert_eq!(initial.level, EncryptionLevel::Initial);
        assert_eq!(initial.offset, 0);
        assert_eq!(initial.bytes, b"initial");
        assert_eq!(handshake.level, EncryptionLevel::Handshake);
        assert_eq!(handshake.offset, 0);
        assert_eq!(handshake.bytes, b"handshake");
    }

    #[test]
    fn crypto_streams_read_tls_by_level() {
        let mut streams = CryptoStreams::new();
        streams
            .insert_frame(EncryptionLevel::Handshake, 4, b"shake")
            .unwrap();
        streams
            .insert_frame(EncryptionLevel::Handshake, 0, b"hand")
            .unwrap();
        streams
            .insert_frame(EncryptionLevel::Initial, 0, b"init")
            .unwrap();

        assert_eq!(streams.read_tls(EncryptionLevel::Initial, 64), b"init");
        assert_eq!(
            streams.read_tls(EncryptionLevel::Handshake, 64),
            b"handshake"
        );
    }

    #[test]
    fn crypto_streams_discard_space_clears_send_and_recv_buffers() {
        let mut streams = CryptoStreams::new();
        streams
            .push_tls(EncryptionLevel::Handshake, b"handshake")
            .unwrap();
        streams
            .insert_frame(EncryptionLevel::Handshake, 0, b"peer")
            .unwrap();
        streams.push_tls(EncryptionLevel::OneRtt, b"app").unwrap();

        streams.discard_space(EncryptionLevel::Handshake);

        assert!(streams.poll_frame(EncryptionLevel::Handshake, 64).is_none());
        assert!(streams.read_tls(EncryptionLevel::Handshake, 64).is_empty());
        assert_eq!(
            streams
                .poll_frame(EncryptionLevel::OneRtt, 64)
                .unwrap()
                .bytes,
            b"app"
        );
    }

    #[test]
    fn crypto_streams_apply_configured_receive_limit_to_every_space() {
        let mut streams = CryptoStreams::new();
        streams.set_max_recv_buffered_data(4);

        for level in [
            EncryptionLevel::Initial,
            EncryptionLevel::ZeroRtt,
            EncryptionLevel::Handshake,
            EncryptionLevel::OneRtt,
        ] {
            assert!(streams.insert_frame(level, 0, b"1234").is_ok());
            assert_eq!(
                streams.insert_frame(level, 4, b"5"),
                Err(CodecError::Transport(
                    TransportErrorCode::CryptoBufferExceeded
                ))
            );
        }
    }
}
