use std::collections::{BTreeMap, VecDeque};

use bytes::{Bytes, BytesMut};
use web_time::{Duration, Instant};

use crate::{
    error::{CodecError, Result},
    frame::Frame,
    ranges::RangeSet,
    transport_error::TransportErrorCode,
    varint::VarInt,
};

pub const DEFAULT_MAX_RECV_BUFFERED_STREAM_DATA: usize = 16 * 1024 * 1024;
const MIN_SEND_BUFFER_CHUNK_SIZE: usize = 256;
const SEND_BUFFER_CHUNK_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub VarInt);

impl StreamId {
    pub const fn initiator(self) -> StreamInitiator {
        if self.0.into_inner() & 0x01 == 0 {
            StreamInitiator::Client
        } else {
            StreamInitiator::Server
        }
    }

    pub const fn is_unidirectional(self) -> bool {
        self.0.into_inner() & 0x02 != 0
    }

    pub const fn ordinal(self) -> u64 {
        self.0.into_inner() >> 2
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInitiator {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamLimitKind {
    Bidi,
    Uni,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub offset: u64,
    pub bytes: Bytes,
    pub fin: bool,
}

impl Chunk {
    pub fn into_stream_frame(self, stream_id: StreamId) -> Result<Frame> {
        Ok(Frame::Stream {
            stream_id: stream_id.0,
            offset: VarInt::new(self.offset)?,
            fin: self.fin,
            data: self.bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFlowController {
    max_data: u64,
    consumed: u64,
}

impl SendFlowController {
    pub const fn new(max_data: u64) -> Self {
        Self {
            max_data,
            consumed: 0,
        }
    }

    pub const fn max_data(&self) -> u64 {
        self.max_data
    }

    pub const fn consumed(&self) -> u64 {
        self.consumed
    }

    pub const fn available(&self) -> u64 {
        self.max_data.saturating_sub(self.consumed)
    }

    pub fn increase_limit(&mut self, max_data: u64) {
        self.max_data = self.max_data.max(max_data);
    }

    pub(crate) fn reset_limit(&mut self, max_data: u64) {
        self.max_data = max_data;
        self.consumed = 0;
    }

    fn consume(&mut self, amount: u64) -> bool {
        if amount > self.available() {
            return false;
        }
        self.consumed += amount;
        true
    }
}

impl Default for SendFlowController {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SendBuffer {
    chunks: VecDeque<BytesMut>,
    queued_len: usize,
    next_offset: u64,
    final_offset: Option<u64>,
    fin_sent: bool,
}

impl SendBuffer {
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        let queued_end = self
            .next_offset
            .checked_add(self.queued_len as u64)
            .and_then(|offset| offset.checked_add(bytes.len() as u64))
            .ok_or(CodecError::ValueOutOfBounds)?;
        if queued_end > VarInt::MAX.into_inner() {
            return Err(CodecError::ValueOutOfBounds);
        }
        if self.final_offset.is_some() {
            return Err(CodecError::Transport(TransportErrorCode::StreamStateError));
        }

        let mut remaining = bytes;
        if self.chunks.capacity() == 0 && !remaining.is_empty() {
            // Most request streams need one chunk. VecDeque's default first
            // growth reserves four descriptors, which then remain live for
            // the lifetime of an otherwise drained stream.
            self.chunks
                .reserve_exact(remaining.len().div_ceil(SEND_BUFFER_CHUNK_SIZE));
        }
        while !remaining.is_empty() {
            let available = self.chunks.back().map_or(0, |chunk| {
                SEND_BUFFER_CHUNK_SIZE.saturating_sub(chunk.len())
            });
            if available == 0 {
                let capacity = if remaining.len() >= SEND_BUFFER_CHUNK_SIZE {
                    SEND_BUFFER_CHUNK_SIZE
                } else {
                    remaining
                        .len()
                        .max(MIN_SEND_BUFFER_CHUNK_SIZE)
                        .next_power_of_two()
                        .min(SEND_BUFFER_CHUNK_SIZE)
                };
                self.chunks.push_back(BytesMut::with_capacity(capacity));
                continue;
            }
            let take = available.min(remaining.len());
            if let Some(chunk) = self.chunks.back_mut() {
                let required = chunk.len() + take;
                if chunk.capacity() < required {
                    let target = chunk
                        .capacity()
                        .saturating_mul(2)
                        .max(required)
                        .min(SEND_BUFFER_CHUNK_SIZE);
                    chunk.reserve(target - chunk.len());
                }
                chunk.extend_from_slice(&remaining[..take]);
            }
            remaining = &remaining[take..];
        }
        self.queued_len += bytes.len();
        Ok(bytes.len())
    }

    pub fn finish(&mut self) {
        self.final_offset = Some(self.next_offset + self.queued_len as u64);
    }

    pub(crate) fn restore_frame(&mut self, offset: u64, bytes: Bytes) -> bool {
        let Some(end) = offset.checked_add(bytes.len() as u64) else {
            return false;
        };
        if end != self.next_offset {
            return false;
        }
        let bytes = match bytes.try_into_mut() {
            Ok(bytes) => bytes,
            Err(bytes) => BytesMut::from(bytes.as_ref()),
        };
        self.queued_len = self.queued_len.saturating_add(bytes.len());
        self.next_offset = offset;
        self.fin_sent = false;
        if !bytes.is_empty() {
            self.chunks.push_front(bytes);
        }
        true
    }

    pub fn poll_frame(
        &mut self,
        flow: &mut SendFlowController,
        max_frame_data: usize,
    ) -> Option<Chunk> {
        self.poll_frame_with_connection_flow(flow, None, max_frame_data)
    }

    pub fn poll_frame_with_connection_flow(
        &mut self,
        stream_flow: &mut SendFlowController,
        connection_flow: Option<&mut SendFlowController>,
        max_frame_data: usize,
    ) -> Option<Chunk> {
        self.poll_frame_with_connection_flow_reusing(
            stream_flow,
            connection_flow,
            max_frame_data,
            Vec::new(),
        )
    }

    pub(crate) fn poll_frame_with_connection_flow_reusing(
        &mut self,
        stream_flow: &mut SendFlowController,
        mut connection_flow: Option<&mut SendFlowController>,
        max_frame_data: usize,
        mut bytes: Vec<u8>,
    ) -> Option<Chunk> {
        let available = stream_flow.available();
        let available = connection_flow
            .as_ref()
            .map_or(available, |flow| available.min(flow.available()));
        let max_frame_data = max_frame_data.min(usize::try_from(available).ok()?);
        if max_frame_data == 0 {
            return self.poll_fin_only(stream_flow);
        }

        let take = self.queued_len.min(max_frame_data);
        if take == 0 {
            return self.poll_fin_only(stream_flow);
        }

        let offset = self.next_offset;
        let frame_bytes = if self.chunks.front()?.len() >= take {
            let chunk = self.chunks.front_mut()?;
            let frame = chunk.split_to(take).freeze();
            if chunk.is_empty() {
                self.chunks.pop_front();
            }
            frame
        } else {
            bytes.clear();
            if bytes.capacity() < take {
                bytes.reserve(take - bytes.capacity());
            }
            while bytes.len() < take {
                let chunk = self.chunks.front_mut()?;
                let copy = chunk.len().min(take - bytes.len());
                bytes.extend_from_slice(&chunk.split_to(copy));
                if chunk.is_empty() {
                    self.chunks.pop_front();
                }
            }
            bytes.into()
        };
        self.queued_len -= take;
        self.next_offset += frame_bytes.len() as u64;
        stream_flow.consume(frame_bytes.len() as u64);
        if let Some(flow) = connection_flow.as_mut() {
            flow.consume(frame_bytes.len() as u64);
        }
        let fin = self.final_offset == Some(self.next_offset) && self.queued_len == 0;
        self.fin_sent |= fin;
        Some(Chunk {
            offset,
            bytes: frame_bytes,
            fin,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.queued_len == 0
    }

    pub const fn queued_len(&self) -> usize {
        self.queued_len
    }

    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub const fn final_offset(&self) -> Option<u64> {
        self.final_offset
    }

    pub fn reset_final_size(&self) -> u64 {
        self.final_offset
            .unwrap_or(self.next_offset + self.queued_len as u64)
    }

    /// Keeps only unsent bytes required by a reliable reset and returns the
    /// number of discarded bytes.
    pub fn prepare_reliable_reset(&mut self, reliable_size: u64) -> Result<(u64, usize)> {
        let final_size = self.reset_final_size();
        if reliable_size > final_size {
            return Err(CodecError::ValueOutOfBounds);
        }
        self.final_offset = Some(final_size);
        let keep = reliable_size
            .saturating_sub(self.next_offset)
            .min(self.queued_len as u64) as usize;
        let discarded = self.queued_len.saturating_sub(keep);
        self.truncate(keep);
        Ok((final_size, discarded))
    }

    fn truncate(&mut self, keep: usize) {
        if keep >= self.queued_len {
            return;
        }
        if keep == 0 {
            self.chunks.clear();
            self.queued_len = 0;
            return;
        }

        let mut remaining = keep;
        let mut retained = VecDeque::new();
        while remaining > 0 {
            let Some(mut chunk) = self.chunks.pop_front() else {
                debug_assert_eq!(remaining, 0);
                break;
            };
            let take = chunk.len().min(remaining);
            chunk.truncate(take);
            retained.push_back(chunk);
            remaining -= take;
        }
        self.chunks = retained;
        self.queued_len = keep;
    }

    fn poll_fin_only(&mut self, _flow: &mut SendFlowController) -> Option<Chunk> {
        if self.fin_sent || self.final_offset != Some(self.next_offset) {
            return None;
        }
        self.fin_sent = true;
        Some(Chunk {
            offset: self.next_offset,
            bytes: Bytes::new(),
            fin: true,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvAssembler {
    contiguous_chunks: VecDeque<(u64, Bytes)>,
    sparse_chunks: BTreeMap<u64, Bytes>,
    delivered: RangeSet,
    final_offset: Option<u64>,
    buffered_bytes: usize,
    max_buffered_bytes: usize,
}

impl RecvAssembler {
    pub const fn new(max_buffered_bytes: usize) -> Self {
        Self {
            contiguous_chunks: VecDeque::new(),
            sparse_chunks: BTreeMap::new(),
            delivered: RangeSet::new(),
            final_offset: None,
            buffered_bytes: 0,
            max_buffered_bytes,
        }
    }

    pub fn insert(&mut self, offset: u64, bytes: impl Into<Bytes>, fin: bool) -> Result<u64> {
        self.insert_with_additional_limit(offset, bytes.into(), fin, usize::MAX)
    }

    fn insert_with_additional_limit(
        &mut self,
        offset: u64,
        bytes: Bytes,
        fin: bool,
        max_additional_buffered_bytes: usize,
    ) -> Result<u64> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(CodecError::ValueOutOfBounds)?;
        if end > VarInt::MAX.into_inner() {
            return Err(CodecError::ValueOutOfBounds);
        }
        if fin && self.final_offset.is_some_and(|existing| existing != end) {
            return Err(CodecError::Transport(TransportErrorCode::FinalSizeError));
        }
        let prospective_final_offset = if fin { Some(end) } else { self.final_offset };
        if prospective_final_offset.is_some_and(|final_offset| end > final_offset) {
            return Err(CodecError::Transport(TransportErrorCode::FinalSizeError));
        }
        if let Some(final_offset) = prospective_final_offset
            && (self
                .contiguous_chunks
                .iter()
                .any(|(start, chunk)| start.saturating_add(chunk.len() as u64) > final_offset)
                || self
                    .sparse_chunks
                    .iter()
                    .any(|(&start, chunk)| start.saturating_add(chunk.len() as u64) > final_offset))
        {
            return Err(CodecError::Transport(TransportErrorCode::FinalSizeError));
        }

        if !bytes.is_empty() {
            let overlaps_contiguous =
                self.contiguous_chunks
                    .front()
                    .is_some_and(|(first_start, _)| {
                        let contiguous_end = self
                            .contiguous_chunks
                            .back()
                            .map_or(*first_start, |(last_start, last)| {
                                last_start.saturating_add(last.len() as u64)
                            });
                        offset < contiguous_end && *first_start < end
                    });
            let overlaps_previous = self
                .sparse_chunks
                .range(..end)
                .next_back()
                .is_some_and(|(&start, chunk)| start.saturating_add(chunk.len() as u64) > offset);
            let overlaps_next = self
                .sparse_chunks
                .range(offset..)
                .next()
                .is_some_and(|(&start, _)| start < end);
            let overlaps_delivered = self
                .delivered
                .iter()
                .any(|(start, delivered_end)| start < end && offset < delivered_end);
            if !overlaps_contiguous && !overlaps_previous && !overlaps_next && !overlaps_delivered {
                let len = bytes.len();
                if len > max_additional_buffered_bytes
                    || self
                        .buffered_bytes
                        .checked_add(len)
                        .is_none_or(|buffered| buffered > self.max_buffered_bytes)
                {
                    return Err(CodecError::Transport(TransportErrorCode::FlowControlError));
                }
                self.final_offset = prospective_final_offset;
                self.buffered_bytes += len;
                self.insert_chunk(offset, bytes);
                return Ok(len as u64);
            }
        }

        let mut new_bytes = 0;
        let fragments = if bytes.is_empty() {
            Vec::new()
        } else {
            let fragments = self.non_duplicate_fragments(offset, bytes)?;
            let new_buffered_bytes = fragments
                .iter()
                .map(|(_, fragment)| fragment.len())
                .try_fold(0usize, usize::checked_add)
                .ok_or(CodecError::ValueOutOfBounds)?;
            if new_buffered_bytes > max_additional_buffered_bytes
                || self
                    .buffered_bytes
                    .checked_add(new_buffered_bytes)
                    .is_none_or(|buffered| buffered > self.max_buffered_bytes)
            {
                return Err(CodecError::Transport(TransportErrorCode::FlowControlError));
            }
            fragments
        };

        self.final_offset = prospective_final_offset;
        for (start, fragment) in fragments {
            new_bytes += fragment.len() as u64;
            self.buffered_bytes += fragment.len();
            self.insert_chunk(start, fragment);
        }
        Ok(new_bytes)
    }

    pub fn read_ordered(&mut self, offset: &mut u64, max: usize) -> Option<Chunk> {
        if max == 0 {
            return None;
        }
        let old_offset = *offset;
        let mut out = self.remove_chunk(*offset)?;
        if out.len() > max {
            let tail = out.split_off(max);
            self.insert_chunk(old_offset + max as u64, tail);
        }
        *offset += out.len() as u64;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(out.len());
        if out.is_empty() {
            return None;
        }
        self.delivered.insert(old_offset, *offset);
        let fin = self.final_offset == Some(*offset);
        Some(Chunk {
            offset: old_offset,
            bytes: out,
            fin,
        })
    }

    pub fn read_unordered(&mut self, max: usize) -> Option<Chunk> {
        let contiguous_offset = self.contiguous_chunks.front().map(|(offset, _)| *offset);
        let sparse_offset = self
            .sparse_chunks
            .first_key_value()
            .map(|(&offset, _)| offset);
        let offset = match (contiguous_offset, sparse_offset) {
            (Some(contiguous), Some(sparse)) => contiguous.min(sparse),
            (Some(offset), None) | (None, Some(offset)) => offset,
            (None, None) => return None,
        };
        let mut bytes = self.remove_chunk(offset)?;
        let take = bytes.len().min(max);
        let fin = self.final_offset == Some(offset + take as u64);
        self.buffered_bytes = self.buffered_bytes.saturating_sub(take);
        if take < bytes.len() {
            let tail = bytes.split_off(take);
            self.insert_chunk(offset + take as u64, tail);
        }
        self.delivered.insert(offset, offset + take as u64);
        Some(Chunk { offset, bytes, fin })
    }

    pub const fn final_offset(&self) -> Option<u64> {
        self.final_offset
    }

    pub const fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    fn discard_buffered(&mut self) -> usize {
        let discarded = self.buffered_bytes;
        self.buffered_bytes = 0;
        self.contiguous_chunks.clear();
        self.sparse_chunks.clear();
        discarded
    }

    fn discard_after(&mut self, end: u64) {
        for (start, bytes) in &mut self.contiguous_chunks {
            bytes.truncate(end.saturating_sub(*start).min(bytes.len() as u64) as usize);
        }
        self.contiguous_chunks
            .retain(|(_, bytes)| !bytes.is_empty());
        self.sparse_chunks.retain(|start, bytes| {
            bytes.truncate(end.saturating_sub(*start).min(bytes.len() as u64) as usize);
            !bytes.is_empty()
        });
        self.buffered_bytes = self
            .contiguous_chunks
            .iter()
            .map(|(_, bytes)| bytes.len())
            .sum::<usize>()
            + self.sparse_chunks.values().map(Bytes::len).sum::<usize>();
    }

    pub fn set_final_offset(&mut self, end: u64) -> Result<()> {
        match self.final_offset {
            Some(existing) if existing != end => {
                Err(CodecError::Transport(TransportErrorCode::FinalSizeError))
            }
            _ => {
                self.final_offset = Some(end);
                Ok(())
            }
        }
    }

    fn non_duplicate_fragments(&self, offset: u64, bytes: Bytes) -> Result<Vec<(u64, Bytes)>> {
        let mut fragments = vec![(offset, bytes)];
        for (delivered_start, delivered_end) in self.delivered.iter() {
            fragments = fragments
                .into_iter()
                .flat_map(|(fragment_start, fragment)| {
                    trim_known_overlap(fragment_start, fragment, delivered_start, delivered_end)
                })
                .collect();
            if fragments.is_empty() {
                return Ok(fragments);
            }
        }
        for (existing_start, existing) in self
            .contiguous_chunks
            .iter()
            .map(|(start, bytes)| (*start, bytes))
            .chain(
                self.sparse_chunks
                    .iter()
                    .map(|(&start, bytes)| (start, bytes)),
            )
        {
            let existing_end = existing_start + existing.len() as u64;
            fragments = fragments
                .into_iter()
                .map(|(fragment_start, fragment)| {
                    trim_existing_overlap(
                        fragment_start,
                        fragment,
                        existing_start,
                        existing_end,
                        existing,
                    )
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect();
            if fragments.is_empty() {
                break;
            }
        }
        Ok(fragments)
    }

    fn insert_chunk(&mut self, offset: u64, bytes: Bytes) {
        if self.contiguous_chunks.is_empty() {
            // Keep one-packet streams small; larger receive queues retain
            // amortized geometric growth after their first chunk.
            if self.contiguous_chunks.capacity() == 0 {
                self.contiguous_chunks.reserve_exact(1);
            }
            self.contiguous_chunks.push_back((offset, bytes));
            self.absorb_adjacent_sparse_chunks();
            return;
        }

        let contiguous_start = self
            .contiguous_chunks
            .front()
            .map_or(offset, |(start, _)| *start);
        let contiguous_end = self
            .contiguous_chunks
            .back()
            .map_or(contiguous_start, |(start, chunk)| {
                start.saturating_add(chunk.len() as u64)
            });
        let end = offset.saturating_add(bytes.len() as u64);
        if offset == contiguous_end {
            self.contiguous_chunks.push_back((offset, bytes));
        } else if end == contiguous_start {
            self.contiguous_chunks.push_front((offset, bytes));
        } else {
            self.sparse_chunks.insert(offset, bytes);
        }
        self.absorb_adjacent_sparse_chunks();
    }

    fn remove_chunk(&mut self, offset: u64) -> Option<Bytes> {
        if self
            .contiguous_chunks
            .front()
            .is_some_and(|(start, _)| *start == offset)
        {
            let (_, bytes) = self.contiguous_chunks.pop_front()?;
            if self.contiguous_chunks.is_empty() {
                self.promote_first_sparse_chunk();
            }
            return Some(bytes);
        }
        self.sparse_chunks.remove(&offset)
    }

    fn promote_first_sparse_chunk(&mut self) {
        let offset = self
            .sparse_chunks
            .first_key_value()
            .map(|(&offset, _)| offset);
        if let Some(offset) = offset
            && let Some(bytes) = self.sparse_chunks.remove(&offset)
        {
            self.contiguous_chunks.push_back((offset, bytes));
            self.absorb_adjacent_sparse_chunks();
        }
    }

    fn absorb_adjacent_sparse_chunks(&mut self) {
        loop {
            let Some(front_start) = self.contiguous_chunks.front().map(|(start, _)| *start) else {
                return;
            };
            let previous = self
                .sparse_chunks
                .range(..front_start)
                .next_back()
                .map(|(&start, chunk)| (start, start.saturating_add(chunk.len() as u64)));
            let Some((previous_start, _)) = previous.filter(|(_, end)| *end == front_start) else {
                break;
            };
            let bytes = self
                .sparse_chunks
                .remove(&previous_start)
                .expect("adjacent sparse chunk is present");
            self.contiguous_chunks.push_front((previous_start, bytes));
        }

        loop {
            let Some(contiguous_end) = self
                .contiguous_chunks
                .back()
                .map(|(start, chunk)| start.saturating_add(chunk.len() as u64))
            else {
                return;
            };
            let Some(bytes) = self.sparse_chunks.remove(&contiguous_end) else {
                break;
            };
            self.contiguous_chunks.push_back((contiguous_end, bytes));
        }
    }
}

impl Default for RecvAssembler {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RECV_BUFFERED_STREAM_DATA)
    }
}

fn trim_known_overlap(
    fragment_start: u64,
    fragment: Bytes,
    existing_start: u64,
    existing_end: u64,
) -> Vec<(u64, Bytes)> {
    let fragment_end = fragment_start + fragment.len() as u64;
    if fragment_end <= existing_start || existing_end <= fragment_start {
        return vec![(fragment_start, fragment)];
    }

    let overlap_start = fragment_start.max(existing_start);
    let overlap_end = fragment_end.min(existing_end);
    let before = (fragment_start < overlap_start).then(|| {
        let len = (overlap_start - fragment_start) as usize;
        (fragment_start, fragment.slice(..len))
    });
    let after = (overlap_end < fragment_end).then(|| {
        let start = (overlap_end - fragment_start) as usize;
        (overlap_end, fragment.slice(start..))
    });
    before.into_iter().chain(after).collect()
}

fn trim_existing_overlap(
    fragment_start: u64,
    fragment: Bytes,
    existing_start: u64,
    existing_end: u64,
    existing: &[u8],
) -> Result<Vec<(u64, Bytes)>> {
    let fragment_end = fragment_start + fragment.len() as u64;
    if fragment_end <= existing_start || existing_end <= fragment_start {
        return Ok(vec![(fragment_start, fragment)]);
    }

    let overlap_start = fragment_start.max(existing_start);
    let overlap_end = fragment_end.min(existing_end);
    let fragment_overlap = byte_range(fragment_start, overlap_start, overlap_end);
    let existing_overlap = byte_range(existing_start, overlap_start, overlap_end);
    if fragment[fragment_overlap.clone()] != existing[existing_overlap] {
        return Err(CodecError::Transport(TransportErrorCode::StreamStateError));
    }

    let before = (fragment_start < overlap_start).then(|| {
        let len = (overlap_start - fragment_start) as usize;
        (fragment_start, fragment.slice(..len))
    });
    let after = (overlap_end < fragment_end).then(|| {
        let start = (overlap_end - fragment_start) as usize;
        (overlap_end, fragment.slice(start..))
    });
    Ok(before.into_iter().chain(after).collect())
}

fn byte_range(base: u64, start: u64, end: u64) -> core::ops::Range<usize> {
    (start - base) as usize..(end - base) as usize
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvFlowController {
    max_data: u64,
    advertised_max_data: u64,
    received: u64,
    window: u64,
    max_window: u64,
    released_since_tune: u64,
    last_tune: Option<Instant>,
}

impl RecvFlowController {
    pub const fn new(max_data: u64) -> Self {
        Self {
            max_data,
            advertised_max_data: max_data,
            received: 0,
            window: max_data,
            max_window: max_data,
            released_since_tune: 0,
            last_tune: None,
        }
    }

    pub const fn received(&self) -> u64 {
        self.received
    }

    pub const fn max_data(&self) -> u64 {
        self.max_data
    }

    pub const fn window(&self) -> u64 {
        self.window
    }

    pub(crate) fn validate_additional(&self, additional: u64) -> Result<()> {
        let end = self
            .received
            .checked_add(additional)
            .ok_or(CodecError::ValueOutOfBounds)?;
        if end > self.max_data {
            return Err(CodecError::Transport(TransportErrorCode::FlowControlError));
        }
        Ok(())
    }

    pub(crate) fn validate_end(&self, offset: u64, len: usize) -> Result<()> {
        let end = offset
            .checked_add(len as u64)
            .ok_or(CodecError::ValueOutOfBounds)?;
        self.validate_additional(end.saturating_sub(self.received))
    }

    pub(crate) fn add_received(&mut self, additional: u64) -> Result<()> {
        self.validate_additional(additional)?;
        self.received = self
            .received
            .checked_add(additional)
            .ok_or(CodecError::ValueOutOfBounds)?;
        Ok(())
    }

    pub fn validate_frame(&mut self, offset: u64, len: usize) -> Result<()> {
        let end = offset
            .checked_add(len as u64)
            .ok_or(CodecError::ValueOutOfBounds)?;
        self.add_received(end.saturating_sub(self.received))?;
        Ok(())
    }

    pub fn increase_limit(&mut self, max_data: u64) {
        self.max_data = self.max_data.max(max_data);
    }

    pub fn set_limit(&mut self, max_data: u64) {
        self.max_data = max_data.max(self.received);
        self.advertised_max_data = self.max_data;
        self.window = self.max_data.saturating_sub(self.received);
        self.max_window = self.max_window.max(self.window);
    }

    pub fn set_max_window(&mut self, max_window: u64) {
        self.max_window = max_window.max(self.window);
    }

    pub fn release(&mut self, amount: u64, now: Instant, smoothed_rtt: Duration) -> Option<u64> {
        if amount == 0 {
            return None;
        }
        self.max_data = self.max_data.saturating_add(amount);
        self.released_since_tune = self.released_since_tune.saturating_add(amount);
        let tune_threshold = self.window.saturating_add(1) / 2;
        if tune_threshold > 0 && self.released_since_tune >= tune_threshold {
            if self
                .last_tune
                .is_some_and(|last| now.saturating_duration_since(last) <= smoothed_rtt * 2)
            {
                let expanded = self.window.saturating_mul(2).min(self.max_window);
                self.max_data = self
                    .max_data
                    .saturating_add(expanded.saturating_sub(self.window));
                self.window = expanded;
            }
            self.released_since_tune = 0;
            self.last_tune = Some(now);
        }
        let update_threshold = (self.window.saturating_add(1) / 2).max(1);
        if self.max_data.saturating_sub(self.advertised_max_data) < update_threshold {
            return None;
        }
        self.advertised_max_data = self.max_data;
        Some(self.max_data)
    }
}

impl Default for RecvFlowController {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvStreamState {
    assembler: RecvAssembler,
    flow: RecvFlowController,
    read_offset: u64,
    delivered: u64,
    stopped: bool,
    reset_error: Option<VarInt>,
    reliable_reset: Option<(VarInt, u64)>,
    connection_released: u64,
}

impl RecvStreamState {
    pub fn new(max_stream_data: u64) -> Self {
        Self::with_max_buffered_data(max_stream_data, DEFAULT_MAX_RECV_BUFFERED_STREAM_DATA)
    }

    pub fn with_max_buffered_data(max_stream_data: u64, max_buffered_data: usize) -> Self {
        Self {
            assembler: RecvAssembler::new(max_buffered_data),
            flow: RecvFlowController::new(max_stream_data),
            read_offset: 0,
            delivered: 0,
            stopped: false,
            reset_error: None,
            reliable_reset: None,
            connection_released: 0,
        }
    }

    pub fn insert_frame(&mut self, offset: u64, data: impl Into<Bytes>, fin: bool) -> Result<u64> {
        self.insert_frame_with_additional_limit(offset, data.into(), fin, usize::MAX)
    }

    fn insert_frame_with_additional_limit(
        &mut self,
        offset: u64,
        data: Bytes,
        fin: bool,
        max_additional_buffered_bytes: usize,
    ) -> Result<u64> {
        let received_before = self.flow.received();
        let len = data.len();
        let end = offset
            .checked_add(len as u64)
            .ok_or(CodecError::ValueOutOfBounds)?;
        if fin && end < received_before {
            return Err(CodecError::Transport(TransportErrorCode::FinalSizeError));
        }
        self.flow.validate_end(offset, len)?;
        if self
            .final_offset()
            .is_some_and(|final_size| end > final_size)
        {
            return Err(CodecError::Transport(TransportErrorCode::FinalSizeError));
        }
        if self.stopped {
            if fin {
                self.assembler.set_final_offset(end)?;
            }
            self.flow.validate_frame(offset, len)?;
            return Ok(self.flow.received().saturating_sub(received_before));
        }
        let data = if let Some((_, reliable)) = self.reliable_reset {
            let keep = reliable.saturating_sub(offset).min(data.len() as u64) as usize;
            data.slice(..keep)
        } else {
            data
        };
        if fin && self.reliable_reset.is_some() {
            self.assembler.set_final_offset(end)?;
        }
        self.assembler.insert_with_additional_limit(
            offset,
            data,
            fin && self.reliable_reset.is_none(),
            max_additional_buffered_bytes,
        )?;
        self.flow.validate_frame(offset, len)?;
        Ok(self.flow.received().saturating_sub(received_before))
    }

    pub fn read_ordered(&mut self, max: usize) -> Option<Chunk> {
        self.read_ordered_with_flow_update_at(max, Instant::now(), Duration::from_millis(333))
            .map(|(chunk, _)| chunk)
    }

    pub fn read_ordered_with_flow_update(&mut self, max: usize) -> Option<(Chunk, Option<u64>)> {
        self.read_ordered_with_flow_update_at(max, Instant::now(), Duration::from_millis(333))
    }

    pub fn read_ordered_with_flow_update_at(
        &mut self,
        max: usize,
        now: Instant,
        smoothed_rtt: Duration,
    ) -> Option<(Chunk, Option<u64>)> {
        let chunk = self.assembler.read_ordered(&mut self.read_offset, max)?;
        self.delivered = self.delivered.saturating_add(chunk.bytes.len() as u64);
        let new_limit = (!chunk.bytes.is_empty())
            .then(|| {
                self.flow
                    .release(chunk.bytes.len() as u64, now, smoothed_rtt)
            })
            .flatten();
        Some((chunk, new_limit))
    }

    pub fn read_unordered_with_flow_update(&mut self, max: usize) -> Option<(Chunk, Option<u64>)> {
        self.read_unordered_with_flow_update_at(max, Instant::now(), Duration::from_millis(333))
    }

    pub fn read_unordered_with_flow_update_at(
        &mut self,
        max: usize,
        now: Instant,
        smoothed_rtt: Duration,
    ) -> Option<(Chunk, Option<u64>)> {
        let chunk = if self
            .reliable_reset
            .is_some_and(|(_, reliable_size)| self.read_offset < reliable_size)
        {
            self.assembler.read_ordered(&mut self.read_offset, max)?
        } else {
            self.assembler.read_unordered(max)?
        };
        self.delivered = self.delivered.saturating_add(chunk.bytes.len() as u64);
        let new_limit = (!chunk.bytes.is_empty())
            .then(|| {
                self.flow
                    .release(chunk.bytes.len() as u64, now, smoothed_rtt)
            })
            .flatten();
        Some((chunk, new_limit))
    }

    pub fn stop(&mut self) -> usize {
        self.stopped = true;
        self.assembler.discard_buffered()
    }

    pub fn reset(&mut self, final_size: u64, error_code: VarInt) -> Result<u64> {
        let received_before = self.flow.received();
        if self
            .reliable_reset
            .is_some_and(|(existing_error, _)| existing_error != error_code)
        {
            return Err(CodecError::Transport(TransportErrorCode::StreamStateError));
        }
        // RESET_STREAM's final size counts against stream flow control just as
        // STREAM data does, even when the peer never sent the intervening
        // bytes. Validate before updating the assembler so a rejected reset
        // leaves the receive state unchanged.
        if final_size > self.flow.max_data() {
            return Err(CodecError::Transport(TransportErrorCode::FlowControlError));
        }
        if final_size < received_before {
            return Err(CodecError::Transport(TransportErrorCode::FinalSizeError));
        }
        self.assembler.set_final_offset(final_size)?;
        self.flow.validate_frame(final_size, 0)?;
        self.stopped = true;
        self.reset_error = Some(error_code);
        self.reliable_reset = None;
        self.assembler.discard_buffered();
        Ok(self.flow.received().saturating_sub(received_before))
    }

    pub fn reset_at(
        &mut self,
        final_size: u64,
        reliable_size: u64,
        error_code: VarInt,
    ) -> Result<u64> {
        if reliable_size > final_size {
            return Err(CodecError::Transport(
                TransportErrorCode::FrameEncodingError,
            ));
        }
        let received_before = self.flow.received();
        if final_size > self.flow.max_data() {
            return Err(CodecError::Transport(TransportErrorCode::FlowControlError));
        }
        if final_size < received_before {
            return Err(CodecError::Transport(TransportErrorCode::FinalSizeError));
        }
        self.assembler.set_final_offset(final_size)?;
        self.flow.validate_frame(final_size, 0)?;
        match self.reliable_reset {
            Some((existing_error, _)) if existing_error != error_code => {
                return Err(CodecError::Transport(TransportErrorCode::StreamStateError));
            }
            Some((_, existing_reliable)) if reliable_size >= existing_reliable => {}
            _ => self.reliable_reset = Some((error_code, reliable_size)),
        }
        if let Some((_, reliable)) = self.reliable_reset {
            self.assembler.discard_after(reliable);
        }
        Ok(self.flow.received().saturating_sub(received_before))
    }

    fn take_connection_release(&mut self) -> u64 {
        let consumed = if self.stopped {
            self.flow.received()
        } else if let Some((_, reliable)) = self.reliable_reset {
            let prefix_read: u64 = self
                .assembler
                .delivered
                .iter()
                .map(|(start, end)| end.min(reliable).saturating_sub(start.min(reliable)))
                .sum();
            self.flow.received().saturating_sub(reliable) + prefix_read
        } else {
            self.delivered
        };
        let released = consumed.saturating_sub(self.connection_released);
        self.connection_released = self.connection_released.max(consumed);
        released
    }

    pub const fn read_offset(&self) -> u64 {
        self.read_offset
    }

    pub const fn delivered(&self) -> u64 {
        self.delivered
    }

    pub const fn final_offset(&self) -> Option<u64> {
        self.assembler.final_offset()
    }

    pub const fn reset_error(&self) -> Option<VarInt> {
        match self.reliable_reset {
            Some((error_code, reliable_size)) if self.read_offset >= reliable_size => {
                Some(error_code)
            }
            Some(_) => None,
            None => self.reset_error,
        }
    }

    pub const fn reliable_size(&self) -> Option<u64> {
        match self.reliable_reset {
            Some((_, reliable_size)) => Some(reliable_size),
            None => None,
        }
    }

    pub const fn buffered_bytes(&self) -> usize {
        self.assembler.buffered_bytes()
    }

    pub const fn flow_limit(&self) -> u64 {
        self.flow.max_data()
    }

    pub const fn flow_received(&self) -> u64 {
        self.flow.received()
    }

    pub const fn flow_window(&self) -> u64 {
        self.flow.window()
    }
}

impl Default for RecvStreamState {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMap {
    recv: BTreeMap<StreamId, RecvStreamState>,
    closed_recv: [RangeSet; 4],
    accepted: VecDeque<StreamId>,
    locally_opened: std::collections::BTreeSet<StreamId>,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    local_initiator: StreamInitiator,
    inbound_max_bidi_streams: u64,
    inbound_max_uni_streams: u64,
    max_recv_buffered_stream_data: usize,
    max_recv_buffered_stream_data_per_connection: usize,
    max_stream_receive_window: u64,
    recv_buffered_stream_data: usize,
    max_metadata_entries: usize,
    released_connection_credit: u64,
}

impl StreamMap {
    pub fn new(initial_max_stream_data: u64) -> Self {
        Self {
            recv: BTreeMap::new(),
            closed_recv: std::array::from_fn(|_| RangeSet::default()),
            accepted: VecDeque::new(),
            locally_opened: std::collections::BTreeSet::new(),
            initial_max_stream_data_bidi_local: initial_max_stream_data,
            initial_max_stream_data_bidi_remote: initial_max_stream_data,
            initial_max_stream_data_uni: initial_max_stream_data,
            local_initiator: StreamInitiator::Client,
            inbound_max_bidi_streams: u64::MAX,
            inbound_max_uni_streams: u64::MAX,
            max_recv_buffered_stream_data: DEFAULT_MAX_RECV_BUFFERED_STREAM_DATA,
            max_recv_buffered_stream_data_per_connection: DEFAULT_MAX_RECV_BUFFERED_STREAM_DATA,
            max_stream_receive_window: DEFAULT_MAX_RECV_BUFFERED_STREAM_DATA as u64,
            recv_buffered_stream_data: 0,
            max_metadata_entries: 16_384,
            released_connection_credit: 0,
        }
    }

    pub fn set_max_recv_buffered_stream_data(&mut self, max_bytes: usize) {
        self.max_recv_buffered_stream_data = max_bytes;
        self.max_stream_receive_window = u64::try_from(max_bytes).unwrap_or(u64::MAX);
        for stream in self.recv.values_mut() {
            stream.flow.set_max_window(self.max_stream_receive_window);
        }
    }

    pub fn set_max_recv_buffered_stream_data_per_connection(&mut self, max_bytes: usize) {
        self.max_recv_buffered_stream_data_per_connection = max_bytes;
    }

    /// Limits receive state, local registrations, and closed-stream ranges.
    pub fn set_max_metadata_entries(&mut self, limit: usize) {
        self.max_metadata_entries = limit;
    }

    fn collect_connection_release(&mut self, stream_id: StreamId) {
        if let Some(stream) = self.recv.get_mut(&stream_id) {
            self.released_connection_credit += stream.take_connection_release();
        }
    }

    pub(crate) fn take_connection_release(&mut self) -> u64 {
        std::mem::take(&mut self.released_connection_credit)
    }

    fn metadata_entries(&self) -> usize {
        self.recv.len() + self.locally_opened.len() + self.closed_recv_stream_range_count()
    }

    pub const fn recv_buffered_stream_data(&self) -> usize {
        self.recv_buffered_stream_data
    }

    pub(crate) fn clear(&mut self) {
        self.recv.clear();
        self.closed_recv = std::array::from_fn(|_| RangeSet::default());
        self.accepted.clear();
        self.locally_opened.clear();
        self.recv_buffered_stream_data = 0;
    }

    pub fn configure_inbound_stream_limits(
        &mut self,
        local_initiator: StreamInitiator,
        max_bidi_streams: u64,
        max_uni_streams: u64,
    ) {
        self.local_initiator = local_initiator;
        self.inbound_max_bidi_streams = max_bidi_streams;
        self.inbound_max_uni_streams = max_uni_streams;
    }

    pub fn configure_receive_stream_data_limits(
        &mut self,
        bidi_local: u64,
        bidi_remote: u64,
        uni: u64,
    ) {
        self.initial_max_stream_data_bidi_local = bidi_local;
        self.initial_max_stream_data_bidi_remote = bidi_remote;
        self.initial_max_stream_data_uni = uni;
    }

    /// Registers a locally opened bidirectional stream so peer response data
    /// is delivered to its existing receive half rather than the accept queue.
    pub fn register_local_stream(&mut self, stream_id: StreamId) -> Result<()> {
        if !self.locally_opened.contains(&stream_id)
            && self.metadata_entries() >= self.max_metadata_entries
        {
            return Err(CodecError::BufferLimitExceeded);
        }
        self.locally_opened.insert(stream_id);
        Ok(())
    }

    pub fn peer_can_stop_sending(&self, stream_id: StreamId) -> bool {
        !stream_id.is_unidirectional() || stream_id.initiator() == self.local_initiator
    }

    pub fn peer_can_send_on_stream(&self, stream_id: StreamId) -> bool {
        !stream_id.is_unidirectional() || stream_id.initiator() != self.local_initiator
    }

    pub fn receive_stream_frame(
        &mut self,
        stream_id: StreamId,
        offset: u64,
        data: impl Into<Bytes>,
        fin: bool,
    ) -> Result<u64> {
        if self.is_recv_stream_closed(stream_id) {
            return Ok(0);
        }
        let data = data.into();
        let is_new = !self.recv.contains_key(&stream_id);
        if is_new {
            self.validate_new_recv_stream(stream_id)?;
        }
        if is_new {
            let initial_max_stream_data = self.initial_max_stream_data(stream_id);
            self.recv.insert(stream_id, {
                let mut stream = RecvStreamState::with_max_buffered_data(
                    initial_max_stream_data,
                    self.max_recv_buffered_stream_data,
                );
                stream.flow.set_max_window(self.max_stream_receive_window);
                stream
            });
        }
        let remaining = self
            .max_recv_buffered_stream_data_per_connection
            .saturating_sub(self.recv_buffered_stream_data);
        let buffered_before = self
            .recv
            .get(&stream_id)
            .map_or(0, RecvStreamState::buffered_bytes);
        let result = self
            .recv
            .get_mut(&stream_id)
            .ok_or(CodecError::Transport(TransportErrorCode::InternalError))?
            .insert_frame_with_additional_limit(offset, data, fin, remaining);
        let new_bytes = match result {
            Ok(new_bytes) => new_bytes,
            Err(error) => {
                if is_new {
                    self.recv.remove(&stream_id);
                }
                return Err(error);
            }
        };
        let buffered_after = self
            .recv
            .get(&stream_id)
            .map_or(0, RecvStreamState::buffered_bytes);
        self.recv_buffered_stream_data = self
            .recv_buffered_stream_data
            .saturating_add(buffered_after.saturating_sub(buffered_before));
        self.collect_connection_release(stream_id);
        if is_new && !self.locally_opened.contains(&stream_id) {
            self.accepted.push_back(stream_id);
        }
        if self
            .recv
            .get(&stream_id)
            .is_some_and(|stream| stream.stopped && stream.final_offset().is_some())
        {
            self.close_recv_stream(stream_id);
        }
        Ok(new_bytes)
    }

    pub fn accept_recv_stream(&mut self) -> Option<StreamId> {
        self.accept_recv_stream_with_limit_update()
            .map(|(stream_id, _)| stream_id)
    }

    pub fn accept_recv_stream_where(
        &mut self,
        predicate: impl Fn(StreamId) -> bool,
    ) -> Option<StreamId> {
        self.accept_recv_stream_where_with_limit_update(predicate)
            .map(|(stream_id, _)| stream_id)
    }

    pub fn accept_recv_stream_with_limit_update(
        &mut self,
    ) -> Option<(StreamId, Option<(StreamLimitKind, u64)>)> {
        let stream_id = self.accepted.pop_front()?;
        let limit_update = self.accept_limit_update(stream_id);
        Some((stream_id, limit_update))
    }

    pub fn accept_recv_stream_where_with_limit_update(
        &mut self,
        predicate: impl Fn(StreamId) -> bool,
    ) -> Option<(StreamId, Option<(StreamLimitKind, u64)>)> {
        let index = self
            .accepted
            .iter()
            .position(|stream_id| predicate(*stream_id))?;
        let stream_id = self.accepted.remove(index)?;
        let limit_update = self.accept_limit_update(stream_id);
        Some((stream_id, limit_update))
    }

    pub fn read_ordered(&mut self, stream_id: StreamId, max: usize) -> Option<Chunk> {
        self.read_ordered_with_flow_update(stream_id, max)
            .map(|(chunk, _)| chunk)
    }

    pub fn read_ordered_with_flow_update(
        &mut self,
        stream_id: StreamId,
        max: usize,
    ) -> Option<(Chunk, Option<u64>)> {
        self.read_ordered_with_flow_update_at(
            stream_id,
            max,
            Instant::now(),
            Duration::from_millis(333),
        )
    }

    pub fn read_ordered_with_flow_update_at(
        &mut self,
        stream_id: StreamId,
        max: usize,
        now: Instant,
        smoothed_rtt: Duration,
    ) -> Option<(Chunk, Option<u64>)> {
        let (mut result, terminal) = {
            let stream = self.recv.get_mut(&stream_id)?;
            let result = stream.read_ordered_with_flow_update_at(max, now, smoothed_rtt)?;
            let terminal = stream.final_offset() == Some(stream.delivered());
            (result, terminal)
        };
        self.recv_buffered_stream_data = self
            .recv_buffered_stream_data
            .saturating_sub(result.0.bytes.len());
        self.collect_connection_release(stream_id);
        if terminal {
            result.1 = None;
            self.close_recv_stream(stream_id);
        }
        Some(result)
    }

    pub fn read_unordered_with_flow_update(
        &mut self,
        stream_id: StreamId,
        max: usize,
    ) -> Option<(Chunk, Option<u64>)> {
        self.read_unordered_with_flow_update_at(
            stream_id,
            max,
            Instant::now(),
            Duration::from_millis(333),
        )
    }

    pub fn read_unordered_with_flow_update_at(
        &mut self,
        stream_id: StreamId,
        max: usize,
        now: Instant,
        smoothed_rtt: Duration,
    ) -> Option<(Chunk, Option<u64>)> {
        let (mut result, terminal) = {
            let stream = self.recv.get_mut(&stream_id)?;
            let result = stream.read_unordered_with_flow_update_at(max, now, smoothed_rtt)?;
            let terminal = stream.final_offset() == Some(stream.delivered());
            (result, terminal)
        };
        self.recv_buffered_stream_data = self
            .recv_buffered_stream_data
            .saturating_sub(result.0.bytes.len());
        self.collect_connection_release(stream_id);
        if terminal {
            result.1 = None;
            self.close_recv_stream(stream_id);
        }
        Some(result)
    }

    pub fn recv_stream(&self, stream_id: StreamId) -> Option<&RecvStreamState> {
        self.recv.get(&stream_id)
    }

    pub(crate) fn is_recv_stream_closed(&self, stream_id: StreamId) -> bool {
        let stream_type = (stream_id.0.into_inner() & 0x03) as usize;
        self.closed_recv[stream_type].contains(stream_id.ordinal())
    }

    pub(crate) fn recv_stream_count(&self) -> usize {
        self.recv.len()
    }

    pub(crate) fn closed_recv_stream_range_count(&self) -> usize {
        self.closed_recv.iter().map(RangeSet::len).sum()
    }

    pub fn stop_recv_stream(&mut self, stream_id: StreamId) -> Result<()> {
        if self.is_recv_stream_closed(stream_id) {
            return Ok(());
        }
        if !self.recv.contains_key(&stream_id) {
            self.receive_stream_frame(stream_id, 0, Bytes::new(), false)?;
        }
        if let Some(stream) = self.recv.get_mut(&stream_id) {
            let discarded = stream.stop();
            self.recv_buffered_stream_data =
                self.recv_buffered_stream_data.saturating_sub(discarded);
        }
        self.collect_connection_release(stream_id);
        if self
            .recv
            .get(&stream_id)
            .is_some_and(|stream| stream.final_offset().is_some())
        {
            self.close_recv_stream(stream_id);
        }
        Ok(())
    }

    pub fn reset_stream(
        &mut self,
        stream_id: StreamId,
        final_size: u64,
        error_code: VarInt,
    ) -> Result<u64> {
        if self.is_recv_stream_closed(stream_id) {
            return Ok(0);
        }
        let was_stopped = self
            .recv
            .get(&stream_id)
            .is_some_and(|stream| stream.stopped);
        let is_new = !self.recv.contains_key(&stream_id);
        if is_new {
            self.validate_new_recv_stream(stream_id)?;
        }
        let buffered_before = self
            .recv
            .get(&stream_id)
            .map_or(0, RecvStreamState::buffered_bytes);
        let initial_max_stream_data = self.initial_max_stream_data(stream_id);
        let result = self
            .recv
            .entry(stream_id)
            .or_insert_with(|| {
                let mut stream = RecvStreamState::with_max_buffered_data(
                    initial_max_stream_data,
                    self.max_recv_buffered_stream_data,
                );
                stream.flow.set_max_window(self.max_stream_receive_window);
                stream
            })
            .reset(final_size, error_code);
        let newly_accounted = match result {
            Ok(newly_accounted) => newly_accounted,
            Err(error) => {
                if is_new {
                    self.recv.remove(&stream_id);
                }
                return Err(error);
            }
        };
        self.recv_buffered_stream_data = self
            .recv_buffered_stream_data
            .saturating_sub(buffered_before);
        if is_new && !self.locally_opened.contains(&stream_id) {
            self.accepted.push_back(stream_id);
        }
        self.collect_connection_release(stream_id);
        if was_stopped {
            self.close_recv_stream(stream_id);
        }
        Ok(newly_accounted)
    }

    pub fn reset_stream_at(
        &mut self,
        stream_id: StreamId,
        final_size: u64,
        reliable_size: u64,
        error_code: VarInt,
    ) -> Result<u64> {
        if self.is_recv_stream_closed(stream_id) {
            return Ok(0);
        }
        let is_new = !self.recv.contains_key(&stream_id);
        if is_new {
            self.validate_new_recv_stream(stream_id)?;
        }
        let buffered_before = self
            .recv
            .get(&stream_id)
            .map_or(0, RecvStreamState::buffered_bytes);
        let initial_max_stream_data = self.initial_max_stream_data(stream_id);
        let result = self
            .recv
            .entry(stream_id)
            .or_insert_with(|| {
                let mut stream = RecvStreamState::with_max_buffered_data(
                    initial_max_stream_data,
                    self.max_recv_buffered_stream_data,
                );
                stream.flow.set_max_window(self.max_stream_receive_window);
                stream
            })
            .reset_at(final_size, reliable_size, error_code);
        let newly_accounted = match result {
            Ok(newly_accounted) => newly_accounted,
            Err(error) => {
                if is_new {
                    self.recv.remove(&stream_id);
                }
                return Err(error);
            }
        };
        let buffered_after = self
            .recv
            .get(&stream_id)
            .map_or(0, RecvStreamState::buffered_bytes);
        self.recv_buffered_stream_data = self
            .recv_buffered_stream_data
            .saturating_sub(buffered_before.saturating_sub(buffered_after));
        if is_new && !self.locally_opened.contains(&stream_id) {
            self.accepted.push_back(stream_id);
        }
        self.collect_connection_release(stream_id);
        if self
            .recv
            .get(&stream_id)
            .is_some_and(|stream| stream.stopped)
        {
            self.close_recv_stream(stream_id);
        }
        Ok(newly_accounted)
    }

    fn initial_max_stream_data(&self, stream_id: StreamId) -> u64 {
        if stream_id.is_unidirectional() {
            self.initial_max_stream_data_uni
        } else if stream_id.initiator() == self.local_initiator {
            self.initial_max_stream_data_bidi_local
        } else {
            self.initial_max_stream_data_bidi_remote
        }
    }

    pub(crate) fn received_stream_data(&self, stream_id: StreamId) -> u64 {
        self.recv
            .get(&stream_id)
            .map_or(0, |stream| stream.flow.received())
    }

    fn close_recv_stream(&mut self, stream_id: StreamId) {
        if let Some(stream) = self.recv.remove(&stream_id) {
            self.recv_buffered_stream_data = self
                .recv_buffered_stream_data
                .saturating_sub(stream.buffered_bytes());
        }
        self.accepted.retain(|accepted| *accepted != stream_id);
        self.locally_opened.remove(&stream_id);
        let stream_type = (stream_id.0.into_inner() & 0x03) as usize;
        let ordinal = stream_id.ordinal();
        self.closed_recv[stream_type].insert(ordinal, ordinal.saturating_add(1));
    }

    fn validate_new_recv_stream(&self, stream_id: StreamId) -> Result<()> {
        if stream_id.is_unidirectional() && stream_id.initiator() == self.local_initiator {
            return Err(CodecError::Transport(TransportErrorCode::StreamStateError));
        }
        if stream_id.initiator() == self.local_initiator {
            if !self.locally_opened.contains(&stream_id) {
                return Err(CodecError::Transport(TransportErrorCode::StreamStateError));
            }
        } else {
            let limit = if stream_id.is_unidirectional() {
                self.inbound_max_uni_streams
            } else {
                self.inbound_max_bidi_streams
            };
            if stream_id.ordinal() >= limit {
                return Err(CodecError::Transport(TransportErrorCode::StreamLimitError));
            }
        }
        if self.metadata_entries() >= self.max_metadata_entries {
            return Err(CodecError::BufferLimitExceeded);
        }
        Ok(())
    }

    pub(crate) fn validate_peer_send_control(&self, stream_id: StreamId) -> Result<()> {
        if stream_id.is_unidirectional() {
            return Err(CodecError::Transport(TransportErrorCode::StreamStateError));
        }
        if self.recv.contains_key(&stream_id) || self.is_recv_stream_closed(stream_id) {
            return Ok(());
        }
        self.validate_new_recv_stream(stream_id)
    }

    fn accept_limit_update(&mut self, stream_id: StreamId) -> Option<(StreamLimitKind, u64)> {
        if stream_id.initiator() == self.local_initiator {
            return None;
        }
        let next_limit = stream_id.ordinal().saturating_add(2);
        if stream_id.is_unidirectional() {
            if next_limit > self.inbound_max_uni_streams {
                self.inbound_max_uni_streams = next_limit;
                return Some((StreamLimitKind::Uni, next_limit));
            }
        } else if next_limit > self.inbound_max_bidi_streams {
            self.inbound_max_bidi_streams = next_limit;
            return Some((StreamLimitKind::Bidi, next_limit));
        }
        None
    }
}

impl Default for StreamMap {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_buffer_respects_flow_control_and_fin() {
        let mut flow = SendFlowController::new(5);
        let mut send = SendBuffer::default();
        send.write(b"hello world").unwrap();

        let first = send.poll_frame(&mut flow, 16).unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(first.bytes.as_ref(), b"hello");
        assert!(!first.fin);
        assert!(send.poll_frame(&mut flow, 16).is_none());

        flow.increase_limit(11);
        send.finish();
        let second = send.poll_frame(&mut flow, 16).unwrap();
        assert_eq!(second.offset, 5);
        assert_eq!(second.bytes.as_ref(), b" world");
        assert!(second.fin);
    }

    #[test]
    fn send_buffer_chunks_large_writes_and_truncates_reliable_reset() {
        let payload = vec![0x5a; SEND_BUFFER_CHUNK_SIZE * 2 + 17];
        let mut send = SendBuffer::default();
        send.write(&payload).unwrap();
        assert_eq!(send.chunks.len(), 3);
        assert_eq!(send.queued_len(), payload.len());

        let mut flow = SendFlowController::new(payload.len() as u64);
        let first = send
            .poll_frame(&mut flow, SEND_BUFFER_CHUNK_SIZE + 7)
            .unwrap();
        assert_eq!(first.bytes.as_ref(), &payload[..SEND_BUFFER_CHUNK_SIZE + 7]);

        let reliable_size = (SEND_BUFFER_CHUNK_SIZE + 12) as u64;
        let (final_size, discarded) = send.prepare_reliable_reset(reliable_size).unwrap();
        assert_eq!(final_size, payload.len() as u64);
        assert_eq!(discarded, payload.len() - SEND_BUFFER_CHUNK_SIZE - 12);
        assert_eq!(send.queued_len(), 5);

        let tail = send.poll_frame(&mut flow, usize::MAX).unwrap();
        assert_eq!(tail.offset, (SEND_BUFFER_CHUNK_SIZE + 7) as u64);
        assert_eq!(tail.bytes.as_ref(), &[0x5a; 5]);
    }

    #[test]
    fn send_buffer_adapts_chunk_capacity_to_small_writes() {
        let mut send = SendBuffer::default();
        send.write(&[0x5a; 32]).unwrap();
        assert_eq!(send.chunks.len(), 1);
        assert_eq!(send.chunks[0].capacity(), MIN_SEND_BUFFER_CHUNK_SIZE);

        for _ in 0..31 {
            send.write(&[0x5a; 32]).unwrap();
        }
        assert_eq!(send.queued_len(), 1024);
        assert_eq!(send.chunks.len(), 1);
        assert_eq!(send.chunks[0].capacity(), 1024);
    }

    #[test]
    fn send_buffer_slices_frames_without_copying_within_a_chunk() {
        let payload = [0x5a; 4096];
        let mut send = SendBuffer::default();
        send.write(&payload).unwrap();
        let buffered_ptr = send.chunks[0].as_ptr();
        let mut flow = SendFlowController::new(payload.len() as u64);

        let frame = send.poll_frame(&mut flow, 1200).unwrap();

        assert_eq!(frame.bytes.len(), 1200);
        assert_eq!(frame.bytes.as_ptr(), buffered_ptr);
        assert_eq!(send.queued_len(), payload.len() - 1200);
    }

    #[test]
    fn recv_assembler_trims_duplicate_overlap() {
        let mut recv = RecvAssembler::default();
        recv.insert(0, b"hello".to_vec(), false).unwrap();
        recv.insert(3, b"lo world".to_vec(), true).unwrap();

        let mut offset = 0;
        let first = recv.read_ordered(&mut offset, 16).unwrap();
        let second = recv.read_ordered(&mut offset, 16).unwrap();

        assert_eq!(first.offset, 0);
        assert_eq!(first.bytes.as_ref(), b"hello");
        assert!(!first.fin);
        assert_eq!(second.offset, 5);
        assert_eq!(second.bytes.as_ref(), b" world");
        assert!(second.fin);
    }

    #[test]
    fn recv_assembler_keeps_in_order_chunks_out_of_sparse_storage() {
        let mut recv = RecvAssembler::default();
        for offset in 0..64 {
            recv.insert(offset, vec![offset as u8], offset == 63)
                .unwrap();
        }

        assert_eq!(recv.contiguous_chunks.len(), 64);
        assert!(recv.sparse_chunks.is_empty());

        let mut offset = 0;
        for expected in 0..64 {
            let chunk = recv.read_ordered(&mut offset, 1).unwrap();
            assert_eq!(chunk.offset, expected);
            assert_eq!(chunk.bytes.as_ref(), &[expected as u8]);
            assert_eq!(chunk.fin, expected == 63);
        }
    }

    #[test]
    fn recv_assembler_moves_gap_fragments_into_contiguous_storage_when_bridged() {
        let mut recv = RecvAssembler::default();
        recv.insert(0, b"ab".to_vec(), false).unwrap();
        recv.insert(4, b"ef".to_vec(), true).unwrap();
        assert_eq!(recv.contiguous_chunks.len(), 1);
        assert_eq!(recv.sparse_chunks.len(), 1);

        recv.insert(2, b"cd".to_vec(), false).unwrap();
        assert_eq!(recv.contiguous_chunks.len(), 3);
        assert!(recv.sparse_chunks.is_empty());

        let mut offset = 0;
        for expected in [b"ab".as_slice(), b"cd", b"ef"] {
            assert_eq!(
                recv.read_ordered(&mut offset, 2).unwrap().bytes.as_ref(),
                expected
            );
        }
        assert_eq!(offset, 6);
    }

    #[test]
    fn recv_assembler_rejects_conflicting_overlap() {
        let mut recv = RecvAssembler::default();
        recv.insert(0, b"hello".to_vec(), false).unwrap();

        let err = recv.insert(3, b"xx".to_vec(), false).unwrap_err();
        assert_eq!(
            err,
            CodecError::Transport(TransportErrorCode::StreamStateError)
        );
    }

    #[test]
    fn recv_assembler_rejects_inconsistent_final_offset() {
        let mut recv = RecvAssembler::default();
        recv.insert(0, b"hello".to_vec(), true).unwrap();

        let err = recv.insert(0, b"hello!".to_vec(), true).unwrap_err();
        assert_eq!(
            err,
            CodecError::Transport(TransportErrorCode::FinalSizeError)
        );
    }

    #[test]
    fn recv_assembler_bounds_buffered_stream_data() {
        let mut recv = RecvAssembler::new(8);
        recv.insert(8, b"abcd".to_vec(), false).unwrap();
        recv.insert(12, b"efgh".to_vec(), false).unwrap();

        let err = recv.insert(16, b"!".to_vec(), false).unwrap_err();
        assert_eq!(
            err,
            CodecError::Transport(TransportErrorCode::FlowControlError)
        );
        assert_eq!(recv.buffered_bytes(), 8);
    }

    #[test]
    fn recv_assembler_does_not_charge_duplicate_data_against_buffer() {
        let mut recv = RecvAssembler::new(8);
        recv.insert(0, b"abcdef".to_vec(), false).unwrap();
        recv.insert(2, b"cdef".to_vec(), false).unwrap();
        recv.insert(6, b"gh".to_vec(), false).unwrap();

        assert_eq!(recv.buffered_bytes(), 8);
    }

    #[test]
    fn recv_assembler_releases_buffer_budget_after_reads() {
        let mut recv = RecvAssembler::new(4);
        recv.insert(0, b"abcd".to_vec(), false).unwrap();

        let mut offset = 0;
        let chunk = recv.read_ordered(&mut offset, 2).unwrap();
        assert_eq!(chunk.bytes.as_ref(), b"ab");
        assert_eq!(recv.buffered_bytes(), 2);

        recv.insert(4, b"ef".to_vec(), false).unwrap();
        assert_eq!(recv.buffered_bytes(), 4);
    }

    #[test]
    fn recv_assembler_trims_retransmissions_over_ordered_delivered_data() {
        let mut recv = RecvAssembler::new(16);
        recv.insert(0, b"abcd".to_vec(), false).unwrap();
        let mut offset = 0;
        assert_eq!(
            recv.read_ordered(&mut offset, 16).unwrap().bytes.as_ref(),
            b"abcd"
        );

        assert_eq!(recv.insert(0, b"abcdefgh".to_vec(), true).unwrap(), 4);
        assert_eq!(recv.buffered_bytes(), 4);
        let tail = recv.read_ordered(&mut offset, 16).unwrap();
        assert_eq!(tail.offset, 4);
        assert_eq!(tail.bytes.as_ref(), b"efgh");
        assert!(tail.fin);
        assert_eq!(recv.buffered_bytes(), 0);
    }

    #[test]
    fn recv_assembler_does_not_redeliver_unordered_retransmissions() {
        let mut recv = RecvAssembler::new(16);
        recv.insert(4, b"efgh".to_vec(), false).unwrap();
        let first = recv.read_unordered(16).unwrap();
        assert_eq!(first.offset, 4);
        assert_eq!(first.bytes.as_ref(), b"efgh");

        assert_eq!(recv.insert(4, b"efgh".to_vec(), false).unwrap(), 0);
        assert!(recv.read_unordered(16).is_none());
        assert_eq!(recv.buffered_bytes(), 0);
    }

    #[test]
    fn recv_flow_control_rejects_data_past_limit() {
        let mut flow = RecvFlowController::new(5);
        flow.validate_frame(0, 5).unwrap();

        let err = flow.validate_frame(5, 1).unwrap_err();
        assert_eq!(
            err,
            CodecError::Transport(TransportErrorCode::FlowControlError)
        );
    }

    #[test]
    fn recv_flow_control_accounts_u64_credit_without_usize_conversion() {
        let mut flow = RecvFlowController::new(u64::MAX);

        flow.add_received(u64::MAX).unwrap();
        assert_eq!(flow.received(), u64::MAX);
        assert_eq!(flow.add_received(1), Err(CodecError::ValueOutOfBounds));
    }

    #[test]
    fn receive_window_auto_tunes_for_sustained_consumption_within_rtt() {
        let start = Instant::now();
        let mut flow = RecvFlowController::new(8);
        flow.set_max_window(32);

        assert_eq!(flow.release(4, start, Duration::from_millis(20)), Some(12));
        assert_eq!(flow.window(), 8);
        assert_eq!(
            flow.release(
                4,
                start + Duration::from_millis(10),
                Duration::from_millis(20),
            ),
            Some(24)
        );
        assert_eq!(flow.window(), 16);

        flow.release(
            8,
            start + Duration::from_millis(15),
            Duration::from_millis(20),
        );
        assert_eq!(flow.window(), 32);
    }

    #[test]
    fn recv_stream_state_delivers_ordered_chunks() {
        let mut recv = RecvStreamState::new(32);
        recv.insert_frame(5, b" world".to_vec(), true).unwrap();
        assert!(recv.read_ordered(64).is_none());
        recv.insert_frame(0, b"hello".to_vec(), false).unwrap();

        let first = recv.read_ordered(64).unwrap();
        let second = recv.read_ordered(64).unwrap();
        assert_eq!(first.bytes.as_ref(), b"hello");
        assert!(!first.fin);
        assert_eq!(second.bytes.as_ref(), b" world");
        assert!(second.fin);
    }

    #[test]
    fn recv_stream_state_uses_configured_buffer_limit() {
        let mut recv = RecvStreamState::with_max_buffered_data(32, 4);
        recv.insert_frame(0, b"abcd".to_vec(), false).unwrap();

        let err = recv.insert_frame(4, b"e".to_vec(), false).unwrap_err();
        assert_eq!(
            err,
            CodecError::Transport(TransportErrorCode::FlowControlError)
        );
    }

    #[test]
    fn stream_map_enforces_aggregate_receive_buffer_limit() {
        let mut streams = StreamMap::new(32);
        streams.set_max_recv_buffered_stream_data(8);
        streams.set_max_recv_buffered_stream_data_per_connection(6);
        let first = StreamId(VarInt::from_u32(1));
        let second = StreamId(VarInt::from_u32(5));

        streams
            .receive_stream_frame(first, 0, b"1234".to_vec(), false)
            .unwrap();
        assert_eq!(streams.recv_buffered_stream_data(), 4);
        assert_eq!(
            streams.receive_stream_frame(second, 0, b"567".to_vec(), false),
            Err(CodecError::Transport(TransportErrorCode::FlowControlError))
        );
        assert!(streams.recv_stream(second).is_none());
        assert_eq!(streams.recv_buffered_stream_data(), 4);

        streams
            .receive_stream_frame(first, 0, b"1234".to_vec(), false)
            .unwrap();
        assert_eq!(streams.recv_buffered_stream_data(), 4);

        let chunk = streams.read_ordered_with_flow_update(first, 2).unwrap().0;
        assert_eq!(chunk.bytes.as_ref(), b"12");
        assert_eq!(streams.recv_buffered_stream_data(), 2);

        streams
            .receive_stream_frame(second, 0, b"5678".to_vec(), false)
            .unwrap();
        assert_eq!(streams.recv_buffered_stream_data(), 6);
    }

    #[test]
    fn stopping_and_resetting_streams_release_aggregate_receive_budget() {
        let mut streams = StreamMap::new(32);
        streams.set_max_recv_buffered_stream_data_per_connection(4);
        let stopped = StreamId(VarInt::from_u32(1));
        let reset = StreamId(VarInt::from_u32(5));

        streams
            .receive_stream_frame(stopped, 0, b"1234".to_vec(), false)
            .unwrap();
        streams.stop_recv_stream(stopped).unwrap();
        assert_eq!(streams.recv_buffered_stream_data(), 0);

        streams
            .receive_stream_frame(reset, 0, b"5678".to_vec(), false)
            .unwrap();
        streams.reset_stream(reset, 4, VarInt::from_u32(9)).unwrap();
        assert_eq!(streams.recv_buffered_stream_data(), 0);
    }

    #[test]
    fn reset_rejects_final_size_below_received_stream_offset() {
        let mut recv = RecvStreamState::new(32);
        recv.insert_frame(4, b"data".to_vec(), false).unwrap();

        assert_eq!(
            recv.reset(7, VarInt::ZERO),
            Err(CodecError::Transport(TransportErrorCode::FinalSizeError))
        );
        assert_eq!(recv.buffered_bytes(), 4);
        assert_eq!(recv.reset_error(), None);
    }

    #[test]
    fn fin_rejects_final_size_below_previously_received_stream_offset() {
        let mut recv = RecvStreamState::new(32);
        recv.insert_frame(0, b"12345678".to_vec(), false).unwrap();
        assert_eq!(recv.read_ordered(32).unwrap().bytes.as_ref(), b"12345678");

        assert_eq!(
            recv.insert_frame(4, Vec::new(), true),
            Err(CodecError::Transport(TransportErrorCode::FinalSizeError))
        );
        assert_eq!(recv.final_offset(), None);
    }

    #[test]
    fn recv_assembler_delivers_unordered_chunks() {
        let mut recv = RecvAssembler::default();
        recv.insert(5, b"world".to_vec(), true).unwrap();
        recv.insert(0, b"hello".to_vec(), false).unwrap();

        let first = recv.read_unordered(5).unwrap();
        let second = recv.read_unordered(5).unwrap();

        assert_eq!(first.offset, 0);
        assert_eq!(first.bytes.as_ref(), b"hello");
        assert!(!first.fin);
        assert_eq!(second.offset, 5);
        assert_eq!(second.bytes.as_ref(), b"world");
        assert!(second.fin);
    }

    #[test]
    fn stream_map_queues_new_recv_streams_once() {
        let mut streams = StreamMap::new(64);
        let stream_id = StreamId(VarInt::from_u32(1));
        streams
            .receive_stream_frame(stream_id, 0, b"hello".to_vec(), false)
            .unwrap();
        streams
            .receive_stream_frame(stream_id, 5, b" world".to_vec(), true)
            .unwrap();

        assert_eq!(streams.accept_recv_stream(), Some(stream_id));
        assert_eq!(streams.accept_recv_stream(), None);
        assert_eq!(
            streams.read_ordered(stream_id, 64).unwrap().bytes.as_ref(),
            b"hello"
        );
        assert_eq!(
            streams.read_ordered(stream_id, 64).unwrap().bytes.as_ref(),
            b" world"
        );
    }

    #[test]
    fn completed_receive_streams_are_reclaimed_into_compact_ranges() {
        let mut streams = StreamMap::new(64);
        for raw_id in [1, 5] {
            let stream_id = StreamId(VarInt::from_u32(raw_id));
            streams
                .receive_stream_frame(stream_id, 0, b"done".to_vec(), true)
                .unwrap();
            assert_eq!(streams.accept_recv_stream(), Some(stream_id));
            let (chunk, limit_update) = streams
                .read_ordered_with_flow_update(stream_id, 64)
                .unwrap();
            assert_eq!(chunk.bytes.as_ref(), b"done");
            assert!(chunk.fin);
            assert_eq!(limit_update, None);
            assert!(streams.is_recv_stream_closed(stream_id));
        }

        assert_eq!(streams.recv_stream_count(), 0);
        assert_eq!(streams.closed_recv_stream_range_count(), 1);

        let closed = StreamId(VarInt::from_u32(1));
        assert_eq!(
            streams
                .receive_stream_frame(closed, 4, b"late".to_vec(), true)
                .unwrap(),
            0
        );
        assert_eq!(streams.reset_stream(closed, 8, VarInt::ZERO).unwrap(), 0);
        assert_eq!(streams.recv_stream_count(), 0);
        assert_eq!(streams.accept_recv_stream(), None);
    }

    #[test]
    fn reset_only_stream_is_accepted_once() {
        let mut streams = StreamMap::new(32);
        let stream_id = StreamId(VarInt::from_u32(1));

        streams
            .reset_stream(stream_id, 0, VarInt::from_u32(42))
            .unwrap();

        assert_eq!(streams.accept_recv_stream(), Some(stream_id));
        assert_eq!(streams.accept_recv_stream(), None);
        assert_eq!(
            streams.recv_stream(stream_id).unwrap().reset_error(),
            Some(VarInt::from_u32(42))
        );
    }

    #[test]
    fn locally_initiated_bidirectional_stream_is_not_accepted_as_incoming() {
        let mut streams = StreamMap::new(32);
        let stream_id = StreamId(VarInt::ZERO);
        streams.register_local_stream(stream_id).unwrap();

        streams
            .receive_stream_frame(stream_id, 0, b"response".to_vec(), false)
            .unwrap();

        assert_eq!(streams.accept_recv_stream(), None);
        assert_eq!(
            streams.read_ordered(stream_id, 32).unwrap().bytes.as_ref(),
            b"response"
        );
    }

    #[test]
    fn reset_on_locally_initiated_bidirectional_stream_is_not_accepted() {
        let mut streams = StreamMap::new(32);
        let stream_id = StreamId(VarInt::ZERO);
        streams.register_local_stream(stream_id).unwrap();

        streams
            .reset_stream(stream_id, 0, VarInt::from_u32(42))
            .unwrap();

        assert_eq!(streams.accept_recv_stream(), None);
        assert_eq!(
            streams.recv_stream(stream_id).unwrap().reset_error(),
            Some(VarInt::from_u32(42))
        );
    }

    #[test]
    fn stream_map_accepts_matching_stream_without_dropping_others() {
        let mut streams = StreamMap::new(64);
        let bidi = StreamId(VarInt::from_u32(1));
        let uni = StreamId(VarInt::from_u32(3));
        streams
            .receive_stream_frame(bidi, 0, b"bidi".to_vec(), false)
            .unwrap();
        streams
            .receive_stream_frame(uni, 0, b"uni".to_vec(), false)
            .unwrap();

        assert_eq!(
            streams.accept_recv_stream_where(|stream_id| stream_id.0.into_inner() & 0x02 != 0),
            Some(uni)
        );
        assert_eq!(streams.accept_recv_stream(), Some(bidi));
    }

    #[test]
    fn stream_map_rejects_peer_initiated_streams_past_configured_limit() {
        let mut streams = StreamMap::new(64);
        streams.configure_inbound_stream_limits(StreamInitiator::Client, 1, 1);
        let first_server_bidi = StreamId(VarInt::from_u32(1));
        let second_server_bidi = StreamId(VarInt::from_u32(5));
        let first_server_uni = StreamId(VarInt::from_u32(3));
        let second_server_uni = StreamId(VarInt::from_u32(7));

        streams
            .receive_stream_frame(first_server_bidi, 0, b"bidi".to_vec(), false)
            .unwrap();
        assert_eq!(
            streams
                .receive_stream_frame(second_server_bidi, 0, b"bidi".to_vec(), false)
                .unwrap_err(),
            CodecError::Transport(TransportErrorCode::StreamLimitError)
        );

        streams
            .receive_stream_frame(first_server_uni, 0, b"uni".to_vec(), false)
            .unwrap();
        assert_eq!(
            streams
                .receive_stream_frame(second_server_uni, 0, b"uni".to_vec(), false)
                .unwrap_err(),
            CodecError::Transport(TransportErrorCode::StreamLimitError)
        );
    }

    #[test]
    fn stream_map_does_not_apply_inbound_limit_to_local_initiated_streams() {
        let mut streams = StreamMap::new(64);
        streams.configure_inbound_stream_limits(StreamInitiator::Client, 0, 0);
        let client_bidi = StreamId(VarInt::from_u32(0));

        streams.register_local_stream(client_bidi).unwrap();
        streams
            .receive_stream_frame(client_bidi, 0, b"response".to_vec(), false)
            .unwrap();

        assert_eq!(streams.accept_recv_stream(), None);
    }

    #[test]
    fn stream_map_rejects_peer_data_on_local_initiated_unidirectional_stream() {
        let mut streams = StreamMap::new(64);
        streams.configure_inbound_stream_limits(StreamInitiator::Client, 100, 100);

        let err = streams
            .receive_stream_frame(StreamId(VarInt::from_u32(2)), 0, b"invalid".to_vec(), false)
            .unwrap_err();

        assert_eq!(
            err,
            CodecError::Transport(TransportErrorCode::StreamStateError)
        );
    }
}
