//! Portable receive and send batch containers with reusable payload storage.

use std::collections::VecDeque;

use crate::{RecvMeta, Transmit};

#[derive(Debug)]
pub struct BatchRecv {
    pub(crate) packets: VecDeque<(Vec<u8>, RecvMeta)>,
    pub(crate) reusable_buffers: Vec<Vec<u8>>,
    next_receive_capacity: usize,
}

impl Default for BatchRecv {
    fn default() -> Self {
        Self {
            packets: VecDeque::new(),
            reusable_buffers: Vec::new(),
            next_receive_capacity: 1,
        }
    }
}

impl BatchRecv {
    pub fn push(&mut self, bytes: Vec<u8>, meta: RecvMeta) {
        self.packets.push_back((bytes, meta));
    }

    pub fn clear(&mut self) {
        for (bytes, _) in self.packets.drain(..) {
            self.reusable_buffers.push(bytes);
        }
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &RecvMeta)> {
        self.packets
            .iter()
            .map(|(bytes, meta)| (&bytes[..meta.len.min(bytes.len())], meta))
    }

    /// Removes the oldest received datagram from the batch.
    pub fn pop_front(&mut self) -> Option<(Vec<u8>, RecvMeta)> {
        self.packets.pop_front()
    }

    /// Returns a processed payload allocation to this batch's reuse pool.
    pub fn recycle(&mut self, buffer: Vec<u8>) {
        self.recycle_buffer(buffer);
    }

    pub(crate) fn take_buffer(&mut self, buffer_size: usize) -> Vec<u8> {
        let mut buffer = self.reusable_buffers.pop().unwrap_or_default();
        buffer.resize(buffer_size, 0);
        buffer
    }

    pub(crate) fn recycle_buffer(&mut self, buffer: Vec<u8>) {
        self.reusable_buffers.push(buffer);
    }

    pub(crate) fn push_received(&mut self, bytes: Vec<u8>, meta: RecvMeta) -> usize {
        let received_len = meta.len.min(bytes.len());
        let Some(segment_size) = meta
            .segment_size
            .filter(|&size| size > 0 && size < received_len)
        else {
            self.push(bytes, meta);
            return 1;
        };

        let segment_count = received_len.div_ceil(segment_size);
        for segment in bytes[..received_len].chunks(segment_size) {
            let mut segment_meta = meta.clone();
            segment_meta.len = segment.len();
            self.push(segment.to_vec(), segment_meta);
        }
        self.recycle_buffer(bytes);
        segment_count
    }

    pub(crate) fn adaptive_receive_capacity(&self, maximum: usize) -> usize {
        if maximum == 0 {
            0
        } else {
            self.next_receive_capacity.clamp(1, maximum)
        }
    }

    pub(crate) fn record_receive_batch(&mut self, requested: usize, received: usize) {
        if requested == 0 {
            return;
        }
        self.next_receive_capacity = if received >= requested {
            requested.saturating_mul(2)
        } else if received.saturating_mul(2) < requested {
            requested.div_ceil(2)
        } else {
            requested
        }
        .max(1);
    }
}

#[derive(Debug, Default)]
pub struct BatchSend {
    transmits: Vec<Transmit>,
    pub(crate) reusable_payloads: Vec<Vec<u8>>,
}

impl BatchSend {
    pub fn push(&mut self, transmit: Transmit) {
        self.transmits.push(transmit);
    }

    pub fn clear(&mut self) {
        for mut transmit in self.transmits.drain(..) {
            transmit.contents.clear();
            self.reusable_payloads.push(transmit.contents);
        }
    }

    pub fn len(&self) -> usize {
        self.transmits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transmits.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Transmit> {
        self.transmits.iter()
    }

    /// Drains the queued transmits while retaining the batch allocation.
    ///
    /// This is useful after a partial non-blocking send, where callers need to
    /// recycle sent payloads and requeue unsent transmits without cloning them.
    pub fn drain(&mut self) -> impl Iterator<Item = Transmit> + '_ {
        self.transmits.drain(..)
    }

    /// Removes the final transmit without releasing the batch allocation.
    pub fn pop(&mut self) -> Option<Transmit> {
        self.transmits.pop()
    }

    /// Returns a payload buffer retained from a previously cleared batch.
    ///
    /// Fill this buffer and pass it in [`Transmit::contents`] to [`Self::push`]
    /// to avoid a new payload allocation. The returned buffer is empty and
    /// retains its previous capacity.
    pub fn take_payload_buffer(&mut self) -> Vec<u8> {
        self.reusable_payloads.pop().unwrap_or_default()
    }

    /// Returns an externally drained payload to this batch's reuse pool.
    pub fn recycle_payload_buffer(&mut self, mut payload: Vec<u8>) {
        payload.clear();
        self.reusable_payloads.push(payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_batch_reuses_initialized_packet_storage() {
        let mut batch = BatchRecv::default();
        let original = vec![0; 64];
        let pointer = original.as_ptr();
        batch.push(
            original,
            RecvMeta {
                local: None,
                remote: "127.0.0.1:4433".parse().unwrap(),
                interface: None,
                ecn: None,
                segment_size: None,
                len: 0,
            },
        );
        batch.clear();
        let reused = batch.take_buffer(32);
        assert_eq!(reused.as_ptr(), pointer);
        assert_eq!(reused.len(), 32);
    }

    #[test]
    fn send_batch_reuses_cleared_payload_buffers() {
        let mut batch = BatchSend::default();
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(b"first");
        let pointer = payload.as_ptr();
        batch.push(Transmit {
            destination: "127.0.0.1:4433".parse().unwrap(),
            source: None,
            ecn: None,
            contents: payload,
            segment_size: None,
            send_at: None,
        });
        batch.clear();
        let reused = batch.take_payload_buffer();
        assert_eq!(reused.as_ptr(), pointer);

        let pointer = reused.as_ptr();
        batch.recycle_payload_buffer(reused);
        let reused_again = batch.take_payload_buffer();
        assert_eq!(reused_again.as_ptr(), pointer);
    }

    #[test]
    fn receive_batch_splits_gro_payload_from_segment_metadata() {
        let mut batch = BatchRecv::default();
        let count = batch.push_received(
            b"abcdefghij".to_vec(),
            RecvMeta {
                local: None,
                remote: "127.0.0.1:4433".parse().unwrap(),
                interface: Some(3),
                ecn: Some(crate::EcnCodepoint::Ect0),
                segment_size: Some(4),
                len: 10,
            },
        );

        assert_eq!(count, 3);
        assert_eq!(
            batch
                .iter()
                .map(|(bytes, meta)| (bytes.to_vec(), meta.len))
                .collect::<Vec<_>>(),
            vec![
                (b"abcd".to_vec(), 4),
                (b"efgh".to_vec(), 4),
                (b"ij".to_vec(), 2)
            ]
        );
    }

    #[test]
    fn receive_batch_capacity_adapts_to_available_bursts() {
        let mut batch = BatchRecv::default();
        assert_eq!(batch.adaptive_receive_capacity(32), 1);

        batch.record_receive_batch(1, 1);
        assert_eq!(batch.adaptive_receive_capacity(32), 2);
        batch.record_receive_batch(2, 2);
        assert_eq!(batch.adaptive_receive_capacity(32), 4);
        batch.record_receive_batch(4, 1);
        assert_eq!(batch.adaptive_receive_capacity(32), 2);
        batch.record_receive_batch(2, 0);
        assert_eq!(batch.adaptive_receive_capacity(32), 1);
    }
}
