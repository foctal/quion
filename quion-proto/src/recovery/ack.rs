use core::time::Duration;

use smallvec::SmallVec;

use crate::{
    crypto::EncryptionLevel,
    ecn::EcnCodepoint,
    frame::{AckRange, Frame},
    ranges::RangeSet,
    varint::VarInt,
};

pub const DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;
/// Maximum disjoint received-packet ranges retained per packet number space.
///
/// A peer can create one range per packet by sending sparse packet numbers.
/// Retaining the newest ranges bounds both ACK frame size and connection memory.
pub const MAX_ACK_RANGES: usize = 256;

// Leave room for long headers and authentication within the minimum 1,200-byte
// path MTU. ACK ranges may be omitted under RFC 9000 Section 13.2.3; the receive
// history remains intact so omitted packets cannot be replayed to the caller.
const MAX_ACK_FRAME_BYTES: usize = 1024;
// Type, largest, delay, range count, first range, and three ECN counters.
const MAX_ACK_FIXED_BYTES: usize = 1 + 7 * 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedAck {
    pub level: EncryptionLevel,
    pub frame: Frame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckTracker {
    initial: AckSpace,
    handshake: AckSpace,
    application_data: AckSpace,
    max_ranges_per_space: usize,
}

impl AckTracker {
    /// Sets the retained range limit, clamped to one to keep ACKs possible.
    pub fn set_max_ranges_per_space(&mut self, max_ranges: usize) {
        let max_ranges = max_ranges.max(1);
        self.max_ranges_per_space = max_ranges;
        for level in [
            EncryptionLevel::Initial,
            EncryptionLevel::Handshake,
            EncryptionLevel::OneRtt,
        ] {
            self.space_mut(level).evict_to_limit(max_ranges);
        }
    }

    pub fn record_received_packet(
        &mut self,
        level: EncryptionLevel,
        packet_number: u64,
        ack_eliciting: bool,
    ) -> bool {
        self.record_received_packet_with_ecn(level, packet_number, ack_eliciting, None)
    }

    pub fn record_received_packet_with_ecn(
        &mut self,
        level: EncryptionLevel,
        packet_number: u64,
        ack_eliciting: bool,
        ecn: Option<EcnCodepoint>,
    ) -> bool {
        let max_ranges = self.max_ranges_per_space;
        self.space_mut(level)
            .record_received_packet(packet_number, ack_eliciting, ecn, max_ranges)
    }

    pub fn has_pending_ack(&self, level: EncryptionLevel) -> bool {
        self.space(level).has_pending_ack()
    }

    pub fn ack_frame(
        &self,
        level: EncryptionLevel,
        ack_delay: Duration,
        ack_delay_exponent: u8,
    ) -> Option<Frame> {
        self.space(level).ack_frame(ack_delay, ack_delay_exponent)
    }

    pub fn take_ack_frame(
        &mut self,
        level: EncryptionLevel,
        ack_delay: Duration,
        ack_delay_exponent: u8,
    ) -> Option<GeneratedAck> {
        let frame = self
            .space_mut(level)
            .take_ack_frame(ack_delay, ack_delay_exponent)?;
        Some(GeneratedAck { level, frame })
    }

    pub fn largest_received(&self, level: EncryptionLevel) -> Option<u64> {
        self.space(level).largest_received()
    }

    /// Returns whether the current receive gaps require an immediate ACK for
    /// the supplied ACK_FREQUENCY reordering threshold.
    pub fn requires_immediate_ack_for_reordering(
        &self,
        level: EncryptionLevel,
        packet_number: u64,
        previous_largest_ack_eliciting: Option<u64>,
        reordering_threshold: u64,
    ) -> bool {
        self.space(level).requires_immediate_ack_for_reordering(
            packet_number,
            previous_largest_ack_eliciting,
            reordering_threshold,
        )
    }

    pub fn largest_ack_eliciting_received(&self, level: EncryptionLevel) -> Option<u64> {
        self.space(level).largest_ack_eliciting_received
    }

    pub fn discard_space(&mut self, level: EncryptionLevel) {
        // 0-RTT and 1-RTT packets share the Application Data packet number
        // space. Discarding 0-RTT keys must not erase received packet numbers:
        // a server acknowledges accepted 0-RTT packets in 1-RTT packets.
        if level == EncryptionLevel::ZeroRtt {
            return;
        }
        *self.space_mut(level) = AckSpace::default();
    }

    pub fn retained_range_count(&self) -> usize {
        self.initial.received.len()
            + self.handshake.received.len()
            + self.application_data.received.len()
    }

    fn space(&self, level: EncryptionLevel) -> &AckSpace {
        match level {
            EncryptionLevel::Initial => &self.initial,
            EncryptionLevel::Handshake => &self.handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => &self.application_data,
        }
    }

    fn space_mut(&mut self, level: EncryptionLevel) -> &mut AckSpace {
        match level {
            EncryptionLevel::Initial => &mut self.initial,
            EncryptionLevel::Handshake => &mut self.handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => &mut self.application_data,
        }
    }
}

impl Default for AckTracker {
    fn default() -> Self {
        Self {
            initial: AckSpace::default(),
            handshake: AckSpace::default(),
            application_data: AckSpace::default(),
            max_ranges_per_space: MAX_ACK_RANGES,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AckSpace {
    received: RangeSet,
    forgotten_through: u64,
    pending_ack: bool,
    largest_ack_eliciting_received: Option<u64>,
    largest_acked_sent: Option<u64>,
    ecn: EcnCounts,
}

impl AckSpace {
    fn record_received_packet(
        &mut self,
        packet_number: u64,
        ack_eliciting: bool,
        ecn: Option<EcnCodepoint>,
        max_ranges: usize,
    ) -> bool {
        // Ranges below this watermark were deliberately evicted. Treat them as
        // duplicates rather than allowing replayed packets to refill the ACK
        // set or to be delivered to the frame dispatcher again.
        if packet_number < self.forgotten_through {
            return false;
        }
        if self.received.contains(packet_number) {
            return false;
        }

        self.received
            .insert(packet_number, packet_number.saturating_add(1));
        self.evict_to_limit(max_ranges);
        self.pending_ack |= ack_eliciting || ecn == Some(EcnCodepoint::Ce);
        if ack_eliciting {
            self.largest_ack_eliciting_received = Some(
                self.largest_ack_eliciting_received
                    .map_or(packet_number, |largest| largest.max(packet_number)),
            );
        }
        self.ecn.record(ecn);
        true
    }

    fn evict_to_limit(&mut self, max_ranges: usize) {
        while self.received.len() > max_ranges {
            let Some((_, end)) = self.received.pop_first() else {
                break;
            };
            self.forgotten_through = self.forgotten_through.max(end);
        }
    }

    const fn has_pending_ack(&self) -> bool {
        self.pending_ack
    }

    fn largest_received(&self) -> Option<u64> {
        self.received.max()
    }

    fn requires_immediate_ack_for_reordering(
        &self,
        packet_number: u64,
        previous_largest_ack_eliciting: Option<u64>,
        reordering_threshold: u64,
    ) -> bool {
        match reordering_threshold {
            0 => false,
            1 => {
                let previous = previous_largest_ack_eliciting.unwrap_or(0);
                packet_number < previous || packet_number > previous.saturating_add(1)
            }
            threshold => {
                let Some((largest_acked, largest_unacked)) = self
                    .largest_acked_sent
                    .zip(self.largest_ack_eliciting_received)
                else {
                    return false;
                };
                let Some(start) = largest_acked
                    .checked_sub(threshold)
                    .and_then(|value| value.checked_add(1))
                else {
                    return false;
                };
                let Some(end) = largest_unacked.checked_add(1) else {
                    return false;
                };
                self.received
                    .smallest_missing(start, end)
                    .is_some_and(|missing| largest_unacked.saturating_sub(missing) >= threshold)
            }
        }
    }

    fn ack_frame(&self, ack_delay: Duration, ack_delay_exponent: u8) -> Option<Frame> {
        let mut ranges = self.received.iter();
        let (largest_start, largest_end) = ranges.next_back()?;
        let largest = largest_end.checked_sub(1)?;
        let first_range = largest.checked_sub(largest_start)?;
        let mut ack_ranges = SmallVec::with_capacity(
            self.received
                .len()
                .saturating_sub(1)
                .min((MAX_ACK_FRAME_BYTES - MAX_ACK_FIXED_BYTES) / 2),
        );
        let mut wire_bytes = MAX_ACK_FIXED_BYTES;
        let mut previous_start = largest_start;

        for (start, end) in ranges.rev() {
            let range_largest = end - 1;
            let gap = previous_start.checked_sub(range_largest)?.checked_sub(2)?;
            let range = AckRange {
                gap: VarInt::new(gap).ok()?,
                range: VarInt::new(range_largest.checked_sub(start)?).ok()?,
            };
            wire_bytes += range.gap.encoded_len() + range.range.encoded_len();
            if wire_bytes > MAX_ACK_FRAME_BYTES {
                break;
            }
            ack_ranges.push(range);
            previous_start = start;
        }

        Some(Frame::Ack {
            largest: VarInt::new(largest).ok()?,
            delay: ack_delay_varint(ack_delay, ack_delay_exponent)?,
            first_range: VarInt::new(first_range).ok()?,
            ranges: ack_ranges,
            ecn: self.ecn.frame_counts()?,
        })
    }

    fn take_ack_frame(&mut self, ack_delay: Duration, ack_delay_exponent: u8) -> Option<Frame> {
        if !self.pending_ack {
            return None;
        }
        let frame = self.ack_frame(ack_delay, ack_delay_exponent)?;
        if let Frame::Ack { largest, .. } = &frame {
            self.largest_acked_sent = Some(largest.into_inner());
        }
        self.pending_ack = false;
        Some(frame)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct EcnCounts {
    ect0: u64,
    ect1: u64,
    ce: u64,
}

impl EcnCounts {
    fn record(&mut self, ecn: Option<EcnCodepoint>) {
        match ecn {
            Some(EcnCodepoint::Ect0) => self.ect0 = self.ect0.saturating_add(1),
            Some(EcnCodepoint::Ect1) => self.ect1 = self.ect1.saturating_add(1),
            Some(EcnCodepoint::Ce) => self.ce = self.ce.saturating_add(1),
            None => {}
        }
    }

    fn frame_counts(&self) -> Option<Option<(VarInt, VarInt, VarInt)>> {
        if self.ect0 == 0 && self.ect1 == 0 && self.ce == 0 {
            return Some(None);
        }
        Some(Some((
            VarInt::new(self.ect0).ok()?,
            VarInt::new(self.ect1).ok()?,
            VarInt::new(self.ce).ok()?,
        )))
    }
}

fn ack_delay_varint(delay: Duration, exponent: u8) -> Option<VarInt> {
    let divisor = 1u128.checked_shl(u32::from(exponent))?;
    let encoded = delay.as_micros() / divisor;
    let encoded = u64::try_from(encoded).ok()?;
    VarInt::new(encoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        #[test]
        fn generated_ack_always_fits_wire_budget(
            numbers in proptest::collection::vec(0..(1u64 << 62), 1..600),
            limit in 0usize..600,
        ) {
            let mut tracker = AckTracker::default();
            tracker.set_max_ranges_per_space(limit);
            for number in numbers {
                tracker.record_received_packet_with_ecn(
                    EncryptionLevel::OneRtt, number, true, Some(EcnCodepoint::Ce),
                );
                proptest::prop_assert!(tracker.retained_range_count() <= limit.max(1));
            }
            let ack = tracker.take_ack_frame(EncryptionLevel::OneRtt, Duration::from_secs(1), 0).unwrap();
            proptest::prop_assert!(ack.frame.encoded_len() <= MAX_ACK_FRAME_BYTES);
        }
    }

    #[test]
    fn zero_range_limit_preserves_ack_progress_after_live_update() {
        let mut tracker = AckTracker::default();
        for number in [0, 2, 4] {
            tracker.record_received_packet(EncryptionLevel::OneRtt, number, true);
        }
        tracker.set_max_ranges_per_space(0);
        assert_eq!(tracker.retained_range_count(), 1);
        assert!(!tracker.record_received_packet(EncryptionLevel::OneRtt, 0, true));
        assert!(tracker.record_received_packet(EncryptionLevel::OneRtt, 6, true));
        assert!(
            tracker
                .take_ack_frame(EncryptionLevel::OneRtt, Duration::ZERO, 3)
                .is_some()
        );
    }

    #[test]
    fn sparse_ack_wire_size_is_bounded_without_forgetting_replay_history() {
        let mut tracker = AckTracker::default();
        for number in 0..MAX_ACK_RANGES as u64 {
            tracker.record_received_packet_with_ecn(
                EncryptionLevel::OneRtt,
                number << 32,
                true,
                Some(EcnCodepoint::Ce),
            );
        }
        let ack = tracker
            .take_ack_frame(EncryptionLevel::OneRtt, Duration::ZERO, 3)
            .unwrap()
            .frame;
        assert!(
            ack.encoded_len() <= 1024,
            "ACK length: {}",
            ack.encoded_len()
        );
        let Frame::Ack { largest, ecn, .. } = ack else {
            panic!("expected ACK")
        };
        assert_eq!(largest.into_inner(), (MAX_ACK_RANGES as u64 - 1) << 32);
        assert_eq!(ecn.unwrap().2.into_inner(), MAX_ACK_RANGES as u64);
        assert!(!tracker.record_received_packet(EncryptionLevel::OneRtt, 0, true));
    }

    #[test]
    fn generates_ack_ranges_from_received_packets() {
        let mut tracker = AckTracker::default();
        for packet_number in [1, 2, 5, 6, 7, 10] {
            assert!(tracker.record_received_packet(EncryptionLevel::Initial, packet_number, true));
        }

        let ack = tracker
            .ack_frame(
                EncryptionLevel::Initial,
                Duration::from_micros(24),
                DEFAULT_ACK_DELAY_EXPONENT,
            )
            .unwrap();

        assert_eq!(
            ack,
            Frame::Ack {
                largest: VarInt::from_u32(10),
                delay: VarInt::from_u32(3),
                first_range: VarInt::ZERO,
                ranges: vec![
                    AckRange {
                        gap: VarInt::from_u32(1),
                        range: VarInt::from_u32(2),
                    },
                    AckRange {
                        gap: VarInt::from_u32(1),
                        range: VarInt::from_u32(1),
                    },
                ]
                .into(),
                ecn: None,
            }
        );
    }

    #[test]
    fn take_ack_frame_only_when_ack_eliciting_packet_is_pending() {
        let mut tracker = AckTracker::default();
        tracker.record_received_packet(EncryptionLevel::Handshake, 4, false);
        assert!(
            tracker
                .take_ack_frame(
                    EncryptionLevel::Handshake,
                    Duration::ZERO,
                    DEFAULT_ACK_DELAY_EXPONENT,
                )
                .is_none()
        );

        assert!(tracker.record_received_packet(EncryptionLevel::Handshake, 5, true));
        let generated = tracker
            .take_ack_frame(
                EncryptionLevel::Handshake,
                Duration::ZERO,
                DEFAULT_ACK_DELAY_EXPONENT,
            )
            .unwrap();
        assert_eq!(generated.level, EncryptionLevel::Handshake);
        assert!(!tracker.has_pending_ack(EncryptionLevel::Handshake));
        assert!(
            tracker
                .take_ack_frame(
                    EncryptionLevel::Handshake,
                    Duration::ZERO,
                    DEFAULT_ACK_DELAY_EXPONENT,
                )
                .is_none()
        );
    }

    #[test]
    fn duplicate_packets_do_not_reopen_ack_pending_state() {
        let mut tracker = AckTracker::default();
        assert!(tracker.record_received_packet(EncryptionLevel::OneRtt, 9, true));
        assert!(
            tracker
                .take_ack_frame(
                    EncryptionLevel::OneRtt,
                    Duration::ZERO,
                    DEFAULT_ACK_DELAY_EXPONENT,
                )
                .is_some()
        );
        assert!(!tracker.record_received_packet(EncryptionLevel::OneRtt, 9, true));
        assert!(!tracker.has_pending_ack(EncryptionLevel::OneRtt));
    }

    #[test]
    fn ack_frame_includes_received_ecn_counters() {
        let mut tracker = AckTracker::default();
        assert!(tracker.record_received_packet_with_ecn(
            EncryptionLevel::OneRtt,
            1,
            true,
            Some(EcnCodepoint::Ect0),
        ));
        assert!(tracker.record_received_packet_with_ecn(
            EncryptionLevel::OneRtt,
            2,
            true,
            Some(EcnCodepoint::Ce),
        ));
        assert!(!tracker.record_received_packet_with_ecn(
            EncryptionLevel::OneRtt,
            2,
            true,
            Some(EcnCodepoint::Ce),
        ));

        let ack = tracker
            .ack_frame(
                EncryptionLevel::OneRtt,
                Duration::ZERO,
                DEFAULT_ACK_DELAY_EXPONENT,
            )
            .unwrap();

        assert_eq!(
            ack,
            Frame::Ack {
                largest: VarInt::from_u32(2),
                delay: VarInt::ZERO,
                first_range: VarInt::from_u32(1),
                ranges: Default::default(),
                ecn: Some((VarInt::from_u32(1), VarInt::ZERO, VarInt::from_u32(1))),
            }
        );
    }

    #[test]
    fn ce_mark_requests_ack_even_for_non_ack_eliciting_packet() {
        let mut tracker = AckTracker::default();
        assert!(tracker.record_received_packet_with_ecn(
            EncryptionLevel::OneRtt,
            0,
            false,
            Some(EcnCodepoint::Ce),
        ));

        assert!(tracker.has_pending_ack(EncryptionLevel::OneRtt));
        assert!(matches!(
            tracker.take_ack_frame(
                EncryptionLevel::OneRtt,
                Duration::ZERO,
                DEFAULT_ACK_DELAY_EXPONENT,
            ),
            Some(GeneratedAck {
                frame: Frame::Ack { .. },
                ..
            })
        ));
    }

    #[test]
    fn bounds_sparse_ack_ranges_and_drops_evicted_packet_numbers() {
        let mut tracker = AckTracker::default();
        for packet_number in (0..=MAX_ACK_RANGES as u64).map(|value| value * 2) {
            assert!(tracker.record_received_packet(EncryptionLevel::OneRtt, packet_number, true));
        }

        let ack = tracker
            .ack_frame(
                EncryptionLevel::OneRtt,
                Duration::ZERO,
                DEFAULT_ACK_DELAY_EXPONENT,
            )
            .unwrap();
        let Frame::Ack {
            largest, ranges, ..
        } = ack
        else {
            panic!("ack tracker must generate an ACK frame");
        };
        assert_eq!(largest.into_inner(), (MAX_ACK_RANGES as u64) * 2);
        assert_eq!(ranges.len(), MAX_ACK_RANGES - 1);
        assert!(!tracker.record_received_packet(EncryptionLevel::OneRtt, 0, true));
    }

    #[test]
    fn configured_ack_range_limit_evicts_oldest_ranges() {
        let mut tracker = AckTracker::default();
        tracker.set_max_ranges_per_space(2);
        for packet_number in [1, 3, 5] {
            assert!(tracker.record_received_packet(EncryptionLevel::OneRtt, packet_number, true));
        }

        assert_eq!(tracker.retained_range_count(), 2);
        assert!(!tracker.record_received_packet(EncryptionLevel::OneRtt, 1, true));
    }

    #[test]
    fn reports_largest_received_per_packet_number_space() {
        let mut tracker = AckTracker::default();
        assert_eq!(tracker.largest_received(EncryptionLevel::Initial), None);
        tracker.record_received_packet(EncryptionLevel::Initial, 2, true);
        tracker.record_received_packet(EncryptionLevel::Initial, 7, true);
        tracker.record_received_packet(EncryptionLevel::Handshake, 5, true);

        assert_eq!(tracker.largest_received(EncryptionLevel::Initial), Some(7));
        assert_eq!(
            tracker.largest_received(EncryptionLevel::Handshake),
            Some(5)
        );
        assert_eq!(tracker.largest_received(EncryptionLevel::OneRtt), None);
    }

    #[test]
    fn discard_space_clears_received_ranges_and_pending_ack() {
        let mut tracker = AckTracker::default();
        assert!(tracker.record_received_packet(EncryptionLevel::Initial, 1, true));
        assert!(tracker.record_received_packet(EncryptionLevel::OneRtt, 9, true));

        tracker.discard_space(EncryptionLevel::Initial);

        assert_eq!(tracker.largest_received(EncryptionLevel::Initial), None);
        assert!(!tracker.has_pending_ack(EncryptionLevel::Initial));
        assert_eq!(tracker.largest_received(EncryptionLevel::OneRtt), Some(9));
        assert!(tracker.has_pending_ack(EncryptionLevel::OneRtt));
    }

    #[test]
    fn zero_rtt_and_one_rtt_share_application_data_packet_numbers() {
        let mut tracker = AckTracker::default();
        assert!(tracker.record_received_packet(EncryptionLevel::ZeroRtt, 4, true));
        assert!(!tracker.record_received_packet(EncryptionLevel::OneRtt, 4, true));
        assert_eq!(tracker.largest_received(EncryptionLevel::OneRtt), Some(4));

        tracker.discard_space(EncryptionLevel::ZeroRtt);

        assert_eq!(tracker.largest_received(EncryptionLevel::OneRtt), Some(4));
        let ack = tracker
            .take_ack_frame(
                EncryptionLevel::OneRtt,
                Duration::ZERO,
                DEFAULT_ACK_DELAY_EXPONENT,
            )
            .unwrap();
        assert_eq!(ack.level, EncryptionLevel::OneRtt);
        assert!(matches!(
            ack.frame,
            Frame::Ack {
                largest,
                first_range,
                ..
            } if largest.into_inner() == 4 && first_range == VarInt::ZERO
        ));
    }
}
