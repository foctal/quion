use std::collections::{BTreeMap, VecDeque};

use smallvec::SmallVec;
use tracing::{debug, trace, trace_span};
use web_time::{Duration, Instant};

use crate::{crypto::EncryptionLevel, ecn::EcnCodepoint, frame::Frame, timer::Timer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentPacket {
    pub level: EncryptionLevel,
    pub packet_number: u64,
    pub bytes: u64,
    pub ack_eliciting: bool,
    pub ecn: Option<EcnCodepoint>,
    pub sent_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub level: EncryptionLevel,
    pub packets: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutOutcome {
    Loss {
        lost_packets: Vec<LossEvent>,
        persistent_congestion: bool,
    },
    Probe(Probe),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossEvent {
    pub level: EncryptionLevel,
    pub packet_number: u64,
    pub bytes: u64,
    pub sent_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckOutcome {
    pub acked_packet_numbers: SmallVec<[u64; 32]>,
    pub newly_acked_packets: SmallVec<[SentPacket; 32]>,
    pub acked_bytes: u64,
    pub largest_acked: u64,
    pub largest_sent: u64,
    pub rtt_sample: Option<Duration>,
    pub lost_packets: Vec<LossEvent>,
    pub persistent_congestion: bool,
    pub ecn: EcnOutcome,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EcnOutcome {
    pub validated: bool,
    pub validation_failed: bool,
    pub ce_delta: u64,
}

#[derive(Debug, Clone)]
pub struct LossDetector {
    initial: LossSpace,
    handshake: LossSpace,
    application_data: LossSpace,
    smoothed_rtt: Duration,
    latest_rtt: Option<Duration>,
    min_rtt: Option<Duration>,
    rttvar: Duration,
    max_ack_delay: Duration,
    ack_delay_exponent: u8,
    handshake_confirmed: bool,
    pto_count: u32,
}

const PACKET_THRESHOLD: u64 = 3;
const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

fn ecn_count_total(ect0: u64, ect1: u64, ce: u64) -> u128 {
    u128::from(ect0) + u128::from(ect1) + u128::from(ce)
}

impl LossDetector {
    pub fn new() -> Self {
        Self {
            initial: LossSpace::default(),
            handshake: LossSpace::default(),
            application_data: LossSpace::default(),
            smoothed_rtt: Duration::from_millis(333),
            latest_rtt: None,
            min_rtt: None,
            rttvar: Duration::from_millis(166),
            max_ack_delay: Duration::from_millis(25),
            ack_delay_exponent: 3,
            handshake_confirmed: false,
            pto_count: 0,
        }
    }

    pub fn set_smoothed_rtt(&mut self, rtt: Duration) {
        self.smoothed_rtt = rtt;
        self.latest_rtt = Some(rtt);
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |min| min.min(rtt)));
        self.rttvar = rtt.mul_f64(0.5);
    }

    pub fn reset_path_rtt(&mut self) {
        self.smoothed_rtt = Duration::from_millis(333);
        self.latest_rtt = None;
        self.min_rtt = None;
        self.rttvar = Duration::from_millis(166);
        self.pto_count = 0;
    }

    pub fn set_ack_delay_config(&mut self, max_ack_delay: Duration, ack_delay_exponent: u8) {
        self.max_ack_delay = max_ack_delay;
        self.ack_delay_exponent = ack_delay_exponent;
    }

    pub fn set_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.max_ack_delay = max_ack_delay;
    }

    pub fn confirm_handshake(&mut self) {
        self.handshake_confirmed = true;
    }

    pub const fn is_handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    pub fn on_packet_sent(
        &mut self,
        level: EncryptionLevel,
        packet_number: u64,
        bytes: u64,
        ack_eliciting: bool,
        sent_at: Instant,
    ) {
        self.on_packet_sent_with_ecn(level, packet_number, bytes, ack_eliciting, None, sent_at);
    }

    pub fn on_packet_sent_with_ecn(
        &mut self,
        level: EncryptionLevel,
        packet_number: u64,
        bytes: u64,
        ack_eliciting: bool,
        ecn: Option<EcnCodepoint>,
        sent_at: Instant,
    ) {
        trace!(
            level = ?level,
            packet_number,
            bytes,
            ack_eliciting,
            ecn = ?ecn,
            "tracking sent packet for loss detection"
        );
        let space = self.space_mut(level);
        space.largest_sent = Some(
            space
                .largest_sent
                .map_or(packet_number, |largest| largest.max(packet_number)),
        );
        let packet = SentPacket {
            level,
            packet_number,
            bytes,
            ack_eliciting,
            ecn,
            sent_at,
        };
        if space.sent.insert(packet_number, packet).is_none() {
            let count = match ecn {
                Some(EcnCodepoint::Ect0) => Some(&mut space.sent_ecn.ect0),
                Some(EcnCodepoint::Ect1) => Some(&mut space.sent_ecn.ect1),
                Some(EcnCodepoint::Ce) => Some(&mut space.sent_ecn.ce),
                None => None,
            };
            if let Some(count) = count {
                *count = count.saturating_add(1);
            }
        }
        if ack_eliciting
            && space
                .last_ack_eliciting
                .is_none_or(|last| last.sent_at <= sent_at)
        {
            space.last_ack_eliciting = Some(packet);
        }
    }

    pub fn acknowledges_unsent_packet(&self, level: EncryptionLevel, frame: &Frame) -> bool {
        let Frame::Ack { largest, .. } = frame else {
            return false;
        };
        self.space(level)
            .largest_sent
            .is_none_or(|largest_sent| largest.into_inner() > largest_sent)
    }

    pub fn has_valid_ack_ranges(&self, frame: &Frame) -> bool {
        for_each_acked_packet_range(frame, |_, _| {}).is_some()
    }

    pub fn on_ack_frame(
        &mut self,
        level: EncryptionLevel,
        frame: &Frame,
        now: Instant,
    ) -> AckOutcome {
        self.try_on_ack_frame(level, frame, now)
            .unwrap_or_else(empty_ack_outcome)
    }

    pub(crate) fn try_on_ack_frame(
        &mut self,
        level: EncryptionLevel,
        frame: &Frame,
        now: Instant,
    ) -> Option<AckOutcome> {
        let _span =
            trace_span!("quion.proto.loss", action = "on_ack_frame", level = ?level).entered();
        let Frame::Ack { largest, .. } = frame else {
            return None;
        };
        let largest_sent = self.space(level).largest_sent?;
        let acked = acknowledged_sent_packet_numbers(self.space(level), frame)?;
        let largest_acked = largest.into_inner();
        let latest_rtt = self
            .space(level)
            .sent
            .get(&largest_acked)
            .map(|packet| now.duration_since(packet.sent_at));
        let ack_delay = ack_delay_duration(
            frame,
            level,
            self.max_ack_delay,
            self.ack_delay_exponent,
            self.handshake_confirmed,
        );
        let space = self.space_mut(level);
        let advances_largest = space
            .largest_acked
            .is_none_or(|previous| largest_acked > previous);
        space.largest_acked = Some(
            space
                .largest_acked
                .map_or(largest_acked, |current| current.max(largest_acked)),
        );
        let mut acked_bytes = 0;
        let mut newly_acked_packets = SmallVec::new();
        let mut newly_acked_ect0 = 0;
        let mut newly_acked_ect1 = 0;
        let mut newly_acked_ce = 0;
        let mut removed_last_ack_eliciting = false;
        for packet_number in &acked {
            if let Some(packet) = space.sent.remove(packet_number) {
                removed_last_ack_eliciting |= space
                    .last_ack_eliciting
                    .is_some_and(|last| last.packet_number == *packet_number);
                newly_acked_packets.push(packet);
                if packet.ack_eliciting {
                    acked_bytes += packet.bytes;
                }
                match packet.ecn {
                    Some(EcnCodepoint::Ect0) => newly_acked_ect0 += 1,
                    Some(EcnCodepoint::Ect1) => newly_acked_ect1 += 1,
                    Some(EcnCodepoint::Ce) => newly_acked_ce += 1,
                    None => {}
                }
            }
        }
        if removed_last_ack_eliciting {
            space.refresh_last_ack_eliciting();
        }
        if let Some(sample) = latest_rtt {
            self.update_rtt(sample, ack_delay);
            trace!(rtt_ms = sample.as_millis() as u64, "updated RTT sample");
        }
        if acked_bytes > 0 {
            self.pto_count = 0;
        }
        // RFC 9000 section 13.4.2.1: stale/reordered ACKs must not fail
        // validation or roll back cumulative ECN counters.
        let ecn = if advances_largest || self.space(level).ecn_failed {
            self.validate_ecn_counts(
                level,
                frame,
                newly_acked_ect0,
                newly_acked_ect1,
                newly_acked_ce,
            )
        } else {
            EcnOutcome::default()
        };
        let lost_packets = self.detect_losses(level, largest_acked, now);
        let persistent_congestion = self.detect_persistent_congestion(&lost_packets);
        trace!(
            acked_packets = acked.len(),
            acked_bytes,
            lost_packets = lost_packets.len(),
            persistent_congestion,
            ecn_ce_delta = ecn.ce_delta,
            "computed ack outcome"
        );
        Some(AckOutcome {
            acked_packet_numbers: acked,
            newly_acked_packets,
            acked_bytes,
            largest_acked,
            largest_sent,
            rtt_sample: latest_rtt,
            lost_packets,
            persistent_congestion,
            ecn,
        })
    }

    pub fn timeout(&self) -> Option<Instant> {
        let loss = self.loss_deadline().map(|(_, deadline)| deadline);
        let pto = self.pto_deadline().map(|(_, deadline)| deadline);
        match (loss, pto) {
            (Some(loss), Some(pto)) => Some(loss.min(pto)),
            (Some(loss), None) => Some(loss),
            (None, Some(pto)) => Some(pto),
            (None, None) => None,
        }
    }

    pub fn on_timeout(&mut self, now: Instant) -> Option<TimeoutOutcome> {
        if let Some((level, deadline)) = self.loss_deadline()
            && now >= deadline
        {
            let largest_acked = self.space(level).largest_acked?;
            let lost_packets = self.detect_losses(level, largest_acked, now);
            if !lost_packets.is_empty() {
                let persistent_congestion = self.detect_persistent_congestion(&lost_packets);
                return Some(TimeoutOutcome::Loss {
                    lost_packets,
                    persistent_congestion,
                });
            }
        }

        let (level, deadline) = self.pto_deadline()?;
        if now < deadline {
            return None;
        }

        self.pto_count = self.pto_count.saturating_add(1);
        debug!(level = ?level, pto_count = self.pto_count, "loss PTO expired");
        Some(TimeoutOutcome::Probe(Probe { level, packets: 2 }))
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.initial.bytes_in_flight()
            + self.handshake.bytes_in_flight()
            + self.application_data.bytes_in_flight()
    }

    pub fn discard_space(&mut self, level: EncryptionLevel) -> u64 {
        if level == EncryptionLevel::ZeroRtt {
            return self.application_data.discard_level(level);
        }
        let bytes_in_flight = self.space(level).bytes_in_flight();
        *self.space_mut(level) = LossSpace::default();
        bytes_in_flight
    }

    pub const fn timer(&self) -> Timer {
        Timer::LossDetection
    }

    pub const fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    pub const fn latest_rtt(&self) -> Option<Duration> {
        self.latest_rtt
    }

    pub const fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    pub const fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// Three probe intervals without retransmission backoff. Repeated losses
    /// must not keep extending an otherwise inactive connection's lifetime.
    pub fn idle_timeout_floor(&self) -> Duration {
        let delay = if self.handshake_confirmed {
            self.max_ack_delay
        } else {
            Duration::ZERO
        };
        self.base_pto_duration()
            .saturating_add(delay)
            .saturating_mul(3)
    }

    pub fn close_drain_duration(&self) -> Duration {
        self.application_pto_duration(self.handshake_confirmed) * 3
    }

    pub fn one_rtt_key_retirement_duration(&self) -> Duration {
        self.application_pto_duration(true) * 3
    }

    fn validate_ecn_counts(
        &mut self,
        level: EncryptionLevel,
        frame: &Frame,
        newly_acked_ect0: u64,
        newly_acked_ect1: u64,
        newly_acked_ce: u64,
    ) -> EcnOutcome {
        if self.space(level).ecn_failed {
            return EcnOutcome {
                validated: false,
                validation_failed: true,
                ce_delta: 0,
            };
        }
        let Frame::Ack {
            ecn: Some((ect0, ect1, ce)),
            ..
        } = frame
        else {
            if ecn_count_total(newly_acked_ect0, newly_acked_ect1, newly_acked_ce) > 0 {
                self.space_mut(level).ecn_failed = true;
                return EcnOutcome {
                    validated: false,
                    validation_failed: true,
                    ce_delta: 0,
                };
            }
            return EcnOutcome::default();
        };
        let current = EcnCounts {
            ect0: ect0.into_inner(),
            ect1: ect1.into_inner(),
            ce: ce.into_inner(),
        };
        let previous = self.space(level).ecn;
        let delta = EcnCounts {
            ect0: current.ect0.saturating_sub(previous.ect0),
            ect1: current.ect1.saturating_sub(previous.ect1),
            ce: current.ce.saturating_sub(previous.ce),
        };
        let sent = self.space(level).sent_ecn;
        // Cumulative counters can include packets omitted from this ACK's
        // ranges. Bound them by actual marked sends, not just newly ACKed ones.
        let validation_failed = current.ect0 < previous.ect0
            || current.ect1 < previous.ect1
            || current.ce < previous.ce
            || current.ect0 > sent.ect0
            || current.ect1 > sent.ect1
            || ecn_count_total(current.ect0, current.ect1, current.ce)
                > ecn_count_total(sent.ect0, sent.ect1, sent.ce)
            || ecn_count_total(delta.ect0, 0, delta.ce) < u128::from(newly_acked_ect0)
            || ecn_count_total(0, delta.ect1, delta.ce) < u128::from(newly_acked_ect1)
            || ecn_count_total(delta.ect0, delta.ect1, delta.ce)
                < ecn_count_total(newly_acked_ect0, newly_acked_ect1, newly_acked_ce);
        if validation_failed {
            self.space_mut(level).ecn_failed = true;
            return EcnOutcome {
                validated: false,
                validation_failed: true,
                ce_delta: 0,
            };
        }
        let space = self.space_mut(level);
        space.ecn = current;
        EcnOutcome {
            validated: true,
            validation_failed: false,
            ce_delta: delta.ce,
        }
    }

    fn detect_losses(
        &mut self,
        level: EncryptionLevel,
        largest_acked: u64,
        now: Instant,
    ) -> Vec<LossEvent> {
        let time_threshold = self.loss_delay();
        let packet_threshold_end = largest_acked
            .checked_sub(PACKET_THRESHOLD)
            .map_or(0, |packet_number| packet_number + 1);
        let mut lost = Vec::new();
        let sent = &self.space(level).sent;

        // Every packet below this boundary is lost by packet threshold. Only
        // the two packet numbers immediately preceding the largest ACK can
        // additionally be lost by time threshold, so do not scan newer
        // outstanding packets on every ACK.
        lost.extend(
            sent.before(packet_threshold_end)
                .filter(|packet| packet.ack_eliciting)
                .map(|packet| LossEvent {
                    level: packet.level,
                    packet_number: packet.packet_number,
                    bytes: packet.bytes,
                    sent_at: packet.sent_at,
                }),
        );
        for packet_number in packet_threshold_end..largest_acked {
            let Some(packet) = sent.get(&packet_number) else {
                continue;
            };
            if packet.ack_eliciting && now.duration_since(packet.sent_at) >= time_threshold {
                lost.push(LossEvent {
                    level: packet.level,
                    packet_number,
                    bytes: packet.bytes,
                    sent_at: packet.sent_at,
                });
            }
        }

        let space = self.space_mut(level);
        let removed_last_ack_eliciting = space.last_ack_eliciting.is_some_and(|last| {
            lost.iter()
                .any(|event| event.packet_number == last.packet_number)
        });
        for event in &lost {
            space.sent.remove(&event.packet_number);
        }
        if removed_last_ack_eliciting {
            space.refresh_last_ack_eliciting();
        }
        if !lost.is_empty() {
            trace!(
                level = ?level,
                largest_acked,
                lost_packets = lost.len(),
                "detected lost packets"
            );
        }
        lost
    }

    fn detect_persistent_congestion(&self, lost_packets: &[LossEvent]) -> bool {
        if lost_packets.len() < 2 {
            return false;
        }
        let Some(first) = lost_packets.iter().map(|packet| packet.sent_at).min() else {
            return false;
        };
        let Some(last) = lost_packets.iter().map(|packet| packet.sent_at).max() else {
            return false;
        };
        last.duration_since(first)
            >= self
                .persistent_congestion_duration()
                .max(Duration::from_millis(1))
    }

    fn persistent_congestion_duration(&self) -> Duration {
        (self.base_pto_duration() + self.max_ack_delay) * PERSISTENT_CONGESTION_THRESHOLD
    }

    fn update_rtt(&mut self, sample: Duration, ack_delay: Duration) {
        let had_sample = self.latest_rtt.is_some();
        self.latest_rtt = Some(sample);
        let min_rtt = self.min_rtt.map_or(sample, |min| min.min(sample));
        self.min_rtt = Some(min_rtt);
        let adjusted = if sample >= min_rtt + ack_delay {
            sample - ack_delay
        } else {
            sample
        };
        if had_sample {
            let variance_sample = duration_abs_diff(self.smoothed_rtt, adjusted);
            self.rttvar = self.rttvar.mul_f64(0.75) + variance_sample.mul_f64(0.25);
            self.smoothed_rtt = self.smoothed_rtt.mul_f64(0.875) + adjusted.mul_f64(0.125);
        } else {
            self.smoothed_rtt = adjusted;
            self.rttvar = adjusted.mul_f64(0.5);
        }
    }

    fn base_pto_duration(&self) -> Duration {
        self.smoothed_rtt
            .saturating_add(self.rttvar.mul_f64(4.0).max(Duration::from_millis(1)))
    }

    fn pto_duration(&self) -> Duration {
        let base = self.base_pto_duration().max(Duration::from_millis(1));
        base * (1 << self.pto_count.min(16))
    }

    fn application_pto_duration(&self, include_ack_delay: bool) -> Duration {
        let delay = if include_ack_delay {
            self.max_ack_delay
        } else {
            Duration::ZERO
        };
        self.base_pto_duration()
            .saturating_add(delay)
            .saturating_mul(1 << self.pto_count.min(16))
    }

    fn pto_deadline(&self) -> Option<(EncryptionLevel, Instant)> {
        let pto = self.pto_duration();
        [
            (EncryptionLevel::Initial, self.initial.next_pto(pto)),
            (EncryptionLevel::Handshake, self.handshake.next_pto(pto)),
        ]
        .into_iter()
        .filter_map(|(level, deadline)| deadline.map(|deadline| (level, deadline)))
        .chain(
            self.application_data
                .next_pto_packet(self.application_pto_duration(self.handshake_confirmed)),
        )
        .min_by_key(|(_, deadline)| *deadline)
    }

    fn loss_deadline(&self) -> Option<(EncryptionLevel, Instant)> {
        let threshold = self.loss_delay();
        [
            EncryptionLevel::Initial,
            EncryptionLevel::Handshake,
            EncryptionLevel::OneRtt,
        ]
        .into_iter()
        .filter_map(|level| {
            let space = self.space(level);
            let largest_acked = space.largest_acked?;
            space
                .sent
                .before(largest_acked)
                .find(|packet| packet.ack_eliciting)
                .map(|packet| packet.sent_at + threshold)
                .map(|deadline| (level, deadline))
        })
        .min_by_key(|(_, deadline)| *deadline)
    }

    fn loss_delay(&self) -> Duration {
        self.latest_rtt
            .unwrap_or(self.smoothed_rtt)
            .max(self.smoothed_rtt)
            .mul_f64(1.125)
            .max(Duration::from_millis(1))
    }

    fn space(&self, level: EncryptionLevel) -> &LossSpace {
        match level {
            EncryptionLevel::Initial => &self.initial,
            EncryptionLevel::Handshake => &self.handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => &self.application_data,
        }
    }

    fn space_mut(&mut self, level: EncryptionLevel) -> &mut LossSpace {
        match level {
            EncryptionLevel::Initial => &mut self.initial,
            EncryptionLevel::Handshake => &mut self.handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => &mut self.application_data,
        }
    }
}

fn ack_delay_duration(
    frame: &Frame,
    level: EncryptionLevel,
    max_ack_delay: Duration,
    ack_delay_exponent: u8,
    handshake_confirmed: bool,
) -> Duration {
    if level != EncryptionLevel::OneRtt {
        return Duration::ZERO;
    }
    let Frame::Ack { delay, .. } = frame else {
        return Duration::ZERO;
    };
    let micros = delay
        .into_inner()
        .checked_shl(u32::from(ack_delay_exponent))
        .unwrap_or(u64::MAX);
    let ack_delay = Duration::from_micros(micros);
    if handshake_confirmed {
        ack_delay.min(max_ack_delay)
    } else {
        ack_delay
    }
}

fn duration_abs_diff(lhs: Duration, rhs: Duration) -> Duration {
    lhs.abs_diff(rhs)
}

impl Default for LossDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default, Clone)]
struct LossSpace {
    sent: SentPacketSlots,
    last_ack_eliciting: Option<SentPacket>,
    largest_sent: Option<u64>,
    largest_acked: Option<u64>,
    ecn: EcnCounts,
    sent_ecn: EcnCounts,
    ecn_failed: bool,
}

#[derive(Debug, Default, Clone)]
struct SentPacketSlots {
    base: u64,
    slots: VecDeque<Option<SentPacket>>,
    sparse: Option<BTreeMap<u64, SentPacket>>,
}

impl SentPacketSlots {
    fn insert(&mut self, packet_number: u64, packet: SentPacket) -> Option<SentPacket> {
        if let Some(sparse) = self.sparse.as_mut() {
            return sparse.insert(packet_number, packet);
        }
        if self.slots.is_empty() {
            self.base = packet_number;
            self.slots.push_back(Some(packet));
            return None;
        }
        if packet_number < self.base {
            let prepend = self.base - packet_number;
            if prepend > 65_536 {
                return self.promote_to_sparse_and_insert(packet_number, packet);
            }
            let prepend = usize::try_from(prepend).unwrap_or(65_536);
            for _ in 0..prepend {
                self.slots.push_front(None);
            }
            self.base = packet_number;
        }
        let distance = packet_number - self.base;
        if distance > 65_536 {
            return self.promote_to_sparse_and_insert(packet_number, packet);
        }
        let index = usize::try_from(distance).unwrap_or(65_536);
        if index >= self.slots.len() {
            self.slots.resize(index.saturating_add(1), None);
        }
        self.slots[index].replace(packet)
    }

    fn get(&self, packet_number: &u64) -> Option<&SentPacket> {
        if let Some(sparse) = self.sparse.as_ref() {
            return sparse.get(packet_number);
        }
        let index = usize::try_from(packet_number.checked_sub(self.base)?).ok()?;
        self.slots.get(index)?.as_ref()
    }

    fn remove(&mut self, packet_number: &u64) -> Option<SentPacket> {
        if let Some(sparse) = self.sparse.as_mut() {
            return sparse.remove(packet_number);
        }
        let index = usize::try_from(packet_number.checked_sub(self.base)?).ok()?;
        let packet = self.slots.get_mut(index)?.take()?;
        self.trim_empty_edges();
        Some(packet)
    }

    fn values(&self) -> SentPacketValues<'_> {
        match self.sparse.as_ref() {
            Some(sparse) => SentPacketValues::Sparse(sparse.values()),
            None => SentPacketValues::Dense(self.slots.iter()),
        }
    }

    fn before(&self, end: u64) -> impl Iterator<Item = &SentPacket> {
        self.values()
            .take_while(move |packet| packet.packet_number < end)
    }

    fn packet_numbers_in_range(&self, start: u64, end: u64) -> impl Iterator<Item = u64> + '_ {
        self.values()
            .skip_while(move |packet| packet.packet_number < start)
            .take_while(move |packet| packet.packet_number <= end)
            .map(|packet| packet.packet_number)
    }

    fn retain(&mut self, mut keep: impl FnMut(&SentPacket) -> bool) {
        if let Some(sparse) = self.sparse.as_mut() {
            sparse.retain(|_, packet| keep(packet));
            return;
        }
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|packet| !keep(packet)) {
                *slot = None;
            }
        }
        self.trim_empty_edges();
    }

    fn trim_empty_edges(&mut self) {
        if self.sparse.is_some() {
            return;
        }
        while self.slots.front().is_some_and(Option::is_none) {
            self.slots.pop_front();
            self.base = self.base.saturating_add(1);
        }
        while self.slots.back().is_some_and(Option::is_none) {
            self.slots.pop_back();
        }
        if self.slots.is_empty() {
            self.base = 0;
        }
    }

    fn promote_to_sparse_and_insert(
        &mut self,
        packet_number: u64,
        packet: SentPacket,
    ) -> Option<SentPacket> {
        let mut sparse = BTreeMap::new();
        for packet in self.slots.drain(..).flatten() {
            sparse.insert(packet.packet_number, packet);
        }
        self.base = 0;
        let replaced = sparse.insert(packet_number, packet);
        self.sparse = Some(sparse);
        replaced
    }
}

enum SentPacketValues<'a> {
    Dense(std::collections::vec_deque::Iter<'a, Option<SentPacket>>),
    Sparse(std::collections::btree_map::Values<'a, u64, SentPacket>),
}

impl<'a> Iterator for SentPacketValues<'a> {
    type Item = &'a SentPacket;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Dense(iter) => iter.find_map(Option::as_ref),
            Self::Sparse(iter) => iter.next(),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct EcnCounts {
    ect0: u64,
    ect1: u64,
    ce: u64,
}

impl LossSpace {
    fn next_pto(&self, duration: Duration) -> Option<Instant> {
        self.last_ack_eliciting
            .map(|packet| packet.sent_at + duration)
    }

    fn next_pto_packet(&self, duration: Duration) -> Option<(EncryptionLevel, Instant)> {
        self.last_ack_eliciting
            .map(|packet| (packet.level, packet.sent_at + duration))
    }

    fn bytes_in_flight(&self) -> u64 {
        self.sent
            .values()
            .filter(|packet| packet.ack_eliciting)
            .map(|packet| packet.bytes)
            .sum()
    }

    fn discard_level(&mut self, level: EncryptionLevel) -> u64 {
        let discarded = self
            .sent
            .values()
            .filter(|packet| packet.level == level && packet.ack_eliciting)
            .map(|packet| packet.bytes)
            .sum();
        self.sent.retain(|packet| packet.level != level);
        self.refresh_last_ack_eliciting();
        discarded
    }

    fn refresh_last_ack_eliciting(&mut self) {
        self.last_ack_eliciting = self
            .sent
            .values()
            .filter(|packet| packet.ack_eliciting)
            .max_by_key(|packet| packet.sent_at)
            .copied();
    }
}

fn empty_ack_outcome() -> AckOutcome {
    AckOutcome {
        acked_packet_numbers: SmallVec::new(),
        newly_acked_packets: SmallVec::new(),
        acked_bytes: 0,
        largest_acked: 0,
        largest_sent: 0,
        rtt_sample: None,
        lost_packets: Vec::new(),
        persistent_congestion: false,
        ecn: EcnOutcome::default(),
    }
}

fn for_each_acked_packet_range(frame: &Frame, mut visit: impl FnMut(u64, u64)) -> Option<()> {
    let Frame::Ack {
        largest,
        first_range,
        ranges,
        ..
    } = frame
    else {
        return None;
    };
    let mut smallest = largest.into_inner().checked_sub(first_range.into_inner())?;
    visit(smallest, largest.into_inner());
    for range in ranges {
        let gap = range.gap.into_inner();
        let range_len = range.range.into_inner();
        let range_largest = smallest.checked_sub(gap)?.checked_sub(2)?;
        smallest = range_largest.checked_sub(range_len)?;
        visit(smallest, range_largest);
    }
    Some(())
}

fn acknowledged_sent_packet_numbers(
    space: &LossSpace,
    frame: &Frame,
) -> Option<SmallVec<[u64; 32]>> {
    let mut acknowledged = SmallVec::new();
    for_each_acked_packet_range(frame, |start, end| {
        acknowledged.extend(space.sent.packet_numbers_in_range(start, end));
    })?;
    Some(acknowledged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frame::AckRange, varint::VarInt};

    #[test]
    fn ack_frame_removes_acked_packets_and_detects_old_losses() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(10));
        loss.on_packet_sent(
            EncryptionLevel::Initial,
            1,
            100,
            true,
            now - Duration::from_millis(20),
        );
        loss.on_packet_sent(
            EncryptionLevel::Initial,
            2,
            100,
            true,
            now - Duration::from_millis(20),
        );
        loss.on_packet_sent(
            EncryptionLevel::Initial,
            3,
            100,
            true,
            now - Duration::from_millis(1),
        );
        let ack = Frame::Ack {
            largest: VarInt::from_u32(3),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        let outcome = loss.on_ack_frame(EncryptionLevel::Initial, &ack, now);

        assert_eq!(
            outcome.lost_packets,
            vec![
                LossEvent {
                    level: EncryptionLevel::Initial,
                    packet_number: 1,
                    bytes: 100,
                    sent_at: now - Duration::from_millis(20),
                },
                LossEvent {
                    level: EncryptionLevel::Initial,
                    packet_number: 2,
                    bytes: 100,
                    sent_at: now - Duration::from_millis(20),
                },
            ]
        );
        assert_eq!(outcome.acked_packet_numbers.as_slice(), &[3]);
        assert_eq!(outcome.acked_bytes, 100);
        assert!(!outcome.persistent_congestion);
        assert_eq!(loss.bytes_in_flight(), 0);
    }

    #[test]
    fn packet_threshold_marks_skipped_packets_lost() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_secs(60));
        for packet_number in 1..=5 {
            loss.on_packet_sent(
                EncryptionLevel::OneRtt,
                packet_number,
                100,
                true,
                now - Duration::from_millis(1),
            );
        }
        let ack = Frame::Ack {
            largest: VarInt::from_u32(5),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        let outcome = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert_eq!(
            outcome
                .lost_packets
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(outcome.acked_packet_numbers.as_slice(), &[5]);
        assert_eq!(outcome.acked_bytes, 100);
    }

    #[test]
    fn ecn_validation_accepts_cumulative_counts_beyond_the_ack_ranges() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        for pn in 1..=2 {
            loss.on_packet_sent_with_ecn(
                EncryptionLevel::OneRtt,
                pn,
                100,
                true,
                Some(EcnCodepoint::Ect0),
                now,
            );
        }
        let ack = Frame::Ack {
            largest: VarInt::from_u32(2),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: Some((VarInt::from_u32(2), VarInt::ZERO, VarInt::ZERO)),
        };
        assert!(
            loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now)
                .ecn
                .validated
        );
    }

    #[test]
    fn ecn_validation_ignores_reordered_ack_counters() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        for pn in 1..=3 {
            loss.on_packet_sent_with_ecn(
                EncryptionLevel::OneRtt,
                pn,
                100,
                true,
                Some(EcnCodepoint::Ect0),
                now,
            );
        }
        let ack = |largest, range, count| Frame::Ack {
            largest: VarInt::from_u32(largest),
            delay: VarInt::ZERO,
            first_range: VarInt::from_u32(range),
            ranges: Default::default(),
            ecn: Some((VarInt::from_u32(count), VarInt::ZERO, VarInt::ZERO)),
        };
        assert!(
            loss.on_ack_frame(EncryptionLevel::OneRtt, &ack(2, 1, 2), now)
                .ecn
                .validated
        );
        assert!(
            !loss
                .on_ack_frame(EncryptionLevel::OneRtt, &ack(1, 0, 1), now)
                .ecn
                .validation_failed
        );
        assert!(
            loss.on_ack_frame(EncryptionLevel::OneRtt, &ack(3, 0, 3), now)
                .ecn
                .validated
        );
    }

    #[test]
    fn ecn_validation_rejects_remarking_to_an_unsent_codepoint() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent_with_ecn(
            EncryptionLevel::OneRtt,
            1,
            100,
            true,
            Some(EcnCodepoint::Ect0),
            now,
        );
        let ack = Frame::Ack {
            largest: VarInt::from_u32(1),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: Some((VarInt::ZERO, VarInt::from_u32(1), VarInt::ZERO)),
        };
        assert!(
            loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now)
                .ecn
                .validation_failed
        );
    }

    #[test]
    fn ecn_validation_counts_marked_non_ack_eliciting_packets() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent_with_ecn(
            EncryptionLevel::OneRtt,
            1,
            100,
            false,
            Some(EcnCodepoint::Ect0),
            now,
        );
        let ack = Frame::Ack {
            largest: VarInt::from_u32(1),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: Some((VarInt::from_u32(1), VarInt::ZERO, VarInt::ZERO)),
        };
        assert!(
            loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now)
                .ecn
                .validated
        );
    }

    #[test]
    fn ecn_validation_accepts_ect0_and_ce_increments() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent_with_ecn(
            EncryptionLevel::OneRtt,
            1,
            100,
            true,
            Some(EcnCodepoint::Ect0),
            now,
        );
        loss.on_packet_sent_with_ecn(
            EncryptionLevel::OneRtt,
            2,
            100,
            true,
            Some(EcnCodepoint::Ect0),
            now,
        );
        let ack = Frame::Ack {
            largest: VarInt::from_u32(2),
            delay: VarInt::ZERO,
            first_range: VarInt::from_u32(1),
            ranges: Default::default(),
            ecn: Some((VarInt::from_u32(1), VarInt::ZERO, VarInt::from_u32(1))),
        };

        let outcome = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert!(outcome.ecn.validated);
        assert!(!outcome.ecn.validation_failed);
        assert_eq!(outcome.ecn.ce_delta, 1);
    }

    #[test]
    fn ecn_validation_rejects_impossible_counter_growth() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent_with_ecn(
            EncryptionLevel::OneRtt,
            1,
            100,
            true,
            Some(EcnCodepoint::Ect0),
            now,
        );
        let ack = Frame::Ack {
            largest: VarInt::from_u32(1),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: Some((VarInt::from_u32(2), VarInt::ZERO, VarInt::ZERO)),
        };

        let outcome = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert!(!outcome.ecn.validated);
        assert!(outcome.ecn.validation_failed);
        assert_eq!(outcome.ecn.ce_delta, 0);
    }

    #[test]
    fn ecn_validation_rejects_missing_ack_counters_and_remains_failed() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent_with_ecn(
            EncryptionLevel::OneRtt,
            1,
            100,
            true,
            Some(EcnCodepoint::Ect0),
            now,
        );
        let ack = Frame::Ack {
            largest: VarInt::from_u32(1),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        let outcome = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert!(!outcome.ecn.validated);
        assert!(outcome.ecn.validation_failed);

        let repeated = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);
        assert!(!repeated.ecn.validated);
        assert!(repeated.ecn.validation_failed);
    }

    #[test]
    fn detects_persistent_congestion_from_wide_loss_period() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(10));
        loss.on_packet_sent(
            EncryptionLevel::OneRtt,
            1,
            100,
            true,
            now - Duration::from_millis(220),
        );
        loss.on_packet_sent(
            EncryptionLevel::OneRtt,
            2,
            100,
            true,
            now - Duration::from_millis(40),
        );
        loss.on_packet_sent(
            EncryptionLevel::OneRtt,
            3,
            100,
            true,
            now - Duration::from_millis(1),
        );
        let ack = Frame::Ack {
            largest: VarInt::from_u32(3),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        let outcome = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert_eq!(outcome.lost_packets.len(), 2);
        assert!(outcome.persistent_congestion);
    }

    #[test]
    fn pto_requests_two_probe_packets_for_oldest_space() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(5));
        loss.on_packet_sent(EncryptionLevel::Handshake, 0, 1200, true, now);

        assert!(loss.on_timeout(now + Duration::from_millis(10)).is_none());
        assert_eq!(
            loss.on_timeout(now + Duration::from_millis(15)),
            Some(TimeoutOutcome::Probe(Probe {
                level: EncryptionLevel::Handshake,
                packets: 2,
            }))
        );
    }

    #[test]
    fn discard_space_removes_loss_state_and_reports_bytes_in_flight() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent(EncryptionLevel::Initial, 0, 1200, true, now);
        loss.on_packet_sent(EncryptionLevel::OneRtt, 0, 800, true, now);

        assert_eq!(loss.discard_space(EncryptionLevel::Initial), 1200);

        assert_eq!(loss.bytes_in_flight(), 800);
        assert!(matches!(
            loss.on_timeout(now + Duration::from_secs(2)),
            Some(TimeoutOutcome::Probe(Probe {
                level: EncryptionLevel::OneRtt,
                ..
            }))
        ));
    }

    #[test]
    fn one_rtt_ack_acknowledges_zero_rtt_packet_in_application_space() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent(EncryptionLevel::ZeroRtt, 3, 700, true, now);
        loss.on_packet_sent(EncryptionLevel::OneRtt, 4, 800, true, now);
        let ack = Frame::Ack {
            largest: VarInt::from_u32(4),
            delay: VarInt::ZERO,
            first_range: VarInt::from_u32(1),
            ranges: Default::default(),
            ecn: None,
        };

        let outcome = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert_eq!(
            outcome
                .newly_acked_packets
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(outcome.acked_bytes, 1500);
        assert_eq!(loss.bytes_in_flight(), 0);
    }

    #[test]
    fn discarding_zero_rtt_keeps_one_rtt_application_loss_state() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent(EncryptionLevel::ZeroRtt, 3, 700, true, now);
        loss.on_packet_sent(EncryptionLevel::OneRtt, 4, 800, true, now);

        assert_eq!(loss.discard_space(EncryptionLevel::ZeroRtt), 700);
        assert_eq!(loss.bytes_in_flight(), 800);
        assert!(matches!(
            loss.on_timeout(now + Duration::from_secs(2)),
            Some(TimeoutOutcome::Probe(Probe {
                level: EncryptionLevel::OneRtt,
                ..
            }))
        ));
    }

    #[test]
    fn application_pto_uses_packet_protection_level_of_latest_send() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(5));
        loss.on_packet_sent(EncryptionLevel::ZeroRtt, 3, 700, true, now);

        assert_eq!(
            loss.on_timeout(now + Duration::from_millis(15)),
            Some(TimeoutOutcome::Probe(Probe {
                level: EncryptionLevel::ZeroRtt,
                packets: 2,
            }))
        );
    }

    #[test]
    fn ack_delay_uses_negotiated_exponent_and_post_confirmation_cap() {
        let ack = Frame::Ack {
            largest: VarInt::ZERO,
            delay: VarInt::from_u32(7),
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };

        assert_eq!(
            ack_delay_duration(
                &ack,
                EncryptionLevel::OneRtt,
                Duration::from_millis(10),
                0,
                false,
            ),
            Duration::from_micros(7)
        );
        assert_eq!(
            ack_delay_duration(
                &ack,
                EncryptionLevel::OneRtt,
                Duration::from_millis(1),
                10,
                false,
            ),
            Duration::from_micros(7_168)
        );
        assert_eq!(
            ack_delay_duration(
                &ack,
                EncryptionLevel::OneRtt,
                Duration::from_millis(1),
                10,
                true,
            ),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn application_pto_backs_off_ack_delay_and_bounds_close_time() {
        let start = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(100));
        loss.set_ack_delay_config(Duration::from_millis(25), 0);
        loss.confirm_handshake();
        loss.on_packet_sent(EncryptionLevel::OneRtt, 0, 100, true, start);
        let initial = loss.timeout().unwrap().duration_since(start);
        let idle_floor = loss.idle_timeout_floor();
        loss.pto_count = 2;
        assert_eq!(loss.idle_timeout_floor(), idle_floor);
        assert_eq!(loss.timeout().unwrap().duration_since(start), initial * 4);
        assert_eq!(loss.close_drain_duration(), initial * 12);
        assert_eq!(loss.one_rtt_key_retirement_duration(), initial * 12);
    }

    #[test]
    fn handshake_confirmation_changes_ack_delay_cap_and_one_rtt_pto() {
        let start = Instant::now();
        let mut unconfirmed = LossDetector::new();
        unconfirmed.set_ack_delay_config(Duration::from_millis(25), 0);
        unconfirmed.set_smoothed_rtt(Duration::from_millis(100));
        unconfirmed.on_packet_sent(EncryptionLevel::OneRtt, 0, 100, true, start);
        let unconfirmed_pto = unconfirmed.timeout().unwrap();

        let mut confirmed = unconfirmed.clone();
        confirmed.confirm_handshake();
        assert!(confirmed.is_handshake_confirmed());
        assert_eq!(
            confirmed.timeout().unwrap().duration_since(unconfirmed_pto),
            Duration::from_millis(25)
        );

        let first_ack = Frame::Ack {
            largest: VarInt::ZERO,
            delay: VarInt::from_u32(50_000),
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        unconfirmed.on_ack_frame(
            EncryptionLevel::OneRtt,
            &first_ack,
            start + Duration::from_millis(160),
        );
        confirmed.on_ack_frame(
            EncryptionLevel::OneRtt,
            &first_ack,
            start + Duration::from_millis(160),
        );

        assert_eq!(unconfirmed.smoothed_rtt(), Duration::from_micros(101_250));
        assert_eq!(confirmed.smoothed_rtt(), Duration::from_micros(104_375));
    }

    #[test]
    fn ack_ranges_are_visited_without_intermediate_allocation() {
        let frame = Frame::Ack {
            largest: VarInt::from_u32(10),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: vec![AckRange {
                gap: VarInt::from_u32(1),
                range: VarInt::from_u32(2),
            }]
            .into(),
            ecn: None,
        };

        let mut visited = Vec::new();
        assert_eq!(
            for_each_acked_packet_range(&frame, |start, end| visited.push((start, end))),
            Some(())
        );
        assert_eq!(visited, vec![(10, 10), (5, 7)]);
    }

    #[test]
    fn huge_ack_range_only_visits_outstanding_packets() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.on_packet_sent(EncryptionLevel::OneRtt, 1, 100, true, now);
        loss.on_packet_sent(
            EncryptionLevel::OneRtt,
            VarInt::MAX.into_inner(),
            100,
            true,
            now,
        );
        let ack = Frame::Ack {
            largest: VarInt::MAX,
            delay: VarInt::ZERO,
            first_range: VarInt::MAX,
            ranges: Default::default(),
            ecn: None,
        };

        let outcome = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert_eq!(
            outcome.acked_packet_numbers.as_slice(),
            &[1, VarInt::MAX.into_inner()]
        );
        assert_eq!(outcome.acked_bytes, 200);
        assert_eq!(loss.bytes_in_flight(), 0);
    }

    #[test]
    fn pto_uses_latest_ack_eliciting_send_time() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(5));
        loss.on_packet_sent(EncryptionLevel::Initial, 0, 100, true, now);
        loss.on_packet_sent(
            EncryptionLevel::Initial,
            1,
            100,
            true,
            now + Duration::from_millis(5),
        );

        assert!(loss.on_timeout(now + Duration::from_millis(19)).is_none());
        assert_eq!(
            loss.on_timeout(now + Duration::from_millis(20)),
            Some(TimeoutOutcome::Probe(Probe {
                level: EncryptionLevel::Initial,
                packets: 2,
            }))
        );
    }

    #[test]
    fn pto_survives_many_ack_only_gaps_and_ack_cycles() {
        let start = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(1));
        loss.confirm_handshake();
        for cycle in 0..1_000_u64 {
            let data_packet = cycle * 2;
            let sent_at = start + Duration::from_micros(cycle * 10);
            loss.on_packet_sent(EncryptionLevel::OneRtt, data_packet, 100, true, sent_at);
            loss.on_packet_sent(EncryptionLevel::OneRtt, data_packet + 1, 30, false, sent_at);
            let ack = Frame::Ack {
                largest: VarInt::new(data_packet).unwrap(),
                delay: VarInt::ZERO,
                first_range: VarInt::ZERO,
                ranges: Default::default(),
                ecn: None,
            };
            loss.on_ack_frame(
                EncryptionLevel::OneRtt,
                &ack,
                sent_at + Duration::from_micros(5),
            );
        }

        let final_sent_at = start + Duration::from_millis(20);
        loss.on_packet_sent(EncryptionLevel::OneRtt, 2_000, 100, true, final_sent_at);

        let deadline = loss.timeout().expect("outstanding data must arm PTO");
        assert!(deadline > final_sent_at);
        assert!(matches!(
            loss.on_timeout(deadline),
            Some(TimeoutOutcome::Probe(Probe {
                level: EncryptionLevel::OneRtt,
                ..
            }))
        ));
    }

    #[test]
    fn pto_selects_the_packet_space_with_the_earliest_deadline() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(5));
        loss.on_packet_sent(EncryptionLevel::Initial, 0, 100, true, now);
        loss.on_packet_sent(
            EncryptionLevel::Handshake,
            0,
            100,
            true,
            now - Duration::from_millis(5),
        );

        assert_eq!(
            loss.on_timeout(now + Duration::from_millis(10)),
            Some(TimeoutOutcome::Probe(Probe {
                level: EncryptionLevel::Handshake,
                packets: 2,
            }))
        );
    }

    #[test]
    fn ack_of_non_ack_eliciting_packet_does_not_reset_pto_backoff() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(5));
        loss.on_packet_sent(EncryptionLevel::OneRtt, 0, 100, true, now);
        assert!(loss.on_timeout(now + Duration::from_millis(40)).is_some());
        assert_eq!(loss.pto_count, 1);

        loss.on_packet_sent(EncryptionLevel::OneRtt, 1, 20, false, now);
        let ack = Frame::Ack {
            largest: VarInt::from_u32(1),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        let outcome = loss.on_ack_frame(EncryptionLevel::OneRtt, &ack, now);

        assert_eq!(outcome.acked_bytes, 0);
        assert_eq!(loss.pto_count, 1);
    }

    #[test]
    fn time_threshold_loss_fires_before_pto() {
        let now = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_smoothed_rtt(Duration::from_millis(100));
        loss.on_packet_sent(EncryptionLevel::OneRtt, 0, 100, true, now);
        loss.on_packet_sent(
            EncryptionLevel::OneRtt,
            1,
            100,
            true,
            now + Duration::from_millis(10),
        );
        let ack = Frame::Ack {
            largest: VarInt::from_u32(1),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        let outcome = loss.on_ack_frame(
            EncryptionLevel::OneRtt,
            &ack,
            now + Duration::from_millis(11),
        );
        assert!(outcome.lost_packets.is_empty());

        let loss_deadline = loss.timeout().unwrap();
        assert!(loss_deadline < now + Duration::from_millis(300));
        assert_eq!(
            loss.on_timeout(loss_deadline),
            Some(TimeoutOutcome::Loss {
                lost_packets: vec![LossEvent {
                    level: EncryptionLevel::OneRtt,
                    packet_number: 0,
                    bytes: 100,
                    sent_at: now,
                }],
                persistent_congestion: false,
            })
        );
    }

    #[test]
    fn rtt_estimator_applies_ack_delay_and_jitter_deterministically() {
        let start = Instant::now();
        let mut loss = LossDetector::new();
        loss.set_ack_delay_config(Duration::from_millis(25), 3);

        loss.on_packet_sent(EncryptionLevel::OneRtt, 0, 100, true, start);
        let first_ack = Frame::Ack {
            largest: VarInt::ZERO,
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        loss.on_ack_frame(
            EncryptionLevel::OneRtt,
            &first_ack,
            start + Duration::from_millis(100),
        );
        assert_eq!(loss.latest_rtt(), Some(Duration::from_millis(100)));
        assert_eq!(loss.smoothed_rtt(), Duration::from_millis(100));
        assert_eq!(loss.rttvar(), Duration::from_millis(50));

        let second_sent = start + Duration::from_millis(100);
        loss.on_packet_sent(EncryptionLevel::OneRtt, 1, 100, true, second_sent);
        let delayed_ack = Frame::Ack {
            largest: VarInt::from_u32(1),
            // 1,250 * 2^3 microseconds = 10 milliseconds.
            delay: VarInt::from_u32(1_250),
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        loss.on_ack_frame(
            EncryptionLevel::OneRtt,
            &delayed_ack,
            second_sent + Duration::from_millis(120),
        );

        assert_eq!(loss.latest_rtt(), Some(Duration::from_millis(120)));
        assert_eq!(loss.min_rtt(), Some(Duration::from_millis(100)));
        assert_eq!(loss.smoothed_rtt(), Duration::from_micros(101_250));
        assert_eq!(loss.rttvar(), Duration::from_millis(40));

        let third_sent = start + Duration::from_millis(300);
        loss.on_packet_sent(EncryptionLevel::OneRtt, 2, 100, true, third_sent);
        let jitter_ack = Frame::Ack {
            largest: VarInt::from_u32(2),
            delay: VarInt::ZERO,
            first_range: VarInt::ZERO,
            ranges: Default::default(),
            ecn: None,
        };
        loss.on_ack_frame(
            EncryptionLevel::OneRtt,
            &jitter_ack,
            third_sent + Duration::from_millis(80),
        );

        assert_eq!(loss.latest_rtt(), Some(Duration::from_millis(80)));
        assert_eq!(loss.min_rtt(), Some(Duration::from_millis(80)));
        assert_eq!(loss.smoothed_rtt(), Duration::from_nanos(98_593_750));
        assert_eq!(loss.rttvar(), Duration::from_nanos(35_312_500));
    }
}
