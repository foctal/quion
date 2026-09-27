use web_time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    Cubic,
    NewReno,
    #[cfg(feature = "unstable-bbr3")]
    Bbr3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionStats {
    pub congestion_window: u64,
    pub bytes_in_flight: u64,
    pub ssthresh: u64,
}

impl Default for CongestionStats {
    fn default() -> Self {
        Self {
            congestion_window: 12_000,
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CongestionController {
    algorithm: CongestionAlgorithm,
    stats: CongestionStats,
    max_datagram_size: u64,
    smoothed_rtt: Duration,
    pacing_capacity: u64,
    pacing_tokens: u64,
    pacing_updated_at: Option<Instant>,
    cubic_epoch_start: Option<Instant>,
    cubic_origin: u64,
    cubic_last_max: u64,
    hystart: HyStartState,
    #[cfg(feature = "unstable-bbr3")]
    bbr_bandwidth: u64,
    #[cfg(feature = "unstable-bbr3")]
    bbr_min_rtt: Duration,
    #[cfg(feature = "unstable-bbr3")]
    bbr_last_ack: Option<Instant>,
}

const CUBIC_BETA: f64 = 0.7;
const CUBIC_C: f64 = 0.4;
#[cfg(feature = "unstable-bbr3")]
const BBR_CWND_GAIN: f64 = 2.0;
#[cfg(feature = "unstable-bbr3")]
const BBR_LOSS_BETA: f64 = 0.85;

impl CongestionController {
    pub fn new(algorithm: CongestionAlgorithm, max_datagram_size: u64) -> Self {
        let initial_window = (10 * max_datagram_size).clamp(12_000, 14_720);
        let pacing_capacity = pacing_capacity(
            Duration::from_millis(333),
            initial_window,
            max_datagram_size,
        );
        Self {
            algorithm,
            stats: CongestionStats {
                congestion_window: initial_window,
                bytes_in_flight: 0,
                ssthresh: u64::MAX,
            },
            max_datagram_size,
            smoothed_rtt: Duration::from_millis(333),
            pacing_capacity,
            pacing_tokens: pacing_capacity,
            pacing_updated_at: None,
            cubic_epoch_start: None,
            cubic_origin: initial_window,
            cubic_last_max: initial_window,
            hystart: HyStartState::default(),
            #[cfg(feature = "unstable-bbr3")]
            bbr_bandwidth: 0,
            #[cfg(feature = "unstable-bbr3")]
            bbr_min_rtt: Duration::MAX,
            #[cfg(feature = "unstable-bbr3")]
            bbr_last_ack: None,
        }
    }

    pub fn can_send(&self, bytes: u64) -> bool {
        self.stats.bytes_in_flight + bytes <= self.stats.congestion_window
    }

    pub fn available_window(&self) -> u64 {
        self.stats
            .congestion_window
            .saturating_sub(self.stats.bytes_in_flight)
    }

    /// Updates packet-size-dependent controller state without increasing the
    /// congestion window measured in bytes.
    pub fn on_mtu_update(&mut self, max_datagram_size: u64) {
        self.max_datagram_size = max_datagram_size.max(1);
        self.pacing_capacity = pacing_capacity(
            self.smoothed_rtt,
            self.stats.congestion_window,
            self.max_datagram_size,
        );
        self.pacing_tokens = self.pacing_tokens.min(self.pacing_capacity);
    }

    pub fn on_packet_sent(&mut self, bytes: u64) {
        self.stats.bytes_in_flight = self.stats.bytes_in_flight.saturating_add(bytes);
    }

    pub fn on_packet_sent_at(&mut self, bytes: u64, now: Instant) {
        self.refill_pacing_tokens(now);
        self.on_packet_sent(bytes);
        self.pacing_tokens = self.pacing_tokens.saturating_sub(bytes);
    }

    pub fn on_packets_acked(&mut self, bytes: u64) {
        self.on_packets_acked_at(bytes, Instant::now());
    }

    /// Updates congestion state after acknowledged ack-eliciting bytes.
    ///
    /// Supplying the ACK time keeps CUBIC's epoch calculation deterministic in
    /// the sans-IO connection core and its simulated-time tests.
    pub fn on_packets_acked_at(&mut self, bytes: u64, now: Instant) {
        self.stats.bytes_in_flight = self.stats.bytes_in_flight.saturating_sub(bytes);
        #[cfg(feature = "unstable-bbr3")]
        if self.algorithm == CongestionAlgorithm::Bbr3 {
            self.on_bbr_ack(bytes, now);
            return;
        }
        if self.stats.congestion_window < self.stats.ssthresh {
            let growth = if self.hystart.phase == HyStartPhase::Conservative {
                bytes / HYSTART_CSS_GROWTH_DIVISOR
            } else {
                bytes
            };
            self.stats.congestion_window = self.stats.congestion_window.saturating_add(growth);
            return;
        }

        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                let increment =
                    (self.max_datagram_size * bytes / self.stats.congestion_window).max(1);
                self.stats.congestion_window =
                    self.stats.congestion_window.saturating_add(increment);
            }
            CongestionAlgorithm::Cubic => self.on_cubic_ack(bytes, now),
            #[cfg(feature = "unstable-bbr3")]
            CongestionAlgorithm::Bbr3 => unreachable!("BBR ACKs are handled before slow start"),
        }
    }

    pub fn on_packets_lost(&mut self, bytes: u64) {
        self.stats.bytes_in_flight = self.stats.bytes_in_flight.saturating_sub(bytes);
        let minimum_window = 2 * self.max_datagram_size;
        if self.algorithm == CongestionAlgorithm::Cubic {
            self.cubic_last_max = self.stats.congestion_window;
            self.cubic_epoch_start = None;
        }
        self.stats.congestion_window = match self.algorithm {
            CongestionAlgorithm::Cubic => {
                ((self.stats.congestion_window as f64 * CUBIC_BETA) as u64).max(minimum_window)
            }
            CongestionAlgorithm::NewReno => (self.stats.congestion_window / 2).max(minimum_window),
            #[cfg(feature = "unstable-bbr3")]
            CongestionAlgorithm::Bbr3 => {
                ((self.stats.congestion_window as f64 * BBR_LOSS_BETA) as u64).max(minimum_window)
            }
        };
        self.stats.ssthresh = self.stats.congestion_window;
        self.hystart.phase = HyStartPhase::Complete;
    }

    pub fn discard_bytes_in_flight(&mut self, bytes: u64) {
        self.stats.bytes_in_flight = self.stats.bytes_in_flight.saturating_sub(bytes);
    }

    pub fn on_persistent_congestion(&mut self) {
        self.stats.congestion_window = 2 * self.max_datagram_size;
        self.stats.ssthresh = self.stats.congestion_window;
        self.cubic_epoch_start = None;
        self.hystart.phase = HyStartPhase::Complete;
    }

    /// Feeds one ACK-derived RTT sample into the RFC 9406 HyStart++ detector.
    ///
    /// Packet numbers delimit rounds: a round ends once the largest packet
    /// outstanding when it began has been acknowledged.
    pub fn on_ack_rtt_sample(&mut self, sample: Duration, largest_acked: u64, largest_sent: u64) {
        #[cfg(feature = "unstable-bbr3")]
        if self.algorithm == CongestionAlgorithm::Bbr3 {
            return;
        }
        if self.hystart.phase == HyStartPhase::Complete
            || self.stats.congestion_window >= self.stats.ssthresh
        {
            return;
        }

        let Some(window_end) = self.hystart.window_end else {
            self.hystart.window_end = Some(largest_sent);
            self.hystart.current_round_min_rtt = Some(sample);
            self.hystart.rtt_sample_count = 1;
            return;
        };

        if largest_acked >= window_end {
            self.finish_hystart_round();
            self.hystart.last_round_min_rtt = self.hystart.current_round_min_rtt;
            self.hystart.current_round_min_rtt = Some(sample);
            self.hystart.rtt_sample_count = 1;
            self.hystart.window_end = Some(largest_sent);
        } else {
            self.hystart.current_round_min_rtt = Some(
                self.hystart
                    .current_round_min_rtt
                    .map_or(sample, |current| current.min(sample)),
            );
            self.hystart.rtt_sample_count = self.hystart.rtt_sample_count.saturating_add(1);
        }
        self.evaluate_hystart_delay();
    }

    pub fn set_smoothed_rtt(&mut self, rtt: Duration) {
        self.smoothed_rtt = rtt.max(Duration::from_micros(1));
        self.update_pacing_capacity();
        #[cfg(feature = "unstable-bbr3")]
        if self.algorithm == CongestionAlgorithm::Bbr3 {
            self.bbr_min_rtt = self.bbr_min_rtt.min(self.smoothed_rtt);
        }
    }

    pub fn send_at(&mut self, now: Instant) -> Option<Instant> {
        self.refill_pacing_tokens(now);
        self.next_send_at(now)
    }

    pub fn next_send_at(&self, now: Instant) -> Option<Instant> {
        let required = self.max_datagram_size.min(self.stats.congestion_window);
        if self.pacing_tokens >= required {
            return None;
        }
        let missing = required.saturating_sub(self.pacing_tokens);
        Some(now + self.pacing_interval(missing))
    }

    pub const fn stats(&self) -> &CongestionStats {
        &self.stats
    }

    pub const fn algorithm(&self) -> CongestionAlgorithm {
        self.algorithm
    }

    fn pacing_interval(&self, bytes: u64) -> Duration {
        #[cfg(feature = "unstable-bbr3")]
        if self.algorithm == CongestionAlgorithm::Bbr3 && self.bbr_bandwidth > 0 {
            return Duration::from_secs_f64(bytes as f64 / self.bbr_bandwidth as f64)
                .max(Duration::from_micros(1));
        }
        let window = self.stats.congestion_window.max(self.max_datagram_size);
        self.smoothed_rtt
            .mul_f64(bytes as f64 / window as f64)
            .max(Duration::from_micros(1))
    }

    fn update_pacing_capacity(&mut self) {
        self.pacing_capacity = pacing_capacity(
            self.smoothed_rtt,
            self.stats.congestion_window,
            self.max_datagram_size,
        );
        self.pacing_tokens = self.pacing_tokens.min(self.pacing_capacity);
    }

    fn refill_pacing_tokens(&mut self, now: Instant) {
        self.update_pacing_capacity();
        let Some(previous) = self.pacing_updated_at.replace(now) else {
            return;
        };
        let elapsed = now.checked_duration_since(previous).unwrap_or_default();
        if elapsed.is_zero() {
            return;
        }
        let interval = self.pacing_interval(self.stats.congestion_window);
        if interval.is_zero() {
            self.pacing_tokens = self.pacing_capacity;
            return;
        }
        let added = (elapsed.as_secs_f64() / interval.as_secs_f64()
            * self.stats.congestion_window as f64) as u64;
        self.pacing_tokens = self
            .pacing_tokens
            .saturating_add(added)
            .min(self.pacing_capacity);
    }

    fn on_cubic_ack(&mut self, bytes: u64, now: Instant) {
        let epoch_start = *self.cubic_epoch_start.get_or_insert(now);
        if epoch_start == now {
            self.cubic_origin = self.stats.congestion_window;
        }
        let elapsed = now.duration_since(epoch_start).as_secs_f64();
        let scale = CUBIC_C * self.max_datagram_size as f64;
        let k = if self.cubic_last_max > self.cubic_origin {
            ((self.cubic_last_max - self.cubic_origin) as f64 / scale).cbrt()
        } else {
            0.0
        };
        let target = (self.cubic_origin as f64 + scale * (elapsed - k).powi(3))
            .max((2 * self.max_datagram_size) as f64) as u64;
        let increment = if target > self.stats.congestion_window {
            target
                .saturating_sub(self.stats.congestion_window)
                .min(bytes)
                .max(1)
        } else {
            (self.max_datagram_size * bytes / self.stats.congestion_window).max(1)
        };
        self.stats.congestion_window = self.stats.congestion_window.saturating_add(increment);
    }

    fn evaluate_hystart_delay(&mut self) {
        if self.hystart.rtt_sample_count < HYSTART_MIN_RTT_SAMPLES {
            return;
        }
        let (Some(last), Some(current)) = (
            self.hystart.last_round_min_rtt,
            self.hystart.current_round_min_rtt,
        ) else {
            return;
        };
        match self.hystart.phase {
            HyStartPhase::Standard => {
                let threshold = last
                    .div_f64(HYSTART_MIN_RTT_DIVISOR)
                    .clamp(HYSTART_MIN_RTT_THRESHOLD, HYSTART_MAX_RTT_THRESHOLD);
                if current >= last.saturating_add(threshold) {
                    self.hystart.phase = HyStartPhase::Conservative;
                    self.hystart.css_baseline_min_rtt = Some(current);
                    // A transition in the middle of a round counts as the
                    // first conservative slow-start round.
                    self.hystart.css_rounds = 1;
                }
            }
            HyStartPhase::Conservative => {
                if self
                    .hystart
                    .css_baseline_min_rtt
                    .is_some_and(|baseline| current < baseline)
                {
                    self.hystart.phase = HyStartPhase::Standard;
                    self.hystart.css_baseline_min_rtt = None;
                    self.hystart.css_rounds = 0;
                }
            }
            HyStartPhase::Complete => {}
        }
    }

    fn finish_hystart_round(&mut self) {
        if self.hystart.phase != HyStartPhase::Conservative {
            return;
        }
        self.hystart.css_rounds = self.hystart.css_rounds.saturating_add(1);
        if self.hystart.css_rounds >= HYSTART_CSS_ROUNDS {
            self.stats.ssthresh = self.stats.congestion_window;
            self.hystart.phase = HyStartPhase::Complete;
        }
    }

    #[cfg(feature = "unstable-bbr3")]
    fn on_bbr_ack(&mut self, bytes: u64, now: Instant) {
        let sample_interval = self
            .bbr_last_ack
            .map(|last| now.saturating_duration_since(last))
            .filter(|interval| !interval.is_zero())
            .unwrap_or(self.smoothed_rtt);
        self.bbr_last_ack = Some(now);

        let sample_bandwidth = (bytes as f64 / sample_interval.as_secs_f64().max(0.000_001)) as u64;
        self.bbr_bandwidth = self.bbr_bandwidth.max(sample_bandwidth);
        self.bbr_min_rtt = self.bbr_min_rtt.min(self.smoothed_rtt);

        let minimum_window = 2 * self.max_datagram_size;
        let target =
            (self.bbr_bandwidth as f64 * self.bbr_min_rtt.as_secs_f64() * BBR_CWND_GAIN) as u64;
        let target = target.max(minimum_window);
        if target > self.stats.congestion_window {
            self.stats.congestion_window = self
                .stats
                .congestion_window
                .saturating_add(bytes)
                .min(target);
        } else {
            self.stats.congestion_window = target;
        }
        self.stats.ssthresh = self.stats.congestion_window;
    }
}

const HYSTART_MIN_RTT_THRESHOLD: Duration = Duration::from_millis(4);
const HYSTART_MAX_RTT_THRESHOLD: Duration = Duration::from_millis(16);
const HYSTART_MIN_RTT_DIVISOR: f64 = 8.0;
const HYSTART_MIN_RTT_SAMPLES: u8 = 8;
const HYSTART_CSS_GROWTH_DIVISOR: u64 = 4;
const HYSTART_CSS_ROUNDS: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HyStartPhase {
    Standard,
    Conservative,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HyStartState {
    phase: HyStartPhase,
    window_end: Option<u64>,
    last_round_min_rtt: Option<Duration>,
    current_round_min_rtt: Option<Duration>,
    rtt_sample_count: u8,
    css_baseline_min_rtt: Option<Duration>,
    css_rounds: u8,
}

impl Default for HyStartState {
    fn default() -> Self {
        Self {
            phase: HyStartPhase::Standard,
            window_end: None,
            last_round_min_rtt: None,
            current_round_min_rtt: None,
            rtt_sample_count: 0,
            css_baseline_min_rtt: None,
            css_rounds: 0,
        }
    }
}

fn pacing_capacity(smoothed_rtt: Duration, window: u64, max_datagram_size: u64) -> u64 {
    const BURST_INTERVAL: Duration = Duration::from_millis(2);
    const MIN_BURST_PACKETS: u64 = 10;
    const MAX_BURST_PACKETS: u64 = 32;

    let capacity = if smoothed_rtt.is_zero() {
        window
    } else {
        (window as f64 * BURST_INTERVAL.as_secs_f64() / smoothed_rtt.as_secs_f64()) as u64
    };
    capacity.clamp(
        MIN_BURST_PACKETS.saturating_mul(max_datagram_size),
        MAX_BURST_PACKETS.saturating_mul(max_datagram_size),
    )
}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new(CongestionAlgorithm::NewReno, 1200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_reno_grows_during_slow_start_and_reacts_to_loss() {
        let mut controller = CongestionController::new(CongestionAlgorithm::NewReno, 1200);
        let initial = controller.stats().congestion_window;
        controller.on_packet_sent(1200);
        assert_eq!(controller.stats().bytes_in_flight, 1200);
        controller.on_packets_acked(1200);
        assert_eq!(controller.stats().bytes_in_flight, 0);
        assert_eq!(controller.stats().congestion_window, initial + 1200);

        controller.on_packet_sent(4800);
        controller.on_packets_lost(2400);
        assert_eq!(controller.stats().bytes_in_flight, 2400);
        assert!(controller.stats().congestion_window < initial + 1200);
        assert_eq!(
            controller.stats().ssthresh,
            controller.stats().congestion_window
        );
    }

    #[test]
    fn mtu_update_does_not_increase_byte_congestion_window() {
        let mut controller = CongestionController::new(CongestionAlgorithm::NewReno, 1_200);
        let window = controller.stats().congestion_window;
        controller.on_mtu_update(1_452);
        assert_eq!(controller.stats().congestion_window, window);
    }

    #[test]
    fn persistent_congestion_collapses_to_minimum_window() {
        let mut controller = CongestionController::new(CongestionAlgorithm::NewReno, 1200);
        controller.on_packet_sent(1200);
        controller.on_packets_acked(1200);

        controller.on_persistent_congestion();

        assert_eq!(controller.stats().congestion_window, 2400);
        assert_eq!(controller.stats().ssthresh, 2400);
    }

    #[test]
    fn pacing_allows_a_timer_granularity_sized_burst() {
        let now = Instant::now();
        let mut controller = CongestionController::new(CongestionAlgorithm::NewReno, 1200);
        controller.set_smoothed_rtt(Duration::from_millis(100));

        assert_eq!(controller.send_at(now), None);
        for _ in 0..10 {
            assert_eq!(controller.send_at(now), None);
            controller.on_packet_sent_at(1200, now);
        }

        let send_at = controller.send_at(now).unwrap();
        assert!(send_at > now);
        assert_eq!(controller.send_at(send_at), None);
    }

    #[test]
    fn pacing_caps_low_rtt_bursts_to_thirty_two_packets() {
        let mut controller = CongestionController::new(CongestionAlgorithm::NewReno, 1200);
        controller.stats.congestion_window = 1_000_000;
        controller.set_smoothed_rtt(Duration::from_micros(1));

        assert_eq!(controller.pacing_capacity, 32 * 1200);
    }

    #[test]
    fn send_permission_respects_congestion_window() {
        let mut controller = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        assert!(controller.can_send(1200));
        controller.on_packet_sent(controller.stats().congestion_window);
        assert!(!controller.can_send(1));
    }

    #[test]
    fn discarding_bytes_in_flight_does_not_reduce_window() {
        let mut controller = CongestionController::new(CongestionAlgorithm::NewReno, 1200);
        let initial_window = controller.stats().congestion_window;
        controller.on_packet_sent(2400);

        controller.discard_bytes_in_flight(1200);

        assert_eq!(controller.stats().bytes_in_flight, 1200);
        assert_eq!(controller.stats().congestion_window, initial_window);
    }

    #[test]
    fn cubic_uses_a_time_based_growth_curve_after_loss() {
        let now = Instant::now();
        let mut cubic = CongestionController::new(CongestionAlgorithm::Cubic, 1200);
        let mut new_reno = CongestionController::new(CongestionAlgorithm::NewReno, 1200);

        cubic.on_packet_sent(1200);
        new_reno.on_packet_sent(1200);
        cubic.on_packets_lost(1200);
        new_reno.on_packets_lost(1200);
        assert_eq!(cubic.stats().congestion_window, 8400);
        assert_eq!(new_reno.stats().congestion_window, 6000);

        cubic.on_packets_acked_at(1200, now);
        new_reno.on_packets_acked_at(1200, now);
        let cubic_first_increment = cubic.stats().congestion_window - 8400;

        cubic.on_packets_acked_at(1200, now + Duration::from_secs(4));
        new_reno.on_packets_acked_at(1200, now + Duration::from_secs(4));

        assert!(cubic.stats().congestion_window > new_reno.stats().congestion_window);
        assert!(cubic.stats().congestion_window - 8400 > cubic_first_increment);
    }

    #[test]
    fn hystart_enters_conservative_growth_after_sustained_delay_increase() {
        let now = Instant::now();
        let mut controller = CongestionController::new(CongestionAlgorithm::Cubic, 1200);

        for packet in 1..=10 {
            controller.on_ack_rtt_sample(Duration::from_millis(10), packet, 10);
        }
        for packet in 11..=18 {
            controller.on_ack_rtt_sample(Duration::from_millis(20), packet, 20);
        }

        assert_eq!(controller.hystart.phase, HyStartPhase::Conservative);
        let before = controller.stats().congestion_window;
        controller.on_packets_acked_at(1200, now);
        assert_eq!(controller.stats().congestion_window, before + 300);
    }

    #[test]
    fn hystart_returns_to_standard_slow_start_when_delay_recovers() {
        let mut controller = CongestionController::new(CongestionAlgorithm::Cubic, 1200);

        for packet in 1..=10 {
            controller.on_ack_rtt_sample(Duration::from_millis(10), packet, 10);
        }
        for packet in 11..=18 {
            controller.on_ack_rtt_sample(Duration::from_millis(20), packet, 20);
        }
        for packet in 20..=27 {
            controller.on_ack_rtt_sample(Duration::from_millis(15), packet, 30);
        }

        assert_eq!(controller.hystart.phase, HyStartPhase::Standard);
    }

    #[cfg(feature = "unstable-bbr3")]
    #[test]
    fn bbr_uses_delivery_rate_and_minimum_rtt_for_its_window() {
        let now = Instant::now();
        let mut bbr = CongestionController::new(CongestionAlgorithm::Bbr3, 1200);
        bbr.set_smoothed_rtt(Duration::from_millis(100));
        bbr.on_packet_sent(12_000);
        bbr.on_packets_acked_at(12_000, now);
        let first_window = bbr.stats().congestion_window;

        bbr.on_packet_sent(12_000);
        bbr.on_packets_acked_at(12_000, now + Duration::from_millis(50));

        assert_eq!(first_window, 24_000);
        assert_eq!(bbr.stats().congestion_window, 36_000);
    }

    #[cfg(feature = "unstable-bbr3")]
    #[test]
    fn bbr_loss_response_is_not_new_reno_multiplicative_decrease() {
        let mut bbr = CongestionController::new(CongestionAlgorithm::Bbr3, 1200);
        let mut new_reno = CongestionController::new(CongestionAlgorithm::NewReno, 1200);
        bbr.on_packet_sent(1200);
        new_reno.on_packet_sent(1200);

        bbr.on_packets_lost(1200);
        new_reno.on_packets_lost(1200);

        assert_eq!(bbr.stats().congestion_window, 10_200);
        assert_eq!(new_reno.stats().congestion_window, 6000);
    }

    #[cfg(feature = "unstable-bbr3")]
    #[test]
    fn bbr_pacing_uses_measured_delivery_rate() {
        let now = Instant::now();
        let mut bbr = CongestionController::new(CongestionAlgorithm::Bbr3, 1200);
        bbr.set_smoothed_rtt(Duration::from_millis(100));
        bbr.on_packets_acked_at(12_000, now);
        for _ in 0..10 {
            bbr.on_packet_sent_at(1200, now);
        }

        assert_eq!(bbr.send_at(now), Some(now + Duration::from_millis(10)));
    }
}
