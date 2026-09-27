use web_time::{Duration, Instant};

const BASE_PLPMTU: u16 = 1_200;
#[cfg(any(test, feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
const MAX_PROBE_ATTEMPTS: u8 = 3;
const BLACK_HOLE_THRESHOLD: usize = 3;

/// Configuration for Datagram Packetization Layer PMTU Discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuDiscoveryConfig {
    upper_bound: u16,
    minimum_change: u16,
    interval: Duration,
    black_hole_cooldown: Duration,
}

impl MtuDiscoveryConfig {
    /// Sets the largest UDP payload size that discovery will probe.
    pub fn set_upper_bound(&mut self, value: u16) -> &mut Self {
        self.upper_bound = value.clamp(BASE_PLPMTU, 65_527);
        self
    }

    /// Returns the largest configured probe size.
    pub const fn upper_bound(&self) -> u16 {
        self.upper_bound
    }

    /// Sets the smallest useful change in discovered payload size.
    pub fn set_minimum_change(&mut self, value: u16) -> &mut Self {
        self.minimum_change = value.max(1);
        self
    }

    /// Returns the smallest useful change in discovered payload size.
    pub const fn minimum_change(&self) -> u16 {
        self.minimum_change
    }

    /// Sets the delay before periodically searching for a larger PMTU.
    pub fn set_interval(&mut self, value: Duration) -> &mut Self {
        self.interval = value;
        self
    }

    /// Returns the delay before periodically searching for a larger PMTU.
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Sets the delay before discovery resumes after black-hole recovery.
    pub fn set_black_hole_cooldown(&mut self, value: Duration) -> &mut Self {
        self.black_hole_cooldown = value;
        self
    }

    /// Returns the delay before discovery resumes after black-hole recovery.
    pub const fn black_hole_cooldown(&self) -> Duration {
        self.black_hole_cooldown
    }
}

impl Default for MtuDiscoveryConfig {
    fn default() -> Self {
        Self {
            upper_bound: 1_452,
            minimum_change: 20,
            interval: Duration::from_secs(600),
            black_hole_cooldown: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MtuDiscovery {
    base_mtu: u16,
    current_mtu: u16,
    peer_limit: u16,
    config: Option<MtuDiscoveryConfig>,
    phase: Phase,
    suspicious_bursts: Vec<LossBurst>,
    recent_delivery: Option<Delivery>,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(any(test, feature = "rustls-ring", feature = "rustls-aws-lc-rs")),
    allow(
        dead_code,
        reason = "MTU probe sending requires a rustls backend; ACK and loss handling share this state"
    )
)]
enum Phase {
    Initial,
    Searching(Search),
    Complete { resume_at: Instant },
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(any(test, feature = "rustls-ring", feature = "rustls-aws-lc-rs")),
    allow(
        dead_code,
        reason = "MTU probe sending requires a rustls backend; ACK and loss handling share this state"
    )
)]
struct Search {
    lower: u16,
    upper: u16,
    candidate: u16,
    in_flight: Option<u64>,
    failed_attempts: u8,
    retry_unsent: bool,
}

#[derive(Debug, Clone, Copy)]
struct LossBurst {
    end_packet: u64,
    smallest_size: u16,
}

#[derive(Debug, Clone, Copy)]
struct Delivery {
    packet_number: u64,
    size: u16,
}

impl MtuDiscovery {
    pub(crate) fn new(initial_mtu: u16, config: Option<MtuDiscoveryConfig>) -> Self {
        let initial_mtu = initial_mtu.clamp(BASE_PLPMTU, 65_527);
        Self {
            base_mtu: BASE_PLPMTU,
            current_mtu: initial_mtu,
            peer_limit: 65_527,
            config,
            phase: Phase::Initial,
            suspicious_bursts: Vec::with_capacity(BLACK_HOLE_THRESHOLD),
            recent_delivery: None,
        }
    }

    pub(crate) const fn current_mtu(&self) -> u16 {
        self.current_mtu
    }

    pub(crate) fn set_peer_limit(&mut self, value: u16) {
        self.peer_limit = value.clamp(BASE_PLPMTU, 65_527);
        self.current_mtu = self.current_mtu.min(self.peer_limit);
        self.phase = Phase::Initial;
    }

    pub(crate) fn reset_path(&mut self, initial_mtu: u16) {
        self.current_mtu = initial_mtu.clamp(self.base_mtu, self.peer_limit);
        self.phase = Phase::Initial;
        self.suspicious_bursts.clear();
        self.recent_delivery = None;
    }

    pub(crate) fn in_flight_probe(&self) -> Option<u64> {
        match self.phase {
            Phase::Searching(search) => search.in_flight,
            Phase::Initial | Phase::Complete { .. } => None,
        }
    }

    #[cfg(any(test, feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn poll_probe(&mut self, now: Instant, packet_number: u64) -> Option<u16> {
        let config = self.config.as_ref()?;
        match self.phase {
            Phase::Initial => {
                self.phase = Phase::Searching(Search::new(
                    self.current_mtu,
                    self.peer_limit.min(config.upper_bound),
                ));
            }
            Phase::Complete { resume_at } if now >= resume_at => {
                self.phase = Phase::Searching(Search::new(
                    self.current_mtu,
                    self.peer_limit.min(config.upper_bound),
                ));
            }
            Phase::Complete { .. } => return None,
            Phase::Searching(_) => {}
        }

        let Phase::Searching(search) = &mut self.phase else {
            return None;
        };
        if search.in_flight.is_some() {
            return None;
        }

        if search.retry_unsent {
            search.retry_unsent = false;
            search.in_flight = Some(packet_number);
            return Some(search.candidate);
        }
        if search.failed_attempts != 0 && search.failed_attempts < MAX_PROBE_ATTEMPTS {
            search.in_flight = Some(packet_number);
            return Some(search.candidate);
        }
        if search.failed_attempts == MAX_PROBE_ATTEMPTS {
            search.upper = search.candidate.saturating_sub(1);
            search.failed_attempts = 0;
        } else {
            search.lower = search.lower.max(self.current_mtu);
        }

        let candidate = next_probe_size(
            search.lower,
            search.upper,
            search.candidate,
            config.minimum_change,
        );
        let Some(candidate) = candidate else {
            self.phase = Phase::Complete {
                resume_at: now + config.interval,
            };
            return None;
        };
        search.candidate = candidate;
        search.in_flight = Some(packet_number);
        Some(candidate)
    }

    #[cfg(any(test, feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn on_probe_not_sent(&mut self, packet_number: u64) {
        if let Phase::Searching(search) = &mut self.phase
            && search.in_flight == Some(packet_number)
        {
            search.in_flight = None;
            search.retry_unsent = true;
        }
    }

    pub(crate) fn on_acked(&mut self, packet_number: u64, size: u16) -> bool {
        if let Phase::Searching(search) = &mut self.phase
            && search.in_flight == Some(packet_number)
        {
            search.in_flight = None;
            search.failed_attempts = 0;
            search.lower = search.lower.max(search.candidate);
            self.current_mtu = search.candidate;
            self.suspicious_bursts.clear();
            self.note_delivery(packet_number, size);
            return true;
        }
        self.note_delivery(packet_number, size);
        false
    }

    pub(crate) fn on_probe_lost(&mut self, packet_number: u64) -> bool {
        if let Phase::Searching(search) = &mut self.phase
            && search.in_flight == Some(packet_number)
        {
            search.in_flight = None;
            search.failed_attempts = search.failed_attempts.saturating_add(1);
            return true;
        }
        false
    }

    pub(crate) fn on_non_probe_losses(
        &mut self,
        losses: impl IntoIterator<Item = (u64, u16)>,
        now: Instant,
    ) -> bool {
        if self.current_mtu <= self.base_mtu {
            return false;
        }
        let mut burst_start = None;
        let mut burst_end = 0;
        let mut smallest_size = u16::MAX;
        let mut previous = None;
        for (packet_number, size) in losses {
            if previous.is_some_and(|value| packet_number != value + 1) {
                self.record_loss_burst(burst_start, burst_end, smallest_size);
                burst_start = None;
                smallest_size = u16::MAX;
            }
            burst_start.get_or_insert(packet_number);
            burst_end = packet_number;
            smallest_size = smallest_size.min(size);
            previous = Some(packet_number);
        }
        self.record_loss_burst(burst_start, burst_end, smallest_size);
        self.recent_delivery = None;

        if self.suspicious_bursts.len() < BLACK_HOLE_THRESHOLD {
            return false;
        }
        self.current_mtu = self.base_mtu;
        self.suspicious_bursts.clear();
        self.recent_delivery = None;
        if let Some(config) = &self.config {
            self.phase = Phase::Complete {
                resume_at: now + config.black_hole_cooldown,
            };
        } else {
            self.phase = Phase::Initial;
        }
        true
    }

    fn note_delivery(&mut self, packet_number: u64, size: u16) {
        self.suspicious_bursts
            .retain(|burst| packet_number <= burst.end_packet || size < burst.smallest_size);
        if self.recent_delivery.is_none_or(|delivery| {
            size > delivery.size
                || (size == delivery.size && packet_number > delivery.packet_number)
        }) {
            self.recent_delivery = Some(Delivery {
                packet_number,
                size,
            });
        }
    }

    fn record_loss_burst(&mut self, start: Option<u64>, end: u64, smallest_size: u16) {
        if start.is_none() || smallest_size <= self.base_mtu {
            return;
        }
        let disproved = self
            .recent_delivery
            .is_some_and(|delivery| delivery.packet_number > end && delivery.size >= smallest_size);
        if !disproved {
            self.suspicious_bursts.push(LossBurst {
                end_packet: end,
                smallest_size,
            });
        }
    }
}

#[cfg(any(test, feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl Search {
    fn new(lower: u16, upper: u16) -> Self {
        Self {
            lower,
            upper: upper.max(lower),
            candidate: lower,
            in_flight: None,
            failed_attempts: 0,
            retry_unsent: false,
        }
    }
}

#[cfg(any(test, feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn next_probe_size(lower: u16, upper: u16, previous: u16, minimum_change: u16) -> Option<u16> {
    if upper <= lower {
        return None;
    }
    let midpoint = lower + (upper - lower) / 2;
    if midpoint.abs_diff(previous) >= minimum_change {
        return Some(midpoint);
    }
    (upper.abs_diff(previous) >= minimum_change).then_some(upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_raises_mtu_after_authenticated_probe_ack() {
        let now = Instant::now();
        let mut discovery = MtuDiscovery::new(1_200, Some(MtuDiscoveryConfig::default()));
        let probe = discovery.poll_probe(now, 7).unwrap();
        assert!(probe > 1_200);
        assert!(discovery.on_acked(7, probe));
        assert_eq!(discovery.current_mtu(), probe);
    }

    #[test]
    fn search_retries_a_probe_three_times_before_reducing_upper_bound() {
        let now = Instant::now();
        let mut discovery = MtuDiscovery::new(1_200, Some(MtuDiscoveryConfig::default()));
        let first = discovery.poll_probe(now, 1).unwrap();
        for packet_number in 1..=3 {
            assert!(discovery.on_probe_lost(packet_number));
            if packet_number < 3 {
                assert_eq!(discovery.poll_probe(now, packet_number + 1), Some(first));
            }
        }
        assert!(discovery.poll_probe(now, 4).unwrap() < first);
    }

    #[test]
    fn later_equal_sized_delivery_disproves_a_suspicious_loss_burst() {
        let now = Instant::now();
        let mut discovery = MtuDiscovery::new(1_452, Some(MtuDiscoveryConfig::default()));
        assert!(!discovery.on_non_probe_losses([(1, 1_452), (2, 1_452)], now));
        discovery.on_acked(3, 1_452);
        for packet_number in [5, 7, 9] {
            assert!(!discovery.on_non_probe_losses([(packet_number, 1_452)], now));
            discovery.on_acked(packet_number + 1, 1_452);
        }
        assert_eq!(discovery.current_mtu(), 1_452);
    }

    #[test]
    fn three_unexplained_large_loss_bursts_restore_base_mtu() {
        let now = Instant::now();
        let mut discovery = MtuDiscovery::new(1_452, Some(MtuDiscoveryConfig::default()));
        assert!(!discovery.on_non_probe_losses([(1, 1_452)], now));
        assert!(!discovery.on_non_probe_losses([(3, 1_452)], now));
        assert!(discovery.on_non_probe_losses([(5, 1_452)], now));
        assert_eq!(discovery.current_mtu(), 1_200);
        assert_eq!(discovery.poll_probe(now, 6), None);
    }

    #[test]
    fn peer_limit_caps_search() {
        let now = Instant::now();
        let mut discovery = MtuDiscovery::new(1_452, Some(MtuDiscoveryConfig::default()));
        discovery.set_peer_limit(1_300);
        assert_eq!(discovery.current_mtu(), 1_300);
        let probe = discovery.poll_probe(now, 1);
        assert_eq!(probe, None);
    }

    #[test]
    fn unsent_probe_can_be_polled_again_without_counting_as_loss() {
        let now = Instant::now();
        let mut discovery = MtuDiscovery::new(1_200, Some(MtuDiscoveryConfig::default()));
        let first = discovery.poll_probe(now, 10).unwrap();
        discovery.on_probe_not_sent(10);
        assert_eq!(discovery.poll_probe(now, 11), Some(first));
    }

    #[test]
    fn path_reset_restores_configured_starting_mtu() {
        let mut discovery = MtuDiscovery::new(1_452, Some(MtuDiscoveryConfig::default()));
        discovery.set_peer_limit(1_400);
        discovery.reset_path(1_300);
        assert_eq!(discovery.current_mtu(), 1_300);
        assert_eq!(discovery.in_flight_probe(), None);
    }
}
