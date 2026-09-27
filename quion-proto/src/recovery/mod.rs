use core::time::Duration;

pub mod ack;
pub mod loss;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttEstimator {
    latest: Option<Duration>,
    smoothed: Option<Duration>,
    min: Option<Duration>,
    variance: Option<Duration>,
}

impl RttEstimator {
    pub const fn new() -> Self {
        Self {
            latest: None,
            smoothed: None,
            min: None,
            variance: None,
        }
    }

    pub fn update(&mut self, sample: Duration) {
        self.update_with_ack_delay(sample, Duration::ZERO, Duration::ZERO);
    }

    pub fn update_with_ack_delay(
        &mut self,
        sample: Duration,
        ack_delay: Duration,
        max_ack_delay: Duration,
    ) {
        self.latest = Some(sample);
        let min_rtt = self.min.map_or(sample, |min| min.min(sample));
        self.min = Some(min_rtt);
        let adjusted = if sample > min_rtt + ack_delay.min(max_ack_delay) {
            sample - ack_delay.min(max_ack_delay)
        } else {
            sample
        };
        match self.smoothed {
            Some(smoothed) => {
                let variance_sample = duration_abs_diff(smoothed, adjusted);
                let variance = self.variance.unwrap_or(variance_sample).mul_f64(0.75)
                    + variance_sample.mul_f64(0.25);
                self.variance = Some(variance);
                self.smoothed = Some(smoothed.mul_f64(0.875) + adjusted.mul_f64(0.125));
            }
            None => {
                self.smoothed = Some(adjusted);
                self.variance = Some(adjusted.mul_f64(0.5));
            }
        }
    }

    pub const fn latest(&self) -> Option<Duration> {
        self.latest
    }

    pub const fn smoothed(&self) -> Option<Duration> {
        self.smoothed
    }

    pub const fn min(&self) -> Option<Duration> {
        self.min
    }

    pub const fn variance(&self) -> Option<Duration> {
        self.variance
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

fn duration_abs_diff(lhs: Duration, rhs: Duration) -> Duration {
    lhs.abs_diff(rhs)
}
