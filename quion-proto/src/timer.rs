use web_time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    AckDelay,
    Idle,
    LossDetection,
    Pacing,
    PathValidation,
    CloseDrain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    pub timer: Timer,
    pub at: Instant,
}

impl Deadline {
    pub fn after(timer: Timer, now: Instant, duration: Duration) -> Self {
        Self {
            timer,
            at: now + duration,
        }
    }
}
