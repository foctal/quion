use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crate::connection::{EndpointMemoryBudget, EndpointMemoryReservation};

/// Structured diagnostic event emitted by the protocol core.
pub type QlogEvent = quion_proto::qlog::QlogEvent;
/// Thread-safe callback invoked synchronously for each qlog event.
pub type QlogHandler = Arc<dyn Fn(&QlogEvent) + Send + Sync + 'static>;

#[derive(Clone)]
pub(crate) struct SharedQlogState {
    handler: Option<QlogHandler>,
    buffered: Arc<Mutex<BufferedQlogEvents>>,
    max_buffered_events: usize,
}

#[derive(Debug, Default)]
struct BufferedQlogEvents {
    events: VecDeque<RetainedQlogEvent>,
    budget: Option<Arc<EndpointMemoryBudget>>,
}

#[derive(Debug)]
struct RetainedQlogEvent {
    event: QlogEvent,
    _reservation: Option<EndpointMemoryReservation>,
}

pub(crate) const DEFAULT_MAX_BUFFERED_QLOG_EVENTS: usize = 0;
const ACCOUNTED_QLOG_EVENT_BYTES: usize = core::mem::size_of::<RetainedQlogEvent>();

impl Default for SharedQlogState {
    fn default() -> Self {
        Self::new(None)
    }
}

impl core::fmt::Debug for SharedQlogState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedQlogState")
            .field("has_handler", &self.handler.is_some())
            .finish()
    }
}

impl SharedQlogState {
    pub(crate) fn new(handler: Option<QlogHandler>) -> Self {
        Self::with_max_buffered_events(handler, DEFAULT_MAX_BUFFERED_QLOG_EVENTS)
    }

    pub(crate) fn with_max_buffered_events(
        handler: Option<QlogHandler>,
        max_buffered_events: usize,
    ) -> Self {
        Self {
            handler,
            buffered: Arc::new(Mutex::new(BufferedQlogEvents::default())),
            max_buffered_events,
        }
    }

    pub(crate) fn attach_endpoint_memory_budget(&self, budget: Arc<EndpointMemoryBudget>) {
        let mut buffered = self
            .buffered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if buffered.budget.is_some() {
            return;
        }
        buffered.budget = Some(budget.clone());
        for retained in &mut buffered.events {
            retained._reservation = budget.try_reserve(ACCOUNTED_QLOG_EVENT_BYTES);
        }
        buffered
            .events
            .retain(|retained| retained._reservation.is_some());
    }

    pub(crate) fn publish(&self, events: Vec<QlogEvent>) {
        if events.is_empty() {
            return;
        }
        {
            let mut buffered = self
                .buffered
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for event in events.iter().cloned() {
                if self.max_buffered_events == 0 {
                    continue;
                }
                if buffered.events.len() == self.max_buffered_events {
                    buffered.events.pop_front();
                }
                let reservation = if let Some(budget) = buffered.budget.clone() {
                    let mut reservation = budget.try_reserve(ACCOUNTED_QLOG_EVENT_BYTES);
                    while reservation.is_none() && !buffered.events.is_empty() {
                        buffered.events.pop_front();
                        reservation = budget.try_reserve(ACCOUNTED_QLOG_EVENT_BYTES);
                    }
                    let Some(reservation) = reservation else {
                        continue;
                    };
                    Some(reservation)
                } else {
                    None
                };
                buffered.events.push_back(RetainedQlogEvent {
                    event,
                    _reservation: reservation,
                });
            }
        }
        if let Some(handler) = &self.handler {
            for event in &events {
                handler(event);
            }
        }
    }

    pub(crate) fn drain(&self) -> Vec<QlogEvent> {
        let mut buffered = self
            .buffered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        buffered
            .events
            .drain(..)
            .map(|retained| retained.event)
            .collect()
    }

    pub(crate) fn buffered_len(&self) -> usize {
        self.buffered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .events
            .len()
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.buffered_len()
            .saturating_mul(ACCOUNTED_QLOG_EVENT_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(packet_number: u64) -> QlogEvent {
        QlogEvent::PacketLost {
            level: "1rtt",
            packet_number,
        }
    }

    #[test]
    fn bounded_buffer_drops_oldest_events() {
        let qlog = SharedQlogState::with_max_buffered_events(None, 3);

        qlog.publish(vec![event(1), event(2)]);
        qlog.publish(vec![event(3), event(4)]);

        assert_eq!(qlog.drain(), vec![event(2), event(3), event(4)]);
        assert!(qlog.drain().is_empty());
    }

    #[test]
    fn zero_buffer_still_calls_handler_without_retaining_events() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = captured.clone();
        let qlog = SharedQlogState::with_max_buffered_events(
            Some(Arc::new(move |event| {
                sink.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(event.clone());
            })),
            0,
        );

        qlog.publish(vec![event(7), event(8)]);

        assert!(qlog.drain().is_empty());
        assert_eq!(
            captured
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            &[event(7), event(8)]
        );
    }

    #[test]
    fn endpoint_budget_bounds_and_releases_buffered_events() {
        let budget = Arc::new(EndpointMemoryBudget::new(ACCOUNTED_QLOG_EVENT_BYTES));
        let qlog = SharedQlogState::with_max_buffered_events(None, 3);
        qlog.attach_endpoint_memory_budget(budget.clone());

        qlog.publish(vec![event(1), event(2), event(3)]);

        assert_eq!(qlog.buffered_len(), 1);
        assert_eq!(qlog.buffered_bytes(), ACCOUNTED_QLOG_EVENT_BYTES);
        assert_eq!(budget.used_bytes(), ACCOUNTED_QLOG_EVENT_BYTES);
        assert_eq!(qlog.drain(), vec![event(3)]);
        assert_eq!(budget.used_bytes(), 0);
    }
}
