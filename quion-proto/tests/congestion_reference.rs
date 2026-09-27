use std::{sync::Arc, time::Duration};

use quinn_proto_reference::congestion::{Controller, NewReno, NewRenoConfig};
use quion_proto::congestion::{CongestionAlgorithm, CongestionController};
use web_time::Instant;

fn run_quion(ack_order: &[u64], ack_delay: Duration) -> u64 {
    let base = Instant::now();
    let mut controller = CongestionController::new(CongestionAlgorithm::NewReno, 1200);
    for bytes in ack_order {
        controller.on_packet_sent(*bytes);
        controller.on_packets_acked_at(*bytes, base + ack_delay);
    }
    controller.stats().congestion_window
}

fn run_quinn_loss(ack_delay: Duration) -> u64 {
    let base = std::time::Instant::now();
    let sent = base + Duration::from_millis(1);
    let mut controller = NewReno::new(Arc::new(NewRenoConfig::default()), base, 1200);
    controller.on_sent(sent, 1200, 1);
    controller.on_congestion_event(
        sent + ack_delay + Duration::from_millis(1),
        sent,
        false,
        1200,
    );
    controller.window()
}

#[test]
fn new_reno_loss_reduction_matches_quinn_across_detection_delays() {
    for delay in [
        Duration::from_millis(5),
        Duration::from_millis(25),
        Duration::from_millis(100),
    ] {
        let mut quion = CongestionController::new(CongestionAlgorithm::NewReno, 1200);
        quion.on_packet_sent(1200);
        quion.on_packets_lost(1200);
        assert_eq!(quion.stats().congestion_window, run_quinn_loss(delay));
    }
}

#[test]
fn new_reno_is_deterministic_under_ack_reordering_and_delay() {
    let scenarios = [
        ([1200, 2400, 3600], Duration::from_millis(5)),
        ([3600, 1200, 2400], Duration::from_millis(25)),
        ([2400, 3600, 1200], Duration::from_millis(100)),
    ];

    for (ack_order, ack_delay) in scenarios {
        assert_eq!(
            run_quion(&ack_order, ack_delay),
            19_200,
            "ACK order {ack_order:?}, delay {ack_delay:?}"
        );
    }
}
