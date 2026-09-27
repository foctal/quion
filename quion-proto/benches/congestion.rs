use std::{hint::black_box, time::Instant as StdInstant};

use quion_proto::congestion::{CongestionAlgorithm, CongestionController};
use web_time::{Duration, Instant};

const ITERATIONS: u64 = 1_000_000;

fn run(name: &str, algorithm: CongestionAlgorithm) {
    let mut controller = CongestionController::new(algorithm, 1200);
    controller.set_smoothed_rtt(Duration::from_millis(50));
    let base = Instant::now();
    let started = StdInstant::now();
    for iteration in 0..ITERATIONS {
        controller.on_packet_sent(1200);
        controller.on_packets_acked_at(
            1200,
            base + Duration::from_micros(iteration.saturating_mul(50)),
        );
        if iteration % 1000 == 999 {
            controller.on_packet_sent(1200);
            controller.on_packets_lost(1200);
        }
        black_box(controller.stats());
    }
    let elapsed = started.elapsed();
    println!(
        "{name}: {ITERATIONS} ACK/loss updates in {elapsed:?} ({:.0} updates/s)",
        ITERATIONS as f64 / elapsed.as_secs_f64()
    );
}

fn main() {
    run("new-reno", CongestionAlgorithm::NewReno);
    run("cubic", CongestionAlgorithm::Cubic);
    #[cfg(feature = "unstable-bbr3")]
    run("bbr3-experimental", CongestionAlgorithm::Bbr3);
}
