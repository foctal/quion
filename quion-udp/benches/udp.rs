use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use quion_udp::{BatchRecv, BatchSend, EcnCodepoint, Transmit, UdpSocket};

const ITERATIONS: usize = 2_000;

fn run(
    name: &str,
    datagrams_per_batch: usize,
    explicit_source: bool,
    ecn: Option<EcnCodepoint>,
    segment_size: Option<usize>,
) {
    let sender = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let destination = receiver.local_addr().unwrap();
    let source = explicit_source.then(|| sender.local_addr().unwrap());
    let payload_len = segment_size.map_or(1200, |size| size * 4);
    let mut send = BatchSend::default();
    for _ in 0..datagrams_per_batch {
        send.push(Transmit {
            destination,
            source,
            ecn,
            contents: vec![0x5a; payload_len],
            segment_size,
            send_at: None,
        });
    }

    let started = Instant::now();
    let mut completed = 0usize;
    let mut recv = BatchRecv::default();
    for _ in 0..ITERATIONS {
        let sent = sender.send_batch(&send).unwrap();
        completed += sent;
        while recv.len() < sent {
            receiver.recv_batch(&mut recv, sent, 65_535).unwrap();
            if recv.len() < sent {
                std::thread::yield_now();
            }
        }
        black_box(recv.iter().map(|(bytes, _)| bytes.len()).sum::<usize>());
        recv.clear();
    }
    let elapsed = started.elapsed().max(Duration::from_nanos(1));
    println!(
        "{name}: {completed} datagrams in {elapsed:?} ({:.0} datagrams/s)",
        completed as f64 / elapsed.as_secs_f64()
    );
}

fn run_single(name: &str, explicit_source: bool, ecn: Option<EcnCodepoint>) {
    let sender = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let source = explicit_source.then(|| sender.local_addr().unwrap());
    let transmit = Transmit {
        destination: receiver.local_addr().unwrap(),
        source,
        ecn,
        contents: vec![0x5a; 1200],
        segment_size: None,
        send_at: None,
    };
    let mut recv_buffer = vec![0; 65_535];

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        sender.send(&transmit).unwrap();
        while receiver.recv(&mut recv_buffer).unwrap().is_none() {
            std::thread::yield_now();
        }
        black_box(&recv_buffer[..transmit.contents.len()]);
    }
    let elapsed = started.elapsed().max(Duration::from_nanos(1));
    println!(
        "{name}: {ITERATIONS} datagrams in {elapsed:?} ({:.0} datagrams/s)",
        ITERATIONS as f64 / elapsed.as_secs_f64()
    );
}

fn main() {
    run_single("single-send", false, None);
    run_single(
        "single-send-quic-control-metadata",
        true,
        Some(EcnCodepoint::Ect0),
    );
    for datagrams_per_batch in [1, 8, 32] {
        run(
            &format!("portable-batch-{datagrams_per_batch}"),
            datagrams_per_batch,
            false,
            None,
            None,
        );
        run(
            &format!("quic-control-metadata-{datagrams_per_batch}"),
            datagrams_per_batch,
            true,
            Some(EcnCodepoint::Ect0),
            None,
        );
    }
    #[cfg(all(target_os = "linux", feature = "gso"))]
    run("linux-gso", 32, true, Some(EcnCodepoint::Ect0), Some(1200));
}
