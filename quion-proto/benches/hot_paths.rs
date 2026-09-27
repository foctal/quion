use std::{
    collections::BTreeMap,
    hint::black_box,
    time::{Duration, Instant},
};

use quion_proto::{
    VarInt,
    cid::ConnectionId,
    connection::Connection,
    crypto::{
        EncryptionLevel, Side,
        initial::{InitialKeys, InitialPacketProtector},
    },
    frame::{AckRange, Frame},
    packet::{Header, LongHeader, PacketType, QUIC_VERSION_1},
    ranges::RangeSet,
    transport_parameters::TransportParameters,
};

const DEFAULT_ITERATIONS: usize = 200_000;
const STREAM_PAYLOAD_SIZE: usize = 1_200;

fn iterations() -> usize {
    std::env::var("QUION_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .unwrap_or(DEFAULT_ITERATIONS)
}

fn report(name: &str, iterations: usize, processed_bytes: usize, elapsed: Duration) {
    let seconds = elapsed.as_secs_f64();
    let operations_per_second = iterations as f64 / seconds;
    let nanoseconds_per_operation = elapsed.as_nanos() as f64 / iterations as f64;
    let mebibytes_per_second = processed_bytes as f64 / (1024.0 * 1024.0) / seconds;
    println!(
        "{{\"benchmark\":\"{name}\",\"iterations\":{iterations},\
         \"elapsed_ns\":{},\"ns_per_operation\":{nanoseconds_per_operation:.2},\
         \"operations_per_second\":{operations_per_second:.0},\
         \"mib_per_second\":{mebibytes_per_second:.2}}}",
        elapsed.as_nanos()
    );
}

fn packet_header_codec(iterations: usize) {
    let header = Header::Long(LongHeader {
        ty: PacketType::Initial,
        version: QUIC_VERSION_1,
        dst_cid: ConnectionId::from_slice(b"destination-cid").unwrap(),
        src_cid: ConnectionId::from_slice(b"source-cid").unwrap(),
        token: vec![0x5a; 32],
        length: Some(VarInt::from_u32(1_220)),
        packet_number_len: 4,
    });
    let encoded = header.encode();
    let started = Instant::now();
    for _ in 0..iterations {
        let bytes = black_box(header.encode());
        let decoded = Header::decode(black_box(&bytes), 0).unwrap();
        black_box(decoded);
    }
    report(
        "packet-header-codec",
        iterations,
        encoded.len().saturating_mul(2).saturating_mul(iterations),
        started.elapsed(),
    );
}

fn stream_frame_codec(iterations: usize) {
    let frame = Frame::Stream {
        stream_id: VarInt::from_u32(16),
        offset: VarInt::from_u32(1 << 20),
        fin: false,
        data: vec![0x5a; STREAM_PAYLOAD_SIZE].into(),
    };
    let encoded = frame.encode();
    let started = Instant::now();
    for _ in 0..iterations {
        let bytes = black_box(frame.encode());
        let decoded = Frame::decode(black_box(&bytes)).unwrap();
        black_box(decoded);
    }
    report(
        "stream-frame-codec",
        iterations,
        encoded.len().saturating_mul(2).saturating_mul(iterations),
        started.elapsed(),
    );
}

fn ack_frame_codec(iterations: usize) {
    let frame = Frame::Ack {
        largest: VarInt::from_u32(1_000_000),
        delay: VarInt::from_u32(125),
        first_range: VarInt::from_u32(31),
        ranges: (0..31)
            .map(|index| AckRange {
                gap: VarInt::from_u32(index % 3),
                range: VarInt::from_u32(7),
            })
            .collect(),
        ecn: Some((
            VarInt::from_u32(900_000),
            VarInt::from_u32(90_000),
            VarInt::from_u32(10_000),
        )),
    };
    let encoded = frame.encode();
    let started = Instant::now();
    for _ in 0..iterations {
        let bytes = black_box(frame.encode());
        let decoded = Frame::decode(black_box(&bytes)).unwrap();
        black_box(decoded);
    }
    report(
        "ack-frame-codec",
        iterations,
        encoded.len().saturating_mul(2).saturating_mul(iterations),
        started.elapsed(),
    );
}

fn transport_parameter_codec(iterations: usize) {
    let parameters = TransportParameters::default();
    let encoded = parameters.encode();
    let started = Instant::now();
    for _ in 0..iterations {
        let bytes = black_box(parameters.encode());
        let decoded = TransportParameters::decode(black_box(&bytes)).unwrap();
        black_box(decoded);
    }
    report(
        "transport-parameter-codec",
        iterations,
        encoded.len().saturating_mul(2).saturating_mul(iterations),
        started.elapsed(),
    );
}

fn initial_packet_protection(iterations: usize) {
    let destination_cid = ConnectionId::from_slice(b"initial-dcid").unwrap();
    let source_cid = ConnectionId::from_slice(b"initial-scid").unwrap();
    let keys = InitialKeys::derive(QUIC_VERSION_1, &destination_cid).unwrap();
    let client = InitialPacketProtector::new(&keys, Side::Client).unwrap();
    let server = InitialPacketProtector::new(&keys, Side::Server).unwrap();
    let header = LongHeader {
        ty: PacketType::Initial,
        version: QUIC_VERSION_1,
        dst_cid: destination_cid,
        src_cid: source_cid,
        token: Vec::new(),
        length: None,
        packet_number_len: 4,
    };
    let payload = vec![0x5a; STREAM_PAYLOAD_SIZE];
    let started = Instant::now();
    for packet_number in 0..iterations {
        let mut packet = client
            .protect_initial_packet(
                black_box(header.clone()),
                packet_number as u64,
                black_box(&payload),
            )
            .unwrap();
        let opened = server
            .open_initial_packet(black_box(&mut packet), None)
            .unwrap();
        black_box(opened.payload);
    }
    report(
        "initial-packet-protection",
        iterations,
        payload.len().saturating_mul(2).saturating_mul(iterations),
        started.elapsed(),
    );
}

fn ack_range_tracking(iterations: usize) {
    let started = Instant::now();
    let mut operations = 0usize;
    for base in 0..iterations {
        let base = (base as u64).saturating_mul(64);
        let mut ranges = RangeSet::default();
        for offset in (0..64).step_by(2) {
            ranges.insert(base + offset, base + offset + 1);
            operations += 1;
        }
        for offset in (1..64).step_by(2) {
            ranges.insert(base + offset, base + offset + 1);
            operations += 1;
        }
        black_box(ranges);
    }
    report("ack-range-tracking", operations, 0, started.elapsed());
}

fn ack_recovery(iterations: usize) {
    let frame = Frame::Ack {
        largest: VarInt::from_u32(63),
        delay: VarInt::ZERO,
        first_range: VarInt::ZERO,
        ranges: (0..31)
            .map(|_| AckRange {
                gap: VarInt::ZERO,
                range: VarInt::ZERO,
            })
            .collect(),
        ecn: Some((VarInt::from_u32(32), VarInt::ZERO, VarInt::ZERO)),
    };
    let encoded = frame.encode();
    let protocol_now = web_time::Instant::now();
    let started = Instant::now();
    for _ in 0..iterations {
        let mut connection = Connection::new();
        for packet_number in 0..64 {
            connection.record_sent_packet(
                EncryptionLevel::OneRtt,
                packet_number,
                1_200,
                true,
                protocol_now,
            );
        }
        let decoded = Frame::decode(black_box(&encoded)).unwrap().0;
        black_box(
            connection
                .handle_frame(EncryptionLevel::OneRtt, decoded, protocol_now)
                .unwrap(),
        );
    }
    report(
        "ack-frame-receive-32-ranges",
        iterations,
        encoded.len().saturating_mul(iterations),
        started.elapsed(),
    );
}

fn datagram_receive(iterations: usize) {
    let encoded = Frame::Datagram {
        data: vec![0x5a; STREAM_PAYLOAD_SIZE].into(),
    }
    .encode();
    let protocol_now = web_time::Instant::now();
    let mut connection = Connection::new();
    let started = Instant::now();
    for _ in 0..iterations {
        let decoded = Frame::decode(black_box(&encoded)).unwrap().0;
        black_box(
            connection
                .handle_frame(EncryptionLevel::OneRtt, decoded, protocol_now)
                .unwrap(),
        );
        black_box(connection.read_datagram());
    }
    report(
        "datagram-frame-receive-1200",
        iterations,
        encoded.len().saturating_mul(iterations),
        started.elapsed(),
    );
}

fn cid_route_lookup(iterations: usize) {
    let routes = (0_u64..1_024)
        .map(|value| {
            let mut bytes = [0_u8; 16];
            bytes[8..].copy_from_slice(&value.to_be_bytes());
            (ConnectionId::from_slice(&bytes).unwrap(), value)
        })
        .collect::<BTreeMap<_, _>>();
    let keys = routes.keys().cloned().collect::<Vec<_>>();
    let started = Instant::now();
    for index in 0..iterations {
        black_box(routes.get(black_box(&keys[index % keys.len()])));
    }
    report("cid-route-lookup", iterations, 0, started.elapsed());
}

fn main() {
    let iterations = iterations();
    packet_header_codec(iterations);
    stream_frame_codec(iterations);
    ack_frame_codec(iterations);
    transport_parameter_codec(iterations);
    initial_packet_protection(iterations);
    ack_range_tracking(iterations / 16);
    ack_recovery(iterations / 64);
    datagram_receive(iterations);
    cid_route_lookup(iterations.saturating_mul(4));
}
