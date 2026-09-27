use quion_proto::{
    CodecError, VarInt,
    connection::Connection,
    crypto::EncryptionLevel,
    frame::Frame,
    streams::{StreamId, StreamInitiator},
    transport_error::TransportErrorCode,
};
use web_time::Instant;

fn receiver() -> Connection {
    let mut conn = Connection::new();
    conn.configure_inbound_stream_limits(StreamInitiator::Server, 100_000, 100_000);
    conn.configure_receive_flow_control(1024, 1024, 1024, 1024);
    conn.set_max_recv_buffered_stream_data_per_connection(1024);
    conn.set_reset_stream_at_enabled(true);
    conn
}

#[test]
fn unopened_local_ids_are_rejected_for_every_peer_stream_frame() {
    for role in [StreamInitiator::Client, StreamInitiator::Server] {
        let id = VarInt::from_u32(if role == StreamInitiator::Client {
            0
        } else {
            1
        });
        let frames = [
            Frame::Stream {
                stream_id: id,
                offset: VarInt::ZERO,
                fin: false,
                data: Vec::new().into(),
            },
            Frame::ResetStream {
                stream_id: id,
                error_code: VarInt::ZERO,
                final_size: VarInt::ZERO,
            },
            Frame::ResetStreamAt {
                stream_id: id,
                error_code: VarInt::ZERO,
                final_size: VarInt::ZERO,
                reliable_size: VarInt::ZERO,
            },
            Frame::StopSending {
                stream_id: id,
                error_code: VarInt::ZERO,
            },
            Frame::MaxStreamData {
                stream_id: id,
                maximum: VarInt::from_u32(1024),
            },
        ];
        for frame in frames {
            let mut conn = receiver();
            conn.configure_inbound_stream_limits(role, 0, 0);
            assert_eq!(
                conn.handle_frame(EncryptionLevel::OneRtt, frame, Instant::now()),
                Err(CodecError::Transport(TransportErrorCode::StreamStateError))
            );
            assert_eq!(conn.memory_stats().recv_stream_states, 0);
            assert_eq!(conn.memory_stats().send_stream_states, 0);
        }
    }
}

#[test]
fn empty_peer_streams_and_fragmented_terminal_ranges_share_a_bound() {
    for terminal in [false, true] {
        let mut conn = receiver();
        conn.set_max_stream_metadata_entries(32);
        for ordinal in 0..32 {
            let id = StreamId(VarInt::from_u32(ordinal * 8));
            conn.receive_stream_frame(id, 0, vec![], terminal).unwrap();
            assert_eq!(conn.accept_recv_stream(), Some(id));
            if terminal {
                conn.stop_recv_stream(id, VarInt::ZERO).unwrap();
            }
        }
        assert_eq!(
            conn.receive_stream_frame(StreamId(VarInt::from_u32(256)), 0, vec![], false),
            Err(CodecError::BufferLimitExceeded)
        );
        let memory = conn.memory_stats();
        assert_eq!(
            memory.recv_stream_states + memory.closed_recv_stream_ranges,
            32
        );
        assert_eq!(memory.recv_stream_bytes, 0);
    }
}

#[test]
fn duplicate_reset_and_stop_late_data_release_credit_once() {
    let mut conn = receiver();
    let id = StreamId(VarInt::ZERO);
    conn.receive_stream_frame(id, 0, vec![1; 512], false)
        .unwrap();
    conn.read_recv_stream(id, 128, true).unwrap();
    conn.stop_recv_stream(id, VarInt::ZERO).unwrap();
    assert_eq!(conn.flow_control_stats().receive_limit, 1536);
    conn.receive_stream_frame(id, 512, vec![2; 512], false)
        .unwrap();
    assert_eq!(conn.flow_control_stats().receive_limit, 2048);
    assert_eq!(conn.memory_stats().recv_stream_bytes, 0);
    let reset = Frame::ResetStream {
        stream_id: id.0,
        error_code: VarInt::ZERO,
        final_size: VarInt::from_u32(1024),
    };
    for _ in 0..8 {
        conn.handle_frame(EncryptionLevel::OneRtt, reset.clone(), Instant::now())
            .unwrap();
    }
    assert_eq!(conn.flow_control_stats().receive_limit, 2048);
    conn.receive_stream_frame(StreamId(VarInt::from_u32(4)), 0, vec![3; 1024], true)
        .unwrap();
}

#[test]
fn reliable_reset_releases_union_of_unordered_reads_and_discarded_suffix() {
    let mut conn = receiver();
    let id = StreamId(VarInt::ZERO);
    conn.receive_stream_frame(id, 768, vec![1; 256], false)
        .unwrap();
    conn.read_recv_stream(id, 256, false).unwrap();
    assert_eq!(conn.flow_control_stats().receive_limit, 1280);
    let reset = Frame::ResetStreamAt {
        stream_id: id.0,
        error_code: VarInt::ZERO,
        final_size: VarInt::from_u32(1024),
        reliable_size: VarInt::from_u32(512),
    };
    for _ in 0..8 {
        conn.handle_frame(EncryptionLevel::OneRtt, reset.clone(), Instant::now())
            .unwrap();
    }
    assert_eq!(conn.flow_control_stats().receive_limit, 1536);
    conn.receive_stream_frame(id, 0, vec![2; 768], false)
        .unwrap();
    assert_eq!(conn.memory_stats().recv_stream_bytes, 512);
    assert_eq!(
        conn.read_recv_stream(id, 1024, false).unwrap().bytes.len(),
        512
    );
    assert_eq!(conn.flow_control_stats().receive_limit, 2048);
    assert_eq!(conn.recv_stream_reset_error(id), Some(VarInt::ZERO));
    assert_eq!(conn.memory_stats().recv_stream_bytes, 0);
}

#[test]
fn stopped_reliable_resets_reclaim_state_during_sequential_churn() {
    let mut conn = receiver();
    conn.set_max_stream_metadata_entries(4);
    for ordinal in 0..128 {
        let id = StreamId(VarInt::from_u32(ordinal * 4));
        conn.receive_stream_frame(id, 0, vec![1; 32], false)
            .unwrap();
        conn.accept_recv_stream();
        conn.stop_recv_stream(id, VarInt::ZERO).unwrap();
        conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::ResetStreamAt {
                stream_id: id.0,
                error_code: VarInt::ZERO,
                final_size: VarInt::from_u32(32),
                reliable_size: VarInt::from_u32(16),
            },
            Instant::now(),
        )
        .unwrap();
        assert_eq!(conn.memory_stats().recv_stream_states, 0);
        assert_eq!(conn.memory_stats().closed_recv_stream_ranges, 1);
    }
}
