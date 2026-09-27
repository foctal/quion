#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

// Each eight-byte operation encodes an action, stream ordinal/direction,
// offset/size, and payload. The cap keeps individual executions bounded.
#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    use quion_proto::{
        VarInt,
        connection::Connection,
        crypto::EncryptionLevel,
        frame::Frame,
        streams::{StreamId, StreamInitiator},
    };
    let mut conn = Connection::new();
    conn.configure_inbound_stream_limits(StreamInitiator::Server, 256, 256);
    conn.configure_receive_flow_control(1024, 1024, 1024, 1024);
    conn.set_max_stream_metadata_entries(32);
    conn.set_reset_stream_at_enabled(true);
    let mut now = web_time::Instant::now();
    for op in data.as_chunks::<8>().0.iter().take(256) {
        let id = StreamId(VarInt::from_u32(
            u32::from(op[1]) * 4 + u32::from(op[2] & 3),
        ));
        let offset = VarInt::from_u32(u32::from(u16::from_le_bytes([op[3], op[4]])));
        let result = match op[0] % 10 {
            0 => conn
                .handle_frame(
                    EncryptionLevel::OneRtt,
                    Frame::Stream {
                        stream_id: id.0,
                        offset,
                        fin: op[5] & 1 != 0,
                        data: op[6..].to_vec().into(),
                    },
                    now,
                )
                .map(|_| ()),
            1 => conn
                .handle_frame(
                    EncryptionLevel::OneRtt,
                    Frame::ResetStream {
                        stream_id: id.0,
                        error_code: VarInt::ZERO,
                        final_size: offset,
                    },
                    now,
                )
                .map(|_| ()),
            2 => conn
                .handle_frame(
                    EncryptionLevel::OneRtt,
                    Frame::ResetStreamAt {
                        stream_id: id.0,
                        error_code: VarInt::ZERO,
                        final_size: offset,
                        reliable_size: VarInt::from_u32(u32::from(op[5])),
                    },
                    now,
                )
                .map(|_| ()),
            3 => conn.stop_recv_stream(id, VarInt::ZERO).map(|_| ()),
            4 => conn.register_local_stream(StreamId(VarInt::from_u32(u32::from(op[1]) * 4 + 1))),
            5 => {
                conn.read_recv_stream(id, usize::from(op[5]), op[6] & 1 == 0);
                Ok(())
            }
            6 => {
                conn.accept_recv_stream();
                Ok(())
            }
            7 => conn
                .handle_frame_payload(EncryptionLevel::OneRtt, &op[1..], now)
                .map(|_| ()),
            8 => {
                now += web_time::Duration::from_millis(u64::from(op[5]));
                conn.on_timeout(now).map(|_| ())
            }
            _ => {
                conn.poll_transmit(now);
                Ok(())
            }
        };
        let memory = conn.memory_stats();
        assert!(memory.recv_stream_states + memory.closed_recv_stream_ranges <= 32);
        assert!(memory.send_stream_states + memory.closed_send_stream_ranges <= 32);
        if result.is_err() {
            break;
        }
    }
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
