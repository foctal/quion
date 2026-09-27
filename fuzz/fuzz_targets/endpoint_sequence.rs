#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use quion_proto::{
        VarInt,
        cid::ConnectionId,
        endpoint::{Admission, Endpoint},
        packet::{LongHeader, PacketType, QUIC_VERSION_1},
    };
    let mut endpoint = Endpoint::new();
    endpoint.set_max_tracked_paths(8);
    endpoint.set_max_retry_replay_entries(8);
    let mut routes = [None; 16];
    for (step, op) in data.as_chunks::<8>().0.iter().take(256).enumerate() {
        let index = usize::from(op[1] % 16);
        let cid = ConnectionId::from_slice(&[index as u8; 8]).unwrap();
        let owner = usize::from(op[2]);
        let remote = std::net::SocketAddr::from(([127, 0, 0, 1], u16::from(op[3])));
        match op[0] % 7 {
            0 => {
                endpoint.insert_route(cid.clone(), owner);
                routes[index] = Some(owner);
            }
            1 => assert_eq!(endpoint.remove_route(&cid), routes[index].take()),
            2 => {
                let expected = routes[index] == Some(owner);
                assert_eq!(endpoint.retire_connection_route(&cid, owner), expected);
                if expected {
                    routes[index] = None;
                }
            }
            3 => {
                endpoint.set_retry_enabled(op[4] & 1 != 0);
                let header = LongHeader {
                    ty: PacketType::Initial,
                    version: QUIC_VERSION_1,
                    dst_cid: cid.clone(),
                    src_cid: ConnectionId::from_slice(&op[..8]).unwrap(),
                    token: Vec::new(),
                    length: Some(VarInt::from_u32(1200)),
                    packet_number_len: 2,
                };
                let admission = endpoint
                    .admit_initial(remote, &header, 1200, step as u64)
                    .unwrap();
                if let Some(owner) = routes[index] {
                    assert!(
                        matches!(admission, Admission::ExistingConnection { connection } if connection == owner)
                    );
                }
            }
            4 => endpoint.path(remote).record_received(u64::from(op[4])),
            5 => {
                let amount = u64::from(u16::from_le_bytes([op[4], op[5]]));
                let budget = endpoint.path(remote);
                let available = budget.available();
                assert_eq!(budget.record_sent(amount), amount <= available);
                assert!(budget.bytes_sent <= budget.bytes_received * 3);
            }
            _ => endpoint.refund_send_to(remote, u64::from(op[4])),
        }
        assert_eq!(endpoint.route(&cid), routes[index]);
        assert!(endpoint.tracked_paths() <= 8);
    }
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
