#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fn keys() -> (
    quion_proto::crypto::rustls::RustlsKeyStore,
    quion_proto::crypto::rustls::RustlsKeyStore,
) {
    use quion_proto::crypto::rustls::{RustlsKeyStore, RustlsProvider};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::{Arc, OnceLock};
    static CONFIG: OnceLock<(Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>)> =
        OnceLock::new();
    let (client, server) = CONFIG.get_or_init(|| {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"fuzz".to_vec()];
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
            )
            .unwrap();
        server.alpn_protocols = client.alpn_protocols.clone();
        (Arc::new(client), Arc::new(server))
    });
    let provider = RustlsProvider;
    let mut client = provider
        .start_client_with_transport_parameters(
            client.clone(),
            ServerName::try_from("localhost").unwrap(),
            vec![],
        )
        .unwrap();
    let mut server = provider
        .start_server_with_transport_parameters(server.clone(), vec![])
        .unwrap();
    let mut client_keys = RustlsKeyStore::default();
    let mut server_keys = RustlsKeyStore::default();
    for _ in 0..32 {
        let mut out = Vec::new();
        if let Some(change) = client.write_handshake(&mut out) {
            client_keys.install(change);
        }
        if !out.is_empty() {
            server.read_handshake(&out).unwrap();
        }
        out.clear();
        if let Some(change) = server.write_handshake(&mut out) {
            server_keys.install(change);
        }
        if !out.is_empty() {
            client.read_handshake(&out).unwrap();
        }
        if client_keys.current_one_rtt_key_phase().is_some()
            && server_keys.current_one_rtt_key_phase().is_some()
        {
            return (client_keys, server_keys);
        }
    }
    panic!("fixture handshake did not install application keys");
}

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    use quion_proto::{
        VarInt,
        cid::ConnectionId,
        connection::Connection,
        crypto::packet::{FramePacketBuilder, FramePacketOpener},
        frame::Frame,
        streams::StreamInitiator,
    };
    let (mut sender, mut receiver) = keys();
    let mut builder = FramePacketBuilder::new(ConnectionId::EMPTY);
    let mut conn = Connection::new();
    conn.confirm_handshake();
    conn.set_receive_datagram_frame_size(Some(VarInt::from_u32(128)));
    conn.set_datagram_queue_limits(8, 1024);
    conn.configure_inbound_stream_limits(StreamInitiator::Server, 16, 16);
    conn.configure_receive_flow_control(4096, 256, 256, 256);
    conn.set_max_stream_metadata_entries(32);
    let mut packets = std::collections::VecDeque::new();
    let mut largest = None;
    let mut now = web_time::Instant::now();
    for op in data.as_chunks::<8>().0.iter().take(128) {
        match op[0] % 10 {
            0 | 1 => {
                let frame = match op[1] % 3 {
                    0 => Frame::Ping,
                    1 => Frame::Datagram {
                        data: op[2..].to_vec().into(),
                    },
                    _ => Frame::Stream {
                        stream_id: VarInt::from_u32(u32::from(op[2] % 16) * 4),
                        offset: VarInt::from_u32(u32::from(op[3])),
                        fin: op[4] & 1 != 0,
                        data: op[5..].to_vec().into(),
                    },
                };
                if packets.len() == 8 {
                    packets.pop_front();
                }
                if let Ok(packet) = builder.build_one_rtt(&sender, &[frame]) {
                    packets.push_back(packet);
                }
            }
            2..=4 if !packets.is_empty() => {
                let index = usize::from(op[1]) % packets.len();
                let mut packet = if op[0] % 10 == 4 {
                    packets[index].clone()
                } else {
                    packets.remove(index).unwrap()
                };
                if op[0] % 10 == 3 {
                    let index = usize::from(op[2]) % packet.len();
                    packet[index] ^= op[3].max(1);
                }
                if let Ok(opened) =
                    FramePacketOpener::open_one_rtt(&mut receiver, &mut packet, 0, largest)
                {
                    largest = Some(largest.map_or(opened.packet_number, |old: u64| {
                        old.max(opened.packet_number)
                    }));
                    if conn.handle_opened_frame_packet(opened, now).is_err() {
                        break;
                    }
                }
            }
            5 => {
                now += web_time::Duration::from_millis(u64::from(op[1]));
                if conn.on_timeout(now).is_err() {
                    break;
                }
                conn.poll_transmit(now);
            }
            6 => {
                let _ = sender.initiate_one_rtt_key_update();
            }
            7 => receiver.discard_previous_one_rtt_key(),
            8 => {
                conn.read_datagram();
            }
            _ => {
                if let Some(stream) = conn.accept_recv_stream() {
                    conn.read_recv_stream(stream, 256, true);
                }
            }
        }
        let memory = conn.memory_stats();
        assert!(memory.recv_stream_states + memory.closed_recv_stream_ranges <= 32);
        assert!(packets.len() <= 8);
    }
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
