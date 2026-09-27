#![cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use quion::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, VarInt};
static NEXT_TEST_CERT_ID: AtomicU64 = AtomicU64::new(0);

fn write_test_cert_materials() -> (PathBuf, PathBuf) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let unique = NEXT_TEST_CERT_ID.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "quion-loopback-{}-{stamp}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&base).unwrap();
    let cert_path = base.join("cert.pem");
    let key_path = base.join("key.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    (cert_path, key_path)
}

async fn connect_loopback(
    client_transport: TransportConfig,
    server_transport: TransportConfig,
) -> (
    Endpoint,
    Endpoint,
    quion::EndpointServerUdpDriverHandle,
    Connection,
    Connection,
) {
    let (cert_path, key_path) = write_test_cert_materials();
    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(&cert_path)
        .unwrap()
        .with_transport_config(client_transport)
        .build();
    let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let server_endpoint = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&cert_path, &key_path)
            .unwrap()
            .with_transport_config(server_transport.clone())
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();

    let client = tokio::time::timeout(Duration::from_secs(1), async {
        client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap()
            .await
    })
    .await
    .expect("connect timed out")
    .unwrap();

    let incoming = tokio::time::timeout(Duration::from_secs(1), server_endpoint.accept())
        .await
        .expect("accept timed out")
        .expect("endpoint closed");
    let server = tokio::time::timeout(Duration::from_secs(1), incoming)
        .await
        .expect("incoming timed out")
        .unwrap();

    (
        client_endpoint,
        server_endpoint,
        server_driver,
        client,
        server,
    )
}

#[tokio::test]
async fn delayed_read_replenishes_credit() {
    let mut transport = TransportConfig::default();
    transport.set_initial_max_stream_data_uni(VarInt::from_u32(1024));
    transport.set_mtu_discovery_config(None);
    let (ce, se, driver, client, server) = connect_loopback(transport.clone(), transport).await;
    let mut send = client.open_uni().await.unwrap();
    send.write_all(&[1; 1024]).await.unwrap();
    let mut recv = server.accept_uni().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut data = [0; 1024];
    recv.read_exact(&mut data).await.unwrap();
    let result = tokio::time::timeout(Duration::from_millis(500), send.write_all(&[2; 1024])).await;
    ce.abort();
    se.abort();
    driver.stop().await.unwrap();
    assert!(
        result.is_ok(),
        "reading an idle stream did not transmit fresh credit within 500 ms"
    );
}

#[tokio::test]
async fn dropped_connecting_cancels_handshake() {
    let (cert_path, key_path) = write_test_cert_materials();
    let client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(
        ClientConfig::builder()
            .with_root_certificates_from_pem_file(&cert_path)
            .unwrap()
            .build(),
    );
    let server = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&cert_path, &key_path)
            .unwrap()
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let driver = server.spawn_default_server_udp_driver(65535).unwrap();
    drop(client.connect(server.local_addr(), "localhost").unwrap());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let active = client.diagnostics().active_connections;
    client.abort();
    server.abort();
    driver.stop().await.unwrap();
    assert_eq!(
        active, 0,
        "dropped Connecting left an established connection registered"
    );
}

#[tokio::test]
async fn dropped_send_stream_notifies_peer() {
    let (ce, se, driver, client, server) =
        connect_loopback(TransportConfig::default(), TransportConfig::default()).await;
    let mut send = client.open_uni().await.unwrap();
    send.write_all(b"request").await.unwrap();
    drop(send);
    let mut recv = server.accept_uni().await.unwrap();
    let result = tokio::time::timeout(Duration::from_millis(300), recv.read_to_end(1024)).await;
    ce.abort();
    se.abort();
    driver.stop().await.unwrap();
    assert!(
        result.is_ok(),
        "dropped sender produced neither FIN nor RESET_STREAM"
    );
}

#[test]
fn reset_releases_connection_credit() {
    use quion_proto::{
        connection::Connection as ProtoConnection, crypto::EncryptionLevel, frame::Frame,
    };
    let mut conn = ProtoConnection::new();
    conn.configure_inbound_stream_limits(quion_proto::streams::StreamInitiator::Server, 10, 10);
    conn.configure_receive_flow_control(1024, 1024, 1024, 1024);
    conn.handle_frame(
        EncryptionLevel::OneRtt,
        Frame::ResetStream {
            stream_id: VarInt::ZERO,
            error_code: VarInt::ZERO,
            final_size: VarInt::from_u32(1024),
        },
        web_time::Instant::now(),
    )
    .unwrap();
    let result = conn.handle_frame(
        EncryptionLevel::OneRtt,
        Frame::ResetStream {
            stream_id: VarInt::from_u32(4),
            error_code: VarInt::ZERO,
            final_size: VarInt::from_u32(1),
        },
        web_time::Instant::now(),
    );
    println!("Additional input result: {result:?}");
    assert!(
        conn.flow_control_stats().receive_limit > 1024,
        "discarded reset bytes never replenish MAX_DATA"
    );
}

#[test]
fn peer_cannot_create_local_bidirectional_streams() {
    use quion_proto::{
        connection::Connection as ProtoConnection, crypto::EncryptionLevel, frame::Frame,
        streams::StreamInitiator,
    };
    let mut conn = ProtoConnection::new();
    conn.configure_inbound_stream_limits(StreamInitiator::Client, 0, 0);
    let mut accepted = 0;
    for ordinal in 0..4096 {
        let result = conn.handle_frame(
            EncryptionLevel::OneRtt,
            Frame::Stream {
                stream_id: VarInt::new(ordinal * 4).unwrap(),
                offset: VarInt::ZERO,
                fin: false,
                data: bytes::Bytes::new(),
            },
            web_time::Instant::now(),
        );
        if result.is_ok() {
            accepted += 1;
        }
    }
    println!(
        "Accepted invalid streams: {accepted}; memory: {:?}",
        conn.memory_stats()
    );
    assert_eq!(
        accepted, 0,
        "peer created unopened local bidirectional streams despite zero inbound limits"
    );
}

#[tokio::test]
async fn cancelling_silent_handshakes_releases_reservations_without_idle_timeout() {
    let (cert_path, _) = write_test_cert_materials();
    let mut transport = TransportConfig::default();
    transport.set_max_idle_timeout(VarInt::ZERO);
    let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        ClientConfig::builder()
            .with_root_certificates_from_pem_file(cert_path)
            .unwrap()
            .with_transport_config(transport)
            .build(),
    );
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let baseline = endpoint.diagnostics().memory;
    for _ in 0..16 {
        let connecting = endpoint
            .connect(silent.local_addr().unwrap(), "localhost")
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        drop(connecting);
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let d = endpoint.diagnostics();
            if d.pending_client_handshakes == 0 && d.active_connections == 0 {
                assert_eq!(
                    d.memory.reserved_payload_bytes,
                    baseline.reserved_payload_bytes
                );
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    endpoint.abort();
}

#[tokio::test]
async fn default_server_survives_client_nat_port_rebinding() {
    use std::sync::{Arc, atomic::AtomicBool};
    let (cert_path, key_path) = write_test_cert_materials();
    let ce = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ce.set_default_client_config(
        ClientConfig::builder()
            .with_root_certificates_from_pem_file(&cert_path)
            .unwrap()
            .build(),
    );
    let se = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&cert_path, &key_path)
            .unwrap()
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let driver = se.spawn_default_server_udp_driver(65535).unwrap();
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let old = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let new = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    let new_addr = new.local_addr().unwrap();
    let server_addr = se.local_addr();
    let rebound = Arc::new(AtomicBool::new(false));
    let flag = rebound.clone();
    let proxy = tokio::spawn(async move {
        let mut a = vec![0; 65535];
        let mut b = a.clone();
        let mut c = a.clone();
        let mut client_addr = None;
        loop {
            tokio::select! {
                result = front.recv_from(&mut a) => {
                    let (n, remote) = result.unwrap(); client_addr = Some(remote);
                    let upstream = if flag.load(Ordering::Acquire) { &new } else { &old };
                    upstream.send_to(&a[..n], server_addr).await.unwrap();
                }
                result = old.recv_from(&mut b) => {
                    let (n, _) = result.unwrap();
                    if !flag.load(Ordering::Acquire) && let Some(remote) = client_addr {
                        front.send_to(&b[..n], remote).await.unwrap();
                    }
                }
                result = new.recv_from(&mut c) => {
                    let (n, _) = result.unwrap();
                    if let Some(remote) = client_addr { front.send_to(&c[..n], remote).await.unwrap(); }
                }
            }
        }
    });
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let client = ce.connect(front_addr, "localhost").unwrap().await.unwrap();
        let server = se.accept().await.unwrap().await.unwrap();
        for iteration in 0..2 {
            if iteration == 1 {
                rebound.store(true, Ordering::Release);
            }
            let (mut send, mut recv) = client.open_bi().await.unwrap();
            send.write_all(b"request").await.unwrap();
            send.finish().unwrap();
            let (mut response, mut request) = server.accept_bi().await.unwrap();
            assert_eq!(request.read_to_end(1024).await.unwrap(), b"request");
            response.write_all(b"response").await.unwrap();
            response.finish().unwrap();
            assert_eq!(recv.read_to_end(1024).await.unwrap(), b"response");
        }
        while server.remote_address() != new_addr {
            tokio::task::yield_now().await;
        }
    })
    .await;
    proxy.abort();
    ce.abort();
    se.abort();
    driver.stop().await.unwrap();
    assert!(
        result.is_ok(),
        "default migration policy stranded a rebound client"
    );
}

async fn delayed_consumers_progress_in_every_read_api() {
    for connection_credit in [false, true] {
        for mode in 0..5 {
            let mut transport = TransportConfig::default();
            transport.set_mtu_discovery_config(None);
            if connection_credit {
                transport.set_initial_max_data(VarInt::from_u32(1024));
            } else {
                transport.set_initial_max_stream_data_uni(VarInt::from_u32(1024));
            }
            let (ce, se, driver, client, server) =
                connect_loopback(transport.clone(), transport).await;
            let mut send = client.open_uni().await.unwrap();
            let writer = tokio::spawn(async move {
                send.write_all(&[1; 2048]).await.unwrap();
                send.finish().unwrap();
            });
            let mut recv = server.accept_uni().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let result = tokio::time::timeout(Duration::from_secs(1), async {
                let mut buffer = [0; 1024];
                match mode {
                    0 => recv.read_exact(&mut buffer).await.unwrap(),
                    1 => {
                        let mut received = 0;
                        while received < 1024 {
                            received += recv
                                .read_chunk(1024 - received, true)
                                .await
                                .unwrap()
                                .unwrap()
                                .bytes
                                .len();
                        }
                    }
                    2 => {
                        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut buffer)
                            .await
                            .unwrap();
                    }
                    3 => assert_eq!(recv.read_to_end(2048).await.unwrap().len(), 2048),
                    _ => {
                        let mut received = 0;
                        while received < 1024 {
                            received += recv.read(&mut buffer[received..]).await.unwrap().unwrap();
                        }
                    }
                }
                writer.await.unwrap();
            })
            .await;
            ce.abort();
            se.abort();
            driver.stop().await.unwrap();
            assert!(
                result.is_ok(),
                "read mode {mode}, connection credit {connection_credit} stalled"
            );
        }
    }
}

#[tokio::test]
async fn current_thread_read_apis_notify_credit_updates() {
    delayed_consumers_progress_in_every_read_api().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multithreaded_read_apis_notify_credit_updates() {
    delayed_consumers_progress_in_every_read_api().await;
}

#[tokio::test]
async fn dropped_receive_half_stops_the_peer() {
    let (ce, se, driver, client, server) =
        connect_loopback(TransportConfig::default(), TransportConfig::default()).await;
    let mut send = client.open_uni().await.unwrap();
    send.write_all(b"request").await.unwrap();
    let recv = server.accept_uni().await.unwrap();
    drop(recv);
    let result = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
    ce.abort();
    se.abort();
    driver.stop().await.unwrap();
    assert_eq!(result.unwrap().unwrap(), Some(VarInt::ZERO));
}
