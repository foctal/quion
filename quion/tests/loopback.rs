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

async fn read_to_end_nonempty(recv: &mut quion::RecvStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(1), recv.read_to_end(4096))
        .await
        .expect("stream read timed out")
        .expect("stream read failed")
}

async fn read_datagram_nonempty(connection: &Connection) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(1), connection.read_datagram())
        .await
        .expect("datagram read timed out")
        .expect("datagram read failed")
}

async fn accept_bi_nonempty(connection: &Connection) -> (quion::SendStream, quion::RecvStream) {
    tokio::time::timeout(Duration::from_secs(1), connection.accept_bi())
        .await
        .expect("accept_bi timed out")
        .expect("accept_bi failed")
}

async fn open_bi_nonempty(connection: &Connection) -> (quion::SendStream, quion::RecvStream) {
    tokio::time::timeout(Duration::from_secs(1), connection.open_bi())
        .await
        .expect("open_bi timed out")
        .expect("open_bi failed")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_exposes_alpn_and_peer_certificates() {
    let (cert_path, key_path) = write_test_cert_materials();
    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(&cert_path)
        .unwrap()
        .with_alpn_protocols([b"quion-echo".to_vec()])
        .build();
    let server_config = ServerConfig::builder()
        .with_single_cert_from_pem_files(&cert_path, &key_path)
        .unwrap()
        .with_alpn_protocols([b"quion-echo".to_vec()])
        .build()
        .unwrap();

    let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();

    let connecting = client_endpoint
        .connect(server_endpoint.local_addr(), "localhost")
        .unwrap();
    let client = tokio::time::timeout(Duration::from_secs(1), connecting)
        .await
        .expect("client connect timed out")
        .unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(1), server_endpoint.accept())
        .await
        .expect("server accept timed out")
        .unwrap();
    let server = tokio::time::timeout(Duration::from_secs(1), incoming)
        .await
        .expect("incoming completion timed out")
        .unwrap();

    assert_eq!(client.alpn_protocol(), Some(b"quion-echo".to_vec()));
    assert_eq!(server.alpn_protocol(), Some(b"quion-echo".to_vec()));
    assert!(client.peer_identity().is_some_and(|cert| !cert.is_empty()));
    assert!(
        client
            .peer_certificates()
            .is_some_and(|certs| !certs.is_empty())
    );
    assert_eq!(server.peer_identity(), None);
    assert_eq!(server.peer_certificates(), None);

    client_endpoint.abort();
    server_endpoint.abort();
    tokio::time::timeout(Duration::from_secs(1), server_driver.stop())
        .await
        .expect("server driver stop timed out")
        .unwrap();
}

#[test]
fn split_runtime_loopback_echo_succeeds() {
    let (cert_path, key_path) = write_test_cert_materials();
    let server_cert_path = cert_path.clone();
    let client_cert_path = cert_path.clone();
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let server_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let server_endpoint = Endpoint::server(
                ServerConfig::builder()
                    .with_single_cert_from_pem_files(&server_cert_path, &key_path)
                    .unwrap()
                    .build()
                    .unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let server_driver = server_endpoint
                .spawn_default_server_udp_driver(65_535)
                .unwrap();
            addr_tx.send(server_endpoint.local_addr()).unwrap();

            let incoming = server_endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let (_, mut recv) = accept_bi_nonempty(&connection).await;
            let payload = read_to_end_nonempty(&mut recv).await;
            let (mut send, _) = open_bi_nonempty(&connection).await;
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let _ = shutdown_rx.await;
            tokio::time::timeout(Duration::from_secs(1), server_driver.stop())
                .await
                .expect("server driver stop timed out")
                .unwrap();
        });
    });

    let server_addr = addr_rx.recv().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let client_config = ClientConfig::builder()
            .with_root_certificates_from_pem_file(&client_cert_path)
            .unwrap()
            .build();
        let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);

        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, _) = open_bi_nonempty(&connection).await;
        send.write_all(b"split-runtime-echo").await.unwrap();
        send.finish().unwrap();

        let (_, mut recv) = accept_bi_nonempty(&connection).await;
        let echoed = read_to_end_nonempty(&mut recv).await;
        assert_eq!(echoed, b"split-runtime-echo");
    });

    let _ = shutdown_tx.send(());
    server_thread.join().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_bidirectional_stream_echo_and_shutdown() {
    let (client_endpoint, server_endpoint, server_driver, client, server) =
        connect_loopback(TransportConfig::default(), TransportConfig::default()).await;

    let server_for_task = server.clone();
    let server_task = tokio::spawn(async move {
        let (_, mut recv) = accept_bi_nonempty(&server_for_task).await;
        let payload = read_to_end_nonempty(&mut recv).await;
        let (mut send, _) = open_bi_nonempty(&server_for_task).await;
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
    });

    let payload = vec![0x5a; 2_048];
    let (mut send, _) = open_bi_nonempty(&client).await;
    send.write_all(&payload).await.unwrap();
    send.finish().unwrap();
    let (_, mut recv) = accept_bi_nonempty(&client).await;
    let echoed = read_to_end_nonempty(&mut recv).await;
    assert_eq!(echoed, payload);

    client.close(VarInt::from_u32(0), b"client done");
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("server echo task timed out")
        .unwrap();
    let client_stats = client_endpoint.stats();
    let server_stats = server_endpoint.stats();
    assert!(client_stats.opened_connections >= 1);
    assert!(client_stats.packets_sent >= 1);
    assert!(client_stats.packets_received >= 1);
    assert!(server_stats.accepted_connections >= 1);
    assert!(server_stats.packets_sent >= 1);
    assert!(server_stats.packets_received >= 1);
    let client_connection_stats = client.stats();
    let server_connection_stats = server.stats();
    assert!(client_connection_stats.handshake_duration.is_some());
    assert!(server_connection_stats.handshake_duration.is_some());
    assert!(client_connection_stats.streams_opened >= 1);
    assert!(server_connection_stats.streams_accepted >= 1);
    client_endpoint.abort();
    server_endpoint.abort();
    tokio::time::timeout(Duration::from_secs(1), server_driver.stop())
        .await
        .expect("server driver stop timed out")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_reset_stream_at_delivers_reliable_prefix() {
    let mut client_transport = TransportConfig::default();
    client_transport.set_reset_stream_at(true);
    let mut server_transport = TransportConfig::default();
    server_transport.set_reset_stream_at(true);
    let (client_endpoint, server_endpoint, server_driver, client, server) =
        connect_loopback(client_transport, server_transport).await;

    assert!(
        client
            .negotiated_transport()
            .is_some_and(|transport| transport.reset_stream_at)
    );
    assert!(
        server
            .negotiated_transport()
            .is_some_and(|transport| transport.reset_stream_at)
    );

    let (mut send, _) = open_bi_nonempty(&client).await;
    send.write_all(b"header-payload").await.unwrap();
    send.reset_at(VarInt::from_u32(42), VarInt::from_u32(6))
        .unwrap();

    let (_, mut recv) = accept_bi_nonempty(&server).await;
    let mut header = [0; 6];
    tokio::time::timeout(Duration::from_secs(1), recv.read_exact(&mut header))
        .await
        .expect("reliable prefix read timed out")
        .expect("reliable prefix read failed");
    assert_eq!(&header, b"header");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), recv.received_reset())
            .await
            .expect("reliable reset notification timed out")
            .expect("reliable reset notification failed"),
        Some(VarInt::from_u32(42))
    );

    client_endpoint.abort();
    server_endpoint.abort();
    tokio::time::timeout(Duration::from_secs(1), server_driver.stop())
        .await
        .expect("server driver stop timed out")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_datagrams_roundtrip_with_negotiated_transport() {
    let mut transport = TransportConfig::default();
    transport.set_max_datagram_frame_size(Some(VarInt::from_u32(1200)));
    let (client_endpoint, server_endpoint, server_driver, client, server) =
        connect_loopback(transport.clone(), transport).await;

    client.send_datagram(b"ping").unwrap();
    let server_datagram = read_datagram_nonempty(&server).await;
    assert_eq!(server_datagram, b"ping");

    let shared_payload = bytes::Bytes::from(vec![0x5a; 1_000]);
    for _ in 0..32 {
        client.send_datagram_bytes(shared_payload.clone()).unwrap();
    }
    for _ in 0..32 {
        let datagram = read_datagram_nonempty(&server).await;
        assert_eq!(datagram, shared_payload);
    }

    server.send_datagram(b"pong").unwrap();
    let client_datagram = read_datagram_nonempty(&client).await;
    assert_eq!(client_datagram, b"pong");

    client_endpoint.abort();
    server_endpoint.abort();
    tokio::time::timeout(Duration::from_secs(1), server_driver.stop())
        .await
        .expect("server driver stop timed out")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_alive_preserves_an_idle_udp_connection() {
    let mut client_transport = TransportConfig::default();
    client_transport.set_max_idle_timeout(VarInt::from_u32(200));
    client_transport.set_keep_alive_interval(Some(Duration::from_millis(40)));
    let mut server_transport = TransportConfig::default();
    server_transport.set_max_idle_timeout(VarInt::from_u32(200));
    let (client_endpoint, server_endpoint, server_driver, client, server) =
        connect_loopback(client_transport, server_transport).await;
    let sent_before = client.stats().packets_sent;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!client.is_closed());
    assert!(!server.is_closed());
    assert!(client.stats().packets_sent > sent_before + 2);
    let mut send = client.open_uni().await.unwrap();
    send.write_all(b"still alive").await.unwrap();
    send.finish().unwrap();
    let mut recv = tokio::time::timeout(Duration::from_secs(1), server.accept_uni())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read_to_end_nonempty(&mut recv).await, b"still alive");
    client_endpoint.abort();
    server_endpoint.abort();
    tokio::time::timeout(Duration::from_secs(1), server_driver.stop())
        .await
        .unwrap()
        .unwrap();
}
