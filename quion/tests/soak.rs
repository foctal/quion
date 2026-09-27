#![cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]

use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use quion::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, VarInt};
use tokio::{
    net::UdpSocket,
    sync::{Notify, oneshot},
    task::JoinHandle,
};

const DEFAULT_CONNECTIONS: usize = 4;
const DEFAULT_STREAMS_PER_CONNECTION: usize = 16;
const DEFAULT_DATAGRAMS_PER_CONNECTION: usize = 16;
const DEFAULT_PAYLOAD_BYTES: usize = 4 * 1024;
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const IMPAIRED_STREAMS: usize = 8;
const IMPAIRED_STREAM_BYTES: usize = 512 * 1024;
const IMPAIRED_DATAGRAMS: usize = 32;
static NEXT_CERTIFICATE_ID: AtomicUsize = AtomicUsize::new(0);

struct TestCertificate {
    directory: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

impl TestCertificate {
    fn generate() -> Self {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let certificate_id = NEXT_CERTIFICATE_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "quion-soak-{}-{stamp}-{certificate_id}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        fs::write(&cert_path, cert.pem()).unwrap();
        fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        Self {
            directory,
            cert: cert_path,
            key: key_path,
        }
    }
}

impl Drop for TestCertificate {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[derive(Clone, Copy)]
struct SoakConfig {
    connections: usize,
    streams_per_connection: usize,
    datagrams_per_connection: usize,
    payload_bytes: usize,
    timeout: Duration,
}

impl SoakConfig {
    fn from_environment() -> Self {
        Self {
            connections: env_usize("QUION_SOAK_CONNECTIONS", DEFAULT_CONNECTIONS, 10_000),
            streams_per_connection: env_usize(
                "QUION_SOAK_STREAMS_PER_CONNECTION",
                DEFAULT_STREAMS_PER_CONNECTION,
                100_000,
            ),
            datagrams_per_connection: env_usize(
                "QUION_SOAK_DATAGRAMS_PER_CONNECTION",
                DEFAULT_DATAGRAMS_PER_CONNECTION,
                100_000,
            ),
            payload_bytes: env_usize(
                "QUION_SOAK_PAYLOAD_BYTES",
                DEFAULT_PAYLOAD_BYTES,
                256 * 1024,
            ),
            timeout: Duration::from_secs(env_u64(
                "QUION_SOAK_TIMEOUT_SECONDS",
                DEFAULT_TIMEOUT_SECONDS,
                24 * 60 * 60,
            )),
        }
    }
}

fn env_usize(name: &str, default: usize, maximum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
        .clamp(1, maximum)
}

fn env_u64(name: &str, default: u64, maximum: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
        .clamp(1, maximum)
}

#[derive(Clone, Copy, Debug, Default)]
struct DirectionFaultStats {
    received: u64,
    forwarded: u64,
    dropped: u64,
    duplicated: u64,
    reordered: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct FaultProxyStats {
    client_to_server: DirectionFaultStats,
    server_to_client: DirectionFaultStats,
}

struct HeldDatagram {
    payload: Vec<u8>,
    destination: SocketAddr,
}

#[derive(Default)]
struct DirectionFaultState {
    sequence: u64,
    held: Option<HeldDatagram>,
    stats: DirectionFaultStats,
}

impl DirectionFaultState {
    async fn process(
        &mut self,
        socket: &UdpSocket,
        payload: &[u8],
        destination: SocketAddr,
    ) -> std::io::Result<()> {
        self.sequence = self.sequence.saturating_add(1);
        self.stats.received = self.stats.received.saturating_add(1);

        if self.sequence > 3 && self.sequence.is_multiple_of(37) {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
            return Ok(());
        }

        if let Some(held) = self.held.take() {
            socket.send_to(payload, destination).await?;
            socket.send_to(&held.payload, held.destination).await?;
            self.stats.forwarded = self.stats.forwarded.saturating_add(2);
            self.stats.reordered = self.stats.reordered.saturating_add(1);
            return Ok(());
        }

        if self.sequence > 3 && self.sequence.is_multiple_of(23) {
            self.held = Some(HeldDatagram {
                payload: payload.to_vec(),
                destination,
            });
            return Ok(());
        }

        socket.send_to(payload, destination).await?;
        self.stats.forwarded = self.stats.forwarded.saturating_add(1);
        if self.sequence > 3 && self.sequence.is_multiple_of(29) {
            socket.send_to(payload, destination).await?;
            self.stats.forwarded = self.stats.forwarded.saturating_add(1);
            self.stats.duplicated = self.stats.duplicated.saturating_add(1);
        }
        Ok(())
    }

    async fn flush(&mut self, socket: &UdpSocket) -> std::io::Result<()> {
        if let Some(held) = self.held.take() {
            socket.send_to(&held.payload, held.destination).await?;
            self.stats.forwarded = self.stats.forwarded.saturating_add(1);
        }
        Ok(())
    }
}

struct FaultProxy {
    local_addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<FaultProxyStats>>,
}

impl FaultProxy {
    async fn start(server_addr: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut client_addr = None;
            let mut client_to_server = DirectionFaultState::default();
            let mut server_to_client = DirectionFaultState::default();
            let mut buffer = vec![0; 65_535];
            let mut flush = tokio::time::interval(Duration::from_millis(10));
            flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            flush.tick().await;

            loop {
                tokio::select! {
                    received = socket.recv_from(&mut buffer) => {
                        let (length, source) = received?;
                        if source == server_addr {
                            if let Some(client_addr) = client_addr {
                                server_to_client
                                    .process(&socket, &buffer[..length], client_addr)
                                    .await?;
                            }
                        } else {
                            client_addr = Some(source);
                            client_to_server
                                .process(&socket, &buffer[..length], server_addr)
                                .await?;
                        }
                    }
                    _ = flush.tick() => {
                        client_to_server.flush(&socket).await?;
                        server_to_client.flush(&socket).await?;
                    }
                    _ = &mut shutdown_rx => {
                        client_to_server.flush(&socket).await?;
                        server_to_client.flush(&socket).await?;
                        return Ok(FaultProxyStats {
                            client_to_server: client_to_server.stats,
                            server_to_client: server_to_client.stats,
                        });
                    }
                }
            }
        });
        Self {
            local_addr,
            shutdown,
            task,
        }
    }

    async fn stop(self) -> FaultProxyStats {
        let _ = self.shutdown.send(());
        self.task.await.unwrap().unwrap()
    }
}

async fn run_server_connection(connection: Connection, config: SoakConfig) {
    for stream_index in 0..config.streams_per_connection {
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let payload = recv
            .read_to_end(config.payload_bytes.saturating_add(1))
            .await
            .unwrap();
        assert_eq!(payload.len(), config.payload_bytes);
        assert_eq!(payload[0], stream_index as u8);
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
    }

    for datagram_index in 0..config.datagrams_per_connection {
        let payload = connection.read_datagram().await.unwrap();
        assert_eq!(payload.len(), config.payload_bytes.min(1_000));
        assert_eq!(payload[0], datagram_index as u8);
        connection.send_datagram(payload).unwrap();
    }

    let _ = connection.closed().await;
}

async fn run_client_connection(connection: &Connection, config: SoakConfig) {
    let mut plateau_bytes = None;
    for stream_index in 0..config.streams_per_connection {
        let payload = vec![stream_index as u8; config.payload_bytes];
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        let echoed = recv
            .read_to_end(config.payload_bytes.saturating_add(1))
            .await
            .unwrap();
        assert_eq!(echoed, payload);

        if stream_index + 1 == config.streams_per_connection / 2 {
            plateau_bytes = Some(connection.diagnostics().memory.payload_bytes());
        }
    }

    if let Some(plateau_bytes) = plateau_bytes {
        let final_bytes = connection.diagnostics().memory.payload_bytes();
        assert!(
            final_bytes <= plateau_bytes.saturating_add(config.payload_bytes.saturating_mul(2)),
            "terminal stream churn retained unexpected payload memory: midpoint={plateau_bytes}, final={final_bytes}"
        );
    }

    let datagram_size = config.payload_bytes.min(1_000);
    for datagram_index in 0..config.datagrams_per_connection {
        let payload = vec![datagram_index as u8; datagram_size];
        connection.send_datagram(payload.clone()).unwrap();
        let echoed = connection.read_datagram().await.unwrap();
        assert_eq!(echoed, payload);
    }

    connection.close(VarInt::ZERO, b"client soak complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_connection_stream_and_datagram_churn() {
    let config = SoakConfig::from_environment();
    let certificate = TestCertificate::generate();
    let mut transport = TransportConfig::default();
    transport
        .set_initial_max_streams_bidi(
            VarInt::new(u64::try_from(config.streams_per_connection).unwrap()).unwrap(),
        )
        .set_max_datagram_frame_size(Some(VarInt::from_u32(1_200)));

    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(&certificate.cert)
        .unwrap()
        .with_transport_config(transport.clone())
        .build();
    let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let server_endpoint = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&certificate.cert, &certificate.key)
            .unwrap()
            .with_transport_config(transport)
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();

    let server = server_endpoint.clone();
    let server_task = tokio::spawn(async move {
        for _ in 0..config.connections {
            let incoming = server.accept().await.expect("server endpoint closed");
            let connection = incoming.await.unwrap();
            run_server_connection(connection, config).await;
        }
    });

    tokio::time::timeout(config.timeout, async {
        for _ in 0..config.connections {
            let connection = client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .unwrap()
                .await
                .unwrap();
            run_client_connection(&connection, config).await;
        }
        server_task.await.unwrap();
    })
    .await
    .expect("configured soak workload timed out");

    let client_stats = client_endpoint.stats();
    let server_stats = server_endpoint.stats();
    assert_eq!(client_stats.opened_connections as usize, config.connections);
    assert_eq!(
        server_stats.accepted_connections as usize,
        config.connections
    );
    assert!(
        client_stats.packets_sent > config.connections as u64,
        "client packet counters did not advance under soak load"
    );
    assert!(
        server_stats.packets_received > config.connections as u64,
        "server packet counters did not advance under soak load"
    );

    client_endpoint.abort();
    server_endpoint.abort();
    tokio::time::timeout(Duration::from_secs(2), server_driver.stop())
        .await
        .expect("server driver stop timed out")
        .unwrap();

    // Stopping the server driver does not join the independent client driver.
    // Allow its aborted in-flight receive batch to drop before checking memory.
    tokio::time::timeout(Duration::from_secs(2), async {
        while client_endpoint.diagnostics().memory.reserved_payload_bytes != 0
            || server_endpoint.diagnostics().memory.reserved_payload_bytes != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("endpoint memory reservations were not released after abort");

    let client_diagnostics = client_endpoint.diagnostics();
    let server_diagnostics = server_endpoint.diagnostics();
    assert_eq!(client_diagnostics.active_connections, 0);
    assert_eq!(server_diagnostics.active_connections, 0);
    assert_eq!(client_diagnostics.memory.reserved_payload_bytes, 0);
    assert_eq!(server_diagnostics.memory.reserved_payload_bytes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_and_stream_recovery_survive_deterministic_network_impairment() {
    let certificate = TestCertificate::generate();
    let mut transport = TransportConfig::default();
    transport
        .set_initial_max_streams_bidi(VarInt::from_u32(IMPAIRED_STREAMS as u32))
        .set_max_datagram_frame_size(Some(VarInt::from_u32(1_200)));

    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(&certificate.cert)
        .unwrap()
        .with_transport_config(transport.clone())
        .build();
    let client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let server_endpoint = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&certificate.cert, &certificate.key)
            .unwrap()
            .with_transport_config(transport)
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();
    let proxy = FaultProxy::start(server_endpoint.local_addr()).await;
    let client_streams_completed = Arc::new(AtomicUsize::new(0));
    let server_streams_completed = Arc::new(AtomicUsize::new(0));
    let client_connection = Arc::new(Mutex::new(None::<Connection>));
    let server_connection = Arc::new(Mutex::new(None::<Connection>));
    let datagram_delivered = Arc::new(Notify::new());

    let server = server_endpoint.clone();
    let server_progress = server_streams_completed.clone();
    let server_diagnostics = server_connection.clone();
    let server_datagram_delivered = datagram_delivered.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("server endpoint closed");
        let connection = incoming.await.unwrap();
        *server_diagnostics.lock().unwrap() = Some(connection.clone());
        for stream_index in 0..IMPAIRED_STREAMS {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let payload = recv.read_to_end(IMPAIRED_STREAM_BYTES + 1).await.unwrap();
            assert_eq!(payload.len(), IMPAIRED_STREAM_BYTES);
            assert_eq!(payload[0], stream_index as u8);
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            server_progress.store(stream_index + 1, Ordering::Relaxed);
        }

        let mut datagrams_received = 0usize;
        while datagrams_received < IMPAIRED_DATAGRAMS {
            let wait = if datagrams_received == 0 {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(100)
            };
            match tokio::time::timeout(wait, connection.read_datagram()).await {
                Ok(Ok(payload)) => {
                    assert_eq!(payload.len(), 1_000);
                    datagrams_received += 1;
                    if datagrams_received == 1 {
                        server_datagram_delivered.notify_one();
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        (connection.stats(), datagrams_received)
    });

    let client_progress = client_streams_completed.clone();
    let client_diagnostics = client_connection.clone();
    let workload = tokio::time::timeout(Duration::from_secs(30), async {
        let connection = client_endpoint
            .connect(proxy.local_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        *client_diagnostics.lock().unwrap() = Some(connection.clone());

        for stream_index in 0..IMPAIRED_STREAMS {
            let payload = vec![stream_index as u8; IMPAIRED_STREAM_BYTES];
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let echoed = recv.read_to_end(IMPAIRED_STREAM_BYTES + 1).await.unwrap();
            assert_eq!(echoed, payload);
            client_progress.store(stream_index + 1, Ordering::Relaxed);
        }

        let delivered = datagram_delivered.notified();
        tokio::pin!(delivered);
        let mut delivery_observed = false;
        for datagram_index in 0..IMPAIRED_DATAGRAMS {
            connection
                .send_datagram(vec![datagram_index as u8; 1_000])
                .unwrap();
            tokio::select! {
                _ = &mut delivered => {
                    delivery_observed = true;
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        if !delivery_observed {
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut delivered).await;
        }
        connection.close(VarInt::ZERO, b"impaired-network soak complete");
        let client_stats = connection.stats();
        let (server_stats, datagrams_received) = server_task.await.unwrap();
        (client_stats, server_stats, datagrams_received)
    })
    .await;
    let proxy_stats = proxy.stop().await;
    let (client_stats, server_stats, datagrams_received) = workload.unwrap_or_else(|_| {
        let client_connection = client_connection
            .lock()
            .unwrap()
            .as_ref()
            .map(Connection::diagnostics);
        let server_connection = server_connection
            .lock()
            .unwrap()
            .as_ref()
            .map(Connection::diagnostics);
        panic!(
            "impaired-network recovery timed out: client_streams={}, server_streams={}, proxy={proxy_stats:?}, client_endpoint={:?}, server_endpoint={:?}, client_connection={client_connection:?}, server_connection={server_connection:?}",
            client_streams_completed.load(Ordering::Relaxed),
            server_streams_completed.load(Ordering::Relaxed),
            client_endpoint.diagnostics(),
            server_endpoint.diagnostics(),
        )
    });
    assert!(datagrams_received > 0);
    assert!(
        client_stats.packets_lost + server_stats.packets_lost > 0,
        "the recovery path did not declare any deliberately dropped packet lost"
    );
    assert!(
        client_stats.retransmissions + server_stats.retransmissions > 0,
        "the recovery path did not retransmit under deliberate loss"
    );
    for (direction, stats) in [
        ("client-to-server", proxy_stats.client_to_server),
        ("server-to-client", proxy_stats.server_to_client),
    ] {
        assert!(stats.received > 0, "{direction} received no proxy traffic");
        assert!(stats.forwarded > 0, "{direction} forwarded no traffic");
        assert!(stats.dropped > 0, "{direction} injected no loss");
        assert!(stats.duplicated > 0, "{direction} injected no duplication");
        assert!(stats.reordered > 0, "{direction} injected no reordering");
    }

    *client_connection.lock().unwrap() = None;
    *server_connection.lock().unwrap() = None;
    client_endpoint.abort();
    server_endpoint.abort();
    tokio::time::timeout(Duration::from_secs(2), server_driver.stop())
        .await
        .expect("server driver stop timed out")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if client_endpoint.diagnostics().memory.reserved_payload_bytes == 0
                && server_endpoint.diagnostics().memory.reserved_payload_bytes == 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("endpoint memory reservations were not released after abort");
    assert_eq!(
        client_endpoint.diagnostics().memory.reserved_payload_bytes,
        0
    );
    assert_eq!(
        server_endpoint.diagnostics().memory.reserved_payload_bytes,
        0
    );
}
