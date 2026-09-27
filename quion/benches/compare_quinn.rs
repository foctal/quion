use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc, Once,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use quion::{
    AckFrequencyConfig, ClientConfig, Connection as QuionConnection, Endpoint as QuionEndpoint,
    EndpointServerUdpDriverHandle, ServerConfig, TransportConfig, VarInt,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
#[cfg(not(debug_assertions))]
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle};

const ALPN: &[u8] = b"quion-performance-comparison";
const STREAM_ECHO_PAYLOAD: &[u8] = b"0123456789abcdef0123456789abcdef";
const MANY_STREAM_PAYLOAD_BYTES: usize = 1_024;
const DATAGRAM_PAYLOAD_BYTES: usize = 1_000;
const SOCKET_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const STREAM_WINDOW_BYTES: u32 = 64 * 1024 * 1024;
const CONNECTION_WINDOW_BYTES: u32 = 256 * 1024 * 1024;
const MAX_STREAMS: u32 = 4_096;
const TIMEOUT: Duration = Duration::from_secs(60);
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

#[cfg(not(debug_assertions))]
#[global_allocator]
static GLOBAL_ALLOCATOR: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

#[cfg(debug_assertions)]
#[global_allocator]
static GLOBAL_ALLOCATOR: dhat::Alloc = dhat::Alloc;

#[derive(Debug, Clone, Copy)]
struct AllocationSnapshot {
    count: u64,
    bytes: u64,
    live_bytes: i128,
}

impl AllocationSnapshot {
    fn capture() -> Self {
        #[cfg(debug_assertions)]
        {
            Self {
                count: 0,
                bytes: 0,
                live_bytes: 0,
            }
        }
        #[cfg(not(debug_assertions))]
        {
            let stats = GLOBAL_ALLOCATOR.stats();
            let live_bytes = stats.bytes_allocated as i128 + stats.bytes_reallocated as i128
                - stats.bytes_deallocated as i128;
            Self {
                count: (stats.allocations + stats.reallocations) as u64,
                bytes: stats
                    .bytes_allocated
                    .saturating_add(stats.bytes_reallocated.max(0) as usize)
                    as u64,
                live_bytes,
            }
        }
    }

    fn elapsed(self) -> Self {
        let current = Self::capture();
        Self {
            count: current.count.saturating_sub(self.count),
            bytes: current.bytes.saturating_sub(self.bytes),
            live_bytes: current.live_bytes - self.live_bytes,
        }
    }
}

#[derive(Debug)]
struct EchoTrial {
    samples: Vec<u64>,
    allocations: AllocationSnapshot,
}

#[derive(Debug, Clone, Copy)]
struct RateTrial {
    elapsed: Duration,
    allocations: AllocationSnapshot,
}

#[derive(Debug, Clone, Copy)]
struct RecoveryTrial {
    elapsed: Duration,
    allocations: AllocationSnapshot,
    declared_lost_packets: u64,
    injected_drops: u64,
    reordered_datagrams: u64,
}

#[cfg(tokio_unstable)]
#[derive(Debug, Clone, Copy)]
struct RuntimeTrial {
    elapsed: Duration,
    worker_busy: Duration,
    task_polls: u64,
    task_schedules: u64,
}

#[cfg(tokio_unstable)]
#[derive(Debug, Clone, Copy)]
struct RuntimeSnapshot {
    worker_busy: Duration,
    task_polls: u64,
    task_schedules: u64,
}

#[cfg(tokio_unstable)]
impl RuntimeSnapshot {
    fn capture() -> Self {
        let metrics = tokio::runtime::Handle::current().metrics();
        let mut worker_busy = Duration::ZERO;
        let mut task_polls = 0;
        let mut task_schedules = metrics.remote_schedule_count();
        for worker in 0..metrics.num_workers() {
            worker_busy += metrics.worker_total_busy_duration(worker);
            task_polls += metrics.worker_poll_count(worker);
            task_schedules += metrics.worker_local_schedule_count(worker);
        }
        Self {
            worker_busy,
            task_polls,
            task_schedules,
        }
    }

    fn elapsed(self) -> Self {
        let current = Self::capture();
        Self {
            worker_busy: current.worker_busy.saturating_sub(self.worker_busy),
            task_polls: current.task_polls.saturating_sub(self.task_polls),
            task_schedules: current.task_schedules.saturating_sub(self.task_schedules),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct IdleConnectionTrial {
    allocations: AllocationSnapshot,
}

#[derive(Debug, Clone, Copy)]
struct BenchmarkConfig {
    trials: usize,
    handshake_iterations: usize,
    echo_iterations: usize,
    echo_warmup: usize,
    bulk_bytes: usize,
    datagrams: usize,
    many_streams: usize,
    active_streams: usize,
    active_stream_warmup: usize,
    short_connections: usize,
    idle_connections: usize,
    idle_connection_warmup: usize,
    recovery_bytes: usize,
    recovery_loss_interval: usize,
    recovery_reorder_interval: usize,
    shutdown_iterations: usize,
    #[cfg(tokio_unstable)]
    runtime_bytes: usize,
    #[cfg(tokio_unstable)]
    runtime_warmup_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackSelection {
    Both,
    Quion,
    Quinn,
}

impl StackSelection {
    fn from_environment() -> Self {
        match std::env::var("QUION_COMPARE_STACK").as_deref() {
            Ok("quion") => Self::Quion,
            Ok("quinn") => Self::Quinn,
            Ok("both") | Err(_) => Self::Both,
            Ok(value) => panic!(
                "unsupported QUION_COMPARE_STACK value {value:?}; expected quion, quinn, or both"
            ),
        }
    }

    const fn includes_quion(self) -> bool {
        matches!(self, Self::Both | Self::Quion)
    }

    const fn includes_quinn(self) -> bool {
        matches!(self, Self::Both | Self::Quinn)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScenarioSelection {
    All,
    Handshake,
    StreamEcho,
    BulkStream,
    ManyStreams,
    ActiveStreams,
    ShortConnections,
    Datagram,
    IdleConnections,
    Recovery,
    RuntimeCost,
    EndpointShutdown,
}

impl ScenarioSelection {
    fn from_environment() -> Self {
        match std::env::var("QUION_COMPARE_SCENARIO").as_deref() {
            Ok("handshake") => Self::Handshake,
            Ok("stream-echo") => Self::StreamEcho,
            Ok("bulk-stream") => Self::BulkStream,
            Ok("many-streams") => Self::ManyStreams,
            Ok("active-streams") => Self::ActiveStreams,
            Ok("short-connections") => Self::ShortConnections,
            Ok("datagram") => Self::Datagram,
            Ok("idle-connections") => Self::IdleConnections,
            Ok("recovery") => Self::Recovery,
            Ok("runtime-cost") => Self::RuntimeCost,
            Ok("endpoint-shutdown") => Self::EndpointShutdown,
            Ok("all") | Err(_) => Self::All,
            Ok(value) => panic!(
                "unsupported QUION_COMPARE_SCENARIO value {value:?}; expected handshake, \
                 stream-echo, bulk-stream, many-streams, active-streams, \
                 short-connections, datagram, idle-connections, recovery, runtime-cost, \
                 endpoint-shutdown, or all"
            ),
        }
    }

    const fn includes(self, scenario: Self) -> bool {
        matches!(self, Self::All) || self as u8 == scenario as u8
    }
}

impl BenchmarkConfig {
    fn from_environment() -> Self {
        let active_stream_warmup = environment_usize("QUION_COMPARE_ACTIVE_STREAM_WARMUP", 16)
            .min(MAX_STREAMS as usize - 1);
        Self {
            trials: environment_usize("QUION_COMPARE_TRIALS", 5),
            handshake_iterations: environment_usize("QUION_COMPARE_HANDSHAKES", 100),
            echo_iterations: environment_usize("QUION_COMPARE_ECHO_ITERATIONS", 2_000),
            echo_warmup: environment_usize("QUION_COMPARE_ECHO_WARMUP", 100),
            bulk_bytes: environment_usize("QUION_COMPARE_BULK_BYTES", 64 * 1024 * 1024),
            datagrams: environment_usize("QUION_COMPARE_DATAGRAMS", 512).min(512),
            many_streams: environment_usize("QUION_COMPARE_MANY_STREAMS", 1_024)
                .min(MAX_STREAMS as usize),
            active_streams: environment_usize("QUION_COMPARE_ACTIVE_STREAMS", 1_024)
                .min(MAX_STREAMS as usize - active_stream_warmup),
            active_stream_warmup,
            short_connections: environment_usize("QUION_COMPARE_SHORT_CONNECTIONS", 100),
            idle_connections: environment_usize("QUION_COMPARE_IDLE_CONNECTIONS", 256),
            idle_connection_warmup: environment_usize("QUION_COMPARE_IDLE_CONNECTION_WARMUP", 16),
            recovery_bytes: environment_usize("QUION_COMPARE_RECOVERY_BYTES", 16 * 1024 * 1024),
            recovery_loss_interval: environment_usize("QUION_COMPARE_RECOVERY_LOSS_INTERVAL", 100)
                .max(4),
            recovery_reorder_interval: environment_usize(
                "QUION_COMPARE_RECOVERY_REORDER_INTERVAL",
                50,
            )
            .max(4),
            shutdown_iterations: environment_usize("QUION_COMPARE_SHUTDOWNS", 20),
            #[cfg(tokio_unstable)]
            runtime_bytes: environment_usize("QUION_COMPARE_RUNTIME_BYTES", 64 * 1024 * 1024),
            #[cfg(tokio_unstable)]
            runtime_warmup_bytes: environment_usize(
                "QUION_COMPARE_RUNTIME_WARMUP_BYTES",
                4 * 1024 * 1024,
            ),
        }
    }
}

struct TestIdentity {
    certificate: CertificateDer<'static>,
    private_key: PrivatePkcs8KeyDer<'static>,
}

impl TestIdentity {
    fn generate() -> Self {
        install_crypto_provider();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        Self {
            certificate: cert.der().clone(),
            private_key: PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
        }
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.clone()).unwrap();
        roots
    }
}

struct QuionPair {
    client_endpoint: QuionEndpoint,
    server_endpoint: QuionEndpoint,
    server_driver: EndpointServerUdpDriverHandle,
    client: QuionConnection,
    server: QuionConnection,
}

impl QuionPair {
    async fn close(self) {
        self.client.abort();
        self.server.abort();
        self.client_endpoint.abort();
        self.server_endpoint.abort();
        timeout(self.server_driver.stop()).await.unwrap();
    }
}

struct QuinnPair {
    client_endpoint: quinn::Endpoint,
    server_endpoint: quinn::Endpoint,
    client: quinn::Connection,
    server: quinn::Connection,
}

impl QuinnPair {
    async fn close(self) {
        self.client.close(0_u32.into(), b"benchmark complete");
        self.server.close(0_u32.into(), b"benchmark complete");
        self.client_endpoint
            .close(0_u32.into(), b"benchmark complete");
        self.server_endpoint
            .close(0_u32.into(), b"benchmark complete");
        self.client_endpoint.wait_idle().await;
        self.server_endpoint.wait_idle().await;
    }
}

fn environment_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .unwrap_or(default)
}

fn install_crypto_provider() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Clone, Copy, Debug, Default)]
struct FaultDirectionStats {
    received: u64,
    forwarded: u64,
    dropped: u64,
    reordered: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct FaultProxyStats {
    client_to_server: FaultDirectionStats,
    server_to_client: FaultDirectionStats,
}

impl FaultProxyStats {
    const fn dropped(self) -> u64 {
        self.client_to_server.dropped + self.server_to_client.dropped
    }

    const fn reordered(self) -> u64 {
        self.client_to_server.reordered + self.server_to_client.reordered
    }
}

struct HeldDatagram {
    payload: Vec<u8>,
    destination: SocketAddr,
}

struct FaultDirection {
    sequence: usize,
    held: Option<HeldDatagram>,
    stats: FaultDirectionStats,
    loss_interval: usize,
    reorder_interval: usize,
}

impl FaultDirection {
    const fn new(loss_interval: usize, reorder_interval: usize) -> Self {
        Self {
            sequence: 0,
            held: None,
            stats: FaultDirectionStats {
                received: 0,
                forwarded: 0,
                dropped: 0,
                reordered: 0,
            },
            loss_interval,
            reorder_interval,
        }
    }

    async fn process(
        &mut self,
        socket: &UdpSocket,
        payload: &[u8],
        destination: SocketAddr,
    ) -> std::io::Result<()> {
        self.sequence += 1;
        self.stats.received += 1;
        if self.sequence.is_multiple_of(self.loss_interval) {
            self.stats.dropped += 1;
            return Ok(());
        }

        if let Some(held) = self.held.take() {
            socket.send_to(payload, destination).await?;
            socket.send_to(&held.payload, held.destination).await?;
            self.stats.forwarded += 2;
            self.stats.reordered += 1;
            return Ok(());
        }

        if self.sequence % self.reorder_interval == self.reorder_interval / 2 {
            self.held = Some(HeldDatagram {
                payload: payload.to_vec(),
                destination,
            });
            return Ok(());
        }

        socket.send_to(payload, destination).await?;
        self.stats.forwarded += 1;
        Ok(())
    }

    async fn flush(&mut self, socket: &UdpSocket) -> std::io::Result<()> {
        if let Some(held) = self.held.take() {
            socket.send_to(&held.payload, held.destination).await?;
            self.stats.forwarded += 1;
        }
        Ok(())
    }
}

struct FaultProxy {
    local_addr: SocketAddr,
    enabled: Arc<AtomicBool>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<FaultProxyStats>>,
}

impl FaultProxy {
    async fn start(server_addr: SocketAddr, loss_interval: usize, reorder_interval: usize) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let enabled = Arc::new(AtomicBool::new(false));
        let task_enabled = enabled.clone();
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut client_addr = None;
            let mut client_to_server = FaultDirection::new(loss_interval, reorder_interval);
            let mut server_to_client = FaultDirection::new(loss_interval, reorder_interval);
            let mut buffer = vec![0; 65_535];
            let mut flush = tokio::time::interval(Duration::from_millis(1));
            flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            flush.tick().await;

            loop {
                tokio::select! {
                    received = socket.recv_from(&mut buffer) => {
                        let (length, source) = received?;
                        let (direction, destination) = if source == server_addr {
                            let Some(client_addr) = client_addr else {
                                continue;
                            };
                            (&mut server_to_client, client_addr)
                        } else {
                            client_addr = Some(source);
                            (&mut client_to_server, server_addr)
                        };
                        if task_enabled.load(Ordering::Acquire) {
                            direction.process(&socket, &buffer[..length], destination).await?;
                        } else {
                            socket.send_to(&buffer[..length], destination).await?;
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
            enabled,
            shutdown,
            task,
        }
    }

    fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    async fn stop(self) -> FaultProxyStats {
        let _ = self.shutdown.send(());
        self.task.await.unwrap().unwrap()
    }
}

fn quion_transport() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .set_initial_mtu(1_452)
        .set_retry_enabled(false)
        .set_initial_max_data(VarInt::from_u32(CONNECTION_WINDOW_BYTES))
        .set_initial_max_stream_data_bidi_local(VarInt::from_u32(STREAM_WINDOW_BYTES))
        .set_initial_max_stream_data_bidi_remote(VarInt::from_u32(STREAM_WINDOW_BYTES))
        .set_initial_max_stream_data_uni(VarInt::from_u32(STREAM_WINDOW_BYTES))
        .set_initial_max_streams_bidi(VarInt::from_u32(MAX_STREAMS))
        .set_initial_max_streams_uni(VarInt::from_u32(MAX_STREAMS))
        .set_max_datagram_frame_size(Some(VarInt::from_u32(65_535)))
        .set_max_send_buffered_stream_data(STREAM_WINDOW_BYTES as usize)
        .set_max_recv_buffered_stream_data(CONNECTION_WINDOW_BYTES as usize)
        .set_max_recv_buffered_stream_data_per_connection(CONNECTION_WINDOW_BYTES as usize)
        .set_max_buffered_qlog_events(0)
        .set_ack_frequency_config(Some(AckFrequencyConfig {
            ack_eliciting_threshold: VarInt::from_u32(9),
            max_ack_delay: None,
            reordering_threshold: VarInt::from_u32(2),
        }))
        .set_congestion_algorithm(quion_proto::congestion::CongestionAlgorithm::Cubic);
    transport
}

fn quinn_transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    let mut ack_frequency = quinn::AckFrequencyConfig::default();
    ack_frequency
        .ack_eliciting_threshold(9u32.into())
        .reordering_threshold(2u32.into());
    transport
        .initial_mtu(1_452)
        .max_concurrent_bidi_streams(MAX_STREAMS.into())
        .max_concurrent_uni_streams(MAX_STREAMS.into())
        .stream_receive_window(STREAM_WINDOW_BYTES.into())
        .receive_window(CONNECTION_WINDOW_BYTES.into())
        .send_window(u64::from(STREAM_WINDOW_BYTES))
        .datagram_receive_buffer_size(Some(SOCKET_BUFFER_BYTES))
        .datagram_send_buffer_size(SOCKET_BUFFER_BYTES)
        .ack_frequency_config(Some(ack_frequency))
        .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    Arc::new(transport)
}

fn quinn_server_config(identity: &TestIdentity) -> quinn::ServerConfig {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.certificate.clone()],
            PrivateKeyDer::Pkcs8(identity.private_key.clone_key()),
        )
        .unwrap();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(quinn_transport());
    config
}

fn quinn_client_config(identity: &TestIdentity) -> quinn::ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(identity.roots())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.resumption = rustls::client::Resumption::disabled();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(quinn_transport());
    config
}

async fn setup_quion(identity: &TestIdentity) -> QuionPair {
    let server_endpoint = QuionEndpoint::server(
        ServerConfig::builder()
            .with_single_cert(
                vec![identity.certificate.clone()],
                PrivateKeyDer::Pkcs8(identity.private_key.clone_key()),
            )
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    server_endpoint
        .set_socket_recv_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    server_endpoint
        .set_socket_send_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();
    let client_endpoint = QuionEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint
        .set_socket_recv_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    client_endpoint
        .set_socket_send_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(identity.roots())
        .with_no_client_auth();
    client_crypto.resumption = rustls::client::Resumption::disabled();
    client_endpoint.set_default_client_config(
        ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build(),
    );
    let client = timeout(
        client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")
            .unwrap(),
    )
    .await
    .unwrap();
    let server = timeout(async {
        server_endpoint
            .accept()
            .await
            .expect("quion server endpoint closed")
            .await
    })
    .await
    .unwrap();
    QuionPair {
        client_endpoint,
        server_endpoint,
        server_driver,
        client,
        server,
    }
}

async fn setup_quinn(identity: &TestIdentity) -> QuinnPair {
    let server_endpoint = quinn::Endpoint::server(
        quinn_server_config(identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quinn_client_config(identity));
    let server_address = server_endpoint.local_addr().unwrap();
    let (client, server) = tokio::join!(
        async {
            timeout(
                client_endpoint
                    .connect(server_address, "localhost")
                    .unwrap(),
            )
            .await
            .unwrap()
        },
        async {
            timeout(server_endpoint.accept())
                .await
                .expect("Quinn server endpoint closed")
                .await
                .unwrap()
        }
    );
    QuinnPair {
        client_endpoint,
        server_endpoint,
        client,
        server,
    }
}

async fn setup_impaired_quion(
    identity: &TestIdentity,
    loss_interval: usize,
    reorder_interval: usize,
) -> (QuionPair, FaultProxy) {
    let server_endpoint = QuionEndpoint::server(
        ServerConfig::builder()
            .with_single_cert(
                vec![identity.certificate.clone()],
                PrivateKeyDer::Pkcs8(identity.private_key.clone_key()),
            )
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    server_endpoint
        .set_socket_recv_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    server_endpoint
        .set_socket_send_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();
    let proxy = FaultProxy::start(
        server_endpoint.local_addr(),
        loss_interval,
        reorder_interval,
    )
    .await;
    let client_endpoint = QuionEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint
        .set_socket_recv_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    client_endpoint
        .set_socket_send_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(identity.roots())
        .with_no_client_auth();
    client_crypto.resumption = rustls::client::Resumption::disabled();
    client_endpoint.set_default_client_config(
        ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build(),
    );
    let client = timeout(
        client_endpoint
            .connect(proxy.local_addr, "localhost")
            .unwrap(),
    )
    .await
    .unwrap();
    let server = timeout(async {
        server_endpoint
            .accept()
            .await
            .expect("quion server endpoint closed")
            .await
    })
    .await
    .unwrap();
    (
        QuionPair {
            client_endpoint,
            server_endpoint,
            server_driver,
            client,
            server,
        },
        proxy,
    )
}

async fn setup_impaired_quinn(
    identity: &TestIdentity,
    loss_interval: usize,
    reorder_interval: usize,
) -> (QuinnPair, FaultProxy) {
    let server_endpoint = quinn::Endpoint::server(
        quinn_server_config(identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let proxy = FaultProxy::start(
        server_endpoint.local_addr().unwrap(),
        loss_interval,
        reorder_interval,
    )
    .await;
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quinn_client_config(identity));
    let (client, server) = tokio::join!(
        async {
            timeout(
                client_endpoint
                    .connect(proxy.local_addr, "localhost")
                    .unwrap(),
            )
            .await
            .unwrap()
        },
        async {
            timeout(server_endpoint.accept())
                .await
                .expect("Quinn server endpoint closed")
                .await
                .unwrap()
        }
    );
    (
        QuinnPair {
            client_endpoint,
            server_endpoint,
            client,
            server,
        },
        proxy,
    )
}

async fn timeout<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("benchmark operation timed out")
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let index = sorted.len().saturating_sub(1).saturating_mul(percentile) / 100;
    sorted[index]
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

// Preserve samples before the summary functions sort them for their medians.
// A separate opt-in JSONL artifact keeps existing summary consumers compatible.
fn report_trial_samples(benchmark: &str, stack: &str, metric: &str, samples: &[f64]) {
    use std::io::Write;
    let Some(mut output) = trial_output_file() else {
        return;
    };
    assert!(samples.iter().all(|sample| sample.is_finite()));
    writeln!(output,
        "{{\"benchmark\":\"{benchmark}\",\"stack\":\"{stack}\",\"metric\":\"{metric}\",\"samples\":{samples:?}}}"
    ).expect("cannot write benchmark trial output");
}

fn trial_output_file() -> Option<std::fs::File> {
    std::env::var_os("QUION_COMPARE_TRIAL_OUTPUT").map(|path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect(
                "cannot open benchmark trial output; use an absolute path with an existing parent",
            )
    })
}

fn report_latency(
    benchmark: &str,
    stack: &str,
    operations: usize,
    trial_p50_ns: &mut [f64],
    trial_p99_ns: &mut [f64],
) {
    report_trial_samples(benchmark, stack, "p50_ns", trial_p50_ns);
    report_trial_samples(benchmark, stack, "p99_ns", trial_p99_ns);
    println!(
        "{{\"benchmark\":\"{benchmark}\",\"stack\":\"{stack}\",\
         \"trials\":{},\"operations_per_trial\":{operations},\
         \"median_p50_ns\":{:.0},\"median_p99_ns\":{:.0}}}",
        trial_p50_ns.len(),
        median(trial_p50_ns),
        median(trial_p99_ns),
    );
}

fn report_rate(
    benchmark: &str,
    stack: &str,
    operations: usize,
    bytes_per_trial: usize,
    trial_seconds: &mut [f64],
) {
    report_trial_samples(benchmark, stack, "seconds", trial_seconds);
    let seconds = median(trial_seconds);
    let min_seconds = trial_seconds[0];
    let max_seconds = trial_seconds[trial_seconds.len() - 1];
    println!(
        "{{\"benchmark\":\"{benchmark}\",\"stack\":\"{stack}\",\
         \"trials\":{},\"operations_per_trial\":{operations},\
         \"bytes_per_trial\":{bytes_per_trial},\"median_seconds\":{seconds:.9},\
         \"min_seconds\":{min_seconds:.9},\"max_seconds\":{max_seconds:.9},\
         \"operations_per_second\":{:.0},\"mib_per_second\":{:.2}}}",
        trial_seconds.len(),
        operations as f64 / seconds,
        bytes_per_trial as f64 / (1024.0 * 1024.0) / seconds,
    );
}

fn report_recovery(
    stack: &str,
    config: &BenchmarkConfig,
    trial_seconds: &mut [f64],
    trial_lost_packets: &mut [f64],
    trial_injected_drops: &mut [f64],
    trial_reordered_datagrams: &mut [f64],
) {
    report_trial_samples("recovery", stack, "seconds", trial_seconds);
    report_trial_samples("recovery", stack, "lost_packets", trial_lost_packets);
    report_trial_samples("recovery", stack, "injected_drops", trial_injected_drops);
    report_trial_samples(
        "recovery",
        stack,
        "reordered_datagrams",
        trial_reordered_datagrams,
    );
    let bytes_per_trial = config.recovery_bytes.saturating_mul(2);
    let seconds = median(trial_seconds);
    let min_seconds = trial_seconds[0];
    let max_seconds = trial_seconds[trial_seconds.len() - 1];
    let lost_packets = median(trial_lost_packets);
    let injected_drops = median(trial_injected_drops);
    let reordered_datagrams = median(trial_reordered_datagrams);
    println!(
        "{{\"benchmark\":\"recovery\",\"stack\":\"{stack}\",\
         \"trials\":{},\"bytes_per_trial\":{bytes_per_trial},\
         \"loss_interval\":{},\
         \"reorder_interval\":{},\
         \"median_seconds\":{seconds:.9},\"min_seconds\":{min_seconds:.9},\
         \"max_seconds\":{max_seconds:.9},\"mib_per_second\":{:.2},\
         \"median_declared_lost_packets\":{lost_packets:.0},\
         \"median_injected_drops\":{injected_drops:.0},\
         \"median_reordered_datagrams\":{reordered_datagrams:.0}}}",
        trial_seconds.len(),
        config.recovery_loss_interval,
        config.recovery_reorder_interval,
        bytes_per_trial as f64 / (1024.0 * 1024.0) / seconds,
    );
}

#[cfg(tokio_unstable)]
fn report_runtime_cost(
    stack: &str,
    bytes_per_trial: usize,
    trial_seconds: &mut [f64],
    trial_worker_busy_seconds: &mut [f64],
    trial_task_polls: &mut [f64],
    trial_task_schedules: &mut [f64],
) {
    report_trial_samples("runtime-cost", stack, "seconds", trial_seconds);
    report_trial_samples(
        "runtime-cost",
        stack,
        "worker_busy_seconds",
        trial_worker_busy_seconds,
    );
    report_trial_samples("runtime-cost", stack, "task_polls", trial_task_polls);
    report_trial_samples(
        "runtime-cost",
        stack,
        "task_schedules",
        trial_task_schedules,
    );
    let seconds = median(trial_seconds);
    let min_seconds = trial_seconds[0];
    let max_seconds = trial_seconds[trial_seconds.len() - 1];
    let worker_busy_seconds = median(trial_worker_busy_seconds);
    let task_polls = median(trial_task_polls);
    let task_schedules = median(trial_task_schedules);
    let mib = bytes_per_trial as f64 / (1024.0 * 1024.0);
    let gib = bytes_per_trial as f64 / (1024.0 * 1024.0 * 1024.0);
    println!(
        "{{\"benchmark\":\"runtime-cost\",\"stack\":\"{stack}\",\
         \"trials\":{},\"bytes_per_trial\":{bytes_per_trial},\
         \"median_seconds\":{seconds:.9},\"min_seconds\":{min_seconds:.9},\
         \"max_seconds\":{max_seconds:.9},\"mib_per_second\":{:.2},\
         \"median_worker_busy_seconds\":{worker_busy_seconds:.9},\
         \"worker_busy_seconds_per_gib\":{:.6},\
         \"median_task_polls\":{task_polls:.0},\"task_polls_per_mib\":{:.2},\
         \"median_task_schedules\":{task_schedules:.0},\
         \"task_schedules_per_mib\":{:.2}}}",
        trial_seconds.len(),
        mib / seconds,
        worker_busy_seconds / gib,
        task_polls / mib,
        task_schedules / mib,
    );
}

fn report_allocations(
    benchmark: &str,
    stack: &str,
    operations: usize,
    bytes_per_trial: usize,
    trial_allocations: &mut [f64],
    trial_allocated_bytes: &mut [f64],
) {
    report_trial_samples(benchmark, stack, "allocations", trial_allocations);
    report_trial_samples(benchmark, stack, "allocated_bytes", trial_allocated_bytes);
    let mib = bytes_per_trial as f64 / (1024.0 * 1024.0);
    let allocations = median(trial_allocations);
    let allocated_bytes = median(trial_allocated_bytes);
    println!(
        "{{\"benchmark\":\"{benchmark}-allocations\",\"stack\":\"{stack}\",\
         \"trials\":{},\"operations_per_trial\":{operations},\
         \"bytes_per_trial\":{bytes_per_trial},\
         \"median_allocations\":{allocations:.0},\
         \"allocations_per_operation\":{:.2},\
         \"allocated_bytes_per_operation\":{:.0},\
         \"allocations_per_mib\":{:.2},\"allocated_bytes_per_mib\":{:.0}}}",
        trial_allocations.len(),
        allocations / operations as f64,
        allocated_bytes / operations as f64,
        allocations / mib,
        allocated_bytes / mib,
    );
}

fn report_idle_connections(
    stack: &str,
    connections: usize,
    trial_allocations: &mut [f64],
    trial_live_bytes: &mut [f64],
) {
    report_trial_samples("idle-connections", stack, "allocations", trial_allocations);
    report_trial_samples(
        "idle-connections",
        stack,
        "retained_bytes",
        trial_live_bytes,
    );
    let allocations = median(trial_allocations);
    let live_bytes = median(trial_live_bytes);
    println!(
        "{{\"benchmark\":\"idle-connections\",\"stack\":\"{stack}\",\
         \"trials\":{},\"connections_per_trial\":{connections},\
         \"median_allocations\":{allocations:.0},\
         \"allocations_per_connection\":{:.2},\
         \"median_retained_bytes\":{live_bytes:.0},\
         \"retained_bytes_per_connection\":{:.0}}}",
        trial_allocations.len(),
        allocations / connections as f64,
        live_bytes / connections as f64,
    );
}

fn report_retained_bytes(
    benchmark: &str,
    stack: &str,
    operations: usize,
    trial_live_bytes: &mut [f64],
) {
    report_trial_samples(benchmark, stack, "retained_bytes", trial_live_bytes);
    let live_bytes = median(trial_live_bytes);
    println!(
        "{{\"benchmark\":\"{benchmark}-retained\",\"stack\":\"{stack}\",\
         \"trials\":{},\"operations_per_trial\":{operations},\
         \"median_retained_bytes\":{live_bytes:.0},\
         \"retained_bytes_per_operation\":{:.0}}}",
        trial_live_bytes.len(),
        live_bytes / operations as f64,
    );
}

async fn quion_echo_trial(identity: &TestIdentity, warmup: usize, iterations: usize) -> EchoTrial {
    let pair = setup_quion(identity).await;
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        for iteration in 0..warmup + iterations {
            let (mut send, mut recv) =
                timeout(server_connection.accept_bi())
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "quion server failed to accept echo stream {iteration}: {error:?}; \
                             diagnostics: {:?}",
                            server_connection.diagnostics()
                        )
                    });
            let request = timeout(recv.read_to_end(64)).await.unwrap();
            timeout(send.write_all(&request)).await.unwrap();
            send.finish().unwrap();
        }
    });
    let mut samples = Vec::with_capacity(iterations);
    let mut allocation_start = None;
    for iteration in 0..warmup + iterations {
        if iteration == warmup {
            allocation_start = Some(AllocationSnapshot::capture());
        }
        let started = Instant::now();
        let (mut send, mut recv) = timeout(pair.client.open_bi()).await.unwrap();
        timeout(send.write_all(STREAM_ECHO_PAYLOAD)).await.unwrap();
        send.finish().unwrap();
        let response = timeout(recv.read_to_end(64)).await.unwrap_or_else(|error| {
            panic!(
                "quion client failed to read echo response {iteration}: {error:?}; \
                 diagnostics: {:?}",
                pair.client.diagnostics()
            )
        });
        assert_eq!(response, STREAM_ECHO_PAYLOAD);
        if iteration >= warmup {
            samples.push(started.elapsed().as_nanos() as u64);
        }
    }
    timeout(server).await.unwrap();
    let allocations = allocation_start
        .expect("echo benchmark must include at least one measured operation")
        .elapsed();
    pair.close().await;
    samples.sort_unstable();
    EchoTrial {
        samples,
        allocations,
    }
}

async fn quinn_echo_trial(identity: &TestIdentity, warmup: usize, iterations: usize) -> EchoTrial {
    let pair = setup_quinn(identity).await;
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        for _ in 0..warmup + iterations {
            let (mut send, mut recv) = timeout(server_connection.accept_bi()).await.unwrap();
            let request = timeout(recv.read_to_end(64)).await.unwrap();
            timeout(send.write_all(&request)).await.unwrap();
            send.finish().unwrap();
        }
    });
    let mut samples = Vec::with_capacity(iterations);
    let mut allocation_start = None;
    for iteration in 0..warmup + iterations {
        if iteration == warmup {
            allocation_start = Some(AllocationSnapshot::capture());
        }
        let started = Instant::now();
        let (mut send, mut recv) = timeout(pair.client.open_bi()).await.unwrap();
        timeout(send.write_all(STREAM_ECHO_PAYLOAD)).await.unwrap();
        send.finish().unwrap();
        let response = timeout(recv.read_to_end(64)).await.unwrap();
        assert_eq!(response, STREAM_ECHO_PAYLOAD);
        if iteration >= warmup {
            samples.push(started.elapsed().as_nanos() as u64);
        }
    }
    timeout(server).await.unwrap();
    let allocations = allocation_start
        .expect("echo benchmark must include at least one measured operation")
        .elapsed();
    pair.close().await;
    samples.sort_unstable();
    EchoTrial {
        samples,
        allocations,
    }
}

async fn quion_bulk_trial(identity: &TestIdentity, bytes: usize) -> RateTrial {
    let pair = setup_quion(identity).await;
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        let mut recv = timeout(server_connection.accept_uni()).await.unwrap();
        timeout(recv.read_to_end(bytes + 1)).await.unwrap().len()
    });
    let payload = vec![0x5a; bytes];
    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    let mut send = timeout(pair.client.open_uni()).await.unwrap();
    timeout(send.write_all(&payload)).await.unwrap();
    send.finish().unwrap();
    assert_eq!(timeout(server).await.unwrap(), bytes);
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    if std::env::var_os("QUION_COMPARE_DIAGNOSTICS").is_some() {
        eprintln!("quion bulk diagnostics: {:?}", pair.client.diagnostics());
    }
    pair.close().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quinn_bulk_trial(identity: &TestIdentity, bytes: usize) -> RateTrial {
    let pair = setup_quinn(identity).await;
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        let mut recv = timeout(server_connection.accept_uni()).await.unwrap();
        timeout(recv.read_to_end(bytes + 1)).await.unwrap().len()
    });
    let payload = vec![0x5a; bytes];
    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    let mut send = timeout(pair.client.open_uni()).await.unwrap();
    timeout(send.write_all(&payload)).await.unwrap();
    send.finish().unwrap();
    assert_eq!(timeout(server).await.unwrap(), bytes);
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    pair.close().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quion_recovery_trial(
    identity: &TestIdentity,
    bytes: usize,
    loss_interval: usize,
    reorder_interval: usize,
) -> RecoveryTrial {
    let (pair, proxy) = setup_impaired_quion(identity, loss_interval, reorder_interval).await;
    let payload = bytes::Bytes::from(vec![0x5a; bytes]);
    let server_payload = payload.clone();
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        let (mut send, mut recv) = timeout(server_connection.accept_bi()).await.unwrap();
        let ((), received) = tokio::join!(
            async {
                timeout(send.write_all(&server_payload)).await.unwrap();
                send.finish().unwrap();
            },
            async { timeout(recv.read_to_end(bytes + 1)).await.unwrap() }
        );
        assert_eq!(received.as_slice(), server_payload.as_ref());
        server_connection.stats()
    });
    proxy.enable();
    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    let (mut send, mut recv) = timeout(pair.client.open_bi()).await.unwrap();
    let ((), received) = tokio::join!(
        async {
            timeout(send.write_all(&payload)).await.unwrap();
            send.finish().unwrap();
        },
        async { timeout(recv.read_to_end(bytes + 1)).await.unwrap() }
    );
    assert_eq!(received.as_slice(), payload.as_ref());
    let server_stats = timeout(server).await.unwrap();
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    let client_stats = pair.client.stats();
    proxy.disable();
    pair.close().await;
    let proxy_stats = proxy.stop().await;
    assert_recovery_faults(proxy_stats);
    let declared_lost_packets = client_stats.packets_lost + server_stats.packets_lost;
    assert!(
        declared_lost_packets > 0,
        "quion declared no packets lost under deterministic impairment"
    );
    assert!(
        client_stats.retransmissions + server_stats.retransmissions > 0,
        "quion did not retransmit under deterministic impairment"
    );
    RecoveryTrial {
        elapsed,
        allocations,
        declared_lost_packets,
        injected_drops: proxy_stats.dropped(),
        reordered_datagrams: proxy_stats.reordered(),
    }
}

async fn quinn_recovery_trial(
    identity: &TestIdentity,
    bytes: usize,
    loss_interval: usize,
    reorder_interval: usize,
) -> RecoveryTrial {
    let (pair, proxy) = setup_impaired_quinn(identity, loss_interval, reorder_interval).await;
    let payload = bytes::Bytes::from(vec![0x5a; bytes]);
    let server_payload = payload.clone();
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        let (mut send, mut recv) = timeout(server_connection.accept_bi()).await.unwrap();
        let ((), received) = tokio::join!(
            async {
                timeout(send.write_all(&server_payload)).await.unwrap();
                send.finish().unwrap();
            },
            async { timeout(recv.read_to_end(bytes + 1)).await.unwrap() }
        );
        assert_eq!(received.as_slice(), server_payload.as_ref());
        server_connection.stats()
    });
    proxy.enable();
    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    let (mut send, mut recv) = timeout(pair.client.open_bi()).await.unwrap();
    let ((), received) = tokio::join!(
        async {
            timeout(send.write_all(&payload)).await.unwrap();
            send.finish().unwrap();
        },
        async { timeout(recv.read_to_end(bytes + 1)).await.unwrap() }
    );
    assert_eq!(received.as_slice(), payload.as_ref());
    let server_stats = timeout(server).await.unwrap();
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    let client_stats = pair.client.stats();
    proxy.disable();
    pair.close().await;
    let proxy_stats = proxy.stop().await;
    assert_recovery_faults(proxy_stats);
    let declared_lost_packets = client_stats.path.lost_packets + server_stats.path.lost_packets;
    assert!(
        declared_lost_packets > 0,
        "Quinn declared no packets lost under deterministic impairment"
    );
    RecoveryTrial {
        elapsed,
        allocations,
        declared_lost_packets,
        injected_drops: proxy_stats.dropped(),
        reordered_datagrams: proxy_stats.reordered(),
    }
}

fn assert_recovery_faults(stats: FaultProxyStats) {
    for (direction, stats) in [
        ("client-to-server", stats.client_to_server),
        ("server-to-client", stats.server_to_client),
    ] {
        assert!(stats.received > 0, "{direction} received no traffic");
        assert!(stats.forwarded > 0, "{direction} forwarded no traffic");
        assert!(stats.dropped > 0, "{direction} injected no loss");
        assert!(stats.reordered > 0, "{direction} injected no reordering");
    }
}

#[cfg(tokio_unstable)]
async fn quion_runtime_trial(
    identity: &TestIdentity,
    warmup_bytes: usize,
    bytes: usize,
) -> RuntimeTrial {
    let pair = setup_quion(identity).await;
    let server_connection = pair.server.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut warmup_send, mut warmup_recv) =
            timeout(server_connection.accept_bi()).await.unwrap();
        let warmup = timeout(warmup_recv.read_to_end(warmup_bytes + 1))
            .await
            .unwrap();
        assert_eq!(warmup.len(), warmup_bytes);
        assert!(warmup.iter().all(|byte| *byte == 0x5a));
        timeout(warmup_send.write_all(&[0xac])).await.unwrap();
        warmup_send.finish().unwrap();
        let _ = ready_tx.send(());

        let (mut send, mut recv) = timeout(server_connection.accept_bi()).await.unwrap();
        let payload = timeout(recv.read_to_end(bytes + 1)).await.unwrap();
        assert_eq!(payload.len(), bytes);
        assert!(payload.iter().all(|byte| *byte == 0x5a));
        timeout(send.write_all(&[0xac])).await.unwrap();
        send.finish().unwrap();
    });
    let warmup_payload = vec![0x5a; warmup_bytes];
    let (mut warmup_send, mut warmup_recv) = timeout(pair.client.open_bi()).await.unwrap();
    timeout(warmup_send.write_all(&warmup_payload))
        .await
        .unwrap();
    warmup_send.finish().unwrap();
    assert_eq!(timeout(warmup_recv.read_to_end(2)).await.unwrap(), [0xac]);
    timeout(ready_rx).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let payload = vec![0x5a; bytes];
    let runtime_start = RuntimeSnapshot::capture();
    let started = Instant::now();
    let (mut send, mut recv) = timeout(pair.client.open_bi()).await.unwrap();
    timeout(send.write_all(&payload)).await.unwrap();
    send.finish().unwrap();
    assert_eq!(timeout(recv.read_to_end(2)).await.unwrap(), [0xac]);
    timeout(server).await.unwrap();
    let elapsed = started.elapsed();
    let runtime = runtime_start.elapsed();
    pair.close().await;
    RuntimeTrial {
        elapsed,
        worker_busy: runtime.worker_busy,
        task_polls: runtime.task_polls,
        task_schedules: runtime.task_schedules,
    }
}

#[cfg(tokio_unstable)]
async fn quinn_runtime_trial(
    identity: &TestIdentity,
    warmup_bytes: usize,
    bytes: usize,
) -> RuntimeTrial {
    let pair = setup_quinn(identity).await;
    let server_connection = pair.server.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut warmup_send, mut warmup_recv) =
            timeout(server_connection.accept_bi()).await.unwrap();
        let warmup = timeout(warmup_recv.read_to_end(warmup_bytes + 1))
            .await
            .unwrap();
        assert_eq!(warmup.len(), warmup_bytes);
        assert!(warmup.iter().all(|byte| *byte == 0x5a));
        timeout(warmup_send.write_all(&[0xac])).await.unwrap();
        warmup_send.finish().unwrap();
        let _ = ready_tx.send(());

        let (mut send, mut recv) = timeout(server_connection.accept_bi()).await.unwrap();
        let payload = timeout(recv.read_to_end(bytes + 1)).await.unwrap();
        assert_eq!(payload.len(), bytes);
        assert!(payload.iter().all(|byte| *byte == 0x5a));
        timeout(send.write_all(&[0xac])).await.unwrap();
        send.finish().unwrap();
    });
    let warmup_payload = vec![0x5a; warmup_bytes];
    let (mut warmup_send, mut warmup_recv) = timeout(pair.client.open_bi()).await.unwrap();
    timeout(warmup_send.write_all(&warmup_payload))
        .await
        .unwrap();
    warmup_send.finish().unwrap();
    assert_eq!(timeout(warmup_recv.read_to_end(2)).await.unwrap(), [0xac]);
    timeout(ready_rx).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let payload = vec![0x5a; bytes];
    let runtime_start = RuntimeSnapshot::capture();
    let started = Instant::now();
    let (mut send, mut recv) = timeout(pair.client.open_bi()).await.unwrap();
    timeout(send.write_all(&payload)).await.unwrap();
    send.finish().unwrap();
    assert_eq!(timeout(recv.read_to_end(2)).await.unwrap(), [0xac]);
    timeout(server).await.unwrap();
    let elapsed = started.elapsed();
    let runtime = runtime_start.elapsed();
    pair.close().await;
    RuntimeTrial {
        elapsed,
        worker_busy: runtime.worker_busy,
        task_polls: runtime.task_polls,
        task_schedules: runtime.task_schedules,
    }
}

async fn quion_many_streams_trial(identity: &TestIdentity, streams: usize) -> RateTrial {
    let pair = setup_quion(identity).await;
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for stream_index in 0..streams {
            let (mut send, mut recv) =
                timeout(server_connection.accept_bi())
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "quion server failed to accept concurrent stream {stream_index}: \
                         {error:?}; diagnostics: {:?}",
                            server_connection.diagnostics()
                        )
                    });
            tasks.spawn(async move {
                let request = timeout(recv.read_to_end(MANY_STREAM_PAYLOAD_BYTES + 1))
                    .await
                    .unwrap();
                timeout(send.write_all(&request)).await.unwrap();
                send.finish().unwrap();
                request.len()
            });
        }
        let mut bytes = 0;
        while let Some(result) = tasks.join_next().await {
            bytes += result.unwrap();
        }
        bytes
    });
    let payload = bytes::Bytes::from(vec![0x5a; MANY_STREAM_PAYLOAD_BYTES]);
    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for stream_index in 0..streams {
        let connection = pair.client.clone();
        let payload = payload.clone();
        tasks.spawn(async move {
            let (mut send, mut recv) =
                timeout(connection.open_bi()).await.unwrap_or_else(|error| {
                    panic!(
                        "quion client failed to open concurrent stream {stream_index}: \
                         {error:?}; diagnostics: {:?}",
                        connection.diagnostics()
                    )
                });
            timeout(send.write_all(&payload)).await.unwrap();
            send.finish().unwrap();
            let response = timeout(recv.read_to_end(MANY_STREAM_PAYLOAD_BYTES + 1))
                .await
                .unwrap();
            assert_eq!(response.as_slice(), payload.as_ref());
            response.len()
        });
    }
    let mut response_bytes = 0;
    while let Some(result) = tasks.join_next().await {
        response_bytes += result.unwrap();
    }
    assert_eq!(response_bytes, streams * MANY_STREAM_PAYLOAD_BYTES);
    assert_eq!(timeout(server).await.unwrap(), response_bytes);
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    pair.close().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quinn_many_streams_trial(identity: &TestIdentity, streams: usize) -> RateTrial {
    let pair = setup_quinn(identity).await;
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..streams {
            let (mut send, mut recv) = timeout(server_connection.accept_bi()).await.unwrap();
            tasks.spawn(async move {
                let request = timeout(recv.read_to_end(MANY_STREAM_PAYLOAD_BYTES + 1))
                    .await
                    .unwrap();
                timeout(send.write_all(&request)).await.unwrap();
                send.finish().unwrap();
                request.len()
            });
        }
        let mut bytes = 0;
        while let Some(result) = tasks.join_next().await {
            bytes += result.unwrap();
        }
        bytes
    });
    let payload = bytes::Bytes::from(vec![0x5a; MANY_STREAM_PAYLOAD_BYTES]);
    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..streams {
        let connection = pair.client.clone();
        let payload = payload.clone();
        tasks.spawn(async move {
            let (mut send, mut recv) = timeout(connection.open_bi()).await.unwrap();
            timeout(send.write_all(&payload)).await.unwrap();
            send.finish().unwrap();
            let response = timeout(recv.read_to_end(MANY_STREAM_PAYLOAD_BYTES + 1))
                .await
                .unwrap();
            assert_eq!(response.as_slice(), payload.as_ref());
            response.len()
        });
    }
    let mut response_bytes = 0;
    while let Some(result) = tasks.join_next().await {
        response_bytes += result.unwrap();
    }
    assert_eq!(response_bytes, streams * MANY_STREAM_PAYLOAD_BYTES);
    assert_eq!(timeout(server).await.unwrap(), response_bytes);
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    pair.close().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quion_active_streams_trial(
    identity: &TestIdentity,
    warmup: usize,
    streams: usize,
) -> RateTrial {
    let pair = setup_quion(identity).await;
    let total_streams = warmup + streams;
    let server_connection = pair.server.clone();
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel::<()>(1);
    let server_handles = Vec::with_capacity(total_streams);
    let server = tokio::spawn(async move {
        let mut handles = server_handles;
        for stream_index in 0..total_streams {
            let handles_for_stream =
                timeout(server_connection.accept_bi())
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "quion server failed to accept active stream {stream_index}: \
                         {error:?}; diagnostics: {:?}",
                            server_connection.diagnostics()
                        )
                    });
            handles.push(handles_for_stream);
            accepted_tx.send(()).await.unwrap();
        }
        handles
    });
    let payload = bytes::Bytes::from(vec![0x5a; MANY_STREAM_PAYLOAD_BYTES]);
    let mut client_handles = Vec::with_capacity(total_streams);
    let mut allocation_start = None;
    let mut started = None;
    for stream_index in 0..total_streams {
        if stream_index == warmup {
            allocation_start = Some(AllocationSnapshot::capture());
            started = Some(Instant::now());
        }
        let (mut send, recv) = timeout(pair.client.open_bi())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "quion client failed to open active stream {stream_index}: \
                     {error:?}; diagnostics: {:?}",
                    pair.client.diagnostics()
                )
            });
        timeout(send.write_all(&payload)).await.unwrap();
        client_handles.push((send, recv));
        timeout(accepted_rx.recv())
            .await
            .expect("quion active-stream server stopped early");
    }
    let elapsed = started
        .expect("active-stream benchmark must include a measured stream")
        .elapsed();
    let allocations = allocation_start
        .expect("active-stream benchmark must include a measured stream")
        .elapsed();
    let server_handles = timeout(server).await.unwrap();
    assert_eq!(client_handles.len(), total_streams);
    assert_eq!(server_handles.len(), total_streams);
    for (_, mut recv) in server_handles {
        let mut request = [0; MANY_STREAM_PAYLOAD_BYTES];
        timeout(recv.read_exact(&mut request)).await.unwrap();
        assert_eq!(request.as_slice(), payload.as_ref());
    }
    drop(client_handles);
    pair.close().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quinn_active_streams_trial(
    identity: &TestIdentity,
    warmup: usize,
    streams: usize,
) -> RateTrial {
    let pair = setup_quinn(identity).await;
    let total_streams = warmup + streams;
    let server_connection = pair.server.clone();
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel::<()>(1);
    let server_handles = Vec::with_capacity(total_streams);
    let server = tokio::spawn(async move {
        let mut handles = server_handles;
        for _ in 0..total_streams {
            handles.push(timeout(server_connection.accept_bi()).await.unwrap());
            accepted_tx.send(()).await.unwrap();
        }
        handles
    });
    let payload = bytes::Bytes::from(vec![0x5a; MANY_STREAM_PAYLOAD_BYTES]);
    let mut client_handles = Vec::with_capacity(total_streams);
    let mut allocation_start = None;
    let mut started = None;
    for stream_index in 0..total_streams {
        if stream_index == warmup {
            allocation_start = Some(AllocationSnapshot::capture());
            started = Some(Instant::now());
        }
        let (mut send, recv) = timeout(pair.client.open_bi()).await.unwrap();
        timeout(send.write_all(&payload)).await.unwrap();
        client_handles.push((send, recv));
        timeout(accepted_rx.recv())
            .await
            .unwrap_or_else(|| panic!("Quinn active-stream server stopped at {stream_index}"));
    }
    let elapsed = started
        .expect("active-stream benchmark must include a measured stream")
        .elapsed();
    let allocations = allocation_start
        .expect("active-stream benchmark must include a measured stream")
        .elapsed();
    let server_handles = timeout(server).await.unwrap();
    assert_eq!(client_handles.len(), total_streams);
    assert_eq!(server_handles.len(), total_streams);
    for (_, mut recv) in server_handles {
        let mut request = [0; MANY_STREAM_PAYLOAD_BYTES];
        timeout(recv.read_exact(&mut request)).await.unwrap();
        assert_eq!(request.as_slice(), payload.as_ref());
    }
    drop(client_handles);
    pair.close().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quion_datagram_trial(identity: &TestIdentity, datagrams: usize) -> RateTrial {
    let pair = setup_quion(identity).await;
    let server_connection = pair.server.clone();
    let client_connection = pair.client.clone();
    let server = tokio::spawn(async move {
        let mut bytes = 0;
        for index in 0..datagrams {
            bytes += timeout(server_connection.read_datagram_bytes())
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "quion server failed to receive DATAGRAM {index}/{datagrams}: \
                         {error:?}; server diagnostics: {:?}; client diagnostics: {:?}",
                        server_connection.diagnostics(),
                        client_connection.diagnostics()
                    )
                })
                .len();
        }
        bytes
    });
    let payload = bytes::Bytes::from(vec![0x5a; DATAGRAM_PAYLOAD_BYTES]);
    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    for _ in 0..datagrams {
        pair.client.send_datagram_bytes(payload.clone()).unwrap();
    }
    assert_eq!(
        timeout(server).await.unwrap(),
        datagrams * DATAGRAM_PAYLOAD_BYTES
    );
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    pair.close().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quinn_datagram_trial(identity: &TestIdentity, datagrams: usize) -> RateTrial {
    let pair = setup_quinn(identity).await;
    let server_connection = pair.server.clone();
    let server = tokio::spawn(async move {
        let mut bytes = 0;
        for _ in 0..datagrams {
            bytes += timeout(server_connection.read_datagram())
                .await
                .unwrap()
                .len();
        }
        bytes
    });
    let payload = bytes::Bytes::from(vec![0x5a; DATAGRAM_PAYLOAD_BYTES]);
    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    for _ in 0..datagrams {
        pair.client.send_datagram(payload.clone()).unwrap();
    }
    assert_eq!(
        timeout(server).await.unwrap(),
        datagrams * DATAGRAM_PAYLOAD_BYTES
    );
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    pair.close().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quion_handshake_trial(identity: &TestIdentity, iterations: usize) -> Vec<u64> {
    let server_endpoint = QuionEndpoint::server(
        ServerConfig::builder()
            .with_single_cert(
                vec![identity.certificate.clone()],
                PrivateKeyDer::Pkcs8(identity.private_key.clone_key()),
            )
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    server_endpoint
        .set_socket_recv_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    server_endpoint
        .set_socket_send_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();
    let client_endpoint = QuionEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint
        .set_socket_recv_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    client_endpoint
        .set_socket_send_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(identity.roots())
        .with_no_client_auth();
    client_crypto.resumption = rustls::client::Resumption::disabled();
    client_endpoint.set_default_client_config(
        ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build(),
    );
    let server_endpoint_for_accept = server_endpoint.clone();
    let (connected_tx, mut connected_rx) = tokio::sync::mpsc::channel::<Duration>(1);
    let server = tokio::spawn(async move {
        for iteration in 0..iterations {
            let connection = timeout(async {
                server_endpoint_for_accept
                    .accept()
                    .await
                    .expect("quion server endpoint closed")
                    .await
            })
            .await
            .unwrap();
            let elapsed = connected_rx
                .recv()
                .await
                .expect("quion client benchmark stopped early");
            if elapsed >= Duration::from_millis(2)
                && std::env::var_os("QUION_COMPARE_DIAGNOSTICS").is_some()
            {
                eprintln!(
                    "quion slow server handshake {iteration} ({elapsed:?}): {:?}",
                    connection.diagnostics()
                );
            }
            connection.abort();
        }
    });
    let mut samples = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let started = Instant::now();
        let connection = timeout(
            client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .unwrap(),
        )
        .await
        .unwrap();
        let elapsed = started.elapsed();
        if elapsed >= Duration::from_millis(2)
            && std::env::var_os("QUION_COMPARE_DIAGNOSTICS").is_some()
        {
            eprintln!(
                "quion slow handshake {iteration} ({elapsed:?}): {:?}",
                connection.diagnostics()
            );
        }
        samples.push(elapsed.as_nanos() as u64);
        connected_tx.send(elapsed).await.unwrap();
        connection.abort();
    }
    timeout(server).await.unwrap();
    client_endpoint.abort();
    server_endpoint.abort();
    timeout(server_driver.stop()).await.unwrap();
    samples.sort_unstable();
    if std::env::var_os("QUION_COMPARE_DIAGNOSTICS").is_some() {
        eprintln!("quion handshake samples (ns): {samples:?}");
    }
    samples
}

async fn quinn_handshake_trial(identity: &TestIdentity, iterations: usize) -> Vec<u64> {
    let server_endpoint = quinn::Endpoint::server(
        quinn_server_config(identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quinn_client_config(identity));
    let server_address = server_endpoint.local_addr().unwrap();
    let server_endpoint_for_accept = server_endpoint.clone();
    let (connected_tx, mut connected_rx) = tokio::sync::mpsc::channel::<()>(1);
    let server = tokio::spawn(async move {
        for _ in 0..iterations {
            let connection = timeout(server_endpoint_for_accept.accept())
                .await
                .expect("Quinn server endpoint closed")
                .await
                .unwrap();
            connected_rx
                .recv()
                .await
                .expect("Quinn client benchmark stopped early");
            connection.close(0_u32.into(), b"iteration complete");
        }
    });
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let connection = timeout(
            client_endpoint
                .connect(server_address, "localhost")
                .unwrap(),
        )
        .await
        .unwrap();
        samples.push(started.elapsed().as_nanos() as u64);
        connected_tx.send(()).await.unwrap();
        connection.close(0_u32.into(), b"iteration complete");
    }
    timeout(server).await.unwrap();
    client_endpoint.close(0_u32.into(), b"benchmark complete");
    server_endpoint.close(0_u32.into(), b"benchmark complete");
    client_endpoint.wait_idle().await;
    server_endpoint.wait_idle().await;
    samples.sort_unstable();
    samples
}

async fn quion_shutdown_trial(identity: &TestIdentity, iterations: usize) -> Vec<u64> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let QuionPair {
            client_endpoint,
            server_endpoint,
            server_driver,
            client,
            server,
        } = setup_quion(identity).await;
        let started = Instant::now();
        client_endpoint.close();
        server_endpoint.close();
        drop(client);
        drop(server);
        timeout(async {
            loop {
                if client_endpoint.diagnostics().active_connections == 0
                    && server_endpoint.diagnostics().active_connections == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        samples.push(started.elapsed().as_nanos() as u64);
        client_endpoint.abort();
        server_endpoint.abort();
        timeout(server_driver.stop()).await.unwrap();
    }
    samples.sort_unstable();
    samples
}

async fn quinn_shutdown_trial(identity: &TestIdentity, iterations: usize) -> Vec<u64> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let QuinnPair {
            client_endpoint,
            server_endpoint,
            client,
            server,
        } = setup_quinn(identity).await;
        let started = Instant::now();
        client_endpoint.close(0_u32.into(), b"benchmark complete");
        server_endpoint.close(0_u32.into(), b"benchmark complete");
        drop(client);
        drop(server);
        tokio::join!(client_endpoint.wait_idle(), server_endpoint.wait_idle());
        samples.push(started.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    samples
}

async fn quion_short_connections_trial(identity: &TestIdentity, connections: usize) -> RateTrial {
    let server_endpoint = QuionEndpoint::server(
        ServerConfig::builder()
            .with_single_cert(
                vec![identity.certificate.clone()],
                PrivateKeyDer::Pkcs8(identity.private_key.clone_key()),
            )
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    server_endpoint
        .set_socket_recv_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    server_endpoint
        .set_socket_send_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();
    let client_endpoint = QuionEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint
        .set_socket_recv_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    client_endpoint
        .set_socket_send_buffer_size(SOCKET_BUFFER_BYTES)
        .unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(identity.roots())
        .with_no_client_auth();
    client_crypto.resumption = rustls::client::Resumption::disabled();
    client_endpoint.set_default_client_config(
        ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build(),
    );
    let server_endpoint_for_accept = server_endpoint.clone();
    let (completed_tx, mut completed_rx) = tokio::sync::mpsc::channel::<()>(1);
    let server = tokio::spawn(async move {
        for connection_index in 0..connections {
            let connection = timeout(async {
                server_endpoint_for_accept
                    .accept()
                    .await
                    .expect("quion server endpoint closed")
                    .await
            })
            .await
            .unwrap();
            let (mut send, mut recv) =
                timeout(connection.accept_bi())
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "quion server failed to accept stream for short connection \
                         {connection_index}: {error:?}; diagnostics: {:?}",
                            connection.diagnostics()
                        )
                    });
            let request = timeout(recv.read_to_end(64)).await.unwrap();
            timeout(send.write_all(&request)).await.unwrap();
            send.finish().unwrap();
            completed_rx
                .recv()
                .await
                .expect("quion client short-connection benchmark stopped early");
            connection.close(VarInt::ZERO, b"");
        }
    });

    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    for connection_index in 0..connections {
        let connection = timeout(
            client_endpoint
                .connect(server_endpoint.local_addr(), "localhost")
                .unwrap(),
        )
        .await
        .unwrap();
        let (mut send, mut recv) = timeout(connection.open_bi()).await.unwrap_or_else(|error| {
            panic!(
                "quion client failed to open stream for short connection \
                     {connection_index}: {error:?}; diagnostics: {:?}",
                connection.diagnostics()
            )
        });
        timeout(send.write_all(STREAM_ECHO_PAYLOAD)).await.unwrap();
        send.finish().unwrap();
        let response = timeout(recv.read_to_end(64)).await.unwrap();
        assert_eq!(response, STREAM_ECHO_PAYLOAD);
        completed_tx.send(()).await.unwrap();
        connection.close(VarInt::ZERO, b"");
    }
    timeout(server).await.unwrap();
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    client_endpoint.abort();
    server_endpoint.abort();
    timeout(server_driver.stop()).await.unwrap();
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quinn_short_connections_trial(identity: &TestIdentity, connections: usize) -> RateTrial {
    let server_endpoint = quinn::Endpoint::server(
        quinn_server_config(identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quinn_client_config(identity));
    let server_address = server_endpoint.local_addr().unwrap();
    let server_endpoint_for_accept = server_endpoint.clone();
    let (completed_tx, mut completed_rx) = tokio::sync::mpsc::channel::<()>(1);
    let server = tokio::spawn(async move {
        for _ in 0..connections {
            let connection = timeout(server_endpoint_for_accept.accept())
                .await
                .expect("Quinn server endpoint closed")
                .await
                .unwrap();
            let (mut send, mut recv) = timeout(connection.accept_bi()).await.unwrap();
            let request = timeout(recv.read_to_end(64)).await.unwrap();
            timeout(send.write_all(&request)).await.unwrap();
            send.finish().unwrap();
            completed_rx
                .recv()
                .await
                .expect("Quinn client short-connection benchmark stopped early");
            connection.close(0_u32.into(), b"");
        }
    });

    let allocation_start = AllocationSnapshot::capture();
    let started = Instant::now();
    for _ in 0..connections {
        let connection = timeout(
            client_endpoint
                .connect(server_address, "localhost")
                .unwrap(),
        )
        .await
        .unwrap();
        let (mut send, mut recv) = timeout(connection.open_bi()).await.unwrap();
        timeout(send.write_all(STREAM_ECHO_PAYLOAD)).await.unwrap();
        send.finish().unwrap();
        let response = timeout(recv.read_to_end(64)).await.unwrap();
        assert_eq!(response, STREAM_ECHO_PAYLOAD);
        completed_tx.send(()).await.unwrap();
        connection.close(0_u32.into(), b"");
    }
    timeout(server).await.unwrap();
    let elapsed = started.elapsed();
    let allocations = allocation_start.elapsed();
    client_endpoint.close(0_u32.into(), b"benchmark complete");
    server_endpoint.close(0_u32.into(), b"benchmark complete");
    client_endpoint.wait_idle().await;
    server_endpoint.wait_idle().await;
    RateTrial {
        elapsed,
        allocations,
    }
}

async fn quion_idle_connection_trial(
    identity: &TestIdentity,
    warmup: usize,
    connections: usize,
) -> IdleConnectionTrial {
    let total_connections = warmup.saturating_add(connections);
    let mut transport = quion_transport();
    let endpoint_memory_bytes = total_connections
        .saturating_mul(2 * 1024 * 1024)
        .max(512 * 1024 * 1024);
    transport
        .set_max_connections(total_connections.saturating_add(16))
        .set_max_pending_handshakes(total_connections.saturating_add(16))
        .set_max_established_connections(total_connections.saturating_add(16))
        .set_max_endpoint_memory_bytes(endpoint_memory_bytes);
    let server_endpoint = QuionEndpoint::server(
        ServerConfig::builder()
            .with_single_cert(
                vec![identity.certificate.clone()],
                PrivateKeyDer::Pkcs8(identity.private_key.clone_key()),
            )
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(transport.clone())
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_driver = server_endpoint
        .spawn_default_server_udp_driver(65_535)
        .unwrap();
    let client_endpoint = QuionEndpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(identity.roots())
        .with_no_client_auth();
    client_crypto.resumption = rustls::client::Resumption::disabled();
    client_endpoint.set_default_client_config(
        ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(transport)
            .build(),
    );

    let mut clients = Vec::with_capacity(total_connections);
    let mut servers = Vec::with_capacity(total_connections);
    for _ in 0..warmup {
        clients.push(
            timeout(
                client_endpoint
                    .connect(server_endpoint.local_addr(), "localhost")
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        servers.push(
            timeout(async {
                server_endpoint
                    .accept()
                    .await
                    .expect("quion server endpoint closed")
                    .await
            })
            .await
            .unwrap(),
        );
    }

    let allocation_start = AllocationSnapshot::capture();
    for _ in 0..connections {
        clients.push(
            timeout(
                client_endpoint
                    .connect(server_endpoint.local_addr(), "localhost")
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        servers.push(
            timeout(async {
                server_endpoint
                    .accept()
                    .await
                    .expect("quion server endpoint closed")
                    .await
            })
            .await
            .unwrap(),
        );
    }
    let allocations = allocation_start.elapsed();

    for connection in clients {
        connection.abort();
    }
    for connection in servers {
        connection.abort();
    }
    client_endpoint.abort();
    server_endpoint.abort();
    timeout(server_driver.stop()).await.unwrap();
    IdleConnectionTrial { allocations }
}

async fn quinn_idle_connection_trial(
    identity: &TestIdentity,
    warmup: usize,
    connections: usize,
) -> IdleConnectionTrial {
    let total_connections = warmup.saturating_add(connections);
    let server_endpoint = quinn::Endpoint::server(
        quinn_server_config(identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quinn_client_config(identity));
    let server_address = server_endpoint.local_addr().unwrap();
    let mut clients = Vec::with_capacity(total_connections);
    let mut servers = Vec::with_capacity(total_connections);

    for _ in 0..warmup {
        let (client, server) = tokio::join!(
            async {
                timeout(
                    client_endpoint
                        .connect(server_address, "localhost")
                        .unwrap(),
                )
                .await
                .unwrap()
            },
            async {
                timeout(server_endpoint.accept())
                    .await
                    .expect("Quinn server endpoint closed")
                    .await
                    .unwrap()
            }
        );
        clients.push(client);
        servers.push(server);
    }

    let allocation_start = AllocationSnapshot::capture();
    for _ in 0..connections {
        let (client, server) = tokio::join!(
            async {
                timeout(
                    client_endpoint
                        .connect(server_address, "localhost")
                        .unwrap(),
                )
                .await
                .unwrap()
            },
            async {
                timeout(server_endpoint.accept())
                    .await
                    .expect("Quinn server endpoint closed")
                    .await
                    .unwrap()
            }
        );
        clients.push(client);
        servers.push(server);
    }
    let allocations = allocation_start.elapsed();

    for connection in clients {
        connection.close(0_u32.into(), b"benchmark complete");
    }
    for connection in servers {
        connection.close(0_u32.into(), b"benchmark complete");
    }
    client_endpoint.close(0_u32.into(), b"benchmark complete");
    server_endpoint.close(0_u32.into(), b"benchmark complete");
    client_endpoint.wait_idle().await;
    server_endpoint.wait_idle().await;
    IdleConnectionTrial { allocations }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // Validate the artifact destination before expensive measurements begin.
    drop(trial_output_file());
    #[cfg(debug_assertions)]
    let _heap_profiler = std::env::var_os("QUION_DHAT_OUTPUT")
        .map(|output| dhat::Profiler::builder().file_name(output).build());
    let config = BenchmarkConfig::from_environment();
    let stack = StackSelection::from_environment();
    let scenario = ScenarioSelection::from_environment();
    #[cfg(not(tokio_unstable))]
    assert!(
        scenario != ScenarioSelection::RuntimeCost,
        "runtime-cost requires RUSTFLAGS='--cfg tokio_unstable'; use scripts/profile-runtime.sh"
    );
    let identity = TestIdentity::generate();
    let diagnostics = std::env::var_os("QUION_COMPARE_DIAGNOSTICS").is_some();

    let mut quion_handshake_p50 = Vec::with_capacity(config.trials);
    let mut quion_handshake_p99 = Vec::with_capacity(config.trials);
    let mut quinn_handshake_p50 = Vec::with_capacity(config.trials);
    let mut quinn_handshake_p99 = Vec::with_capacity(config.trials);
    let mut quion_shutdown_p50 = Vec::with_capacity(config.trials);
    let mut quion_shutdown_p99 = Vec::with_capacity(config.trials);
    let mut quinn_shutdown_p50 = Vec::with_capacity(config.trials);
    let mut quinn_shutdown_p99 = Vec::with_capacity(config.trials);
    let mut quion_echo_p50 = Vec::with_capacity(config.trials);
    let mut quion_echo_p99 = Vec::with_capacity(config.trials);
    let mut quinn_echo_p50 = Vec::with_capacity(config.trials);
    let mut quinn_echo_p99 = Vec::with_capacity(config.trials);
    let mut quion_echo_allocations = Vec::with_capacity(config.trials);
    let mut quion_echo_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quinn_echo_allocations = Vec::with_capacity(config.trials);
    let mut quinn_echo_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quion_bulk_seconds = Vec::with_capacity(config.trials);
    let mut quinn_bulk_seconds = Vec::with_capacity(config.trials);
    let mut quion_datagram_seconds = Vec::with_capacity(config.trials);
    let mut quinn_datagram_seconds = Vec::with_capacity(config.trials);
    let mut quion_bulk_allocations = Vec::with_capacity(config.trials);
    let mut quion_bulk_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quinn_bulk_allocations = Vec::with_capacity(config.trials);
    let mut quinn_bulk_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quion_many_stream_seconds = Vec::with_capacity(config.trials);
    let mut quinn_many_stream_seconds = Vec::with_capacity(config.trials);
    let mut quion_many_stream_allocations = Vec::with_capacity(config.trials);
    let mut quion_many_stream_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quinn_many_stream_allocations = Vec::with_capacity(config.trials);
    let mut quinn_many_stream_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quion_active_stream_seconds = Vec::with_capacity(config.trials);
    let mut quion_active_stream_allocations = Vec::with_capacity(config.trials);
    let mut quion_active_stream_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quion_active_stream_live_bytes = Vec::with_capacity(config.trials);
    let mut quinn_active_stream_seconds = Vec::with_capacity(config.trials);
    let mut quinn_active_stream_allocations = Vec::with_capacity(config.trials);
    let mut quinn_active_stream_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quinn_active_stream_live_bytes = Vec::with_capacity(config.trials);
    let mut quion_short_connection_seconds = Vec::with_capacity(config.trials);
    let mut quinn_short_connection_seconds = Vec::with_capacity(config.trials);
    let mut quion_short_connection_allocations = Vec::with_capacity(config.trials);
    let mut quion_short_connection_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quion_short_connection_live_bytes = Vec::with_capacity(config.trials);
    let mut quinn_short_connection_allocations = Vec::with_capacity(config.trials);
    let mut quinn_short_connection_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quinn_short_connection_live_bytes = Vec::with_capacity(config.trials);
    let mut quion_datagram_allocations = Vec::with_capacity(config.trials);
    let mut quion_datagram_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quinn_datagram_allocations = Vec::with_capacity(config.trials);
    let mut quinn_datagram_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quion_idle_allocations = Vec::with_capacity(config.trials);
    let mut quion_idle_live_bytes = Vec::with_capacity(config.trials);
    let mut quinn_idle_allocations = Vec::with_capacity(config.trials);
    let mut quinn_idle_live_bytes = Vec::with_capacity(config.trials);
    let mut quion_recovery_seconds = Vec::with_capacity(config.trials);
    let mut quion_recovery_allocations = Vec::with_capacity(config.trials);
    let mut quion_recovery_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quion_recovery_lost_packets = Vec::with_capacity(config.trials);
    let mut quion_recovery_injected_drops = Vec::with_capacity(config.trials);
    let mut quion_recovery_reordered_datagrams = Vec::with_capacity(config.trials);
    let mut quinn_recovery_seconds = Vec::with_capacity(config.trials);
    let mut quinn_recovery_allocations = Vec::with_capacity(config.trials);
    let mut quinn_recovery_allocated_bytes = Vec::with_capacity(config.trials);
    let mut quinn_recovery_lost_packets = Vec::with_capacity(config.trials);
    let mut quinn_recovery_injected_drops = Vec::with_capacity(config.trials);
    let mut quinn_recovery_reordered_datagrams = Vec::with_capacity(config.trials);
    #[cfg(tokio_unstable)]
    let mut quion_runtime_seconds = Vec::with_capacity(config.trials);
    #[cfg(tokio_unstable)]
    let mut quion_runtime_worker_busy_seconds = Vec::with_capacity(config.trials);
    #[cfg(tokio_unstable)]
    let mut quion_runtime_task_polls = Vec::with_capacity(config.trials);
    #[cfg(tokio_unstable)]
    let mut quion_runtime_task_schedules = Vec::with_capacity(config.trials);
    #[cfg(tokio_unstable)]
    let mut quinn_runtime_seconds = Vec::with_capacity(config.trials);
    #[cfg(tokio_unstable)]
    let mut quinn_runtime_worker_busy_seconds = Vec::with_capacity(config.trials);
    #[cfg(tokio_unstable)]
    let mut quinn_runtime_task_polls = Vec::with_capacity(config.trials);
    #[cfg(tokio_unstable)]
    let mut quinn_runtime_task_schedules = Vec::with_capacity(config.trials);

    for _ in 0..config.trials {
        if scenario.includes(ScenarioSelection::Handshake) {
            if diagnostics {
                eprintln!("running handshake trials");
            }
            if stack.includes_quion() {
                let samples = quion_handshake_trial(&identity, config.handshake_iterations).await;
                quion_handshake_p50.push(percentile(&samples, 50) as f64);
                quion_handshake_p99.push(percentile(&samples, 99) as f64);
            }
            if stack.includes_quinn() {
                let samples = quinn_handshake_trial(&identity, config.handshake_iterations).await;
                quinn_handshake_p50.push(percentile(&samples, 50) as f64);
                quinn_handshake_p99.push(percentile(&samples, 99) as f64);
            }
        }

        if scenario.includes(ScenarioSelection::EndpointShutdown) {
            if diagnostics {
                eprintln!("running endpoint shutdown trials");
            }
            if stack.includes_quion() {
                let samples = quion_shutdown_trial(&identity, config.shutdown_iterations).await;
                quion_shutdown_p50.push(percentile(&samples, 50) as f64);
                quion_shutdown_p99.push(percentile(&samples, 99) as f64);
            }
            if stack.includes_quinn() {
                let samples = quinn_shutdown_trial(&identity, config.shutdown_iterations).await;
                quinn_shutdown_p50.push(percentile(&samples, 50) as f64);
                quinn_shutdown_p99.push(percentile(&samples, 99) as f64);
            }
        }

        if scenario.includes(ScenarioSelection::StreamEcho) {
            if diagnostics {
                eprintln!("running stream echo trials");
            }
            if stack.includes_quion() {
                let trial =
                    quion_echo_trial(&identity, config.echo_warmup, config.echo_iterations).await;
                quion_echo_p50.push(percentile(&trial.samples, 50) as f64);
                quion_echo_p99.push(percentile(&trial.samples, 99) as f64);
                quion_echo_allocations.push(trial.allocations.count as f64);
                quion_echo_allocated_bytes.push(trial.allocations.bytes as f64);
            }
            if stack.includes_quinn() {
                let trial =
                    quinn_echo_trial(&identity, config.echo_warmup, config.echo_iterations).await;
                quinn_echo_p50.push(percentile(&trial.samples, 50) as f64);
                quinn_echo_p99.push(percentile(&trial.samples, 99) as f64);
                quinn_echo_allocations.push(trial.allocations.count as f64);
                quinn_echo_allocated_bytes.push(trial.allocations.bytes as f64);
            }
        }

        if scenario.includes(ScenarioSelection::BulkStream) {
            if diagnostics {
                eprintln!("running bulk stream trials");
            }
            if stack.includes_quion() {
                let trial = quion_bulk_trial(&identity, config.bulk_bytes).await;
                quion_bulk_seconds.push(trial.elapsed.as_secs_f64());
                quion_bulk_allocations.push(trial.allocations.count as f64);
                quion_bulk_allocated_bytes.push(trial.allocations.bytes as f64);
            }
            if stack.includes_quinn() {
                let trial = quinn_bulk_trial(&identity, config.bulk_bytes).await;
                quinn_bulk_seconds.push(trial.elapsed.as_secs_f64());
                quinn_bulk_allocations.push(trial.allocations.count as f64);
                quinn_bulk_allocated_bytes.push(trial.allocations.bytes as f64);
            }
        }

        if scenario.includes(ScenarioSelection::ManyStreams) {
            if diagnostics {
                eprintln!("running many-stream trials");
            }
            if stack.includes_quion() {
                let trial = quion_many_streams_trial(&identity, config.many_streams).await;
                quion_many_stream_seconds.push(trial.elapsed.as_secs_f64());
                quion_many_stream_allocations.push(trial.allocations.count as f64);
                quion_many_stream_allocated_bytes.push(trial.allocations.bytes as f64);
            }
            if stack.includes_quinn() {
                let trial = quinn_many_streams_trial(&identity, config.many_streams).await;
                quinn_many_stream_seconds.push(trial.elapsed.as_secs_f64());
                quinn_many_stream_allocations.push(trial.allocations.count as f64);
                quinn_many_stream_allocated_bytes.push(trial.allocations.bytes as f64);
            }
        }

        if scenario.includes(ScenarioSelection::ActiveStreams) {
            if diagnostics {
                eprintln!("running active-stream trials");
            }
            if stack.includes_quion() {
                let trial = quion_active_streams_trial(
                    &identity,
                    config.active_stream_warmup,
                    config.active_streams,
                )
                .await;
                quion_active_stream_seconds.push(trial.elapsed.as_secs_f64());
                quion_active_stream_allocations.push(trial.allocations.count as f64);
                quion_active_stream_allocated_bytes.push(trial.allocations.bytes as f64);
                quion_active_stream_live_bytes.push(trial.allocations.live_bytes as f64);
            }
            if stack.includes_quinn() {
                let trial = quinn_active_streams_trial(
                    &identity,
                    config.active_stream_warmup,
                    config.active_streams,
                )
                .await;
                quinn_active_stream_seconds.push(trial.elapsed.as_secs_f64());
                quinn_active_stream_allocations.push(trial.allocations.count as f64);
                quinn_active_stream_allocated_bytes.push(trial.allocations.bytes as f64);
                quinn_active_stream_live_bytes.push(trial.allocations.live_bytes as f64);
            }
        }

        if scenario.includes(ScenarioSelection::ShortConnections) {
            if diagnostics {
                eprintln!("running short-connection trials");
            }
            if stack.includes_quion() {
                let trial =
                    quion_short_connections_trial(&identity, config.short_connections).await;
                quion_short_connection_seconds.push(trial.elapsed.as_secs_f64());
                quion_short_connection_allocations.push(trial.allocations.count as f64);
                quion_short_connection_allocated_bytes.push(trial.allocations.bytes as f64);
                quion_short_connection_live_bytes.push(trial.allocations.live_bytes as f64);
            }
            if stack.includes_quinn() {
                let trial =
                    quinn_short_connections_trial(&identity, config.short_connections).await;
                quinn_short_connection_seconds.push(trial.elapsed.as_secs_f64());
                quinn_short_connection_allocations.push(trial.allocations.count as f64);
                quinn_short_connection_allocated_bytes.push(trial.allocations.bytes as f64);
                quinn_short_connection_live_bytes.push(trial.allocations.live_bytes as f64);
            }
        }

        if scenario.includes(ScenarioSelection::Datagram) {
            if diagnostics {
                eprintln!("running datagram trials");
            }
            if stack.includes_quion() {
                let trial = quion_datagram_trial(&identity, config.datagrams).await;
                quion_datagram_seconds.push(trial.elapsed.as_secs_f64());
                quion_datagram_allocations.push(trial.allocations.count as f64);
                quion_datagram_allocated_bytes.push(trial.allocations.bytes as f64);
            }
            if stack.includes_quinn() {
                let trial = quinn_datagram_trial(&identity, config.datagrams).await;
                quinn_datagram_seconds.push(trial.elapsed.as_secs_f64());
                quinn_datagram_allocations.push(trial.allocations.count as f64);
                quinn_datagram_allocated_bytes.push(trial.allocations.bytes as f64);
            }
        }

        if scenario.includes(ScenarioSelection::IdleConnections) {
            if diagnostics {
                eprintln!("running idle connection trials");
            }
            if stack.includes_quion() {
                let trial = quion_idle_connection_trial(
                    &identity,
                    config.idle_connection_warmup,
                    config.idle_connections,
                )
                .await;
                quion_idle_allocations.push(trial.allocations.count as f64);
                quion_idle_live_bytes.push(trial.allocations.live_bytes as f64);
            }
            if stack.includes_quinn() {
                let trial = quinn_idle_connection_trial(
                    &identity,
                    config.idle_connection_warmup,
                    config.idle_connections,
                )
                .await;
                quinn_idle_allocations.push(trial.allocations.count as f64);
                quinn_idle_live_bytes.push(trial.allocations.live_bytes as f64);
            }
        }

        if scenario.includes(ScenarioSelection::Recovery) {
            if diagnostics {
                eprintln!("running recovery trials");
            }
            if stack.includes_quion() {
                let trial = quion_recovery_trial(
                    &identity,
                    config.recovery_bytes,
                    config.recovery_loss_interval,
                    config.recovery_reorder_interval,
                )
                .await;
                quion_recovery_seconds.push(trial.elapsed.as_secs_f64());
                quion_recovery_allocations.push(trial.allocations.count as f64);
                quion_recovery_allocated_bytes.push(trial.allocations.bytes as f64);
                quion_recovery_lost_packets.push(trial.declared_lost_packets as f64);
                quion_recovery_injected_drops.push(trial.injected_drops as f64);
                quion_recovery_reordered_datagrams.push(trial.reordered_datagrams as f64);
            }
            if stack.includes_quinn() {
                let trial = quinn_recovery_trial(
                    &identity,
                    config.recovery_bytes,
                    config.recovery_loss_interval,
                    config.recovery_reorder_interval,
                )
                .await;
                quinn_recovery_seconds.push(trial.elapsed.as_secs_f64());
                quinn_recovery_allocations.push(trial.allocations.count as f64);
                quinn_recovery_allocated_bytes.push(trial.allocations.bytes as f64);
                quinn_recovery_lost_packets.push(trial.declared_lost_packets as f64);
                quinn_recovery_injected_drops.push(trial.injected_drops as f64);
                quinn_recovery_reordered_datagrams.push(trial.reordered_datagrams as f64);
            }
        }

        #[cfg(tokio_unstable)]
        if scenario.includes(ScenarioSelection::RuntimeCost) {
            if diagnostics {
                eprintln!("running runtime-cost trials");
            }
            if stack.includes_quion() {
                let trial = quion_runtime_trial(
                    &identity,
                    config.runtime_warmup_bytes,
                    config.runtime_bytes,
                )
                .await;
                quion_runtime_seconds.push(trial.elapsed.as_secs_f64());
                quion_runtime_worker_busy_seconds.push(trial.worker_busy.as_secs_f64());
                quion_runtime_task_polls.push(trial.task_polls as f64);
                quion_runtime_task_schedules.push(trial.task_schedules as f64);
            }
            if stack.includes_quinn() {
                let trial = quinn_runtime_trial(
                    &identity,
                    config.runtime_warmup_bytes,
                    config.runtime_bytes,
                )
                .await;
                quinn_runtime_seconds.push(trial.elapsed.as_secs_f64());
                quinn_runtime_worker_busy_seconds.push(trial.worker_busy.as_secs_f64());
                quinn_runtime_task_polls.push(trial.task_polls as f64);
                quinn_runtime_task_schedules.push(trial.task_schedules as f64);
            }
        }
    }

    if scenario.includes(ScenarioSelection::Handshake) {
        if stack.includes_quion() {
            report_latency(
                "handshake",
                "quion",
                config.handshake_iterations,
                &mut quion_handshake_p50,
                &mut quion_handshake_p99,
            );
        }
        if stack.includes_quinn() {
            report_latency(
                "handshake",
                "quinn",
                config.handshake_iterations,
                &mut quinn_handshake_p50,
                &mut quinn_handshake_p99,
            );
        }
    }
    if scenario.includes(ScenarioSelection::EndpointShutdown) {
        if stack.includes_quion() {
            report_latency(
                "endpoint-shutdown",
                "quion",
                config.shutdown_iterations,
                &mut quion_shutdown_p50,
                &mut quion_shutdown_p99,
            );
        }
        if stack.includes_quinn() {
            report_latency(
                "endpoint-shutdown",
                "quinn",
                config.shutdown_iterations,
                &mut quinn_shutdown_p50,
                &mut quinn_shutdown_p99,
            );
        }
    }
    if scenario.includes(ScenarioSelection::StreamEcho) {
        if stack.includes_quion() {
            report_latency(
                "stream-echo",
                "quion",
                config.echo_iterations,
                &mut quion_echo_p50,
                &mut quion_echo_p99,
            );
            report_allocations(
                "stream-echo",
                "quion",
                config.echo_iterations,
                config.echo_iterations * STREAM_ECHO_PAYLOAD.len() * 2,
                &mut quion_echo_allocations,
                &mut quion_echo_allocated_bytes,
            );
        }
        if stack.includes_quinn() {
            report_latency(
                "stream-echo",
                "quinn",
                config.echo_iterations,
                &mut quinn_echo_p50,
                &mut quinn_echo_p99,
            );
            report_allocations(
                "stream-echo",
                "quinn",
                config.echo_iterations,
                config.echo_iterations * STREAM_ECHO_PAYLOAD.len() * 2,
                &mut quinn_echo_allocations,
                &mut quinn_echo_allocated_bytes,
            );
        }
    }
    if scenario.includes(ScenarioSelection::BulkStream) {
        if stack.includes_quion() {
            report_rate(
                "bulk-stream",
                "quion",
                1,
                config.bulk_bytes,
                &mut quion_bulk_seconds,
            );
            report_allocations(
                "bulk-stream",
                "quion",
                1,
                config.bulk_bytes,
                &mut quion_bulk_allocations,
                &mut quion_bulk_allocated_bytes,
            );
        }
        if stack.includes_quinn() {
            report_rate(
                "bulk-stream",
                "quinn",
                1,
                config.bulk_bytes,
                &mut quinn_bulk_seconds,
            );
            report_allocations(
                "bulk-stream",
                "quinn",
                1,
                config.bulk_bytes,
                &mut quinn_bulk_allocations,
                &mut quinn_bulk_allocated_bytes,
            );
        }
    }
    if scenario.includes(ScenarioSelection::ManyStreams) {
        let bytes_per_trial = config.many_streams * MANY_STREAM_PAYLOAD_BYTES * 2;
        if stack.includes_quion() {
            report_rate(
                "many-streams",
                "quion",
                config.many_streams,
                bytes_per_trial,
                &mut quion_many_stream_seconds,
            );
            report_allocations(
                "many-streams",
                "quion",
                config.many_streams,
                bytes_per_trial,
                &mut quion_many_stream_allocations,
                &mut quion_many_stream_allocated_bytes,
            );
        }
        if stack.includes_quinn() {
            report_rate(
                "many-streams",
                "quinn",
                config.many_streams,
                bytes_per_trial,
                &mut quinn_many_stream_seconds,
            );
            report_allocations(
                "many-streams",
                "quinn",
                config.many_streams,
                bytes_per_trial,
                &mut quinn_many_stream_allocations,
                &mut quinn_many_stream_allocated_bytes,
            );
        }
    }
    if scenario.includes(ScenarioSelection::ActiveStreams) {
        let bytes_per_trial = config.active_streams * MANY_STREAM_PAYLOAD_BYTES;
        if stack.includes_quion() {
            report_rate(
                "active-streams",
                "quion",
                config.active_streams,
                bytes_per_trial,
                &mut quion_active_stream_seconds,
            );
            report_allocations(
                "active-streams",
                "quion",
                config.active_streams,
                bytes_per_trial,
                &mut quion_active_stream_allocations,
                &mut quion_active_stream_allocated_bytes,
            );
            report_retained_bytes(
                "active-streams",
                "quion",
                config.active_streams,
                &mut quion_active_stream_live_bytes,
            );
        }
        if stack.includes_quinn() {
            report_rate(
                "active-streams",
                "quinn",
                config.active_streams,
                bytes_per_trial,
                &mut quinn_active_stream_seconds,
            );
            report_allocations(
                "active-streams",
                "quinn",
                config.active_streams,
                bytes_per_trial,
                &mut quinn_active_stream_allocations,
                &mut quinn_active_stream_allocated_bytes,
            );
            report_retained_bytes(
                "active-streams",
                "quinn",
                config.active_streams,
                &mut quinn_active_stream_live_bytes,
            );
        }
    }
    if scenario.includes(ScenarioSelection::ShortConnections) {
        let bytes_per_trial = config.short_connections * STREAM_ECHO_PAYLOAD.len() * 2;
        if stack.includes_quion() {
            report_rate(
                "short-connections",
                "quion",
                config.short_connections,
                bytes_per_trial,
                &mut quion_short_connection_seconds,
            );
            report_allocations(
                "short-connections",
                "quion",
                config.short_connections,
                bytes_per_trial,
                &mut quion_short_connection_allocations,
                &mut quion_short_connection_allocated_bytes,
            );
            report_retained_bytes(
                "short-connections",
                "quion",
                config.short_connections,
                &mut quion_short_connection_live_bytes,
            );
        }
        if stack.includes_quinn() {
            report_rate(
                "short-connections",
                "quinn",
                config.short_connections,
                bytes_per_trial,
                &mut quinn_short_connection_seconds,
            );
            report_allocations(
                "short-connections",
                "quinn",
                config.short_connections,
                bytes_per_trial,
                &mut quinn_short_connection_allocations,
                &mut quinn_short_connection_allocated_bytes,
            );
            report_retained_bytes(
                "short-connections",
                "quinn",
                config.short_connections,
                &mut quinn_short_connection_live_bytes,
            );
        }
    }
    if scenario.includes(ScenarioSelection::Datagram) {
        if stack.includes_quion() {
            report_rate(
                "datagram",
                "quion",
                config.datagrams,
                config.datagrams * DATAGRAM_PAYLOAD_BYTES,
                &mut quion_datagram_seconds,
            );
            report_allocations(
                "datagram",
                "quion",
                config.datagrams,
                config.datagrams * DATAGRAM_PAYLOAD_BYTES,
                &mut quion_datagram_allocations,
                &mut quion_datagram_allocated_bytes,
            );
        }
        if stack.includes_quinn() {
            report_rate(
                "datagram",
                "quinn",
                config.datagrams,
                config.datagrams * DATAGRAM_PAYLOAD_BYTES,
                &mut quinn_datagram_seconds,
            );
            report_allocations(
                "datagram",
                "quinn",
                config.datagrams,
                config.datagrams * DATAGRAM_PAYLOAD_BYTES,
                &mut quinn_datagram_allocations,
                &mut quinn_datagram_allocated_bytes,
            );
        }
    }
    if scenario.includes(ScenarioSelection::IdleConnections) {
        if stack.includes_quion() {
            report_idle_connections(
                "quion",
                config.idle_connections,
                &mut quion_idle_allocations,
                &mut quion_idle_live_bytes,
            );
        }
        if stack.includes_quinn() {
            report_idle_connections(
                "quinn",
                config.idle_connections,
                &mut quinn_idle_allocations,
                &mut quinn_idle_live_bytes,
            );
        }
    }
    if scenario.includes(ScenarioSelection::Recovery) {
        let bytes_per_trial = config.recovery_bytes.saturating_mul(2);
        if stack.includes_quion() {
            report_recovery(
                "quion",
                &config,
                &mut quion_recovery_seconds,
                &mut quion_recovery_lost_packets,
                &mut quion_recovery_injected_drops,
                &mut quion_recovery_reordered_datagrams,
            );
            report_allocations(
                "recovery",
                "quion",
                1,
                bytes_per_trial,
                &mut quion_recovery_allocations,
                &mut quion_recovery_allocated_bytes,
            );
        }
        if stack.includes_quinn() {
            report_recovery(
                "quinn",
                &config,
                &mut quinn_recovery_seconds,
                &mut quinn_recovery_lost_packets,
                &mut quinn_recovery_injected_drops,
                &mut quinn_recovery_reordered_datagrams,
            );
            report_allocations(
                "recovery",
                "quinn",
                1,
                bytes_per_trial,
                &mut quinn_recovery_allocations,
                &mut quinn_recovery_allocated_bytes,
            );
        }
    }
    #[cfg(tokio_unstable)]
    if scenario.includes(ScenarioSelection::RuntimeCost) {
        if stack.includes_quion() {
            report_runtime_cost(
                "quion",
                config.runtime_bytes,
                &mut quion_runtime_seconds,
                &mut quion_runtime_worker_busy_seconds,
                &mut quion_runtime_task_polls,
                &mut quion_runtime_task_schedules,
            );
        }
        if stack.includes_quinn() {
            report_runtime_cost(
                "quinn",
                config.runtime_bytes,
                &mut quinn_runtime_seconds,
                &mut quinn_runtime_worker_busy_seconds,
                &mut quinn_runtime_task_polls,
                &mut quinn_runtime_task_schedules,
            );
        }
    }
}
