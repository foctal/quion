#![cfg(all(
    feature = "runtime-tokio",
    feature = "rustls-ring",
    feature = "datagram"
))]

use std::{
    fs,
    future::Future,
    path::PathBuf,
    sync::{
        Arc, Once,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use quion::{AckFrequencyConfig, ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};

const ALPN: &[u8] = b"quion-quinn-interop";
const TIMEOUT: Duration = Duration::from_secs(10);
static NEXT_CERTIFICATE_ID: AtomicU64 = AtomicU64::new(0);
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();
static INTEROP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(feature = "zero-rtt")]
#[derive(Debug)]
struct ObservedTickets {
    cache: rustls::client::ClientSessionMemoryCache,
    received: tokio::sync::Notify,
}

#[cfg(feature = "zero-rtt")]
impl rustls::client::ClientSessionStore for ObservedTickets {
    fn set_kx_hint(&self, name: rustls::pki_types::ServerName<'static>, group: rustls::NamedGroup) {
        self.cache.set_kx_hint(name, group);
    }
    fn kx_hint(&self, name: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.cache.kx_hint(name)
    }
    fn set_tls12_session(
        &self,
        name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.cache.set_tls12_session(name, value);
    }
    fn tls12_session(
        &self,
        name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.cache.tls12_session(name)
    }
    fn remove_tls12_session(&self, name: &rustls::pki_types::ServerName<'static>) {
        self.cache.remove_tls12_session(name);
    }
    fn insert_tls13_ticket(
        &self,
        name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.cache.insert_tls13_ticket(name, value);
        self.received.notify_one();
    }
    fn take_tls13_ticket(
        &self,
        name: &rustls::pki_types::ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.cache.take_tls13_ticket(name)
    }
}

#[cfg(feature = "zero-rtt")]
fn observed_resumption_config(
    identity: &TestIdentity,
) -> (rustls::ClientConfig, Arc<ObservedTickets>) {
    let mut roots = RootCertStore::empty();
    roots.add(identity.certificate.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tickets = Arc::new(ObservedTickets {
        cache: rustls::client::ClientSessionMemoryCache::new(16),
        received: tokio::sync::Notify::new(),
    });
    tls.resumption = rustls::client::Resumption::store(tickets.clone());
    (tls, tickets)
}

fn install_crypto_provider() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct TestIdentity {
    certificate: CertificateDer<'static>,
    private_key: PrivatePkcs8KeyDer<'static>,
    directory: PathBuf,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
}

impl TestIdentity {
    fn generate() -> Self {
        install_crypto_provider();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let unique = NEXT_CERTIFICATE_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "quion-quinn-interop-{}-{stamp}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let certificate_path = directory.join("certificate.pem");
        let private_key_path = directory.join("private-key.pem");
        fs::write(&certificate_path, cert.pem()).unwrap();
        fs::write(&private_key_path, signing_key.serialize_pem()).unwrap();
        Self {
            certificate: cert.der().clone(),
            private_key: PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
            directory,
            certificate_path,
            private_key_path,
        }
    }
}

impl Drop for TestIdentity {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn quion_transport() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .set_max_datagram_frame_size(Some(65_535u32.into()))
        .set_ack_frequency_config(Some(AckFrequencyConfig {
            ack_eliciting_threshold: VarInt::from_u32(9),
            max_ack_delay: None,
            reordering_threshold: VarInt::from_u32(2),
        }));
    transport
}

fn quinn_ack_frequency_transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    let mut ack_frequency = quinn::AckFrequencyConfig::default();
    ack_frequency
        .ack_eliciting_threshold(9u32.into())
        .reordering_threshold(2u32.into());
    transport.ack_frequency_config(Some(ack_frequency));
    Arc::new(transport)
}

fn quinn_server_config(identity: &TestIdentity) -> quinn::ServerConfig {
    quinn_server_config_with_zero_rtt(identity, false)
}

fn quinn_server_config_with_zero_rtt(
    identity: &TestIdentity,
    accept_zero_rtt: bool,
) -> quinn::ServerConfig {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.certificate.clone()],
            identity.private_key.clone_key().into(),
        )
        .unwrap();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.max_early_data_size = if accept_zero_rtt { u32::MAX } else { 0 };
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(quinn_ack_frequency_transport());
    config
}

fn quinn_client_config(identity: &TestIdentity) -> quinn::ClientConfig {
    quinn_client_config_with_zero_rtt(identity, false)
}

fn quinn_client_config_with_zero_rtt(
    identity: &TestIdentity,
    enable_zero_rtt: bool,
) -> quinn::ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(identity.certificate.clone()).unwrap();
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.enable_early_data = enable_zero_rtt;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(quinn_ack_frequency_transport());
    config
}

fn quinn_idle_transport(timeout: Duration) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(timeout.try_into().unwrap()));
    Arc::new(transport)
}

async fn timeout<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("interoperability operation timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quion_client_interoperates_with_quinn_server() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let quinn_server = quinn::Endpoint::server(
        quinn_server_config(&identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_address = quinn_server.local_addr().unwrap();
    let quinn_server_endpoint = quinn_server.clone();
    let server_task = tokio::spawn(async move {
        let quinn_connection = timeout(quinn_server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed")
            .await
            .unwrap();
        let (mut send, mut recv) = timeout(quinn_connection.accept_bi()).await.unwrap();
        let request = timeout(recv.read_to_end(4096)).await.unwrap();
        assert_eq!(request, b"quion-to-quinn");
        timeout(send.write_all(b"quinn-to-quion")).await.unwrap();
        send.finish().unwrap();

        let datagram = timeout(quinn_connection.read_datagram()).await.unwrap();
        assert_eq!(datagram.as_ref(), b"quion-datagram");
        quinn_connection
            .send_datagram(b"quinn-datagram".as_slice().into())
            .unwrap();
        quinn_connection
    });

    let quion_client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quion_client.set_default_client_config(
        ClientConfig::builder()
            .with_root_certificates_from_pem_file(&identity.certificate_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(quion_transport())
            .build(),
    );

    let quion_connect = tokio::time::timeout(
        TIMEOUT,
        quion_client.connect(server_address, "localhost").unwrap(),
    )
    .await;
    let quion_connection = match quion_connect {
        Ok(result) => result.unwrap(),
        Err(error) => panic!(
            "quion client timed out: {error}; quion={:?}; quinn={:?}",
            quion_client.diagnostics(),
            quinn_server.stats()
        ),
    };
    let (mut send, mut recv) = timeout(quion_connection.open_bi()).await.unwrap();
    timeout(send.write_all(b"quion-to-quinn")).await.unwrap();
    send.finish().unwrap();
    assert_eq!(
        timeout(recv.read_to_end(4096)).await.unwrap(),
        b"quinn-to-quion"
    );

    quion_connection
        .send_datagram(b"quion-datagram".to_vec())
        .unwrap();
    assert_eq!(
        timeout(quion_connection.read_datagram()).await.unwrap(),
        b"quinn-datagram"
    );
    let quinn_connection = timeout(server_task).await.unwrap();
    assert!(
        quinn_connection.stats().frame_rx.ack_frequency > 0,
        "Quinn did not receive quion's ACK_FREQUENCY request"
    );

    quion_client.abort();
    quinn_server.close(0u32.into(), b"test complete");
    quinn_server.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quion_client_interoperates_with_quinn_server_retry() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let quinn_server = quinn::Endpoint::server(
        quinn_server_config(&identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_address = quinn_server.local_addr().unwrap();
    let server_endpoint = quinn_server.clone();
    let server_task = tokio::spawn(async move {
        let first = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed");
        assert!(!first.remote_address_validated());
        assert!(first.may_retry());
        let original_destination_cid = first.orig_dst_cid();
        first.retry().unwrap();

        let retried = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed");
        assert!(retried.remote_address_validated());
        assert_eq!(retried.orig_dst_cid(), original_destination_cid);
        let connection = retried.await.unwrap();
        let (mut send, mut recv) = timeout(connection.accept_bi()).await.unwrap();
        let request = timeout(recv.read_to_end(64)).await.unwrap();
        assert_eq!(request, b"quion-retry");
        timeout(send.write_all(b"quinn-retry")).await.unwrap();
        send.finish().unwrap();
        connection
    });

    let quion_client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quion_client.set_default_client_config(
        ClientConfig::builder()
            .with_root_certificates_from_pem_file(&identity.certificate_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .build(),
    );
    let connection = timeout(quion_client.connect(server_address, "localhost").unwrap())
        .await
        .unwrap();
    let (mut send, mut recv) = timeout(connection.open_bi()).await.unwrap();
    timeout(send.write_all(b"quion-retry")).await.unwrap();
    send.finish().unwrap();
    assert_eq!(timeout(recv.read_to_end(64)).await.unwrap(), b"quinn-retry");
    let _server_connection = timeout(server_task).await.unwrap();

    connection.abort();
    quion_client.abort();
    quinn_server.close(0u32.into(), b"test complete");
    quinn_server.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quinn_client_interoperates_with_quion_server() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let server_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut transport = quion_transport();
    let event_sink = server_events.clone();
    transport.set_qlog_handler(move |event| {
        event_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event.clone());
    });
    let quion_server = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&identity.certificate_path, &identity.private_key_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(transport)
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let quion_driver = quion_server
        .spawn_default_server_udp_driver(65_535)
        .unwrap();

    let mut quinn_client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quinn_client.set_default_client_config(quinn_client_config(&identity));
    let quinn_connect = tokio::time::timeout(
        TIMEOUT,
        quinn_client
            .connect(quion_server.local_addr(), "localhost")
            .unwrap(),
    )
    .await;
    let quinn_connection = match quinn_connect {
        Ok(result) => result.unwrap(),
        Err(error) => {
            quion_server.abort();
            let driver_result = quion_driver.stop().await;
            panic!(
                "Quinn client timed out: {error}; quinn={:?}; quion={:?}; driver={driver_result:?}",
                quinn_client.stats(),
                quion_server.diagnostics()
            )
        }
    };
    let quion_connection = timeout(async {
        quion_server
            .accept()
            .await
            .expect("quion endpoint closed")
            .await
    })
    .await
    .unwrap();

    let server_connection = quion_connection.clone();
    let server_task = tokio::spawn(async move {
        let (mut send, mut recv) = timeout(server_connection.accept_bi()).await.unwrap();
        let request = timeout(recv.read_to_end(4096)).await.unwrap();
        assert_eq!(request, b"quinn-to-quion");
        timeout(send.write_all(b"quion-to-quinn")).await.unwrap();
        send.finish().unwrap();

        let datagram = timeout(server_connection.read_datagram()).await.unwrap();
        assert_eq!(datagram, b"quinn-datagram");
        server_connection
            .send_datagram(b"quion-datagram".to_vec())
            .unwrap();
    });

    let (mut send, mut recv) = timeout(quinn_connection.open_bi()).await.unwrap();
    timeout(send.write_all(b"quinn-to-quion")).await.unwrap();
    send.finish().unwrap();
    assert_eq!(
        timeout(recv.read_to_end(4096)).await.unwrap(),
        b"quion-to-quinn"
    );

    quinn_connection
        .send_datagram(b"quinn-datagram".as_slice().into())
        .unwrap();
    assert_eq!(
        timeout(quinn_connection.read_datagram())
            .await
            .unwrap()
            .as_ref(),
        b"quion-datagram"
    );
    timeout(server_task).await.unwrap();
    assert!(
        quion_connection
            .diagnostics()
            .stats
            .ack_frequency_frames_received
            > 0,
        "quion did not receive Quinn's ACK_FREQUENCY request"
    );
    assert!(
        server_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|event| matches!(
                event,
                quion::QlogEvent::EndpointStateUpdated {
                    state: "retry_sent",
                    packet_type: "retry",
                }
            ))
    );

    quinn_client.close(0u32.into(), b"test complete");
    quinn_client.wait_idle().await;
    quion_server.abort();
    timeout(quion_driver.stop()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quinn_client_observes_quion_version_negotiation() {
    const DRAFT_VERSION: u32 = 0xff00_001d;

    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let server_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut transport = quion_transport();
    let event_sink = server_events.clone();
    transport.set_qlog_handler(move |event| {
        event_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event.clone());
    });
    let quion_server = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&identity.certificate_path, &identity.private_key_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(transport)
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let quion_driver = quion_server
        .spawn_default_server_udp_driver(65_535)
        .unwrap();

    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.supported_versions(vec![DRAFT_VERSION, 1]);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut quinn_client =
        quinn::Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime)).unwrap();
    let mut client_config = quinn_client_config(&identity);
    client_config.version(DRAFT_VERSION);
    quinn_client.set_default_client_config(client_config);

    let connect_error = timeout(
        quinn_client
            .connect(quion_server.local_addr(), "localhost")
            .unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        connect_error,
        quinn::ConnectionError::VersionMismatch
    ));
    assert!(
        server_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|event| matches!(
                event,
                quion::QlogEvent::EndpointStateUpdated {
                    state: "version_negotiation_sent",
                    packet_type: "version_negotiation",
                }
            ))
    );

    quinn_client.close(0u32.into(), b"test complete");
    quinn_client.wait_idle().await;
    quion_server.abort();
    timeout(quion_driver.stop()).await.unwrap();
}

#[cfg(feature = "zero-rtt")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quinn_client_sends_zero_rtt_to_quion_server() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let server_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut transport = quion_transport();
    transport.set_retry_enabled(false);
    let event_sink = server_events.clone();
    transport.set_qlog_handler(move |event| {
        event_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event.clone());
    });
    let quion_server = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&identity.certificate_path, &identity.private_key_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(transport)
            .with_zero_rtt()
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let quion_driver = quion_server
        .spawn_default_server_udp_driver(65_535)
        .unwrap();

    let mut quinn_client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quinn_client.set_default_client_config(quinn_client_config_with_zero_rtt(&identity, true));

    let first_quinn = timeout(
        quinn_client
            .connect(quion_server.local_addr(), "localhost")
            .unwrap(),
    )
    .await
    .unwrap();
    let first_quion = timeout(async {
        quion_server
            .accept()
            .await
            .expect("quion endpoint closed")
            .await
    })
    .await
    .unwrap();

    let mut ticket_signal = timeout(first_quion.open_uni()).await.unwrap();
    timeout(ticket_signal.write_all(b"ticket-ready"))
        .await
        .unwrap();
    ticket_signal.finish().unwrap();
    let mut ticket_signal = timeout(first_quinn.accept_uni()).await.unwrap();
    assert_eq!(
        timeout(ticket_signal.read_to_end(64)).await.unwrap(),
        b"ticket-ready"
    );

    let connecting = quinn_client
        .connect(quion_server.local_addr(), "localhost")
        .unwrap();
    let (resumed_quinn, zero_rtt_accepted) = connecting
        .into_0rtt()
        .unwrap_or_else(|_| panic!("Quinn did not receive a resumption ticket from quion"));
    let mut early_send = timeout(resumed_quinn.open_uni()).await.unwrap();
    timeout(early_send.write_all(b"quinn-zero-rtt"))
        .await
        .unwrap();
    early_send.finish().unwrap();

    let resumed_incoming = match tokio::time::timeout(TIMEOUT, quion_server.accept()).await {
        Ok(incoming) => incoming.expect("quion endpoint closed"),
        Err(error) => {
            let driver_finished = quion_driver.is_finished();
            let driver_result = quion_driver.stop().await;
            panic!(
                "resumed quion server accept timed out: {error}; driver_finished={driver_finished}; driver_result={driver_result:?}; quion={:?}; quinn={:?}; events={:?}",
                quion_server.diagnostics(),
                resumed_quinn.stats(),
                server_events
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            )
        }
    };
    let resumed_quion = match tokio::time::timeout(TIMEOUT, resumed_incoming).await {
        Ok(result) => result.unwrap(),
        Err(error) => panic!(
            "resumed quion server handshake timed out: {error}; quion={:?}; quinn={:?}",
            quion_server.diagnostics(),
            resumed_quinn.stats()
        ),
    };
    let mut early_recv = timeout(resumed_quion.accept_uni()).await.unwrap();
    assert_eq!(
        timeout(early_recv.read_to_end(64)).await.unwrap(),
        b"quinn-zero-rtt"
    );
    assert!(timeout(zero_rtt_accepted).await);
    assert_eq!(
        resumed_quion.zero_rtt_status(),
        quion::ZeroRttStatus::Accepted
    );

    first_quinn.close(0u32.into(), b"test complete");
    first_quion.abort();
    resumed_quinn.close(0u32.into(), b"test complete");
    resumed_quion.abort();
    quinn_client.close(0u32.into(), b"test complete");
    quinn_client.wait_idle().await;
    quion_server.abort();
    timeout(quion_driver.stop()).await.unwrap();
}

#[cfg(feature = "zero-rtt")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quion_client_sends_zero_rtt_to_quinn_server() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let quinn_server = quinn::Endpoint::server(
        quinn_server_config_with_zero_rtt(&identity, true),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_address = quinn_server.local_addr().unwrap();
    let server_endpoint = quinn_server.clone();
    let server_task = tokio::spawn(async move {
        let first = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed")
            .await
            .unwrap();
        let mut ticket_signal = timeout(first.open_uni()).await.unwrap();
        timeout(ticket_signal.write_all(b"ticket-ready"))
            .await
            .unwrap();
        ticket_signal.finish().unwrap();

        let resumed = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed")
            .await
            .unwrap();
        let mut early_recv = timeout(resumed.accept_uni()).await.unwrap();
        assert_eq!(
            timeout(early_recv.read_to_end(64)).await.unwrap(),
            b"quion-zero-rtt"
        );
        (first, resumed)
    });

    let client_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut transport = quion_transport();
    let event_sink = client_events.clone();
    transport.set_qlog_handler(move |event| {
        event_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event.clone());
    });
    let (tls, tickets) = observed_resumption_config(&identity);
    let quion_client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quion_client.set_default_client_config(
        ClientConfig::builder()
            .with_rustls_config(tls)
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(transport)
            .with_zero_rtt()
            .build(),
    );

    let first = timeout(quion_client.connect(server_address, "localhost").unwrap())
        .await
        .unwrap();
    let mut ticket_signal = timeout(first.accept_uni()).await.unwrap();
    assert_eq!(
        timeout(ticket_signal.read_to_end(64)).await.unwrap(),
        b"ticket-ready"
    );

    // STREAM and post-handshake CRYPTO delivery are independently ordered.
    // An application message cannot prove that a TLS ticket has been stored.
    timeout(tickets.received.notified()).await;
    let connecting = quion_client.connect(server_address, "localhost").unwrap();
    let (resumed, zero_rtt_accepted) = connecting
        .into_0rtt()
        .unwrap_or_else(|_| panic!("quion did not receive a resumption ticket from Quinn"));
    let mut early_send = timeout(resumed.open_uni()).await.unwrap();
    timeout(early_send.write_all(b"quion-zero-rtt"))
        .await
        .unwrap();
    early_send.finish().unwrap();

    assert!(timeout(zero_rtt_accepted).await.unwrap());
    assert_eq!(resumed.zero_rtt_status(), quion::ZeroRttStatus::Accepted);
    let (first_quinn, resumed_quinn) = timeout(server_task).await.unwrap();
    assert!(
        client_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|event| matches!(
                event,
                quion::QlogEvent::PacketSent {
                    level: "0rtt",
                    frame_type: "stream",
                    ..
                }
            ))
    );

    first.abort();
    resumed.abort();
    first_quinn.close(0u32.into(), b"test complete");
    resumed_quinn.close(0u32.into(), b"test complete");
    quion_client.abort();
    quinn_server.close(0u32.into(), b"test complete");
    quinn_server.wait_idle().await;
}

#[cfg(feature = "zero-rtt")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quion_client_requeues_zero_rtt_stream_after_quinn_retry() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let quinn_server = quinn::Endpoint::server(
        quinn_server_config_with_zero_rtt(&identity, true),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_address = quinn_server.local_addr().unwrap();
    let server_endpoint = quinn_server.clone();
    let server_task = tokio::spawn(async move {
        let first = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed")
            .await
            .unwrap();
        let mut ticket_signal = timeout(first.open_uni()).await.unwrap();
        timeout(ticket_signal.write_all(b"ticket-ready"))
            .await
            .unwrap();
        ticket_signal.finish().unwrap();

        let early = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed");
        assert!(early.may_retry());
        early.retry().unwrap();

        let retried = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed");
        assert!(retried.remote_address_validated());
        let resumed = retried.await.unwrap();
        let mut replayed_recv = timeout(resumed.accept_uni()).await.unwrap();
        assert_eq!(
            timeout(replayed_recv.read_to_end(64)).await.unwrap(),
            b"replay-safe-zero-rtt"
        );
        (first, resumed)
    });

    let (tls, tickets) = observed_resumption_config(&identity);
    let quion_client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quion_client.set_default_client_config(
        ClientConfig::builder()
            .with_rustls_config(tls)
            .with_alpn_protocols([ALPN.to_vec()])
            .with_zero_rtt()
            .build(),
    );
    let first = timeout(quion_client.connect(server_address, "localhost").unwrap())
        .await
        .unwrap();
    let mut ticket_signal = timeout(first.accept_uni()).await.unwrap();
    assert_eq!(
        timeout(ticket_signal.read_to_end(64)).await.unwrap(),
        b"ticket-ready"
    );

    // STREAM and post-handshake CRYPTO delivery are independently ordered.
    // An application message cannot prove that a TLS ticket has been stored.
    timeout(tickets.received.notified()).await;
    let connecting = quion_client.connect(server_address, "localhost").unwrap();
    let (resumed, zero_rtt_accepted) = connecting
        .into_0rtt()
        .unwrap_or_else(|_| panic!("quion did not receive a resumption ticket from Quinn"));
    let mut early_send = timeout(resumed.open_uni()).await.unwrap();
    timeout(early_send.write_all(b"replay-safe-zero-rtt"))
        .await
        .unwrap();
    early_send.finish().unwrap();

    assert!(!timeout(zero_rtt_accepted).await.unwrap());
    assert_eq!(resumed.zero_rtt_status(), quion::ZeroRttStatus::Rejected);
    let (first_quinn, resumed_quinn) = timeout(server_task).await.unwrap();

    first.abort();
    resumed.abort();
    first_quinn.close(0u32.into(), b"test complete");
    resumed_quinn.close(0u32.into(), b"test complete");
    quion_client.abort();
    quinn_server.close(0u32.into(), b"test complete");
    quinn_server.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quion_application_close_is_observed_by_quinn() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let quinn_server = quinn::Endpoint::server(
        quinn_server_config(&identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_address = quinn_server.local_addr().unwrap();
    let server_endpoint = quinn_server.clone();
    let server_task = tokio::spawn(async move {
        let connection = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed")
            .await
            .unwrap();
        timeout(connection.closed()).await
    });

    let quion_client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quion_client.set_default_client_config(
        ClientConfig::builder()
            .with_root_certificates_from_pem_file(&identity.certificate_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .build(),
    );
    let connection = timeout(quion_client.connect(server_address, "localhost").unwrap())
        .await
        .unwrap();
    connection.close(quion::VarInt::from_u32(42), b"quion shutdown");

    match timeout(server_task).await.unwrap() {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code, 42u32.into());
            assert_eq!(close.reason.as_ref(), b"quion shutdown");
        }
        error => panic!("unexpected Quinn close error: {error:?}"),
    }

    quion_client.abort();
    quinn_server.close(0u32.into(), b"test complete");
    quinn_server.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quinn_application_close_is_observed_by_quion() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let identity = TestIdentity::generate();
    let quion_server = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&identity.certificate_path, &identity.private_key_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let quion_driver = quion_server
        .spawn_default_server_udp_driver(65_535)
        .unwrap();

    let mut quinn_client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quinn_client.set_default_client_config(quinn_client_config(&identity));
    let quinn_connection = timeout(
        quinn_client
            .connect(quion_server.local_addr(), "localhost")
            .unwrap(),
    )
    .await
    .unwrap();
    let quion_connection = timeout(async {
        quion_server
            .accept()
            .await
            .expect("quion endpoint closed")
            .await
    })
    .await
    .unwrap();

    quinn_connection.close(73u32.into(), b"quinn shutdown");
    assert_eq!(
        timeout(quion_connection.closed()).await,
        quion::ConnectionError::ApplicationClosed {
            code: quion::VarInt::from_u32(73),
            reason: "quinn shutdown".to_string(),
        }
    );

    quinn_client.close(0u32.into(), b"test complete");
    quinn_client.wait_idle().await;
    quion_server.abort();
    timeout(quion_driver.stop()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_live_connections_interoperate_in_both_roles() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    const CONNECTIONS: usize = 4;

    let identity = TestIdentity::generate();
    let quinn_server = quinn::Endpoint::server(
        quinn_server_config(&identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server_endpoint = quinn_server.clone();
    let server_task = tokio::spawn(async move {
        let mut connections = Vec::with_capacity(CONNECTIONS);
        for expected in 0..CONNECTIONS {
            let connection = timeout(server_endpoint.accept())
                .await
                .expect("Quinn endpoint closed")
                .await
                .unwrap();
            let (mut send, mut recv) = timeout(connection.accept_bi()).await.unwrap();
            let payload = timeout(recv.read_to_end(64)).await.unwrap();
            assert_eq!(payload, format!("quion-{expected}").as_bytes());
            timeout(send.write_all(&payload)).await.unwrap();
            send.finish().unwrap();
            connections.push(connection);
        }
        connections
    });

    let quion_client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quion_client.set_default_client_config(
        ClientConfig::builder()
            .with_root_certificates_from_pem_file(&identity.certificate_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .build(),
    );
    let mut quion_connections = Vec::with_capacity(CONNECTIONS);
    for index in 0..CONNECTIONS {
        let connection = timeout(
            quion_client
                .connect(quinn_server.local_addr().unwrap(), "localhost")
                .unwrap(),
        )
        .await
        .unwrap();
        let (mut send, mut recv) = timeout(connection.open_bi()).await.unwrap();
        let payload = format!("quion-{index}");
        timeout(send.write_all(payload.as_bytes())).await.unwrap();
        send.finish().unwrap();
        let response = tokio::time::timeout(TIMEOUT, recv.read_to_end(64)).await;
        let response = match response {
            Ok(response) => response.unwrap(),
            Err(error) => panic!(
                "quion connection {index} response timed out: {error}; connection={:?}; endpoint={:?}; quinn={:?}; server_task_finished={}",
                connection.diagnostics(),
                quion_client.diagnostics(),
                quinn_server.stats(),
                server_task.is_finished()
            ),
        };
        assert_eq!(response, payload.as_bytes());
        quion_connections.push(connection);
    }
    let quinn_server_connections = timeout(server_task).await.unwrap();

    drop(quinn_server_connections);
    for connection in quion_connections {
        connection.abort();
    }
    quion_client.abort();
    quinn_server.close(0u32.into(), b"test complete");
    quinn_server.wait_idle().await;

    let quion_server = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&identity.certificate_path, &identity.private_key_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let quion_driver = quion_server
        .spawn_default_server_udp_driver(65_535)
        .unwrap();
    let mut quinn_client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quinn_client.set_default_client_config(quinn_client_config(&identity));
    let mut quinn_connections = Vec::with_capacity(CONNECTIONS);
    let mut quion_server_connections = Vec::with_capacity(CONNECTIONS);
    for index in 0..CONNECTIONS {
        let connect = tokio::time::timeout(
            TIMEOUT,
            quinn_client
                .connect(quion_server.local_addr(), "localhost")
                .unwrap(),
        )
        .await;
        let quinn_connection = match connect {
            Ok(result) => result.unwrap(),
            Err(error) => panic!(
                "Quinn connection {index} handshake timed out: {error}; quion_endpoint={:?}; quion_driver_finished={}; live_quion_connections={:?}",
                quion_server.diagnostics(),
                quion_driver.is_finished(),
                quion_server_connections
                    .iter()
                    .map(quion::Connection::diagnostics)
                    .collect::<Vec<_>>()
            ),
        };
        let quion_connection = timeout(async {
            quion_server
                .accept()
                .await
                .expect("quion endpoint closed")
                .await
        })
        .await
        .unwrap();
        let server_connection = quion_connection.clone();
        let server_stream = tokio::spawn(async move {
            let (mut send, mut recv) = match tokio::time::timeout(
                TIMEOUT,
                server_connection.accept_bi(),
            )
            .await
            {
                Ok(result) => result.unwrap(),
                Err(error) => panic!(
                    "quion server connection {index} stream accept timed out: {error}; connection={:?}",
                    server_connection.diagnostics()
                ),
            };
            let payload = match tokio::time::timeout(TIMEOUT, recv.read_to_end(64)).await {
                Ok(result) => result.unwrap(),
                Err(error) => panic!(
                    "quion server connection {index} stream read timed out: {error}; connection={:?}",
                    server_connection.diagnostics()
                ),
            };
            timeout(send.write_all(&payload)).await.unwrap();
            send.finish().unwrap();
        });
        let (mut send, mut recv) = timeout(quinn_connection.open_bi()).await.unwrap();
        let payload = format!("quinn-{index}");
        timeout(send.write_all(payload.as_bytes())).await.unwrap();
        send.finish().unwrap();
        let response = tokio::time::timeout(TIMEOUT, recv.read_to_end(64)).await;
        let response = match response {
            Ok(response) => response.unwrap(),
            Err(error) => panic!(
                "Quinn connection {index} response timed out: {error}; quinn={:?}; quion_connection={:?}; quion_endpoint={:?}; quion_driver_finished={}; server_task_finished={}",
                quinn_connection.stats(),
                quion_connection.diagnostics(),
                quion_server.diagnostics(),
                quion_driver.is_finished(),
                server_stream.is_finished()
            ),
        };
        assert_eq!(response, payload.as_bytes());
        timeout(server_stream).await.unwrap();
        quinn_connections.push(quinn_connection);
        quion_server_connections.push(quion_connection);
    }

    drop(quinn_connections);
    for connection in quion_server_connections {
        connection.abort();
    }
    quinn_client.close(0u32.into(), b"test complete");
    quinn_client.wait_idle().await;
    quion_server.abort();
    timeout(quion_driver.stop()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quion_client_and_quinn_server_honor_idle_timeout() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let idle_timeout = Duration::from_millis(200);
    let identity = TestIdentity::generate();
    let mut server_config = quinn_server_config(&identity);
    server_config.transport_config(quinn_idle_transport(idle_timeout));
    let quinn_server =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_endpoint = quinn_server.clone();
    let server_task = tokio::spawn(async move {
        let connection = timeout(server_endpoint.accept())
            .await
            .expect("Quinn endpoint closed")
            .await
            .unwrap();
        timeout(connection.closed()).await
    });

    let mut transport = TransportConfig::default();
    transport.set_max_idle_timeout(quion::VarInt::from_u32(200));
    let quion_client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quion_client.set_default_client_config(
        ClientConfig::builder()
            .with_root_certificates_from_pem_file(&identity.certificate_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(transport)
            .build(),
    );
    let connection = timeout(
        quion_client
            .connect(quinn_server.local_addr().unwrap(), "localhost")
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(
        timeout(connection.closed()).await,
        quion::ConnectionError::TimedOut
    );
    assert!(matches!(
        timeout(server_task).await.unwrap(),
        quinn::ConnectionError::TimedOut
    ));

    quion_client.abort();
    quinn_server.close(0u32.into(), b"test complete");
    quinn_server.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quinn_client_and_quion_server_honor_idle_timeout() {
    let _interop_guard = INTEROP_TEST_LOCK.lock().await;
    let idle_timeout = Duration::from_millis(200);
    let identity = TestIdentity::generate();
    let mut transport = TransportConfig::default();
    transport.set_max_idle_timeout(quion::VarInt::from_u32(200));
    let quion_server = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(&identity.certificate_path, &identity.private_key_path)
            .unwrap()
            .with_alpn_protocols([ALPN.to_vec()])
            .with_transport_config(transport)
            .build()
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let quion_driver = quion_server
        .spawn_default_server_udp_driver(65_535)
        .unwrap();

    let mut client_config = quinn_client_config(&identity);
    client_config.transport_config(quinn_idle_transport(idle_timeout));
    let mut quinn_client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    quinn_client.set_default_client_config(client_config);
    let quinn_connection = timeout(
        quinn_client
            .connect(quion_server.local_addr(), "localhost")
            .unwrap(),
    )
    .await
    .unwrap();
    let quion_connection = timeout(async {
        quion_server
            .accept()
            .await
            .expect("quion endpoint closed")
            .await
    })
    .await
    .unwrap();

    let quinn_error = timeout(quinn_connection.closed()).await;
    assert!(
        matches!(quinn_error, quinn::ConnectionError::TimedOut),
        "unexpected Quinn idle close: {quinn_error:?}; quion={:?}",
        quion_connection.diagnostics()
    );
    assert_eq!(
        timeout(quion_connection.closed()).await,
        quion::ConnectionError::TimedOut
    );

    quinn_client.close(0u32.into(), b"test complete");
    quinn_client.wait_idle().await;
    quion_server.abort();
    timeout(quion_driver.stop()).await.unwrap();
}
