#![cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]

use std::{
    error::Error,
    fs,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use quion::{
    ClientConfig, ConnectionError, Endpoint, QlogEvent, ServerConfig, TransportConfig, VarInt,
};

const ALPN_PROTOCOLS: [&[u8]; 2] = [b"hq-interop", b"http/0.9"];
const H3_ALPN_PROTOCOLS: [&[u8]; 1] = [b"h3"];
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_INTEROP_DATAGRAM_SIZE: u32 = 1_200;

fn required_argument(args: &[String], index: usize, name: &str) -> Result<String, Box<dyn Error>> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("missing {name} argument").into())
}

fn endpoint_event_observer(
    expected_state: &'static str,
    expected_packet_type: &'static str,
) -> (TransportConfig, Arc<AtomicBool>) {
    let observed = Arc::new(AtomicBool::new(false));
    let observer = Arc::clone(&observed);
    let mut transport = TransportConfig::default();
    transport.set_qlog_handler(move |event| {
        if let QlogEvent::EndpointStateUpdated { state, packet_type } = event
            && *state == expected_state
            && *packet_type == expected_packet_type
        {
            observer.store(true, Ordering::Release);
        }
    });
    (transport, observed)
}

fn idle_transport(timeout_ms: u32) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.set_max_idle_timeout(VarInt::from_u32(timeout_ms));
    transport
}

fn datagram_transport() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.set_max_datagram_frame_size(Some(VarInt::from_u32(MAX_INTEROP_DATAGRAM_SIZE)));
    transport
}

fn h3_datagram(flow_id: u8, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if flow_id > 63 {
        return Err("the interop adapter only supports one-byte HTTP/3 flow IDs".into());
    }
    let mut datagram = Vec::with_capacity(payload.len().saturating_add(1));
    datagram.push(flow_id);
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

fn verify_h3_datagram(
    datagram: &[u8],
    expected_flow_id: u8,
    expected_payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let expected = h3_datagram(expected_flow_id, expected_payload)?;
    if datagram != expected {
        return Err(format!(
            "unexpected HTTP/3 DATAGRAM: received={datagram:?}, expected={expected:?}"
        )
        .into());
    }
    Ok(())
}

async fn run_client(
    args: &[String],
    expected_endpoint_event: Option<(&'static str, &'static str)>,
    version_negotiation_probe: bool,
) -> Result<(), Box<dyn Error>> {
    let server_addr: SocketAddr = required_argument(args, 2, "server address")?.parse()?;
    let ca_cert_path = required_argument(args, 3, "CA certificate path")?;
    let output_path = required_argument(args, 4, "output path")?;

    let (transport, endpoint_event_observed) = expected_endpoint_event
        .map(|(state, packet_type)| endpoint_event_observer(state, packet_type))
        .unzip();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(ca_cert_path)?
        .with_alpn_protocols(ALPN_PROTOCOLS.map(<[u8]>::to_vec));
    if let Some(transport) = transport {
        client_config = client_config.with_transport_config(transport);
    }
    if version_negotiation_probe {
        client_config = client_config.with_version_negotiation_probe();
    }
    let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config.build());

    let connection = tokio::time::timeout(
        Duration::from_secs(10),
        endpoint.connect(server_addr, "localhost")?,
    )
    .await
    .map_err(|_| "QUIC handshake timed out")??;
    if endpoint_event_observed
        .as_ref()
        .is_some_and(|observed| !observed.load(Ordering::Acquire))
    {
        let (state, packet_type) =
            expected_endpoint_event.expect("an observer requires an expected endpoint event");
        return Err(
            format!("the quion client completed without observing {state}/{packet_type}").into(),
        );
    }
    let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(10), connection.open_bi())
        .await
        .map_err(|_| "opening a bidirectional stream timed out")??;
    send.write_all(b"GET /quion-interop\r\n").await?;
    send.finish()?;
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        recv.read_to_end(MAX_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| "reading the HTTP/0.9 response timed out")??;
    fs::write(output_path, response)?;

    connection.close(VarInt::from_u32(0x51), b"quion hq interop complete");
    tokio::time::sleep(Duration::from_millis(250)).await;
    endpoint.abort();
    Ok(())
}

#[cfg(feature = "zero-rtt")]
async fn exchange_hq_request(connection: &quion::Connection) -> Result<Vec<u8>, Box<dyn Error>> {
    let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(10), connection.open_bi())
        .await
        .map_err(|_| "opening a bidirectional stream timed out")??;
    send.write_all(b"GET /quion-interop\r\n").await?;
    send.finish()?;
    tokio::time::timeout(
        Duration::from_secs(10),
        recv.read_to_end(MAX_RESPONSE_BYTES),
    )
    .await
    .map_err(|_| "reading the HTTP/0.9 response timed out")?
    .map_err(Into::into)
}

#[cfg(feature = "zero-rtt")]
async fn run_zero_rtt_client(args: &[String]) -> Result<(), Box<dyn Error>> {
    let server_addr: SocketAddr = required_argument(args, 2, "server address")?.parse()?;
    let ca_cert_path = required_argument(args, 3, "CA certificate path")?;
    let output_path = required_argument(args, 4, "output path")?;

    let early_stream_observed = Arc::new(AtomicBool::new(false));
    let observer = Arc::clone(&early_stream_observed);
    let mut transport = TransportConfig::default();
    transport.set_qlog_handler(move |event| {
        if matches!(
            event,
            QlogEvent::PacketSent {
                level: "0rtt",
                frame_type: "stream",
                ..
            }
        ) {
            observer.store(true, Ordering::Release);
        }
    });
    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(ca_cert_path)?
        .with_alpn_protocols(ALPN_PROTOCOLS.map(<[u8]>::to_vec))
        .with_transport_config(transport)
        .with_zero_rtt()
        .build();
    let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let first = tokio::time::timeout(
        Duration::from_secs(10),
        endpoint.connect(server_addr, "localhost")?,
    )
    .await
    .map_err(|_| "initial QUIC handshake timed out")??;
    let first_response = exchange_hq_request(&first).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let connecting = endpoint.connect(server_addr, "localhost")?;
    let (resumed, accepted) = connecting
        .into_0rtt()
        .map_err(|_| "the quiche server did not provide usable resumption state")?;
    let resumed_response = exchange_hq_request(&resumed).await?;
    let accepted = tokio::time::timeout(Duration::from_secs(10), accepted)
        .await
        .map_err(|_| "waiting for the 0-RTT decision timed out")??;
    if !accepted || resumed.zero_rtt_status() != quion::ZeroRttStatus::Accepted {
        return Err("the quiche server rejected quion's 0-RTT STREAM".into());
    }
    if !early_stream_observed.load(Ordering::Acquire) {
        return Err("quion did not transmit the replay-safe request in a 0-RTT packet".into());
    }
    if first_response != resumed_response {
        return Err("the initial and resumed responses differed".into());
    }
    fs::write(output_path, resumed_response)?;

    first.close(VarInt::ZERO, b"quion 0-RTT warmup complete");
    resumed.close(VarInt::ZERO, b"quion 0-RTT interop complete");
    tokio::time::sleep(Duration::from_millis(250)).await;
    endpoint.abort();
    Ok(())
}

async fn run_server(
    args: &[String],
    expected_endpoint_event: Option<(&'static str, &'static str)>,
) -> Result<(), Box<dyn Error>> {
    let bind_addr: SocketAddr = required_argument(args, 2, "bind address")?.parse()?;
    let cert_path = required_argument(args, 3, "certificate path")?;
    let key_path = required_argument(args, 4, "private key path")?;
    let response_path = required_argument(args, 5, "response path")?;
    let response = fs::read(response_path)?;

    let (transport, endpoint_event_observed) = expected_endpoint_event
        .map(|(state, packet_type)| endpoint_event_observer(state, packet_type))
        .unzip();
    let mut server_config = ServerConfig::builder()
        .with_single_cert_from_pem_files(cert_path, key_path)?
        .with_alpn_protocols(ALPN_PROTOCOLS.map(<[u8]>::to_vec));
    if let Some(transport) = transport {
        server_config = server_config.with_transport_config(transport);
    }
    let server_config = server_config.build()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    let driver = endpoint.spawn_default_server_udp_driver(65_535)?;

    let incoming = tokio::time::timeout(Duration::from_secs(15), endpoint.accept())
        .await
        .map_err(|_| "waiting for a client Initial timed out")?
        .ok_or("endpoint closed before accepting a connection")?;
    let connection = tokio::time::timeout(Duration::from_secs(10), incoming)
        .await
        .map_err(|_| "server handshake timed out")??;
    if endpoint_event_observed
        .as_ref()
        .is_some_and(|observed| !observed.load(Ordering::Acquire))
    {
        let (state, packet_type) =
            expected_endpoint_event.expect("an observer requires an expected endpoint event");
        return Err(
            format!("the quion server completed without observing {state}/{packet_type}").into(),
        );
    }
    let (mut send, mut recv) =
        tokio::time::timeout(Duration::from_secs(10), connection.accept_bi())
            .await
            .map_err(|_| "accepting a bidirectional stream timed out")??;
    let request = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(64 * 1024))
        .await
        .map_err(|_| "reading the HTTP/0.9 request timed out")??;
    if request != b"GET /quion-interop\r\n" {
        return Err(format!("unexpected HTTP/0.9 request: {request:?}").into());
    }
    send.write_all(&response).await?;
    send.finish()?;

    let close = tokio::time::timeout(Duration::from_secs(10), connection.closed())
        .await
        .map_err(|_| "waiting for the peer close timed out")?;
    if !matches!(close, quion::ConnectionError::ApplicationClosed { .. }) {
        return Err(format!("unexpected terminal connection state: {close}").into());
    }

    endpoint.abort();
    driver.stop().await?;
    Ok(())
}

#[cfg(feature = "zero-rtt")]
async fn serve_hq_request(
    connection: &quion::Connection,
    response: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (mut send, mut recv) =
        tokio::time::timeout(Duration::from_secs(10), connection.accept_bi())
            .await
            .map_err(|_| "accepting a bidirectional stream timed out")??;
    let request = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(64 * 1024))
        .await
        .map_err(|_| "reading the HTTP/0.9 request timed out")??;
    if request != b"GET /quion-interop\r\n" {
        return Err(format!("unexpected HTTP/0.9 request: {request:?}").into());
    }
    send.write_all(response).await?;
    send.finish()?;
    Ok(())
}

#[cfg(feature = "zero-rtt")]
async fn run_zero_rtt_server(args: &[String]) -> Result<(), Box<dyn Error>> {
    let bind_addr: SocketAddr = required_argument(args, 2, "bind address")?.parse()?;
    let cert_path = required_argument(args, 3, "certificate path")?;
    let key_path = required_argument(args, 4, "private key path")?;
    let response_path = required_argument(args, 5, "response path")?;
    let response = fs::read(response_path)?;

    let early_stream_observed = Arc::new(AtomicBool::new(false));
    let observer = Arc::clone(&early_stream_observed);
    let mut transport = TransportConfig::default();
    transport.set_retry_enabled(false);
    transport.set_qlog_handler(move |event| {
        if matches!(event, QlogEvent::PacketReceived { level: "0rtt", .. }) {
            observer.store(true, Ordering::Release);
        }
    });
    let server_config = ServerConfig::builder()
        .with_single_cert_from_pem_files(cert_path, key_path)?
        .with_alpn_protocols(ALPN_PROTOCOLS.map(<[u8]>::to_vec))
        .with_transport_config(transport)
        .with_zero_rtt()
        .build()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    let driver = endpoint.spawn_default_server_udp_driver(65_535)?;

    for connection_index in 0..2 {
        let incoming = tokio::time::timeout(Duration::from_secs(15), endpoint.accept())
            .await
            .map_err(|_| "waiting for a client Initial timed out")?
            .ok_or("endpoint closed before accepting a connection")?;
        let connection = tokio::time::timeout(Duration::from_secs(10), incoming)
            .await
            .map_err(|_| "server handshake timed out")??;
        let expected_status = if connection_index == 0 {
            quion::ZeroRttStatus::NotAttempted
        } else {
            quion::ZeroRttStatus::Accepted
        };
        if connection.zero_rtt_status() != expected_status {
            return Err(format!(
                "unexpected 0-RTT status for connection {connection_index}: {:?}",
                connection.zero_rtt_status()
            )
            .into());
        }
        serve_hq_request(&connection, &response).await?;
        let _ = connection.drain_qlog_events();
        let close = tokio::time::timeout(Duration::from_secs(10), connection.closed())
            .await
            .map_err(|_| "waiting for the peer close timed out")?;
        if !matches!(close, quion::ConnectionError::ApplicationClosed { .. }) {
            return Err(format!("unexpected terminal connection state: {close}").into());
        }
    }
    if !early_stream_observed.load(Ordering::Acquire) {
        return Err("quion did not receive the resumed request in a 0-RTT packet".into());
    }

    endpoint.abort();
    driver.stop().await?;
    Ok(())
}

async fn run_idle_client(args: &[String]) -> Result<(), Box<dyn Error>> {
    let server_addr: SocketAddr = required_argument(args, 2, "server address")?.parse()?;
    let ca_cert_path = required_argument(args, 3, "CA certificate path")?;
    let timeout_ms: u32 = required_argument(args, 4, "idle timeout milliseconds")?.parse()?;

    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(ca_cert_path)?
        .with_alpn_protocols(ALPN_PROTOCOLS.map(<[u8]>::to_vec))
        .with_transport_config(idle_transport(timeout_ms))
        .build();
    let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let connection = tokio::time::timeout(
        Duration::from_secs(10),
        endpoint.connect(server_addr, "localhost")?,
    )
    .await
    .map_err(|_| "QUIC handshake timed out")??;

    let close = tokio::time::timeout(
        Duration::from_millis(u64::from(timeout_ms).saturating_add(5_000)),
        connection.closed(),
    )
    .await
    .map_err(|_| "waiting for the negotiated idle timeout timed out")?;
    if close != ConnectionError::TimedOut {
        return Err(format!("unexpected terminal connection state: {close}").into());
    }

    endpoint.abort();
    Ok(())
}

async fn run_idle_server(args: &[String]) -> Result<(), Box<dyn Error>> {
    let bind_addr: SocketAddr = required_argument(args, 2, "bind address")?.parse()?;
    let cert_path = required_argument(args, 3, "certificate path")?;
    let key_path = required_argument(args, 4, "private key path")?;
    let timeout_ms: u32 = required_argument(args, 5, "idle timeout milliseconds")?.parse()?;

    let server_config = ServerConfig::builder()
        .with_single_cert_from_pem_files(cert_path, key_path)?
        .with_alpn_protocols(ALPN_PROTOCOLS.map(<[u8]>::to_vec))
        .with_transport_config(idle_transport(timeout_ms))
        .build()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    let driver = endpoint.spawn_default_server_udp_driver(65_535)?;
    let incoming = tokio::time::timeout(Duration::from_secs(15), endpoint.accept())
        .await
        .map_err(|_| "waiting for a client Initial timed out")?
        .ok_or("endpoint closed before accepting a connection")?;
    let connection = tokio::time::timeout(Duration::from_secs(10), incoming)
        .await
        .map_err(|_| "server handshake timed out")??;
    let (_send, mut recv) = tokio::time::timeout(Duration::from_secs(10), connection.accept_bi())
        .await
        .map_err(|_| "accepting a bidirectional stream timed out")??;
    let request = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(64 * 1024))
        .await
        .map_err(|_| "reading the HTTP/0.9 request timed out")??;
    if request != b"GET /quion-interop\r\n" {
        return Err(format!("unexpected HTTP/0.9 request: {request:?}").into());
    }

    let close = tokio::time::timeout(
        Duration::from_millis(u64::from(timeout_ms).saturating_add(5_000)),
        connection.closed(),
    )
    .await
    .map_err(|_| "waiting for the negotiated idle timeout timed out")?;
    if close != ConnectionError::TimedOut {
        return Err(format!("unexpected terminal connection state: {close}").into());
    }

    endpoint.abort();
    driver.stop().await?;
    Ok(())
}

async fn run_datagram_client(args: &[String]) -> Result<(), Box<dyn Error>> {
    let server_addr: SocketAddr = required_argument(args, 2, "server address")?.parse()?;
    let ca_cert_path = required_argument(args, 3, "CA certificate path")?;
    let outgoing_payload = required_argument(args, 4, "outgoing DATAGRAM payload")?;
    let expected_payload = required_argument(args, 5, "expected DATAGRAM payload")?;

    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(ca_cert_path)?
        .with_alpn_protocols(H3_ALPN_PROTOCOLS.map(<[u8]>::to_vec))
        .with_transport_config(datagram_transport())
        .build();
    let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let connection = tokio::time::timeout(
        Duration::from_secs(10),
        endpoint.connect(server_addr, "localhost")?,
    )
    .await
    .map_err(|_| "QUIC handshake timed out")??;
    if connection
        .negotiated_transport()
        .and_then(|transport| transport.max_datagram_frame_size)
        .is_none()
    {
        return Err("the quiche server did not negotiate QUIC DATAGRAM".into());
    }

    connection.send_datagram(h3_datagram(0, outgoing_payload.as_bytes())?)?;
    let received =
        tokio::time::timeout(Duration::from_secs(10), connection.read_datagram()).await??;
    verify_h3_datagram(&received, 1, expected_payload.as_bytes())?;

    tokio::time::sleep(Duration::from_millis(500)).await;
    connection.close(VarInt::from_u32(0x52), b"quion DATAGRAM interop complete");
    tokio::time::sleep(Duration::from_millis(250)).await;
    endpoint.abort();
    Ok(())
}

async fn run_datagram_server(args: &[String]) -> Result<(), Box<dyn Error>> {
    let bind_addr: SocketAddr = required_argument(args, 2, "bind address")?.parse()?;
    let cert_path = required_argument(args, 3, "certificate path")?;
    let key_path = required_argument(args, 4, "private key path")?;
    let expected_payload = required_argument(args, 5, "expected DATAGRAM payload")?;
    let outgoing_payload = required_argument(args, 6, "outgoing DATAGRAM payload")?;

    let server_config = ServerConfig::builder()
        .with_single_cert_from_pem_files(cert_path, key_path)?
        .with_alpn_protocols(H3_ALPN_PROTOCOLS.map(<[u8]>::to_vec))
        .with_transport_config(datagram_transport())
        .build()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    let driver = endpoint.spawn_default_server_udp_driver(65_535)?;
    let incoming = tokio::time::timeout(Duration::from_secs(15), endpoint.accept())
        .await
        .map_err(|_| "waiting for a client Initial timed out")?
        .ok_or("endpoint closed before accepting a connection")?;
    let connection = tokio::time::timeout(Duration::from_secs(10), incoming)
        .await
        .map_err(|_| "server handshake timed out")??;
    if connection
        .negotiated_transport()
        .and_then(|transport| transport.max_datagram_frame_size)
        .is_none()
    {
        return Err("the quiche client did not negotiate QUIC DATAGRAM".into());
    }

    let received =
        tokio::time::timeout(Duration::from_secs(10), connection.read_datagram()).await??;
    verify_h3_datagram(&received, 0, expected_payload.as_bytes())?;
    connection.send_datagram(h3_datagram(1, outgoing_payload.as_bytes())?)?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    connection.close(VarInt::from_u32(0x52), b"quion DATAGRAM interop complete");
    tokio::time::sleep(Duration::from_millis(250)).await;

    endpoint.abort();
    driver.stop().await?;
    Ok(())
}

fn generate_identity(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cert_path = required_argument(args, 2, "certificate path")?;
    let key_path = required_argument(args, 3, "private key path")?;
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, signing_key.serialize_pem())?;
    Ok(())
}

fn usage(executable: &str) {
    eprintln!("Usage:");
    eprintln!("  {executable} client SERVER_ADDR CA_CERT OUTPUT");
    eprintln!("  {executable} client-retry SERVER_ADDR CA_CERT OUTPUT");
    eprintln!("  {executable} client-version-negotiation SERVER_ADDR CA_CERT OUTPUT");
    #[cfg(feature = "zero-rtt")]
    eprintln!("  {executable} client-zero-rtt SERVER_ADDR CA_CERT OUTPUT");
    eprintln!("  {executable} client-idle SERVER_ADDR CA_CERT TIMEOUT_MS");
    eprintln!("  {executable} client-datagram SERVER_ADDR CA_CERT SEND EXPECT");
    eprintln!("  {executable} server BIND_ADDR CERT KEY RESPONSE");
    eprintln!("  {executable} server-retry BIND_ADDR CERT KEY RESPONSE");
    eprintln!("  {executable} server-version-negotiation BIND_ADDR CERT KEY RESPONSE");
    #[cfg(feature = "zero-rtt")]
    eprintln!("  {executable} server-zero-rtt BIND_ADDR CERT KEY RESPONSE");
    eprintln!("  {executable} server-idle BIND_ADDR CERT KEY TIMEOUT_MS");
    eprintln!("  {executable} server-datagram BIND_ADDR CERT KEY EXPECT SEND");
    eprintln!("  {executable} identity CERT KEY");
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("client") => run_client(&args, None, false).await,
        Some("client-retry") => run_client(&args, Some(("retry_received", "retry")), false).await,
        Some("client-version-negotiation") => {
            run_client(
                &args,
                Some(("version_negotiation_received", "version_negotiation")),
                true,
            )
            .await
        }
        #[cfg(feature = "zero-rtt")]
        Some("client-zero-rtt") => run_zero_rtt_client(&args).await,
        Some("client-idle") => run_idle_client(&args).await,
        Some("client-datagram") => run_datagram_client(&args).await,
        Some("server") => run_server(&args, None).await,
        Some("server-retry") => run_server(&args, Some(("retry_sent", "retry"))).await,
        Some("server-version-negotiation") => {
            run_server(
                &args,
                Some(("version_negotiation_sent", "version_negotiation")),
            )
            .await
        }
        #[cfg(feature = "zero-rtt")]
        Some("server-zero-rtt") => run_zero_rtt_server(&args).await,
        Some("server-idle") => run_idle_server(&args).await,
        Some("server-datagram") => run_datagram_server(&args).await,
        Some("identity") => generate_identity(&args),
        _ => {
            usage(args.first().map(String::as_str).unwrap_or("hq_interop"));
            Err("expected client or server mode".into())
        }
    }
}
