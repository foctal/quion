#![cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]

use std::{error::Error, fs, net::SocketAddr, path::Path};

use quion::{Endpoint, ServerConfig};

async fn handle_connection(connection: quion::Connection) -> Result<(), Box<dyn Error>> {
    let (_, mut recv) = connection.accept_bi().await?;
    let payload = recv.read_to_end(64 * 1024).await?;
    let (mut send, _) = connection.open_bi().await?;
    send.write_all(&payload).await?;
    send.finish()?;
    Ok(())
}

fn ensure_example_certificates(cert_path: &Path, key_path: &Path) -> Result<(), Box<dyn Error>> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    if let Some(parent) = cert_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, signing_key.serialize_pem())?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    let bind_addr: SocketAddr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:4433".to_string())
        .parse()?;
    let cert_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "quion-echo-cert.pem".to_string());
    let key_path = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "quion-echo-key.pem".to_string());
    ensure_example_certificates(Path::new(&cert_path), Path::new(&key_path))?;

    let server_config = ServerConfig::builder()
        .with_single_cert_from_pem_files(&cert_path, &key_path)?
        .build()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    let _driver = endpoint.spawn_default_server_udp_driver(65_535)?;

    println!("quion echo server listening on {}", endpoint.local_addr());
    println!("using cert {}", cert_path);

    loop {
        let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
        let connection = incoming.await?;
        handle_connection(connection).await?;
    }
}
