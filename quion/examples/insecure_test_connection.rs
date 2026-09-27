#![cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]

use std::{error::Error, fs, path::Path};

use quion::{ClientConfig, Endpoint, ServerConfig, VarInt};

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
    let cert_path = Path::new("quion-insecure-test-cert.pem");
    let key_path = Path::new("quion-insecure-test-key.pem");
    ensure_example_certificates(cert_path, key_path)?;

    let server_endpoint = Endpoint::server(
        ServerConfig::builder()
            .with_single_cert_from_pem_files(cert_path, key_path)?
            .build()?,
        "127.0.0.1:0".parse()?,
    )?;
    let server_driver = server_endpoint.spawn_default_server_udp_driver(65_535)?;

    let server_task = {
        let server_endpoint = server_endpoint.clone();
        tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.ok_or("endpoint closed")?;
            let connection = incoming.await?;
            let (_, mut recv) = connection.accept_bi().await?;
            let payload = recv.read_to_end(64 * 1024).await?;
            let (mut send, _) = connection.open_bi().await?;
            send.write_all(&payload).await?;
            send.finish()?;
            connection.close(VarInt::ZERO, b"done");
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
    };

    let client_config = ClientConfig::builder()
        .with_insecure_no_certificate_verification()
        .build();
    let client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);

    let connection = client_endpoint
        .connect(server_endpoint.local_addr(), "localhost")?
        .await?;
    let (mut send, _) = connection.open_bi().await?;
    send.write_all(b"insecure local test").await?;
    send.finish()?;
    let (_, mut recv) = connection.accept_bi().await?;
    let echoed = recv.read_to_end(64 * 1024).await?;
    println!("{}", String::from_utf8_lossy(&echoed));
    connection.close(VarInt::ZERO, b"done");

    if let Err(error) = server_task.await? {
        return Err(error.to_string().into());
    }
    server_driver.stop().await?;
    Ok(())
}
