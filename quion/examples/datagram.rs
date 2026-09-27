#![cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"),
    feature = "datagram"
))]

use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use quion::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};

fn write_test_cert_materials() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let base = std::env::temp_dir().join(format!(
        "quion-example-datagram-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&base)?;
    let cert_path = base.join("cert.pem");
    let key_path = base.join("key.pem");
    fs::write(&cert_path, cert.pem())?;
    fs::write(&key_path, signing_key.serialize_pem())?;
    Ok((cert_path, key_path))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let (cert_path, key_path) = write_test_cert_materials()?;

    let mut transport = TransportConfig::default();
    transport.set_max_datagram_frame_size(Some(VarInt::from_u32(1200)));

    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(&cert_path)?
        .with_transport_config(transport.clone())
        .build();
    let server_config = ServerConfig::builder()
        .with_single_cert_from_pem_files(&cert_path, &key_path)?
        .with_transport_config(transport)
        .build()?;

    let client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let server_driver = server_endpoint.spawn_default_server_udp_driver(65_535)?;

    let server_task = {
        let server_endpoint = server_endpoint.clone();
        tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.ok_or("endpoint closed")?;
            let connection = incoming.await?;
            let payload = connection.read_datagram().await?;
            println!("server received: {}", String::from_utf8_lossy(&payload));
            connection.send_datagram(b"pong")?;
            connection.close(VarInt::ZERO, b"done");
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
    };

    let client = tokio::time::timeout(Duration::from_secs(1), async {
        client_endpoint
            .connect(server_endpoint.local_addr(), "localhost")?
            .await
    })
    .await??;

    client.send_datagram(b"ping")?;
    let response = tokio::time::timeout(Duration::from_secs(1), client.read_datagram()).await??;
    println!("client received: {}", String::from_utf8_lossy(&response));

    client.close(VarInt::ZERO, b"done");
    if let Err(error) = server_task.await? {
        return Err(error.to_string().into());
    }
    server_driver.stop().await?;
    Ok(())
}
