#![cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]

use std::{error::Error, net::SocketAddr};

use quion::{ClientConfig, Endpoint, VarInt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    let server_addr: SocketAddr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:4433".to_string())
        .parse()?;
    let ca_cert_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "quion-echo-cert.pem".to_string());
    let message = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "hello over quion".to_string());
    let server_name = args
        .get(4)
        .cloned()
        .unwrap_or_else(|| "localhost".to_string());

    let client_config = ClientConfig::builder()
        .with_root_certificates_from_pem_file(&ca_cert_path)?
        .build();
    let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint.connect(server_addr, &server_name)?.await?;
    let (mut send, _) = connection.open_bi().await?;
    send.write_all(message.as_bytes()).await?;
    send.finish()?;

    let (_, mut recv) = connection.accept_bi().await?;
    let echoed = recv.read_to_end(64 * 1024).await?;
    println!("{}", String::from_utf8_lossy(&echoed));

    connection.close(VarInt::ZERO, b"done");
    Ok(())
}
