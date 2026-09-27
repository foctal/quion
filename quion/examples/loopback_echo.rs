#![cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]

use std::{error::Error, sync::Arc, time::Duration};

use quion::{ClientConfig, Endpoint, ServerConfig, VarInt};

fn test_client_server_configs() -> (rustls::ClientConfig, rustls::ServerConfig) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let provider = default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
    );
    let server = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .unwrap();
    (client, server)
}

#[cfg(feature = "rustls-ring")]
fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[cfg(all(not(feature = "rustls-ring"), feature = "rustls-aws-lc-rs"))]
fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

async fn read_to_end_nonempty(recv: &mut quion::RecvStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(1), recv.read_to_end(4096))
        .await
        .expect("stream read timed out")
        .expect("stream read failed")
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let (client_crypto, server_crypto) = test_client_server_configs();
    let client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    client_endpoint.set_default_client_config(
        ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .build(),
    );
    let server_endpoint =
        Endpoint::server(ServerConfig::builder().build()?, "127.0.0.1:0".parse()?)?;
    let server_driver =
        server_endpoint.spawn_server_udp_driver(Arc::new(server_crypto), Default::default(), 1500);

    let server_task = {
        let server_endpoint = server_endpoint.clone();
        tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("endpoint closed");
            let connection = incoming.await.expect("incoming failed");
            let (_, mut recv) = connection.accept_bi().await.expect("accept bi failed");
            let payload = read_to_end_nonempty(&mut recv).await;
            let (mut send, _) = connection.open_bi().await.expect("open bi failed");
            send.write_all(&payload).await.expect("echo write failed");
            send.finish().expect("echo finish failed");
            connection.close(VarInt::from_u32(0), b"server done");
        })
    };

    let connection = client_endpoint
        .connect(server_endpoint.local_addr(), "localhost")?
        .await?;
    let (mut send, _) = connection.open_bi().await?;
    send.write_all(b"hello from client").await?;
    send.finish()?;
    let (_, mut recv) = connection.accept_bi().await?;
    let echoed = read_to_end_nonempty(&mut recv).await;
    println!("{}", String::from_utf8_lossy(&echoed));

    connection.close(VarInt::from_u32(0), b"client done");
    server_task.await?;
    server_driver.stop().await?;
    Ok(())
}
