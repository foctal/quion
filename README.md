# quion

A QUIC transport library for Rust, with a sans-I/O protocol core and an async
API built on Tokio.

quion is experimental. Its API may change, and it is not yet recommended for
production use. See [known limitations](docs/limitations.md) for unsupported
features and outstanding validation.

## Features

- QUIC v1 with rustls for TLS, certificate verification, and ALPN
- Bidirectional and unidirectional streams with flow control
- Unreliable datagrams (RFC 9221)
- Retry, version negotiation, and connection-ID routing
- NewReno and CUBIC congestion control
- Connection statistics, memory diagnostics, and qlog events
- Opt-in 0-RTT and reliable stream resets (`RESET_STREAM_AT`)

Rust 1.88 or later is required. Default features enable Tokio, the rustls ring
backend, datagrams, and qlog. HTTP/3 and WebTransport sessions are not
implemented.

## Try the echo example

From a checkout of this repository, run the server:

```sh
cargo run -p quion --example echo_server -- 127.0.0.1:4445
```

The server generates a self-signed localhost certificate and private key in
`quion-echo-cert.pem` and `quion-echo-key.pem`. These files are for local use
and are ignored by Git.

In another terminal, run the client:

```sh
cargo run -p quion --example echo_client -- 127.0.0.1:4445 quion-echo-cert.pem "hello over quic" localhost
```

The client trusts the generated certificate and prints `hello over quic`.

## Client example

This example connects to the echo server above and sends a message:

```rust,no_run
use quion::{ClientConfig, Endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::builder()
        .with_root_certificates_from_pem_file("quion-echo-cert.pem")?
        .build();

    let endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(config);

    let connection = endpoint
        .connect("127.0.0.1:4445".parse()?, "localhost")?
        .await?;

    let (mut send, _recv) = connection.open_bi().await?;
    send.write_all(b"hello over quic").await?;
    send.finish()?;

    let (_send, mut recv) = connection.accept_bi().await?;
    let response = recv.read_to_end(64 * 1024).await?;
    println!("{}", String::from_utf8(response)?);
    Ok(())
}
```

See the [API guide](docs/api.md) for server setup, TLS configuration, stream
lifecycle, datagrams, and resource limits.

## Workspace

| Crate | Purpose |
| --- | --- |
| `quion` | Async client and server API |
| `quion-proto` | Sans-I/O protocol state machine |
| `quion-udp` | UDP sockets, packet batching, and platform support |
| `quion-h3` | Reserved for future HTTP/3 work; unpublished |
| `quion-fuzz` | Internal fuzz targets; unpublished |

## Documentation

- [Architecture](docs/architecture.md)
- [Protocol support](docs/protocol-compliance.md)
- [Security considerations](docs/security.md)
- [Interoperability](docs/interop.md)
- [Testing](docs/testing.md)
- [Benchmarking and profiling](docs/performance.md)
- [WebTransport prerequisites](docs/webtransport.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

To build the API reference locally, run `cargo doc -p quion --no-deps --open`.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
