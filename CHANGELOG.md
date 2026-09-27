# Changelog

## 0.2.0

- Add `Connection::export_keying_material` and `ExportKeyingMaterialError` for
  TLS 1.3 exporters with either rustls provider after the handshake.
- Add `RecvStream::final_size` and `RecvStream::received_final_size` to report
  or await the peer's final byte offset, including bytes discarded by a reset.
  Preserve this metadata after EOF or `stop` until the receive handle is dropped.
- Fix reliable stream reset handling for zero-length prefixes, unordered reads,
  retransmissions, flow-control accounting, acknowledgements, and STOP_SENDING.
- Expand the WebTransport adapter guide and regression coverage for transport
  prerequisites, session flow control, and session keying material.

Requires Rust 1.88 or later. HTTP/3 and WebTransport sessions remain unimplemented;
`quion-h3` remains unpublished. See [known limitations](docs/limitations.md).

## 0.1.0

Initial experimental release:

- QUIC v1 transport with a sans-I/O core and Tokio client/server API.
- TLS configuration through rustls, including PEM and native certificate roots.
- Bidirectional and unidirectional streams, datagrams, and flow control.
- Retry, version negotiation, NewReno and CUBIC congestion control.
- Opt-in 0-RTT and reliable stream resets.
- Connection statistics, memory diagnostics, and qlog support.
- Echo examples, interoperability tests, fuzz targets, and benchmarks.

Requires Rust 1.88 or later. HTTP/3 is not included. See
[known limitations](docs/limitations.md) before using quion in a deployment.
