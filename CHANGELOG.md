# Changelog

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
