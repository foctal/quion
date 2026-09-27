# Known limitations

quion is experimental and has not completed the validation needed for a
production-ready QUIC implementation. Passing local tests does not establish
full protocol conformance or suitability for an internet-facing service.

## Unsupported and experimental features

- `quion-h3` contains no HTTP/3 implementation. WebTransport sessions, QPACK,
  Extended CONNECT, and HTTP Datagrams are not available.
- Tokio is the implemented endpoint runtime. The `runtime-smol` and `wasm`
  feature flags do not provide working runtime integrations.
- 0-RTT requires the `zero-rtt` feature and explicit configuration on each
  endpoint. Applications must restrict early data to replay-safe operations.
- Active migration is disabled by default and needs further interoperability
  testing. Default server-side NAT rebinding validates the candidate address
  before switching paths.
- `unstable-bbr3` is an experimental controller, not a complete BBRv3
  implementation. The other `unstable-*` features are not supported for
  production use.
- ACK_FREQUENCY and RESET_STREAM_AT are draft extensions. Outgoing
  ACK_FREQUENCY requests and reliable stream resets require explicit opt-in.

## Outstanding validation

Quinn tests and a quiche smoke-test script cover both endpoint roles. The
ngtcp2, s2n-quic, and MsQuic adapters for the broader interoperability matrix
are not included. Stateless reset and connection-ID rotation, migration, and
key lifecycle behavior need broader independent-peer coverage.

Further work includes sustained authenticated state-machine fuzzing,
long-running tests with loss and idle connections, and CPU and memory
profiling at large connection and stream counts. The fuzz targets do not
cover the complete async runtime or all cancellation paths.

Native Linux, macOS, and Windows results must be checked for the revision
being released. UDP metadata and offload support differ by platform; portable
fallbacks do not provide all native capabilities. Established-path GSO/GRO
behavior under loss and partial sends needs further testing.

Memory diagnostics count retained payloads and selected metadata. They do not
measure all heap allocations, allocator overhead, or kernel socket memory.
Stream metadata limits count entries separately from payload bytes.

See [testing](testing.md), [interoperability](interop.md), and the
[release checklist](release-checklist.md) for validation procedures.
