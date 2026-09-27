# Security Notes

## Transport security

- The protocol and high-level crates deny `unsafe_code`. The UDP crate uses
  platform-specific unsafe code for socket operations.
- QUIC-TLS handshakes are backed by rustls.
- Retry token validation and transport parameter decoding are covered by unit
  and integration tests.
- Remote path and anti-amplification state has a configurable endpoint limit
  with deterministic least-recently-used eviction.
- Connection-ID lifecycle validation rejects zero-length-ID replacement and
  retirement frames, conflicting sequence/token reuse, and attempts to retire
  the Destination CID carrying the retirement frame.
- High-level and sans-I/O endpoint defaults generate independent Retry secrets
  and keyed Retry source connection-ID sequences from the operating system
  random source. Every Retry token authenticates its selected source connection
  ID, preventing a valid token from being moved onto another pending route.
- The high-level client and server examples perform authenticated TLS
  handshakes with certificate verification.
- 0-RTT remains rejected unless both the Cargo feature and explicit endpoint
  builder opt-in are present. Custom rustls configurations cannot bypass this
  default because quion normalizes the effective early-data settings when the
  high-level configuration is built.

## Certificate Handling

- Client roots can be loaded from the operating system trust store or from PEM
  files, or installed directly as a `rustls::RootCertStore`.
- Server certificates can be loaded from PEM files or from in-memory rustls
  certificate chains.
- Private keys in PKCS#8, PKCS#1, and SEC1 PEM formats are accepted.
- TLS key logging can be enabled explicitly for debugging through rustls'
  `SSLKEYLOGFILE` support.

## Peer Authentication Surface

- `Connection::peer_identity()` exposes the leaf certificate when the peer
  authenticated with certificates.
- `Connection::peer_certificates()` exposes the full presented certificate
  chain.
- `Connection::alpn_protocol()` exposes the negotiated ALPN value.

Servers that do not require client certificates should expect
`peer_identity()` and `peer_certificates()` to return `None`.

## Operational Advice

- Prefer explicit ALPN configuration for every deployment.
- Never use `with_insecure_no_certificate_verification()` outside local tests
  or tightly controlled development environments.
- Treat every 0-RTT request as replayable. Enabling
  `ClientConfigBuilder::with_zero_rtt()` or
  `ServerConfigBuilder::with_zero_rtt()` is only appropriate when the
  application protocol independently restricts early operations to
  replay-safe behavior. `Connecting::into_0rtt()` reports the server decision
  asynchronously; reliable transport retransmission after rejection does not
  prevent an attacker from replaying an accepted early request.
- Rotate certificates and Retry token keys according to your operational
  policies.
- Size `set_max_tracked_endpoint_paths`, connection admission limits, and
  routed-datagram memory limits for the expected deployment.
- Treat the current project as pre-1.0 software and validate it in a controlled
  environment before exposing it to untrusted internet traffic.

## Resource limits

Stream metadata is bounded separately from payload buffers. Closed-stream
ranges count toward the metadata limit even after their payload is released.
These limits do not account for all allocator overhead. See
[resource policies](api.md#lifecycle-and-resource-policies) for defaults and
[known limitations](limitations.md) for outstanding validation.

Cancelling an ordinary connection attempt releases its background handshake.
Client handshakes have a finite deadline even when idle timeout is disabled.
Server-side NAT rebinding requires authenticated input and a matching path
validation response before the new address is used.
