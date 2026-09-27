# API Guide

This guide covers endpoint configuration, streams, datagrams, and resource
limits in the high-level `quion` API.

## Endpoint Setup

Create a client endpoint with `Endpoint::client`, then install a default client
configuration built through `ClientConfig::builder()`.
Use `Endpoint::client_with_config` when the client needs non-default endpoint
admission or shared-memory limits.

Create a server endpoint with `Endpoint::server`, passing a fully built
`ServerConfig`. For rustls-backed operation, use
`ServerConfig::builder().with_single_cert_from_pem_files(...).build()?`.

Internet-facing servers should size admission and memory controls through
`TransportConfig`. In particular,
`set_max_tracked_endpoint_paths` bounds retained anti-amplification state for
remote addresses and evicts the least recently used entry at capacity.
`set_max_endpoint_memory_bytes` applies one retained-payload ceiling across
pending handshakes, active connection protocol state, application STREAM and
DATAGRAM writes, and routed UDP input. `Endpoint::diagnostics()` reports path
limits together with reserved, maximum, and available shared payload bytes.

## TLS Configuration

Client TLS roots can be loaded through:

- `ClientConfig::builder().with_native_roots()?`
- `ClientConfig::builder().with_root_certificates_from_pem_file(path)?`
- `ClientConfig::builder().with_root_certificates(root_store)?`

Server certificates can be loaded through:

- `ServerConfig::builder().with_single_cert_from_pem_files(cert, key)?`
- `ServerConfig::builder().with_single_cert(certs, key)?`

ALPN protocols are configured on both client and server builders with
`with_alpn_protocols(...)`.

TLS key logging can be enabled on both builders with `with_key_logging()`.
rustls writes secrets through its standard `SSLKEYLOGFILE` integration.

For local tests only, clients can disable certificate verification with
`ClientConfig::builder().with_insecure_no_certificate_verification()`.

## Version Negotiation Probe

Clients normally start directly with QUIC v1. Interoperability and deployment
validation can opt into a reserved-version probe with
`ClientConfig::builder().with_version_negotiation_probe()`. The peer cannot
select the probe version: quion validates the Version Negotiation packet and
restarts the connection from clean Initial, TLS, recovery, and packet-number
state using QUIC v1.

The probe adds one network round trip and is therefore disabled by default. It
is intended for explicit validation rather than routine connection setup.

## Connection Lifecycle

Use `Endpoint::connect(remote, server_name)?` to obtain a `Connecting` future.
Awaiting it yields an established `Connection` after the QUIC and TLS handshake
completes.

On the server side, `Endpoint::accept().await` yields an `Incoming`, and
awaiting the `Incoming` future yields the established `Connection`.

`Connection` is a compact shared-state handle. Clone it when independent
tasks need to open or accept streams; cloning does not duplicate protocol,
transport-configuration, or connection-ID state. Connection-local
synchronization state shares the same allocation; services retained by stream
and operation futures remain independently reference counted.

Use `Connection::close(error_code, reason)` to close an established connection.

## Streams

Open locally initiated streams with:

- `Connection::open_bi().await?`
- `Connection::open_uni().await?`

Accept peer-initiated streams with:

- `Connection::accept_bi().await?`
- `Connection::accept_uni().await?`

`SendStream::finish()` marks the send side complete after all buffered data has
been queued.

`RecvStream::read_chunk(max_size, ordered)` returns a `Chunk` whose payload is
shared immutable `bytes::Bytes`. Ordered reads may return adjacent packet
payloads as separate chunks so the transport can preserve their decrypted
backing storage without copying. `read`, `read_exact`, and `read_to_end`
continue to present contiguous application buffers and drain adjacent chunks
in bounded batches under one connection lock.

`SendStream::reset_at(error_code, reliable_size)` resets a stream while
guaranteeing delivery of its prefix through an absolute byte offset. Enable the
extension with `TransportConfig::set_reset_stream_at(true)` and verify
`NegotiatedTransport::reset_stream_at` after the handshake. See
[`webtransport.md`](webtransport.md) for its WebTransport use.

`RecvStream::final_size()` reports the peer's final byte offset once known,
including data discarded by a reset. `received_final_size().await` waits for
that value without consuming the stream. The size remains available after
reading EOF or calling `stop`, until the receive handle is dropped.

With a rustls provider enabled, `Connection::export_keying_material` derives
TLS 1.3 keying material after the handshake. Adapters that multiplex sessions
must use their protocol's session-specific exporter label and context.

## Datagrams

When DATAGRAM support is negotiated, applications can call:

- `Connection::send_datagram(bytes)?`
- `Connection::send_datagram_bytes(shared_bytes)?`
- `Connection::read_datagram().await?`
- `Connection::read_datagram_bytes().await?` for immutable payload storage

`Connection::max_datagram_size()` returns the current conservative payload
limit, accounting for negotiated frame size and path MTU. It returns `None`
until usable support is negotiated. The sender uses a length-bearing DATAGRAM
encoding and reserves packet-header space, so this is not the transport
parameter's raw value. Recheck after path changes: queued unreliable payloads
may be dropped if they no longer fit. Receive support must be explicitly
advertised with `set_max_datagram_frame_size`; absent or zero disables it.

`send_datagram_bytes` accepts `bytes::Bytes`; cloning a shared payload is
constant-time and the same allocation is retained through packetization.
`read_datagram_bytes` similarly retains the decoded immutable payload through
the receive queue and application handoff; `read_datagram` remains the
compatible `Vec<u8>`-returning API.

`send_datagram` accepts payloads converted to `Vec<u8>`. Use
`Connection::negotiated_transport()` to inspect the negotiated datagram limit.

## ACK Frequency

quion advertises a one-millisecond `min_ack_delay` by default so a peer can
request updated acknowledgment behavior. Outgoing ACK_FREQUENCY requests are
opt-in:

```rust
use quion::{AckFrequencyConfig, TransportConfig, VarInt};

let mut ack_frequency = AckFrequencyConfig::default();
ack_frequency
    .ack_eliciting_threshold(VarInt::from_u32(9))
    .reordering_threshold(VarInt::from_u32(2));

let mut transport = TransportConfig::default();
transport.set_ack_frequency_config(Some(ack_frequency));
```

Set `min_ack_delay` to `None` to disable negotiation entirely. ACK_FREQUENCY
remains an Internet-Draft extension, so applications should keep the sender
policy opt-in and validate it against their deployment's loss and latency
profile.

## Statistics

`Connection::stats()` and `Endpoint::stats()` return aggregate stable counters.
Use `Connection::congestion_stats()`, `Connection::path_stats()`, and
`Connection::stream_stats(id)` for scoped snapshots. Connection statistics
include traffic, loss, retransmission, RTT, congestion, ECN, stream,
flow-control, datagram, handshake-duration, and migration counters.

## Peer Identity and ALPN

After the handshake completes:

- `Connection::peer_identity()` returns the first peer certificate as DER bytes
  when the peer presented a certificate chain.
- `Connection::peer_certificates()` returns the full peer certificate chain.
- `Connection::alpn_protocol()` returns the negotiated ALPN protocol bytes.

On a typical server configuration without client authentication, the server's
`Connection` will return `None` for peer certificate accessors.

## Runtime Drivers

For Tokio-based servers, call `Endpoint::spawn_default_server_udp_driver(...)`
after constructing the endpoint. This driver progresses Initial, Handshake, and
routed 1-RTT traffic using the endpoint-owned UDP socket.

For Tokio-based clients, the first runtime-driven `Endpoint::connect(...)`
starts one endpoint-owned UDP driver. Concurrent handshakes and established
connections share that driver, which routes packets by connection ID.

`Runtime` is the public scheduling boundary for task spawn, timer sleep, and
cooperative yield. `TokioRuntime` is the first implementation and is used by
the Tokio driver work limiter. UDP readiness remains runtime-specific; a smol
driver must supply equivalent nonblocking UDP readiness before
`runtime-smol` can become a supported endpoint runtime.

## Idle Lifetime and Keep-Alive

`TransportConfig::set_keep_alive_interval(Some(Duration::from_secs(5)))`
enables PINGs on otherwise idle established connections. `None` or zero disables
it; the default is disabled. The interval is capped at half the effective idle
timeout with a one-millisecond minimum. Effective idle time includes the
three-PTO floor. Configure the interval before creating the connection.

Keep-alive can maintain NAT mappings and idle sessions when the peer responds.
It is not an application heartbeat or a guarantee against disconnection.
Unanswered repeated sends do not keep resetting the connection's idle timer.

## Memory Diagnostics

`Connection::diagnostics().memory` reports bytes retained by stream, DATAGRAM,
CRYPTO, retransmission, routed-packet, connection-ID, and buffered qlog state,
plus bounded ACK/control metadata. `Endpoint::diagnostics()` reports
endpoint-wide routed-datagram bytes, pending-handshake payloads, aggregate
registered connection bytes, the enforced shared reservation and ceiling, its
routed-byte cap, and retained CID route aliases. These are portable counters
and intentionally exclude allocator bookkeeping.

Queue retention can be tuned with `TransportConfig` setters for stream and
DATAGRAM bytes, control frames, ACK ranges, CRYPTO buffering, qlog events,
routed endpoint datagrams, Retry replay entries, pending handshakes, and
established connections. Exhausting the shared endpoint payload ceiling rejects
new client handshakes, applies explicit STREAM/DATAGRAM backpressure, and drops
network input that cannot be retained. Send-side APIs report backpressure;
receive-side DATAGRAM and qlog queues retain the newest entries, sparse ACK ranges evict the
oldest ranges, and Retry replay detection evicts its oldest entry at capacity.
Buffered high-level qlog events hold per-event reservations from the same
endpoint-wide memory budget and release them when drained, evicted, or dropped.
High-level qlog retention defaults to zero to keep the data path allocation-free;
configure a synchronous qlog handler or a nonzero
`set_max_buffered_qlog_events` limit when event collection is required.

## Path MTU

`TransportConfig::set_initial_mtu` selects the starting UDP payload size.
The default 1,200-byte value is safe for Internet paths. DPLPMTUD probes with
protected PING and PADDING packets, respects the peer's
`max_udp_payload_size`, and falls back to 1,200 bytes after repeated
size-correlated loss bursts. Use `set_mtu_discovery_config` to tune the search
or pass `None` to keep a deployment-known fixed size.

## 0-RTT

When the `zero-rtt` feature is enabled, both endpoint roles still reject
early-data use by default. `ClientConfigBuilder::with_zero_rtt()` permits
session resumption to derive client write keys, and
`ServerConfigBuilder::with_zero_rtt()` explicitly enables server acceptance.
The corresponding `zero_rtt_enabled()` accessors expose the effective policy.
After handshake resolution, `Connection::zero_rtt_status()` reports
`NotAttempted`, `Accepted`, or `Rejected`. For a resumed client handshake,
`Connecting::into_0rtt()` returns an immediately usable `Connection` plus a
`ZeroRttAccepted` future when cached TLS and QUIC state is available. The
connection initially reports `Attempted`; awaiting the decision future yields
`true` for acceptance, `false` for rejection, or a connection error.

Only replay-safe operations may be written before that decision resolves.
Cached peer flow-control, stream-count, and DATAGRAM limits constrain early
writes. If the server rejects 0-RTT or sends Retry, quion restores reliable
STREAM and control data to the send queues, applies the fresh peer limits, and
transmits it under 1-RTT protection when permitted. Already transmitted
DATAGRAM frames are intentionally not replayed because DATAGRAM is unreliable.
The API cannot determine whether an application operation is idempotent; that
policy remains the caller's responsibility.

## Examples

The workspace includes runnable examples for common setups:

- `echo_server`: simple echo server with generated self-signed certificates
- `echo_client`: simple echo client using a trusted PEM root
- `loopback_echo`: single-process loopback echo with both endpoints
- `datagram`: negotiated DATAGRAM send/receive over loopback
- `insecure_test_connection`: local-only example using an intentionally unsafe
  builder-based client verifier override for test environments
- `custom_runtime`: manual Tokio runtime construction around `quion`

## Current Scope

The high-level API is experimental. See [known limitations](limitations.md)
for unsupported features and outstanding validation.

## Lifecycle and resource policies

Dropping an unfinished `SendStream` queues FIN after the bytes already accepted
by that stream. It does not wait for delivery; call `reset` to abandon outgoing
data explicitly. Dropping `RecvStream` discards unread data and requests
STOP_SENDING with application error code zero. Use `stop(code)` for an explicit
application code. These notifications require a live connection and available
control capacity. Dropping a read/write future alone leaves its owning stream
alive. Retain both halves of an accepted bidirectional stream when both are
needed; binding a half to `_` drops it immediately.

Dropping ordinary `Connecting` cancels its background handshake and cleans an
undelivered handoff. `into_0rtt` explicitly transfers connection ownership;
dropping only the returned acceptance future does not cancel that connection.
Client handshakes have a 30-second deadline, shortened by a nonzero configured
idle timeout. Setting idle timeout to zero does not disable this handshake cap.

`TransportConfig::set_max_stream_metadata_entries` bounds stream metadata
independently of buffered payload. The default is 16,384 entries in each
send/receive direction. Receive entries include active states, local stream
registrations, and closed-stream ranges; send entries include active states
and closed ranges. Sparse lifetime history consumes entries even after payload
is released. Exhaustion rejects new state instead of allocating without bound.
This is an entry-count limit, not exact heap-byte accounting; endpoint payload
statistics do not include every metadata allocation.

Servers authenticate and validate candidate client addresses for NAT rebinding
even under the default `disable_active_migration` policy. Clients continue to
reject unexpected server addresses. This does not make active migration a
supported production feature; independent-peer migration tests remain
outstanding.

The sans-I/O `register_local_stream` and `increase_stream_send_limit` methods
return `Result` because admission can fail. Callers must handle the result.
`Transmit::path_response` identifies a response token so a runtime can route it
back to the corresponding PATH_CHALLENGE source independently of its candidate
probe destination.
