# Interoperability

## Test coverage

The repository includes tests for:

- in-process loopback client/server handshakes
- split-runtime loopback operation
- separate-process QUIC stream echo using `examples/echo_client.rs` and
  `examples/echo_server.rs`
- automated Quinn 0.11.11 interoperability with quion in both the client and
  server roles, including bidirectional stream transfer and bidirectional
  QUIC DATAGRAM transfer, application close, idle timeout, and four concurrent
  live connections per role
- automated Cloudflare quiche interoperability in both quion roles for TLS
  handshake, same-stream HTTP/0.9 request/response transfer, bidirectional QUIC
  DATAGRAM payloads, Retry, successful Version Negotiation followed by a QUIC
  v1 restart, negotiated idle timeout, and peer-observed application close

## Interop Matrix Runner

`scripts/interop/run-matrix.sh` runs the required peer/scenario matrix. Supply
an adapter executable for each peer on `PATH` (these adapters are not bundled):

- `quion-interop-quinn`
- `quion-interop-quiche`
- `quion-interop-ngtcp2`
- `quion-interop-s2n-quic`
- `quion-interop-msquic`

Each adapter receives `--scenario NAME --role client|server` and must start the
peer plus the matching quion example, validate payload transfer and exit
nonzero on failure. The standard scenarios are handshake in both roles,
stream transfer, DATAGRAM, Retry, Version Negotiation, close, idle timeout,
and 0-RTT when enabled. This stable command contract lets CI environments pin
peer builds independently from the Rust workspace. Handshake scenarios select
their named role; every other scenario runs in both roles. The five-peer matrix
dispatches 70 invocations by default and 80 with `QUION_INTEROP_ZERO_RTT=1`.
`python3 scripts/interop/test-matrix.py` checks the exact dispatch set with
recording adapters and verifies failure on a missing adapter. This contract
test does not establish interoperability with real peers.

## Automated Quinn Smoke Test

Run the in-workspace independent-stack smoke test with:

```sh
cargo test -p quion --test quinn_interop --all-features
```

The test pins Quinn 0.11.11 and covers:

- quion client to Quinn server handshake
- Quinn client to quion server handshake
- ACK_FREQUENCY negotiation and frame exchange in both directions
- bidirectional stream request and response in both role combinations
- bidirectional DATAGRAM transfer in both role combinations
- Retry in both role combinations
- application close propagation, including error code and reason, in both role
  combinations
- negotiated idle-timeout enforcement in both role combinations
- four simultaneously live connections over one client UDP socket in both
  role combinations
- Quinn client session resumption with an application STREAM sent in 0-RTT and
  accepted by a quion server
- quion client session resumption with an application STREAM sent in 0-RTT and
  accepted by a Quinn server
- Quinn Retry rejecting a quion client's 0-RTT attempt, followed by automatic
  1-RTT retransmission of the replay-safe STREAM
- a Quinn client starting with a supported draft version observing quion's
  Version Negotiation response and terminating with `VersionMismatch`

## Automated quiche Smoke Test

Run the repository-owned quiche transport smoke test with:

```sh
./scripts/interop/quiche-smoke.sh
```

The script uses the official Cloudflare quiche client/server image pinned by
digest. It generates an ephemeral localhost identity, runs quion as a client
against the quiche server, then runs the quiche client against a quion server.
Both directions negotiate `hq-interop`, exchange and byte-compare an HTTP/0.9
request and response on one bidirectional stream, require a Retry packet to be
observed by quion, and verify that the peer observes an application close.
Separate connections require successful Version Negotiation in both roles.
The quion client starts with the reserved version `0x0a0a0a0a`, verifies the
quiche server's response, resets its Initial, TLS, recovery, and packet-number
state, and completes the transfer over QUIC v1. The quiche client starts with
its reserved wire version, verifies quion's response, and likewise restarts
over QUIC v1. The adapter requires the corresponding quion qlog endpoint event
before accepting either transfer as evidence.
Separate connections advertise a 250 ms idle timeout from both peers and
require quion and quiche to report the negotiated idle timeout. Docker is
required. The image, two UDP ports, and idle timeout can be overridden with
`QUION_QUICHE_IMAGE`, `QUION_QUICHE_SERVER_PORT`,
`QUION_QUICHE_QUION_SERVER_PORT`, and `QUION_QUICHE_IDLE_TIMEOUT_MS`.

The quiche applications expose transport DATAGRAM testing through their
HTTP/3 `oneway` mode. Separate `h3` connections therefore exchange one QUIC
DATAGRAM in each direction. The adapter validates the one-byte HTTP/3 flow ID
and application payload exactly, while the script independently matches
quiche's received flow ID, encoded length, and byte array. This is RFC 9221
transport evidence; it does not claim that `quion-h3` implements HTTP/3 or
HTTP Datagrams.

The 0-RTT profile uses two connections per role. The first connection exchanges
an exact HTTP/0.9 request and response and obtains a session ticket. The second
connection sends the same replay-safe GET before handshake completion. When
quion is the client, the adapter requires its early-data acceptance future and
final transport status to report acceptance, and requires a qlog
`PacketSent` event for a STREAM frame at the `0rtt` level. When quiche is the
client, both invocations share quiche's session file and the second enables
early data; the quion server requires accepted transport status, exact
request/response bytes, and a received-packet qlog event at the `0rtt` level.
This is transport 0-RTT evidence only. Applications remain responsible for
restricting early data to operations that are safe to replay.

This smoke test is part of the manually dispatched extended CI workflow and
the extended release-gate script.

## Manual Interop Workflow

For local quion-to-quion inspection or while developing the remaining peer
adapters, use the following manual workflow:

1. Start `cargo run -p quion --example echo_server -- 127.0.0.1:4455`.
2. Connect with `cargo run -p quion --example echo_client -- 127.0.0.1:4455 quion-echo-cert.pem "hello" localhost`.
3. Verify the client prints the echoed payload and the server remains healthy.

## Coverage limits

Automated stream, DATAGRAM, close, idle-timeout, and concurrent-connection
coverage against Quinn is present, and both role combinations assert that
Retry occurred. Both 0-RTT role combinations include actual early STREAM data,
and the quion-client role additionally verifies rejection and reliable replay
after Quinn Retry. Quinn independently validates quion's Version Negotiation
response, but Quinn 0.11 does not restart with a mutually supported version.
The quiche smoke provides successful restart evidence in both roles, in
addition to handshake, stream, DATAGRAM, Retry, idle-timeout, and close
coverage. Both quiche role combinations also send an application STREAM in
accepted 0-RTT. All ngtcp2, s2n-quic, and MsQuic coverage is still pending.
The existing smoke tests are correctness evidence, not a substitute for the
complete release interop matrix.
