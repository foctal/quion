# Protocol support

quion implements QUIC v1. This page summarizes the implementation; it is not
a conformance certification. See [known limitations](limitations.md) for
features and behavior that need further validation.

| Area | Implementation |
| --- | --- |
| Transport | Packet and frame codecs, transport parameters, connection IDs, Retry, version negotiation, stateless reset, and anti-amplification limits |
| TLS | rustls handshake integration, packet protection, key updates, and opt-in session resumption with 0-RTT |
| Streams | Bidirectional and unidirectional streams, flow control, ordered and unordered reads, reset, and STOP_SENDING |
| Recovery | ACK processing, RTT estimation, packet- and time-threshold loss detection, PTO, and retransmission |
| Congestion control | NewReno and CUBIC, HyStart++, pacing, and ECN validation |
| Paths | Path validation, server-side NAT rebinding, and DPLPMTUD |
| Datagrams | Negotiated unreliable datagrams with bounded send and receive queues |
| Diagnostics | qlog events, connection and endpoint statistics, and memory counters |

## Extensions

ACK_FREQUENCY negotiation is enabled through `min_ack_delay`; outgoing
requests require explicit configuration. RESET_STREAM_AT is opt-in and allows
a stream reset to preserve delivery of a reliable prefix. Both are draft
extensions. See the [API guide](api.md) for configuration.

0-RTT requires a Cargo feature and builder opt-in. Cached peer limits constrain
early writes. After rejection or Retry, reliable stream and control data are
queued for transmission under fresh 1-RTT limits; unreliable datagrams are not
replayed. Applications are responsible for replay safety.

## Validation

Unit and integration tests cover packet parsing, protected handshakes,
recovery, resource limits, and connection lifecycle. Independent-peer tests
exercise Quinn and quiche; see [interoperability](interop.md) for the tested
scenarios and their limits.
