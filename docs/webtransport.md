# WebTransport prerequisites

quion provides streams, datagrams, reliable resets, and TLS exporters for
higher-level protocols. It does not implement HTTP/3 or WebTransport sessions;
`quion-h3` remains a placeholder.

This guide describes transport API usage for
[WebTransport over HTTP/3 draft-16](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-16.html)
and [QUIC Stream Resets with Partial Delivery draft-11](https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html).
HTTP/3 SETTINGS, QPACK, Extended CONNECT, HTTP Datagram framing, and session
management must be implemented by a higher-level library.

## Configuration and negotiation

Enable datagrams and reliable resets on both endpoints:

```rust
use quion::{TransportConfig, VarInt};

let mut transport = TransportConfig::default();
transport
    .set_reset_stream_at(true)
    .set_max_datagram_frame_size(Some(VarInt::from_u32(65_535)));
```

After the handshake, check
`Connection::negotiated_transport().is_some_and(|t| t.reset_stream_at)` and
`Connection::max_datagram_size()`. A draft-16 adapter must require the peer's
transport capabilities as well as the appropriate HTTP/3 SETTINGS. Ordinary
RESET_STREAM fallback for legacy peers is a separate compatibility policy;
it does not satisfy draft-16 reliable stream association requirements.

## Adapter surface

| Adapter need | quion API |
| --- | --- |
| Open and accept streams | `Connection::{open,accept}_{bi,uni}` |
| Stream identification | `SendStream::id`, `RecvStream::id` |
| Async protocol codecs | Tokio `AsyncRead` and `AsyncWrite` |
| Reliable reset | `SendStream::reset_at` |
| Reset observation | `RecvStream::received_reset` |
| Stop sending and observe completion | `RecvStream::stop`, `SendStream::stopped` |
| Final size, including discarded bytes | `RecvStream::final_size`, `RecvStream::received_final_size` |
| QUIC datagrams | `Connection::send_datagram`, `Connection::read_datagram`, `Connection::max_datagram_size` |
| Peer capabilities | `Connection::negotiated_transport`, `Connection::peer_transport_parameters` |
| TLS identity and ALPN | `Connection::peer_identity`, `Connection::alpn_protocol` |
| TLS exporter | `Connection::export_keying_material` |
| Stream scheduling | `SendStream::set_priority` |
| Connection close | `Connection::close`, `Connection::closed` |

## Reliable reset semantics

quion implements the empty `reset_stream_at` transport parameter (`0x1d`) and
RESET_STREAM_AT frame (`0x24`). Pass an absolute reliable offset that includes
the entire WebTransport stream header and session ID. Resetting immediately
after that header is supported, including equal final and reliable sizes.

The receiver delivers the reliable prefix and then reports the reset code.
Reliable-prefix chunks do not report FIN, and receive state retains the reset
until stop or handle drop. Unordered reads track the consumed prefix even when
some bytes were read before the reset arrived. A zero-length reliable prefix
reports a reset without waiting for STREAM data.

The sender retransmits the prefix and current reset information, charges the
final size against flow control once, and waits for both acknowledgements
before releasing send state. Reducing the reliable size preserves the original
error code and final size. A STOP_SENDING received after a reliable reset also
preserves that error code in the resulting RESET_STREAM.

## Session flow control

`RecvStream::final_size()` returns `None` until FIN or a reset supplies the
size. It includes the protocol header and bytes discarded by a reset; counting
only application reads would undercount session credit. The adapter subtracts
its stream header length and applies its own session accounting exactly once.

Use `received_final_size().await` to wait without consuming data, including
after `stop()`. Both APIs retain the size for the lifetime of the receive handle,
even after normal EOF or receive-state cleanup. A pending size waiter fails if
the connection closes before the size arrives. Keep the handle until accounting
is complete; dropping it releases its cached metadata.

Session flow-control capsules, per-session limits, and association of streams
with sessions are implemented above QUIC.

## Session keying material

With either rustls provider enabled, `Connection::export_keying_material` uses
the completed TLS 1.3 handshake. It returns `ExportKeyingMaterialError` if keying
material is unavailable or rustls rejects the requested output. It never uses
the early exporter.

For a WebTransport exporter, use the label `EXPORTER-WebTransport`. Build its
context from the session ID as an eight-byte big-endian integer, followed by a
one-byte application-label length and the label, then a one-byte context length
and the application context. Validate each application field's length before
encoding. Different session IDs must produce different exporter contexts.
Do not expose an arbitrary connection-wide TLS exporter as a session exporter.
