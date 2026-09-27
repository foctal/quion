# WebTransport prerequisites

quion provides QUIC streams, datagrams, and reliable stream resets that can
support a WebTransport implementation. It does not implement HTTP/3 or
WebTransport sessions.

## RESET_STREAM_AT

`quion` implements the QUIC Stream Resets with Partial Delivery extension:

- empty `reset_stream_at` transport parameter (`0x1d`)
- `RESET_STREAM_AT` frame (`0x24`)
- Final Size, Reliable Size, flow-control, and stream-state validation
- retransmission of the reliable STREAM prefix and the reset frame
- delayed reset delivery until the application consumes the reliable prefix
- public `SendStream::reset_at(error_code, reliable_size)` API

The extension is opt-in:

```rust
use quion::{TransportConfig, VarInt};

let mut transport = TransportConfig::default();
transport
    .set_reset_stream_at(true)
    .set_max_datagram_frame_size(Some(VarInt::from_u32(65_535)));
```

After the handshake, check
`Connection::negotiated_transport().is_some_and(|t| t.reset_stream_at)` before
using `SendStream::reset_at`. For a WebTransport data stream, pass a Reliable
Size that covers the complete stream header, including the session ID.

## Adapter Surface

An adapter can use the following transport APIs:

| WebTransport need | quion API |
| --- | --- |
| Open and accept streams | `Connection::{open,accept}_{bi,uni}` |
| Stream identification | `SendStream::id`, `RecvStream::id` |
| Async protocol codecs | Tokio `AsyncRead` and `AsyncWrite` implementations |
| Reliable reset | `SendStream::reset_at` |
| Reset observation | `RecvStream::received_reset` |
| QUIC datagrams | `Connection::send_datagram`, `Connection::read_datagram` |
| Peer capability | `NegotiatedTransport::reset_stream_at` |
| TLS identity and ALPN | `Connection::peer_identity`, `Connection::alpn_protocol` |
| Session close | `Connection::close`, `Connection::closed` |

## HTTP/3 requirements

`quion-h3` is reserved for future work. A WebTransport implementation still
needs HTTP/3 control streams, SETTINGS, QPACK, Extended CONNECT, and HTTP
Datagram support, along with session establishment and stream association.

For reliable resets, enable RESET_STREAM_AT on both peers and include the
complete WebTransport stream header in the reliable prefix. The transport
extension follows the
[QUIC reliable stream reset draft](https://quicwg.org/reliable-stream-reset/draft-ietf-quic-reliable-stream-reset.html).
