# Architecture

quion is split into three transport layers:

- `quion-proto`: deterministic sans-IO protocol core.
- `quion-udp`: UDP socket and packet batch support.
- `quion`: user-facing async API that drives the protocol core.

The protocol core never performs socket I/O and never depends on a runtime. Time,
randomness, packet input, and application events are injected through explicit
interfaces so tests can reproduce state transitions exactly.

## UDP address families

`quion-udp` binds the exact `SocketAddr` supplied by the application. Bind an
IPv4 address such as `0.0.0.0:4433` to serve IPv4 peers, or an IPv6 address
such as `[::]:4433` to serve IPv6 peers. Dual-stack behavior for an IPv6
wildcard socket is controlled by the operating system and must not be relied on
for portable deployments; bind one IPv4 socket and one IPv6 socket when both
families are required. The portable fallback does not select a source address
or local interface per datagram, so multi-homed deployments should bind the
specific local address they intend to use.
