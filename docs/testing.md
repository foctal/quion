# Testing

Unit and integration tests cover codecs, packet protection, handshakes,
streams, flow control, loss recovery, resource limits, and endpoint lifecycle.
Property tests exercise codecs and ranges. The fuzz crate includes parser,
connection-state, and protected-packet targets.

## Continuous integration

The main CI job runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --lib --bins --tests -- -D warnings
cargo test --workspace
python3 scripts/interop/test-matrix.py
python3 scripts/test-benchmark-summary.py
```

Automatic CI also runs bare, ring-only, AWS-LC-only, and all-feature tests
and rustdoc warning checks, the Rust 1.88 MSRV check, dependency policy, and
high-level loopback/regression tests on Linux, macOS, and Windows. The manually
dispatched `Extended validation` workflow adds fuzz, Miri, soak, external interop,
and benchmark work. Release candidates must additionally run:

```sh
./scripts/fuzz-smoke.sh
QUION_SOAK_CONNECTIONS=100 ./scripts/soak.sh
./scripts/interop/quiche-smoke.sh
./scripts/interop/run-matrix.sh
cargo bench -p quion-proto --bench congestion
cargo bench -p quion-udp --bench udp --all-features
./scripts/profile-allocations.sh all
./scripts/profile-runtime.sh
```

The manually dispatched workflow's one-minute fuzz runs are regression smoke
tests; they do not replace the release fuzzing budget below.

`scripts/profile-allocations.sh rss` runs the quion and Quinn idle-connection
scenarios in separate child processes at configurable baseline and measured
populations. It records peak RSS from `/usr/bin/time` and emits the population
slope as JSON. `scripts/profile-allocations.sh call-sites` builds the dedicated
symbolized `dhat` Cargo profile and emits one DHAT heap artifact plus a compact
JSON summary per stack. Outputs default to a timestamped directory under
`target/quion-profiles`; set `QUION_PROFILE_OUTPUT_DIR` to retain them as CI
artifacts. `QUION_PROFILE_CALLSITE_SCENARIO` selects the isolated workload;
the corresponding `QUION_PROFILE_CALLSITE_BULK_BYTES`, `DATAGRAMS`,
`MANY_STREAMS`, `ACTIVE_STREAMS`, `ACTIVE_STREAM_WARMUP`,
`SHORT_CONNECTIONS`, `ECHO_ITERATIONS`, `IDLE_CONNECTIONS`, `RECOVERY_BYTES`,
`RECOVERY_LOSS_INTERVAL`, and `RECOVERY_REORDER_INTERVAL` variables set its
size and deterministic impairment. The extended workflow executes both modes.

`scripts/profile-runtime.sh` builds the comparison benchmark with
`tokio_unstable` in an isolated Cargo configuration and runs quion and Quinn in
separate processes. It records per-trial Tokio worker busy time, task polls and
task scheduling events, plus whole-process POSIX user and system CPU time.
`QUION_RUNTIME_PROFILE_TRIALS`, `QUION_RUNTIME_PROFILE_WARMUP_BYTES`, and
`QUION_RUNTIME_PROFILE_BYTES` configure the workload; use
`QUION_RUNTIME_PROFILE_OUTPUT_DIR` to select the retained artifact directory.

The `endpoint-shutdown` comparison is part of the normal `compare_quinn`
benchmark and therefore of the extended release gate. It measures complete
connection removal from both endpoint registries after bilateral graceful
close. `QUION_COMPARE_SHUTDOWNS` controls the independent endpoint pairs per
trial; `QUION_COMPARE_SCENARIO=endpoint-shutdown` isolates the workload.

## Soak profiles

`scripts/soak.sh` runs the normal loopback suite, two integration workloads,
and focused robustness regressions for PTO/loss recovery, conflicting stream
overlap, NAT rebinding validation, and Retry-enabled and Retry-disabled
admission floods. The configurable workload performs sequential connection
churn, multiple bidirectional stream echoes and DATAGRAM echoes per connection,
checks that terminal stream payload memory reaches a plateau, and verifies
that endpoint abort releases all shared payload reservations.

The second integration workload routes both directions through a deterministic
UDP fault proxy. It transfers eight 512 KiB bidirectional stream echoes and
best-effort DATAGRAM traffic while dropping every 37th packet, holding and
reordering every 23rd packet, and duplicating every 29th packet after the
initial handshake flight. The test requires actual loss declarations and
retransmissions, verifies that every fault class was injected in both
directions, and checks endpoint memory release after shutdown. DATAGRAM
submission is paced until the server confirms the first delivery, so the
best-effort assertion does not depend on a fixed scheduler delay. Endpoint
reservation cleanup has a two-second bound and still fails on a retained-byte
leak.

The workload accepts:

- `QUION_SOAK_CONNECTIONS`
- `QUION_SOAK_STREAMS_PER_CONNECTION`
- `QUION_SOAK_DATAGRAMS_PER_CONNECTION`
- `QUION_SOAK_PAYLOAD_BYTES`
- `QUION_SOAK_TIMEOUT_SECONDS`

`QUION_SOAK_ITERATIONS` remains a compatibility alias for the connection count
when `QUION_SOAK_CONNECTIONS` is unset. The extended workflow uses 100
connections, 32 streams and 32 DATAGRAMs per connection, and 16 KiB stream
payloads. This deterministic loopback profile is a regression gate; it does
not replace multi-hour impaired-network or idle-connection tests.

## Fuzzing policy

The manual release workflow builds and smoke-runs every fuzz target. Routine
pull-request CI does neither, keeping per-change validation lightweight.

Before a release candidate, run every target with a shared corpus for at least
24 CPU-hours per target, retain the resulting corpus, and record the exact
command, toolchain, operating system, elapsed CPU time, corpus revision, and
crash status with the release validation records. A clean smoke run or a
successful build alone does not satisfy this requirement.

For example:

```sh
cd fuzz
cargo fuzz run --features fuzzing connection_sequence corpus/connection_sequence -- -max_total_time=86400
```

The `fuzzing` feature is mandatory: without it, these targets compile a no-op
fallback main. The smoke script and extended workflow enable it and load
checked-in regression seeds. Extended CI caches and uploads corpora and crash
artifacts.

`connection_sequence` limits each execution to 256 operations and mixes frame
input, application consumption/stop/open/accept, timeout advancement, and
transmits, asserting bounded stream metadata. It uses frame dispatch rather
than authenticated endpoint routing. Runtime cancellation/progress invariants
still need dedicated fuzz targets.
`endpoint_sequence` separately interleaves CID ownership and retirement,
Initial admission, path churn, and amplification accounting against a bounded
reference model. It does not perform an authenticated TLS handshake or fuzz
established key transitions. `protected_sequence` creates real rustls application
keys, then interleaves protected packets, sender key updates, receiver old-key
retirement, corruption, duplicates, reordering, reads, and timers. Each case is
bounded to 128 operations and eight queued packets. It does not exercise runtime
cancellation or a complete bidirectional recovery exchange. All three stateful
targets have checked-in seeds.
