# Benchmarking and profiling

Run benchmarks on the machines and network paths you intend to use. Loopback
measurements are useful for finding regressions, but do not establish
performance on real networks or across operating systems.

## Microbenchmarks

```sh
cargo bench -p quion-proto --bench congestion
cargo bench -p quion-proto --features rustls-ring --bench hot_paths
cargo bench -p quion-udp --bench udp --all-features
```

The protocol hot-path benchmark emits JSON for codecs, packet protection, ACK
ranges, recovery, datagrams, and connection-ID lookup. Set
`QUION_BENCH_ITERATIONS` to control its sample size. Congestion benchmarks
measure controller update cost, not network throughput or fairness.

## Quinn comparison

```sh
cargo bench -p quion --bench compare_quinn --all-features
```

The benchmark emits one JSON object per stack and scenario. Stream echo, bulk,
many-stream, active-stream, short-connection, and DATAGRAM scenarios also emit
allocator-call and requested-byte rates measured over the workload interval
with an instrumented system allocator.

The idle-connections scenario establishes a warmup population, then
reports connection-establishment allocations and the incremental live
requested bytes retained by the measured population. One loopback connection
includes both client-side and server-side state, so
`retained_bytes_per_connection` is the combined in-process cost of the two
peers. It is not process RSS and excludes allocator metadata, fragmentation,
TLS-library static state established before the snapshot, and kernel socket
memory. The comparison uses ring, CUBIC, identical ALPN, transport windows, a known-safe 1,452-byte loopback
initial MTU, 16 MiB UDP socket-buffer requests, disabled TLS resumption, and
the same ACK_FREQUENCY request of nine packets with a reordering threshold of
two on both stacks.

`QUION_COMPARE_STACK` selects `quion`, `quinn`, or `both`.
`QUION_COMPARE_SCENARIO` selects `handshake`, `stream-echo`, `bulk-stream`,
`many-streams`, `active-streams`, `short-connections`, `datagram`,
`idle-connections`, `recovery`, `endpoint-shutdown`, or `all`. These selectors
let external profilers isolate one implementation and workload without
changing benchmark parameters.

Set `QUION_COMPARE_TRIALS` to change the number of trials and
`QUION_COMPARE_DIAGNOSTICS=1` to write progress to standard error. For example:

```sh
mkdir -p target/benchmarks
QUION_COMPARE_TRIALS=15 QUION_COMPARE_SCENARIO=bulk-stream \
  cargo bench -p quion --bench compare_quinn --all-features \
  > target/benchmarks/compare-quinn.jsonl
```

Retain the revision, toolchain, feature flags, machine details, configuration,
and raw trials with any published comparison. Repeat measurements and report
variation, including cases where quion is slower or uses more memory.

## Allocation and resident memory profiles

```sh
./scripts/profile-allocations.sh all
```

The `call-sites` mode uses the symbolized `dhat` Cargo profile and writes
`*.dhat-heap.json` files. `QUION_PROFILE_CALLSITE_SCENARIO` selects the workload.
The `rss` mode runs each stack in separate processes at two idle-connection
populations and reports the difference in peak RSS per additional connection.
A loopback connection includes both endpoint roles. RSS depends on allocator
behavior, TLS configuration, operating-system accounting, and population size.

Outputs go under `target/quion-profiles` by default. Set
`QUION_PROFILE_OUTPUT_DIR` to use another directory. RSS profiling requires
macOS or Linux and `/usr/bin/time`.

## CPU and Tokio scheduler profiles

```sh
./scripts/profile-runtime.sh
```

This script builds the benchmark with `tokio_unstable` in an isolated Cargo
configuration. It runs quion and Quinn in separate processes and records worker
busy time, task polls, scheduling events, and process CPU time. Scheduling
events are not a direct count of `Waker::wake` calls: notifications may
coalesce, and spawning a task can also schedule it.

Use `QUION_RUNTIME_PROFILE_TRIALS`, `QUION_RUNTIME_PROFILE_WARMUP_BYTES`, and
`QUION_RUNTIME_PROFILE_BYTES` to configure the workload. Outputs go under
`target/quion-runtime-profiles`; `QUION_RUNTIME_PROFILE_OUTPUT_DIR` overrides
the location. Process CPU time includes setup and warmup.

## Experimental BBR3

The `unstable-bbr3` feature enables a model-based congestion controller. It is
not a complete implementation of BBRv3 and is not a production default.

```sh
cargo test -p quion-proto --features unstable-bbr3 congestion
cargo bench -p quion-proto --features unstable-bbr3 --bench congestion
```

## Tuning

Reuse endpoints to share their UDP socket and driver. Configure transport
windows and queue limits for the expected workload, and inspect diagnostics
when an application is blocked by backpressure. Socket buffer requests may be
clamped by the operating system, so check the effective values.

Benchmark equivalent TLS, congestion, MTU, ACK, stream-window, and socket
settings when comparing implementations. Allocation counters exclude allocator
metadata and kernel memory; short-connection samples taken immediately after
close may still include closing or draining state.
