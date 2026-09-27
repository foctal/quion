# Release checklist

Release and publishing operations remain manual. Before selecting a release
candidate, retain the commands, environment, peer versions, durations, raw
results, and known failures with its validation records. Check logs for local
paths, credentials, and application data before sharing them.

- [ ] Review tracked files and crate contents for generated files and secrets
- [ ] Update the changelog and [known limitations](limitations.md)
- [ ] `cargo +1.88.0 check --workspace --all-targets --all-features`
- [ ] `cargo fmt --check --all`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo doc --workspace --all-features --no-deps`
- [ ] `cargo deny check`
- [ ] `cargo build --manifest-path fuzz/Cargo.toml --all-features`
- [ ] Complete the documented 24 CPU-hour fuzz budget for every target
- [ ] `cargo miri test -p quion-proto` for codec, ranges, streams, and tokens
- [ ] `QUION_SOAK_CONNECTIONS=100 ./scripts/soak.sh`
- [ ] `./scripts/interop/quiche-smoke.sh`
- [ ] `./scripts/interop/run-matrix.sh`
- [ ] Run comparative Quinn/quiche benchmarks and store raw output
- [ ] `./scripts/profile-runtime.sh` and retain CPU/runtime metric artifacts
- [ ] Verify Linux, macOS, and Windows library CI
- [ ] Verify the alternate rustls AWS-LC backend
- [ ] Review public API, defaults, security limits, and known failures

Do not publish, tag, create a release, or make production/competitive claims
from an incomplete checklist.
