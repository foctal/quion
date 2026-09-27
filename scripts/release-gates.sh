#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo deny check
cargo build --manifest-path fuzz/Cargo.toml --all-features

if [[ "${QUION_RELEASE_EXTENDED:-0}" == "1" ]]; then
  ./scripts/fuzz-smoke.sh
  ./scripts/soak.sh
  ./scripts/interop/quiche-smoke.sh
  ./scripts/interop/run-matrix.sh
  cargo bench -p quion-proto --bench congestion
  cargo bench -p quion-proto --bench hot_paths
  cargo bench -p quion-udp --bench udp --all-features
  cargo bench -p quion --bench compare_quinn
  ./scripts/profile-allocations.sh all
  ./scripts/profile-runtime.sh
fi
