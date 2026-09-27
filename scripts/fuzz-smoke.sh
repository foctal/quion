#!/usr/bin/env bash
set -euo pipefail

seconds="${QUION_FUZZ_SMOKE_SECONDS:-60}"
toolchain="${QUION_FUZZ_TOOLCHAIN:-nightly}"
targets=(
  packet_decode
  coalesced_packet_decode
  frame_decode
  transport_parameters
  retry_validation
  version_negotiation
  crypto_frame_buffer
  stream_assembler
  protected_initial_open
  connection_receive
  connection_sequence
  endpoint_sequence
  protected_sequence
)

for target in "${targets[@]}"; do
  (
    cd fuzz
    mkdir -p "corpus/${target}"
    if [[ -d "seeds/${target}" ]]; then
      cp "seeds/${target}/"* "corpus/${target}/"
    fi
    cargo "+${toolchain}" fuzz run --features fuzzing "${target}" -- "-max_total_time=${seconds}" -timeout=10
  )
done
