#!/usr/bin/env bash
set -euo pipefail

iterations="${QUION_SOAK_ITERATIONS:-100}"
connections="${QUION_SOAK_CONNECTIONS:-${iterations}}"
streams_per_connection="${QUION_SOAK_STREAMS_PER_CONNECTION:-32}"
datagrams_per_connection="${QUION_SOAK_DATAGRAMS_PER_CONNECTION:-32}"
payload_bytes="${QUION_SOAK_PAYLOAD_BYTES:-16384}"
timeout_seconds="${QUION_SOAK_TIMEOUT_SECONDS:-300}"

echo "soak connections=${connections} streams_per_connection=${streams_per_connection} datagrams_per_connection=${datagrams_per_connection} payload_bytes=${payload_bytes}"

cargo test -p quion --test loopback --all-features -- --test-threads=1

QUION_SOAK_CONNECTIONS="${connections}" \
QUION_SOAK_STREAMS_PER_CONNECTION="${streams_per_connection}" \
QUION_SOAK_DATAGRAMS_PER_CONNECTION="${datagrams_per_connection}" \
QUION_SOAK_PAYLOAD_BYTES="${payload_bytes}" \
QUION_SOAK_TIMEOUT_SECONDS="${timeout_seconds}" \
  cargo test -p quion --test soak --all-features -- --test-threads=1

cargo test -p quion-proto \
  recovery::loss::tests::ack_frame_removes_acked_packets_and_detects_old_losses \
  --all-features
cargo test -p quion-proto \
  recovery::loss::tests::pto_survives_many_ack_only_gaps_and_ack_cycles \
  --all-features
cargo test -p quion-proto \
  streams::tests::stream_map_enforces_aggregate_receive_buffer_limit \
  --all-features
cargo test -p quion-proto \
  streams::tests::recv_assembler_rejects_conflicting_overlap \
  --all-features
cargo test -p quion \
  connection::tests::authenticated_nat_rebinding_validates_before_switching_active_path \
  --all-features
cargo test -p quion \
  connection::tests::failed_candidate_path_keeps_original_active_path \
  --all-features
cargo test -p quion \
  endpoint::tests::retry_enabled_socket_handshake_flood_respects_endpoint_memory_limit \
  --all-features
cargo test -p quion \
  endpoint::tests::retry_disabled_socket_handshake_flood_respects_endpoint_memory_limit \
  --all-features
