#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

output_dir="${QUION_RUNTIME_PROFILE_OUTPUT_DIR:-${repo_root}/target/quion-runtime-profiles/$(date -u +%Y%m%dT%H%M%SZ)}"
trials="${QUION_RUNTIME_PROFILE_TRIALS:-5}"
warmup_bytes="${QUION_RUNTIME_PROFILE_WARMUP_BYTES:-4194304}"
measured_bytes="${QUION_RUNTIME_PROFILE_BYTES:-67108864}"
runtime_rustflags="${RUSTFLAGS:+${RUSTFLAGS} }--cfg tokio_unstable"
mkdir -p "${output_dir}"

build_output="$(RUSTFLAGS="${runtime_rustflags}" cargo build --release -p quion \
  --bench compare_quinn --all-features --message-format=json-render-diagnostics)"
benchmark_binary="$(printf '%s\n' "${build_output}" \
  | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' \
  | tail -n 1)"
if [[ -z "${benchmark_binary}" ]]; then
  echo "unable to resolve the compare_quinn benchmark executable" >&2
  exit 1
fi

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -a)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "benchmark_binary=${benchmark_binary}"
  echo "rustflags=${runtime_rustflags}"
  echo "trials=${trials}"
  echo "warmup_bytes_per_trial=${warmup_bytes}"
  echo "measured_bytes_per_trial=${measured_bytes}"
} >"${output_dir}/metadata.txt"

summary_file="${output_dir}/process-cpu.jsonl"
: >"${summary_file}"
for stack in quion quinn; do
  stdout_file="${output_dir}/${stack}-runtime-cost.jsonl"
  time_file="${output_dir}/${stack}-runtime-cost.time.txt"
  /usr/bin/time -p env \
    QUION_COMPARE_STACK="${stack}" \
    QUION_COMPARE_SCENARIO=runtime-cost \
    QUION_COMPARE_TRIALS="${trials}" \
    QUION_COMPARE_RUNTIME_WARMUP_BYTES="${warmup_bytes}" \
    QUION_COMPARE_RUNTIME_BYTES="${measured_bytes}" \
    "${benchmark_binary}" >"${stdout_file}" 2>"${time_file}"

  user_seconds="$(awk '$1 == "user" { print $2; exit }' "${time_file}")"
  system_seconds="$(awk '$1 == "sys" { print $2; exit }' "${time_file}")"
  if [[ -z "${user_seconds}" || -z "${system_seconds}" ]]; then
    echo "unable to parse process CPU time for ${stack}" >&2
    exit 1
  fi
  accounted_bytes=$((trials * (warmup_bytes + measured_bytes)))
  awk -v stack="${stack}" \
    -v trials="${trials}" \
    -v bytes="${accounted_bytes}" \
    -v user="${user_seconds}" \
    -v sys_time="${system_seconds}" \
    'BEGIN {
      cpu = user + sys_time;
      gib = bytes / (1024 * 1024 * 1024);
      printf "{\"benchmark\":\"process-cpu\",\"stack\":\"%s\",", stack;
      printf "\"trials\":%d,\"accounted_payload_bytes\":%d,", trials, bytes;
      printf "\"user_seconds\":%.6f,\"system_seconds\":%.6f,", user, sys_time;
      printf "\"cpu_seconds\":%.6f,\"cpu_seconds_per_gib\":%.6f}\n", cpu, cpu / gib;
    }' >>"${summary_file}"
done

echo "${output_dir}"
