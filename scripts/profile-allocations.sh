#!/usr/bin/env bash
set -euo pipefail

mode="${1:-all}"
case "${mode}" in
  rss | call-sites | all) ;;
  *)
    echo "usage: $0 [rss|call-sites|all]" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

output_dir="${QUION_PROFILE_OUTPUT_DIR:-${repo_root}/target/quion-profiles/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "${output_dir}"

build_benchmark() {
  local profile="$1"
  local build_output
  build_output="$(cargo build --profile "${profile}" -p quion --bench compare_quinn \
    --all-features --message-format=json-render-diagnostics)"
  local resolved
  resolved="$(printf '%s\n' "${build_output}" \
    | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' \
    | tail -n 1)"
  if [[ -z "${resolved}" ]]; then
    echo "unable to resolve the compare_quinn benchmark executable" >&2
    exit 1
  fi
  printf '%s\n' "${resolved}"
}

benchmark_binary="$(build_benchmark release)"

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -a)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "benchmark_binary=${benchmark_binary}"
  echo "mode=${mode}"
} >"${output_dir}/metadata.txt"

run_timed_idle_population() {
  local stack="$1"
  local connections="$2"
  local label="$3"
  local stdout_file="${output_dir}/${stack}-${label}.jsonl"
  local time_file="${output_dir}/${stack}-${label}.time.txt"

  if [[ "$(uname -s)" == "Darwin" ]]; then
    /usr/bin/time -l env \
      QUION_COMPARE_STACK="${stack}" \
      QUION_COMPARE_SCENARIO=idle-connections \
      QUION_COMPARE_TRIALS=1 \
      QUION_COMPARE_IDLE_CONNECTION_WARMUP="${QUION_PROFILE_IDLE_WARMUP:-8}" \
      QUION_COMPARE_IDLE_CONNECTIONS="${connections}" \
      "${benchmark_binary}" >"${stdout_file}" 2>"${time_file}"
    awk '/maximum resident set size/ { print $1; exit }' "${time_file}"
  elif [[ "$(uname -s)" == "Linux" ]]; then
    /usr/bin/time -v env \
      QUION_COMPARE_STACK="${stack}" \
      QUION_COMPARE_SCENARIO=idle-connections \
      QUION_COMPARE_TRIALS=1 \
      QUION_COMPARE_IDLE_CONNECTION_WARMUP="${QUION_PROFILE_IDLE_WARMUP:-8}" \
      QUION_COMPARE_IDLE_CONNECTIONS="${connections}" \
      "${benchmark_binary}" >"${stdout_file}" 2>"${time_file}"
    awk '/Maximum resident set size/ { print $NF * 1024; exit }' "${time_file}"
  else
    echo "RSS profiling supports macOS and Linux" >&2
    exit 1
  fi
}

run_rss_profiles() {
  local baseline="${QUION_PROFILE_RSS_BASELINE_CONNECTIONS:-16}"
  local measured="${QUION_PROFILE_RSS_MEASURED_CONNECTIONS:-256}"
  if (( measured <= baseline )); then
    echo "QUION_PROFILE_RSS_MEASURED_CONNECTIONS must exceed the baseline" >&2
    exit 2
  fi

  local result_file="${output_dir}/rss.jsonl"
  : >"${result_file}"
  for stack in quion quinn; do
    local baseline_rss
    local measured_rss
    baseline_rss="$(run_timed_idle_population "${stack}" "${baseline}" "rss-${baseline}")"
    measured_rss="$(run_timed_idle_population "${stack}" "${measured}" "rss-${measured}")"
    local connection_delta=$((measured - baseline))
    local rss_delta=$((measured_rss - baseline_rss))
    local bytes_per_connection
    bytes_per_connection="$(awk -v bytes="${rss_delta}" -v count="${connection_delta}" \
      'BEGIN { printf "%.0f", bytes / count }')"

    printf '{"benchmark":"idle-connections-rss","stack":"%s","baseline_connections":%d,' \
      "${stack}" "${baseline}" >>"${result_file}"
    printf '"measured_connections":%d,"baseline_peak_rss_bytes":%d,' \
      "${measured}" "${baseline_rss}" >>"${result_file}"
    printf '"measured_peak_rss_bytes":%d,"incremental_peak_rss_bytes":%d,' \
      "${measured_rss}" "${rss_delta}" >>"${result_file}"
    printf '"incremental_peak_rss_bytes_per_connection":%s}\n' \
      "${bytes_per_connection}" >>"${result_file}"
  done
}

run_call_site_profiles() {
  local scenario="${QUION_PROFILE_CALLSITE_SCENARIO:-stream-echo}"
  local echo_iterations="${QUION_PROFILE_CALLSITE_ECHO_ITERATIONS:-2000}"
  local bulk_bytes="${QUION_PROFILE_CALLSITE_BULK_BYTES:-8388608}"
  local datagrams="${QUION_PROFILE_CALLSITE_DATAGRAMS:-10000}"
  local many_streams="${QUION_PROFILE_CALLSITE_MANY_STREAMS:-1024}"
  local active_streams="${QUION_PROFILE_CALLSITE_ACTIVE_STREAMS:-1024}"
  local active_stream_warmup="${QUION_PROFILE_CALLSITE_ACTIVE_STREAM_WARMUP:-16}"
  local short_connections="${QUION_PROFILE_CALLSITE_SHORT_CONNECTIONS:-100}"
  local idle_connections="${QUION_PROFILE_CALLSITE_IDLE_CONNECTIONS:-256}"
  local recovery_bytes="${QUION_PROFILE_CALLSITE_RECOVERY_BYTES:-16777216}"
  local recovery_loss_interval="${QUION_PROFILE_CALLSITE_RECOVERY_LOSS_INTERVAL:-100}"
  local recovery_reorder_interval="${QUION_PROFILE_CALLSITE_RECOVERY_REORDER_INTERVAL:-50}"
  local summary_file="${output_dir}/dhat-summary.jsonl"
  : >"${summary_file}"

  benchmark_binary="$(build_benchmark dhat)"
  echo "dhat_benchmark_binary=${benchmark_binary}" >>"${output_dir}/metadata.txt"

  for stack in quion quinn; do
    local profile_env=(
      "QUION_COMPARE_STACK=${stack}"
      "QUION_COMPARE_SCENARIO=${scenario}"
      "QUION_COMPARE_TRIALS=1"
      "QUION_COMPARE_ECHO_WARMUP=${QUION_PROFILE_CALLSITE_ECHO_WARMUP:-100}"
      "QUION_COMPARE_ECHO_ITERATIONS=${echo_iterations}"
      "QUION_COMPARE_BULK_BYTES=${bulk_bytes}"
      "QUION_COMPARE_DATAGRAMS=${datagrams}"
      "QUION_COMPARE_MANY_STREAMS=${many_streams}"
      "QUION_COMPARE_ACTIVE_STREAMS=${active_streams}"
      "QUION_COMPARE_ACTIVE_STREAM_WARMUP=${active_stream_warmup}"
      "QUION_COMPARE_SHORT_CONNECTIONS=${short_connections}"
      "QUION_COMPARE_IDLE_CONNECTION_WARMUP=${QUION_PROFILE_IDLE_WARMUP:-8}"
      "QUION_COMPARE_IDLE_CONNECTIONS=${idle_connections}"
      "QUION_COMPARE_RECOVERY_BYTES=${recovery_bytes}"
      "QUION_COMPARE_RECOVERY_LOSS_INTERVAL=${recovery_loss_interval}"
      "QUION_COMPARE_RECOVERY_REORDER_INTERVAL=${recovery_reorder_interval}"
      "QUION_DHAT_OUTPUT=${output_dir}/${stack}-${scenario}.dhat-heap.json"
    )
    env "${profile_env[@]}" "${benchmark_binary}" \
      >"${output_dir}/${stack}-${scenario}.jsonl" \
      2>"${output_dir}/${stack}-${scenario}.dhat.txt"

    local total_bytes
    local total_blocks
    local peak_bytes
    local peak_blocks
    local end_bytes
    local end_blocks
    total_bytes="$(awk '/dhat: Total:/ { gsub(",", "", $3); print $3; exit }' \
      "${output_dir}/${stack}-${scenario}.dhat.txt")"
    total_blocks="$(awk '/dhat: Total:/ { gsub(",", "", $6); print $6; exit }' \
      "${output_dir}/${stack}-${scenario}.dhat.txt")"
    peak_bytes="$(awk '/dhat: At t-gmax:/ { gsub(",", "", $4); print $4; exit }' \
      "${output_dir}/${stack}-${scenario}.dhat.txt")"
    peak_blocks="$(awk '/dhat: At t-gmax:/ { gsub(",", "", $7); print $7; exit }' \
      "${output_dir}/${stack}-${scenario}.dhat.txt")"
    end_bytes="$(awk '/dhat: At t-end:/ { gsub(",", "", $4); print $4; exit }' \
      "${output_dir}/${stack}-${scenario}.dhat.txt")"
    end_blocks="$(awk '/dhat: At t-end:/ { gsub(",", "", $7); print $7; exit }' \
      "${output_dir}/${stack}-${scenario}.dhat.txt")"
    printf '{"benchmark":"dhat-call-sites","stack":"%s","scenario":"%s",' \
      "${stack}" "${scenario}" >>"${summary_file}"
    printf '"total_bytes":%s,"total_blocks":%s,"peak_bytes":%s,' \
      "${total_bytes}" "${total_blocks}" "${peak_bytes}" >>"${summary_file}"
    printf '"peak_blocks":%s,"end_bytes":%s,"end_blocks":%s}\n' \
      "${peak_blocks}" "${end_bytes}" "${end_blocks}" >>"${summary_file}"
  done
}

if [[ "${mode}" == "rss" || "${mode}" == "all" ]]; then
  run_rss_profiles
fi
if [[ "${mode}" == "call-sites" || "${mode}" == "all" ]]; then
  run_call_site_profiles
fi

echo "${output_dir}"
