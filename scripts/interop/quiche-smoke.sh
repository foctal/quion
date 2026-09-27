#!/usr/bin/env bash
set -euo pipefail

readonly QUICHE_IMAGE_DEFAULT="cloudflare/quiche@sha256:2356a63ac61f1b578dfff266382a9667cb92e9fc246fda46c5dc2f69206b81e0"
readonly QUICHE_IMAGE="${QUION_QUICHE_IMAGE:-${QUICHE_IMAGE_DEFAULT}}"
readonly QUICHE_PLATFORM="${QUION_QUICHE_PLATFORM:-linux/amd64}"
readonly QUICHE_SERVER_PORT="${QUION_QUICHE_SERVER_PORT:-44330}"
readonly QUION_SERVER_PORT="${QUION_QUICHE_QUION_SERVER_PORT:-44331}"
readonly IDLE_TIMEOUT_MS="${QUION_QUICHE_IDLE_TIMEOUT_MS:-250}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for the pinned quiche interoperability smoke test" >&2
  exit 2
fi

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_directory="$(mktemp -d)"
quiche_server_container="quion-quiche-server-$$"
quion_server_pid=""

cleanup() {
  status="$1"
  if [[ "${status}" -ne 0 && -n "${quiche_server_container}" ]]; then
    docker logs "${quiche_server_container}" >&2 || true
  fi
  if [[ -n "${quion_server_pid}" ]]; then
    kill "${quion_server_pid}" >/dev/null 2>&1 || true
    wait "${quion_server_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${quiche_server_container}" ]]; then
    docker rm -f "${quiche_server_container}" >/dev/null 2>&1 || true
  fi
  rm -rf "${test_directory}"
}

wait_for_container_log() {
  local container_name="$1"
  local pattern="$2"
  local output_path="$3"
  for _ in {1..50}; do
    docker logs "${container_name}" >"${output_path}" 2>&1 || true
    if grep -Fq "${pattern}" "${output_path}"; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

trap 'status=$?; trap - EXIT; cleanup "${status}"; exit "${status}"' EXIT

cert_path="${test_directory}/certificate.pem"
key_path="${test_directory}/private-key.pem"
expected_path="${test_directory}/quion-interop"
quion_client_output="${test_directory}/quion-client-response"
quiche_client_output="${test_directory}/quiche-client-response"
mkdir -p "${quiche_client_output}"

cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  identity \
  "${cert_path}" \
  "${key_path}"
printf '%s' "quiche and quion transport interoperability" >"${expected_path}"

echo "interop peer=quiche role=server-under-test scenarios=handshake,stream,retry,close"
docker run \
  --detach \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  --name "${quiche_server_container}" \
  --env RUST_LOG=trace \
  --publish "127.0.0.1:${QUICHE_SERVER_PORT}:4433/udp" \
  --volume "${cert_path}:/cert.pem:ro" \
  --volume "${key_path}:/key.pem:ro" \
  --volume "${test_directory}:/www:ro" \
  "${QUICHE_IMAGE}" \
  quiche-server \
  --listen "0.0.0.0:4433" \
  --cert /cert.pem \
  --key /key.pem \
  --root /www \
  --no-grease \
  --disable-gso \
  --http-version HTTP/0.9 \
  >/dev/null
sleep 1

cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  client-retry \
  "127.0.0.1:${QUICHE_SERVER_PORT}" \
  "${cert_path}" \
  "${quion_client_output}"
cmp "${expected_path}" "${quion_client_output}"
if ! wait_for_container_log \
  "${quiche_server_container}" \
  "rx frm APPLICATION_CLOSE err=51" \
  "${test_directory}/quiche-close-server.log"; then
  echo "quiche server did not observe quion's application close" >&2
  cat "${test_directory}/quiche-close-server.log" >&2
  exit 1
fi
docker rm -f "${quiche_server_container}" >/dev/null
quiche_server_container=""

echo "interop peer=quiche role=client-under-test scenarios=handshake,stream,retry,close"
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  server-retry \
  "0.0.0.0:${QUION_SERVER_PORT}" \
  "${cert_path}" \
  "${key_path}" \
  "${expected_path}" &
quion_server_pid="$!"
sleep 1

if [[ "$(uname -s)" == "Linux" ]]; then
  docker run \
    --rm \
    --platform "${QUICHE_PLATFORM}" \
    --network host \
    --volume "${quiche_client_output}:/responses" \
    "${QUICHE_IMAGE}" \
    quiche-client \
    --wire-version 1 \
    --http-version HTTP/0.9 \
    --no-verify \
    --no-grease \
    --connect-to "127.0.0.1:${QUION_SERVER_PORT}" \
    --dump-responses /responses \
    "https://localhost/quion-interop"
else
  docker_host_ip="$(
    docker run \
      --rm \
      --platform "${QUICHE_PLATFORM}" \
      --add-host "host.docker.internal:host-gateway" \
      --entrypoint /bin/sh \
      "${QUICHE_IMAGE}" \
      -c "getent ahostsv4 host.docker.internal" |
      awk 'NR == 1 { print $1 }'
  )"
  if [[ -z "${docker_host_ip}" ]]; then
    echo "could not resolve the Docker Desktop host gateway" >&2
    exit 1
  fi
  docker run \
    --rm \
    --platform "${QUICHE_PLATFORM}" \
    --add-host "host.docker.internal:host-gateway" \
    --volume "${quiche_client_output}:/responses" \
    "${QUICHE_IMAGE}" \
    quiche-client \
    --wire-version 1 \
    --http-version HTTP/0.9 \
    --no-verify \
    --no-grease \
    --connect-to "${docker_host_ip}:${QUION_SERVER_PORT}" \
    --dump-responses /responses \
    "https://localhost/quion-interop"
fi

wait "${quion_server_pid}"
quion_server_pid=""

response_file="$(find "${quiche_client_output}" -type f -print -quit)"
if [[ -z "${response_file}" ]]; then
  echo "quiche client did not write a response" >&2
  exit 1
fi
cmp "${expected_path}" "${response_file}"

quiche_server_container="quion-quiche-version-negotiation-server-$$"
echo "interop peer=quiche role=server-under-test scenarios=version-negotiation,handshake,stream"
docker run \
  --detach \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  --name "${quiche_server_container}" \
  --env RUST_LOG=trace \
  --publish "127.0.0.1:${QUICHE_SERVER_PORT}:4433/udp" \
  --volume "${cert_path}:/cert.pem:ro" \
  --volume "${key_path}:/key.pem:ro" \
  --volume "${test_directory}:/www:ro" \
  "${QUICHE_IMAGE}" \
  quiche-server \
  --listen "0.0.0.0:4433" \
  --cert /cert.pem \
  --key /key.pem \
  --root /www \
  --no-retry \
  --no-grease \
  --disable-gso \
  --http-version HTTP/0.9 \
  >/dev/null
sleep 1
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  client-version-negotiation \
  "127.0.0.1:${QUICHE_SERVER_PORT}" \
  "${cert_path}" \
  "${quion_client_output}"
cmp "${expected_path}" "${quion_client_output}"
if ! wait_for_container_log \
  "${quiche_server_container}" \
  "Doing version negotiation" \
  "${test_directory}/quiche-version-negotiation-server.log"; then
  echo "quiche server did not report Version Negotiation" >&2
  cat "${test_directory}/quiche-version-negotiation-server.log" >&2
  exit 1
fi
docker rm -f "${quiche_server_container}" >/dev/null
quiche_server_container=""

quiche_version_client_output="${test_directory}/quiche-version-client-response"
mkdir -p "${quiche_version_client_output}"
echo "interop peer=quiche role=client-under-test scenarios=version-negotiation,handshake,stream"
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  server-version-negotiation \
  "0.0.0.0:${QUION_SERVER_PORT}" \
  "${cert_path}" \
  "${key_path}" \
  "${expected_path}" &
quion_server_pid="$!"
sleep 1
if [[ "$(uname -s)" == "Linux" ]]; then
  version_client_network_args=(--network host)
  version_client_connect_addr="127.0.0.1:${QUION_SERVER_PORT}"
else
  version_client_network_args=(--add-host "host.docker.internal:host-gateway")
  version_client_connect_addr="${docker_host_ip}:${QUION_SERVER_PORT}"
fi
docker run \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  "${version_client_network_args[@]}" \
  --volume "${quiche_version_client_output}:/responses" \
  "${QUICHE_IMAGE}" \
  quiche-client \
  --http-version HTTP/0.9 \
  --no-verify \
  --no-grease \
  --connect-to "${version_client_connect_addr}" \
  --dump-responses /responses \
  "https://localhost/quion-interop"
wait "${quion_server_pid}"
quion_server_pid=""
version_response_file="$(find "${quiche_version_client_output}" -type f -print -quit)"
if [[ -z "${version_response_file}" ]]; then
  echo "quiche client did not write a response after Version Negotiation" >&2
  exit 1
fi
cmp "${expected_path}" "${version_response_file}"

quiche_server_container="quion-quiche-zero-rtt-server-$$"
echo "interop peer=quiche role=server-under-test scenarios=zero-rtt"
docker run \
  --detach \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  --name "${quiche_server_container}" \
  --env RUST_LOG=info \
  --publish "127.0.0.1:${QUICHE_SERVER_PORT}:4433/udp" \
  --volume "${cert_path}:/cert.pem:ro" \
  --volume "${key_path}:/key.pem:ro" \
  --volume "${test_directory}:/www:ro" \
  "${QUICHE_IMAGE}" \
  quiche-server \
  --listen "0.0.0.0:4433" \
  --cert /cert.pem \
  --key /key.pem \
  --root /www \
  --early-data \
  --no-retry \
  --no-grease \
  --disable-gso \
  --http-version HTTP/0.9 \
  >/dev/null
sleep 1
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  client-zero-rtt \
  "127.0.0.1:${QUICHE_SERVER_PORT}" \
  "${cert_path}" \
  "${quion_client_output}"
cmp "${expected_path}" "${quion_client_output}"
docker rm -f "${quiche_server_container}" >/dev/null
quiche_server_container=""

quiche_zero_rtt_session="${test_directory}/quiche-zero-rtt-session"
quiche_zero_rtt_first_output="${test_directory}/quiche-zero-rtt-first-response"
quiche_zero_rtt_resumed_output="${test_directory}/quiche-zero-rtt-resumed-response"
mkdir -p \
  "${quiche_zero_rtt_session}" \
  "${quiche_zero_rtt_first_output}" \
  "${quiche_zero_rtt_resumed_output}"
echo "interop peer=quiche role=client-under-test scenarios=zero-rtt"
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  server-zero-rtt \
  "0.0.0.0:${QUION_SERVER_PORT}" \
  "${cert_path}" \
  "${key_path}" \
  "${expected_path}" &
quion_server_pid="$!"
sleep 1
docker run \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  "${version_client_network_args[@]}" \
  --volume "${quiche_zero_rtt_session}:/session" \
  --volume "${quiche_zero_rtt_first_output}:/responses" \
  "${QUICHE_IMAGE}" \
  quiche-client \
  --wire-version 1 \
  --http-version HTTP/0.9 \
  --session-file /session/ticket \
  --no-verify \
  --no-grease \
  --connect-to "${version_client_connect_addr}" \
  --dump-responses /responses \
  "https://localhost/quion-interop"
docker run \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  "${version_client_network_args[@]}" \
  --volume "${quiche_zero_rtt_session}:/session" \
  --volume "${quiche_zero_rtt_resumed_output}:/responses" \
  "${QUICHE_IMAGE}" \
  quiche-client \
  --wire-version 1 \
  --http-version HTTP/0.9 \
  --session-file /session/ticket \
  --early-data \
  --no-verify \
  --no-grease \
  --connect-to "${version_client_connect_addr}" \
  --dump-responses /responses \
  "https://localhost/quion-interop"
wait "${quion_server_pid}"
quion_server_pid=""
zero_rtt_first_response="$(find "${quiche_zero_rtt_first_output}" -type f -print -quit)"
zero_rtt_resumed_response="$(find "${quiche_zero_rtt_resumed_output}" -type f -print -quit)"
if [[ -z "${zero_rtt_first_response}" || -z "${zero_rtt_resumed_response}" ]]; then
  echo "quiche client did not write both 0-RTT scenario responses" >&2
  exit 1
fi
cmp "${expected_path}" "${zero_rtt_first_response}"
cmp "${expected_path}" "${zero_rtt_resumed_response}"

quiche_server_container="quion-quiche-datagram-server-$$"
echo "interop peer=quiche role=server-under-test scenarios=datagram"
docker run \
  --detach \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  --name "${quiche_server_container}" \
  --env RUST_LOG=info \
  --publish "127.0.0.1:${QUICHE_SERVER_PORT}:4433/udp" \
  --volume "${cert_path}:/cert.pem:ro" \
  --volume "${key_path}:/key.pem:ro" \
  --volume "${test_directory}:/www:ro" \
  "${QUICHE_IMAGE}" \
  quiche-server \
  --listen "0.0.0.0:4433" \
  --cert /cert.pem \
  --key /key.pem \
  --root /www \
  --no-retry \
  --no-grease \
  --disable-gso \
  --http-version HTTP/3 \
  --dgram-proto oneway \
  --dgram-count 1 \
  --dgram-data quiche-server \
  >/dev/null
sleep 1
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  client-datagram \
  "127.0.0.1:${QUICHE_SERVER_PORT}" \
  "${cert_path}" \
  quion-client \
  quiche-server
if ! wait_for_container_log \
  "${quiche_server_container}" \
  "Received DATAGRAM flow_id=0 len=13 data=[113, 117, 105, 111, 110, 45, 99, 108, 105, 101, 110, 116]" \
  "${test_directory}/quiche-datagram-server.log"; then
  echo "quiche server did not receive quion's expected DATAGRAM bytes" >&2
  cat "${test_directory}/quiche-datagram-server.log" >&2
  exit 1
fi
docker rm -f "${quiche_server_container}" >/dev/null
quiche_server_container=""

echo "interop peer=quiche role=client-under-test scenarios=datagram"
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  server-datagram \
  "0.0.0.0:${QUION_SERVER_PORT}" \
  "${cert_path}" \
  "${key_path}" \
  quiche-client \
  quion-server &
quion_server_pid="$!"
sleep 1
if [[ "$(uname -s)" == "Linux" ]]; then
  datagram_client_network_args=(--network host)
  datagram_client_connect_addr="127.0.0.1:${QUION_SERVER_PORT}"
else
  datagram_client_network_args=(--add-host "host.docker.internal:host-gateway")
  datagram_client_connect_addr="${docker_host_ip}:${QUION_SERVER_PORT}"
fi
if docker run \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  "${datagram_client_network_args[@]}" \
  --env RUST_LOG=info \
  "${QUICHE_IMAGE}" \
  quiche-client \
  --wire-version 1 \
  --http-version HTTP/3 \
  --dgram-proto oneway \
  --dgram-count 1 \
  --dgram-data quiche-client \
  --no-verify \
  --no-grease \
  --connect-to "${datagram_client_connect_addr}" \
  "https://localhost/quion-interop" \
  >"${test_directory}/quiche-datagram-client.log" 2>&1; then
  quiche_datagram_client_status=0
else
  quiche_datagram_client_status="$?"
fi
wait "${quion_server_pid}"
quion_server_pid=""
if ! grep -Fq \
  "Received DATAGRAM flow_id=1 len=13 data=[113, 117, 105, 111, 110, 45, 115, 101, 114, 118, 101, 114]" \
  "${test_directory}/quiche-datagram-client.log"; then
  echo "quiche client did not receive quion's expected DATAGRAM bytes" >&2
  cat "${test_directory}/quiche-datagram-client.log" >&2
  exit 1
fi
if [[ "${quiche_datagram_client_status}" -ne 0 && "${quiche_datagram_client_status}" -ne 254 ]]; then
  echo "quiche client returned unexpected status ${quiche_datagram_client_status}" >&2
  cat "${test_directory}/quiche-datagram-client.log" >&2
  exit 1
fi

quiche_server_container="quion-quiche-idle-server-$$"
echo "interop peer=quiche role=server-under-test scenarios=idle-timeout"
docker run \
  --detach \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  --name "${quiche_server_container}" \
  --env RUST_LOG=trace \
  --publish "127.0.0.1:${QUICHE_SERVER_PORT}:4433/udp" \
  --volume "${cert_path}:/cert.pem:ro" \
  --volume "${key_path}:/key.pem:ro" \
  "${QUICHE_IMAGE}" \
  quiche-server \
  --listen "0.0.0.0:4433" \
  --cert /cert.pem \
  --key /key.pem \
  --no-retry \
  --no-grease \
  --disable-gso \
  --idle-timeout "${IDLE_TIMEOUT_MS}" \
  --http-version HTTP/0.9 \
  >/dev/null
sleep 1
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  client-idle \
  "127.0.0.1:${QUICHE_SERVER_PORT}" \
  "${cert_path}" \
  "${IDLE_TIMEOUT_MS}"
if ! wait_for_container_log \
  "${quiche_server_container}" \
  "timed out" \
  "${test_directory}/quiche-idle-server.log"; then
  echo "quiche server did not report the negotiated idle timeout" >&2
  cat "${test_directory}/quiche-idle-server.log" >&2
  exit 1
fi
docker rm -f "${quiche_server_container}" >/dev/null
quiche_server_container=""

echo "interop peer=quiche role=client-under-test scenarios=idle-timeout"
cargo run \
  --quiet \
  -p quion \
  --example hq_interop \
  --all-features \
  -- \
  server-idle \
  "0.0.0.0:${QUION_SERVER_PORT}" \
  "${cert_path}" \
  "${key_path}" \
  "${IDLE_TIMEOUT_MS}" &
quion_server_pid="$!"
sleep 1
if [[ "$(uname -s)" == "Linux" ]]; then
  idle_client_network_args=(--network host)
  idle_client_connect_addr="127.0.0.1:${QUION_SERVER_PORT}"
else
  idle_client_network_args=(--add-host "host.docker.internal:host-gateway")
  idle_client_connect_addr="${docker_host_ip}:${QUION_SERVER_PORT}"
fi
if docker run \
  --rm \
  --platform "${QUICHE_PLATFORM}" \
  "${idle_client_network_args[@]}" \
  --env RUST_LOG=trace \
  --volume "${quiche_client_output}:/responses" \
  "${QUICHE_IMAGE}" \
  quiche-client \
  --wire-version 1 \
  --http-version HTTP/0.9 \
  --idle-timeout "${IDLE_TIMEOUT_MS}" \
  --no-verify \
  --no-grease \
  --connect-to "${idle_client_connect_addr}" \
  --dump-responses /responses \
  "https://localhost/quion-interop" \
  >"${test_directory}/quiche-idle-client.log" 2>&1; then
  quiche_idle_client_status=0
else
  quiche_idle_client_status="$?"
fi
wait "${quion_server_pid}"
quion_server_pid=""
if ! grep -qi "timed out" "${test_directory}/quiche-idle-client.log"; then
  echo "quiche client did not report the negotiated idle timeout" >&2
  cat "${test_directory}/quiche-idle-client.log" >&2
  exit 1
fi
if [[ "${quiche_idle_client_status}" -ne 0 && "${quiche_idle_client_status}" -ne 254 ]]; then
  echo "quiche client returned unexpected status ${quiche_idle_client_status}" >&2
  cat "${test_directory}/quiche-idle-client.log" >&2
  exit 1
fi

echo "quiche interoperability smoke test passed"
