#!/usr/bin/env bash
set -euo pipefail

peers=(quinn quiche ngtcp2 s2n-quic msquic)
scenarios=(
  client-handshake
  server-handshake
  stream-transfer
  datagram
  retry
  version-negotiation
  close
  idle-timeout
)

if [[ "${QUION_INTEROP_ZERO_RTT:-0}" == "1" ]]; then
  scenarios+=(zero-rtt)
fi

for peer in "${peers[@]}"; do
  adapter="quion-interop-${peer}"
  if ! command -v "${adapter}" >/dev/null 2>&1; then
    echo "missing interop adapter: ${adapter}" >&2
    exit 2
  fi
  for scenario in "${scenarios[@]}"; do
    case "$scenario" in
      client-handshake) roles=(client) ;;
      server-handshake) roles=(server) ;;
      *) roles=(client server) ;;
    esac
    for role in "${roles[@]}"; do
      echo "interop peer=${peer} scenario=${scenario} role=${role}"
      "${adapter}" --scenario "$scenario" --role "$role"
    done
  done
done
