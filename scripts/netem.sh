#!/usr/bin/env bash
# TEST-2: netem fault injection for the Docker harness.
#
# Usage: scripts/netem.sh <service> <preset>
#   <service>  compose service name: alpha | beta
#   <preset>   latency | loss | reorder | clear
#
# Presets (applied to the container's eth0 egress via `tc qdisc`):
#   latency  - 200ms +/- 50ms delay
#   loss     - 10% packet loss
#   reorder  - 50ms delay with 25% of packets reordered (50% correlation)
#   clear    - remove any netem qdisc (restore normal networking)
#
# Requires the container to have NET_ADMIN (set in docker-compose.yml) and
# iproute2 (installed in the runtime image). Run from the repo root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/../docker/docker-compose.yml"
COMPOSE=(docker compose -f "${COMPOSE_FILE}")

IFACE="${NETEM_IFACE:-eth0}"

usage() {
    echo "usage: $0 <alpha|beta> <latency|loss|reorder|clear>" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
SERVICE="$1"
PRESET="$2"

case "${SERVICE}" in
    alpha | beta) ;;
    *) echo "unknown service: ${SERVICE}" >&2; usage ;;
esac

# Best-effort removal of any existing netem qdisc (ignore "nothing there").
clear_qdisc() {
    "${COMPOSE[@]}" exec -T "${SERVICE}" \
        tc qdisc del dev "${IFACE}" root 2>/dev/null || true
}

case "${PRESET}" in
    latency)
        clear_qdisc
        "${COMPOSE[@]}" exec -T "${SERVICE}" \
            tc qdisc add dev "${IFACE}" root netem delay 200ms 50ms
        echo "[netem] ${SERVICE}: delay 200ms +/-50ms"
        ;;
    loss)
        clear_qdisc
        "${COMPOSE[@]}" exec -T "${SERVICE}" \
            tc qdisc add dev "${IFACE}" root netem loss 10%
        echo "[netem] ${SERVICE}: loss 10%"
        ;;
    reorder)
        clear_qdisc
        "${COMPOSE[@]}" exec -T "${SERVICE}" \
            tc qdisc add dev "${IFACE}" root netem delay 50ms reorder 25% 50%
        echo "[netem] ${SERVICE}: delay 50ms reorder 25% 50%"
        ;;
    clear)
        clear_qdisc
        echo "[netem] ${SERVICE}: cleared"
        ;;
    *)
        echo "unknown preset: ${PRESET}" >&2
        usage
        ;;
esac
