#!/usr/bin/env bash
# TEST-1: Docker multi-device integration harness for universal-clipboard.
#
# Brings up two ucb daemons (`alpha`, `beta`) in containers on one bridge
# network, pairs them, runs both in headless file-backed clipboard mode, and
# verifies a clip written on one device propagates to the other (both
# directions). Prints PASS/FAIL per check and tears everything down on exit.
#
# Usage:
#   scripts/harness-test.sh [--netem] [--no-build] [--keep]
#     --netem     also re-run the sync check under the `latency` and `loss`
#                 netem presets (TEST-2). Requires NET_ADMIN (set in compose).
#     --no-build  skip `docker compose build` (reuse the existing image)
#     --keep      do not tear down containers on exit (for debugging)
#
# Requires: docker (with compose v2). Run from anywhere; paths are resolved
# relative to this script.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker/docker-compose.yml"
NETEM="${SCRIPT_DIR}/netem.sh"

COMPOSE=(docker compose -f "${COMPOSE_FILE}")

# Per-container paths (inside the containers).
CFG="/data/cfg"
HEAD="/data/head"
PORT=48521

# Options.
DO_NETEM=0
DO_BUILD=1
KEEP=0
for arg in "$@"; do
    case "${arg}" in
        --netem) DO_NETEM=1 ;;
        --no-build) DO_BUILD=0 ;;
        --keep) KEEP=1 ;;
        -h | --help)
            sed -n '2,20p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *) echo "unknown arg: ${arg}" >&2; exit 2 ;;
    esac
done

PASS_COUNT=0
FAIL_COUNT=0

log()  { echo "[harness] $*"; }
pass() { echo "  PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "  FAIL: $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# Teardown on any exit unless --keep.
cleanup() {
    local ec=$?
    if [ "${KEEP}" -eq 1 ]; then
        log "--keep set; leaving containers up"
    else
        log "tearing down..."
        "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
    fi
    exit "${ec}"
}
trap cleanup EXIT INT TERM

# Run a command in a service (foreground, no TTY).
dex() {
    local svc="$1"; shift
    "${COMPOSE[@]}" exec -T "${svc}" "$@"
}

# Run a command in a service detached (backgrounded inside the container).
dex_bg() {
    local svc="$1"; shift
    "${COMPOSE[@]}" exec -dT "${svc}" "$@"
}

# ---------------------------------------------------------------------------
# 1. Build + bring up.
# ---------------------------------------------------------------------------
if [ "${DO_BUILD}" -eq 1 ]; then
    log "building image..."
    "${COMPOSE[@]}" build || { fail "docker build"; exit 1; }
fi

log "starting containers..."
"${COMPOSE[@]}" up -d || { fail "docker compose up"; exit 1; }

# Give the containers a moment to be exec-ready.
for svc in alpha beta; do
    for _ in $(seq 1 10); do
        if dex "${svc}" true 2>/dev/null; then break; fi
        sleep 1
    done
done

# ---------------------------------------------------------------------------
# 2. init on both devices.
# ---------------------------------------------------------------------------
log "initializing devices..."
for svc in alpha beta; do
    dex "${svc}" mkdir -p "${CFG}" "${HEAD}"
    out="$(dex "${svc}" ucb --config-dir "${CFG}" init --name "${svc}" --file-keystore --print-id 2>&1)"
    if [ $? -eq 0 ] && echo "${out}" | grep -q '{'; then
        pass "init ${svc} (${out})"
    else
        fail "init ${svc}: ${out}"
        log "init failed — daemon flags likely not merged yet; aborting."
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 3. Pair alpha <-> beta.
#    alpha listens (detached, auto-confirm), beta connects.
# ---------------------------------------------------------------------------
log "pairing..."
dex_bg alpha ucb --config-dir "${CFG}" pair --listen --yes
sleep 2
if dex beta ucb --config-dir "${CFG}" pair --connect "alpha:${PORT}" --yes; then
    pass "pair beta -> alpha"
else
    fail "pair beta -> alpha (continuing; static peer add is the fallback)"
fi
sleep 1

# ---------------------------------------------------------------------------
# 4. Static peers (mDNS multicast is unreliable on the docker bridge, so we
#    dial explicitly) then start the headless daemons.
# ---------------------------------------------------------------------------
log "adding static peers..."
dex alpha ucb --config-dir "${CFG}" peer add "beta:${PORT}"  || fail "peer add on alpha"
dex beta  ucb --config-dir "${CFG}" peer add "alpha:${PORT}" || fail "peer add on beta"

log "starting headless daemons..."
dex_bg alpha ucb --config-dir "${CFG}" run --headless-dir "${HEAD}"
dex_bg beta  ucb --config-dir "${CFG}" run --headless-dir "${HEAD}"
# Let sessions establish.
sleep 5

# ---------------------------------------------------------------------------
# Sync check helper: write a marker into <from>'s clip-in, poll <to>'s
# clip-out for it (30s timeout).
# ---------------------------------------------------------------------------
check_sync() {
    local from="$1" to="$2" label="$3"
    local marker="hello-from-${from}-${RANDOM}"
    log "sync ${from} -> ${to} (marker=${marker})"
    dex "${from}" sh -c "printf '%s\n' '${marker}' > ${HEAD}/clip-in"
    local i out
    for i in $(seq 1 30); do
        out="$(dex "${to}" sh -c "cat ${HEAD}/clip-out 2>/dev/null" || true)"
        if printf '%s' "${out}" | grep -qF "${marker}"; then
            pass "${label}: ${from} -> ${to} propagated (${i}s)"
            return 0
        fi
        sleep 1
    done
    fail "${label}: ${from} -> ${to} did NOT propagate within 30s"
    log "  beta clip-log tail:"; dex "${to}" sh -c "tail -n 5 ${HEAD}/clip-log.jsonl 2>/dev/null" || true
    return 1
}

# ---------------------------------------------------------------------------
# 5. Baseline sync checks (both directions).
# ---------------------------------------------------------------------------
log "=== baseline ==="
check_sync alpha beta "baseline"
check_sync beta alpha "baseline"

# ---------------------------------------------------------------------------
# 6. Optional netem runs.
# ---------------------------------------------------------------------------
if [ "${DO_NETEM}" -eq 1 ]; then
    for preset in latency loss; do
        log "=== netem: ${preset} ==="
        bash "${NETEM}" alpha "${preset}" || fail "apply netem ${preset} on alpha"
        bash "${NETEM}" beta "${preset}"  || fail "apply netem ${preset} on beta"
        check_sync alpha beta "netem-${preset}"
        check_sync beta alpha "netem-${preset}"
        bash "${NETEM}" alpha clear || true
        bash "${NETEM}" beta clear  || true
    done
fi

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
echo
log "=== summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
if [ "${FAIL_COUNT}" -gt 0 ]; then
    exit 1
fi
exit 0
