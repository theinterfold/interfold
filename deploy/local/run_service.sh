#!/usr/bin/env bash
# =============================================================================
# CRISP Service Runner — called by VS Code tasks.
# Handles dependency waiting and launches one service.
#
# Usage: bash deploy/local/run_service.sh <service>
#   anvil      → start anvil
#   deploy     → deploy contracts + setup wallets/noir/ciphernodes + daemon
#   cn1..cn5   → start an individual ciphernode (waits for /tmp/crisp-dev-daemon-ready)
#   program    → start program server (waits for anvil :8545)
#   server     → start CRISP server (waits for program :13151)
#   client     → start CRISP client (waits for server :4000 + signal file)
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRISP_ROOT="$REPO_ROOT/examples/CRISP"
SIGNAL_FILE="/tmp/crisp-dev-daemon-ready"

SERVICE="${1:-}"

die() { echo "[run_service] ERROR: $*" >&2; exit 1; }

# ── Helpers ─────────────────────────────────────────────────────────────────
wait_for_port() {
    local host port label max
    host="${1:-localhost}"
    port="$2"
    label="${3:-$port}"
    max="${4:-120}"
    local attempt=0
    echo "[run_service] Waiting for $label ($host:$port)..."
    while (( attempt <= max )); do
        if curl -s "http://${host}:${port}" >/dev/null 2>&1; then
            echo "[run_service] $label is ready"
            return 0
        fi
        sleep 1
        (( attempt += 1 ))
    done
    die "$label did not start after ${max}s"
}

wait_for_file() {
    local file label max
    file="$1"
    label="${2:-$file}"
    max="${3:-120}"
    local attempt=0
    echo "[run_service] Waiting for $label..."
    while (( attempt <= max )); do
        if [ -f "$file" ]; then
            echo "[run_service] $label found"
            return 0
        fi
        sleep 1
        (( attempt += 1 ))
    done
    die "$label did not appear after ${max}s"
}

case "$SERVICE" in
  anvil)
    exec anvil \
      --host 0.0.0.0 \
      --chain-id 31337 \
      --block-time 1 \
      --mnemonic "test test test test test test test test test test test junk"
    ;;

  deploy)
    # Clean stale signal from a previous run so nodes don't start prematurely
    rm -f "$SIGNAL_FILE"
    exec bash "${REPO_ROOT}/deploy/local/setup_nodes.sh"
    ;;

  cn1|cn2|cn3|cn4|cn5)
    cd "${CRISP_ROOT}"
    wait_for_file "${SIGNAL_FILE}" "deploy signal file"
    echo "[run_service] Deploy done. Starting ${SERVICE} directly..."
    exec interfold --name "${SERVICE}" start -v
    ;;

  program)
    wait_for_port localhost 8545 "Anvil"
    echo "[run_service] Anvil ready. Starting program server..."
    cd "${CRISP_ROOT}"
    exec bash scripts/dev_program.sh
    ;;

  server)
    wait_for_port localhost 13151 "Program Server"
    echo "[run_service] Program server ready. Starting server..."
    cd "${CRISP_ROOT}"
    exec bash scripts/dev_server.sh
    ;;

  client)
    wait_for_port localhost 4000 "Server"
    wait_for_file "${SIGNAL_FILE}" "deploy signal file"
    echo "[run_service] Ready. Starting client..."
    cd "${CRISP_ROOT}"
    exec bash scripts/dev_client.sh
    ;;

  *)
    die "Unknown service: '${SERVICE}'. Valid: anvil, deploy, cn1..cn5, program, server, client"
    ;;
esac
