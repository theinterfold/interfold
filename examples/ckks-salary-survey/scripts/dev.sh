#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# One-command dev runner for the CKKS salary survey (CRISP's scripts/dev.sh
# shape). Boots, in order:
#   1. anvil + Interfold contracts (mock verifiers + real Honk verifiers for
#      the three CKKS legs) + enables CkksSalaryE3Program
#   2. five real ciphernodes (DKG + relin ceremony run automatically per E3)
#   3. the coordinator server (indexer + relayer + evaluator) on :8091
#   4. the Vite client on :5174
#
#   ./scripts/dev.sh              # foreground; Ctrl-C tears everything down
#   HEADLESS=1 ./scripts/dev.sh   # no client (used by test/e2e.mjs)
#
# Env knobs: CKKS_TOOLS_PROFILE (debug|release; release strongly
# recommended — the ceremony blocks a debug node's event loop),
# INTERFOLD_BIN (defaults to target/<profile>/interfold), CKKS_RELIN_KEY_DIR
# (default /tmp/ckks-relin-keys; MUST be shared by nodes and server),
# E3_DURATION (input window seconds, default 120).
#
# Reuses tests/integration/fns.sh for the node bring-up (same wallets /
# addresses / config the integration tests use). Lessons baked in: wipe
# .interfold/data BEFORE wallet set; find||true for polls; explicit exit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$APP_DIR/../.." && pwd)"
INTEG_DIR="$ROOT_DIR/tests/integration"

export CKKS_TOOLS_PROFILE="${CKKS_TOOLS_PROFILE:-release}"
export INTERFOLD_BIN="${INTERFOLD_BIN:-$ROOT_DIR/target/$CKKS_TOOLS_PROFILE/interfold}"
export CKKS_RELIN_KEY_DIR="${CKKS_RELIN_KEY_DIR:-/tmp/ckks-relin-keys}"
E3_DURATION="${E3_DURATION:-120}"
SERVER_PORT="${SERVER_PORT:-8091}"
CLIENT_PORT="${CLIENT_PORT:-5174}"
LOG_DIR="${LOG_DIR:-$APP_DIR/.dev-logs}"
mkdir -p "$LOG_DIR" "$CKKS_RELIN_KEY_DIR"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
  echo "[dev] tearing down"
  [[ -n "$CLIENT_PID" ]] && kill "$CLIENT_PID" 2>/dev/null || true
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  pkill -9 -f "target/(debug|release)/interfold" 2>/dev/null || true
  pkill -9 -f "interfold start" 2>/dev/null || true
  pkill -9 -f anvil 2>/dev/null || true
  jobs -p | xargs -r kill -9 2>/dev/null || true
  # Node event DBs grow multi-GB per ceremony run; keep the disk clean.
  find "$INTEG_DIR/.interfold/data" -type d -name db -path '*cn*' -prune -exec rm -rf {} + 2>/dev/null || true
  exit "${1:-0}"
}
trap 'cleanup 0' INT TERM

if [[ ! -x "$INTERFOLD_BIN" ]]; then
  echo "[dev] $INTERFOLD_BIN missing — build with: cargo build --release -p interfold (and the ckks tools)" >&2
  exit 1
fi
if pgrep -f 'release/interfold|debug/interfold|anvil' >/dev/null; then
  echo "[dev] a stack is already running (interfold/anvil processes). Stop it first." >&2
  exit 1
fi

echo "[dev] disk: $(df -h / | awk 'NR==2 {print $4}') free"

# ── 1. chain + contracts ────────────────────────────────────────────────
cd "$INTEG_DIR"
# fns.sh is only sourced INSIDE this runner (never in diagnostic shells —
# its cleanup trap kills the stack).
# shellcheck disable=SC1091
source "$INTEG_DIR/fns.sh"
# shellcheck disable=SC1091
source "$INTEG_DIR/lib/utils.sh"
trap 'cleanup 0' INT TERM

heading "Start anvil"
launch_evm
until curl -sf -X POST http://localhost:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' >/dev/null; do sleep 1; done

pnpm evm:clean
heading "Deploy contracts (real Honk verifiers for the 3 CKKS legs)"
pnpm evm:deploy
heading "Sync integration config"
(cd "$ROOT_DIR/packages/interfold-contracts" && pnpm utils:sync-integration-config)

heading "Enable CkksSalaryE3Program on Interfold"
SALARY_PROGRAM="$(node -e "const d=require('$ROOT_DIR/packages/interfold-contracts/deployed_contracts.json');process.stdout.write(d.localhost.CkksSalaryE3Program.address)")"
(cd "$ROOT_DIR/packages/interfold-contracts" && npx hardhat interfold:enableE3 --e3-address "$SALARY_PROGRAM" --network localhost)

# ── 2. ciphernodes ──────────────────────────────────────────────────────
# Fresh node state BEFORE wallet setup (wallets live under .interfold/data).
rm -rf "$INTEG_DIR/.interfold/data"
interfold_wallet_set cn1 "$PRIVATE_KEY_CN1"
interfold_wallet_set cn2 "$PRIVATE_KEY_CN2"
interfold_wallet_set cn3 "$PRIVATE_KEY_CN3"
interfold_wallet_set cn4 "$PRIVATE_KEY_CN4"
interfold_wallet_set cn5 "$PRIVATE_KEY_CN5"

heading "Setup ZK prover"
$INTERFOLD_BIN noir setup

interfold_nodes_up
sleep 4
for addr in "$CIPHERNODE_ADDRESS_1" "$CIPHERNODE_ADDRESS_2" "$CIPHERNODE_ADDRESS_3" "$CIPHERNODE_ADDRESS_4" "$CIPHERNODE_ADDRESS_5"; do
  heading "Add ciphernode $addr"
  pnpm ciphernode:add --ciphernode-address "$addr" --network localhost
done

# ── 3. server ───────────────────────────────────────────────────────────
cd "$APP_DIR"
node scripts/sync-config.mjs --relin-key-dir "$CKKS_RELIN_KEY_DIR" --port "$SERVER_PORT" --duration "$E3_DURATION"
rm -rf "$APP_DIR/database"
heading "Start salary-survey server on :$SERVER_PORT"
(cd "$APP_DIR" && ./target/release/server >"$LOG_DIR/server.log" 2>&1) &
SERVER_PID=$!
until curl -sf "http://127.0.0.1:$SERVER_PORT/health" >/dev/null; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "[dev] server died; see $LOG_DIR/server.log" >&2
    cleanup 1
  fi
  sleep 1
done
echo "[dev] server: http://127.0.0.1:$SERVER_PORT  (log $LOG_DIR/server.log)"

# ── 4. client ───────────────────────────────────────────────────────────
if [[ "${HEADLESS:-0}" != "1" ]]; then
  heading "Start Vite client on :$CLIENT_PORT"
  (cd "$APP_DIR/client" && pnpm dev >"$LOG_DIR/client.log" 2>&1) &
  CLIENT_PID=$!
  until curl -sf "http://127.0.0.1:$CLIENT_PORT/" >/dev/null; do sleep 1; done
  echo "[dev] client: http://127.0.0.1:$CLIENT_PORT  (log $LOG_DIR/client.log)"
fi

heading "STACK READY"
echo "  anvil        http://127.0.0.1:8545"
echo "  ciphernodes  5 (registered); relin keys → $CKKS_RELIN_KEY_DIR/<chain>:<e3>"
echo "  server       http://127.0.0.1:$SERVER_PORT"
[[ "${HEADLESS:-0}" != "1" ]] && echo "  client       http://127.0.0.1:$CLIENT_PORT"
echo "  program      $SALARY_PROGRAM"
echo "READY" >"$LOG_DIR/ready"

while true; do sleep 3600; done
