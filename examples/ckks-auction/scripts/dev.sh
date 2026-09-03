#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# One-command dev boot for the CKKS auction (CRISP `dev.sh` shape):
#   anvil → deploy contracts (mocks + CkksAuctionE3Program + ParamSet 2) → 5 ciphernodes →
#   coordination server (:8090) → Vite client (:5173).
#
#   pnpm dev:up                      # from examples/ckks-auction
#
# Ctrl-C tears everything down. Set CKKS_AUCTION_NO_CLIENT=1 to skip the client (e2e drives it).
# Requires: the release node + tool binaries (`cargo build --release --bin interfold` at the
# root), compiled circuits (`circuits/bin/threshold/target/*_ps2.json`), pnpm installed here and
# in packages/interfold-contracts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT="$(cd "$APP_ROOT/../.." && pwd)"
export APP_ROOT ROOT
export INTERFOLD_BIN="${INTERFOLD_BIN:-$ROOT/target/release/interfold}"
export CKKS_RELIN_KEY_DIR="${CKKS_RELIN_KEY_DIR:-/tmp/ckks-relin-keys}"
export SERVER_PORT="${SERVER_PORT:-8090}"
export CLIENT_PORT="${CLIENT_PORT:-5173}"
READY_FILE="$APP_ROOT/.interfold/ready"

cleanup() {
  echo "Cleaning up processes..."
  pkill -9 -f "target/release/interfold" 2>/dev/null || true
  pkill -9 -f "target/debug/interfold" 2>/dev/null || true
  pkill -9 -f "anvil" 2>/dev/null || true
  jobs -p | xargs kill -9 2>/dev/null || true
  sleep 1
  echo "Cleanup complete"
  exit 0
}
trap cleanup INT TERM

[[ -x "$INTERFOLD_BIN" ]] || { echo "missing $INTERFOLD_BIN — build with: cargo build --release --bin interfold" >&2; exit 1; }
[[ -x "$APP_ROOT/target/release/server" ]] || { echo "missing server binary — run: pnpm build:server" >&2; exit 1; }
for c in user_data_encryption_ckks_ct0_ps2 user_data_encryption_ckks_ct1_ps2 ckks_auction_validity_ps2; do
  [[ -f "$ROOT/circuits/bin/threshold/target/$c.json" ]] || { echo "missing compiled circuit $c (nargo compile in circuits/bin/threshold)" >&2; exit 1; }
done

rm -rf "$APP_ROOT/.interfold/ready" "$CKKS_RELIN_KEY_DIR"
mkdir -p "$APP_ROOT/.interfold" "$CKKS_RELIN_KEY_DIR"

echo "DEV SCRIPT STARTING (server :$SERVER_PORT, client :$CLIENT_PORT)"

CLIENT_CMD="wait-on tcp:$SERVER_PORT && wait-on file:$READY_FILE && $SCRIPT_DIR/dev_client.sh"
if [[ "${CKKS_AUCTION_NO_CLIENT:-0}" == "1" ]]; then
  CLIENT_CMD="echo client skipped"
fi

pnpm concurrently \
  -ks first \
  --names "ANVIL,STACK,SERVER,CLIENT" \
  --prefix-colors "blue,green,magenta,cyan" \
  "anvil --host 0.0.0.0 --chain-id 31337 --block-time 1 --mnemonic 'test test test test test test test test test test test junk' --silent" \
  "$SCRIPT_DIR/deploy.sh && $SCRIPT_DIR/dev_cipher.sh $READY_FILE" \
  "wait-on file:$APP_ROOT/server/.env.deployed && $SCRIPT_DIR/dev_server.sh" \
  "$CLIENT_CMD"
