#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Boot the 5 ciphernodes against the deployed stack (mirrors tests/integration/ckks-demo-env.sh
# WITHOUT sourcing fns.sh: its traps kill everything on exit). Uses the integration config
# (tests/integration/interfold.config.yaml) synced by deploy.sh. Writes $1 once nodes are
# registered.

set -euo pipefail

READY_FILE="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
INTEGRATION="$ROOT/tests/integration"
CONFIG="$INTEGRATION/interfold.config.yaml"
INTERFOLD_BIN="${INTERFOLD_BIN:-$ROOT/target/release/interfold}"
export CKKS_RELIN_KEY_DIR="${CKKS_RELIN_KEY_DIR:-/tmp/ckks-relin-keys}"

# Fresh node state BEFORE wallet setup (wallets live under .interfold/data).
rm -rf "$INTEGRATION/.interfold/data"

# anvil accounts 1–5.
KEYS=(
  0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
  0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
  0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
  0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
  0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba
)
ADDRS=(
  0x70997970C51812dc3A010C7d01b50e0d17dc79C8
  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
  0x90F79bf6EB2c4f870365E785982E1f101E93b906
  0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
  0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
)
for i in 0 1 2 3 4; do
  "$INTERFOLD_BIN" wallet set --name "cn$((i + 1))" --config "$CONFIG" --private-key "${KEYS[$i]}"
done

echo "Setting up ZK prover..."
"$INTERFOLD_BIN" noir setup

# The integration scripts REQUIRE cwd = tests/integration.
cd "$INTEGRATION"
"$INTERFOLD_BIN" nodes up -v --config "$CONFIG" &
SWARM_PID=$!
cleanup_swarm() { kill -TERM "$SWARM_PID" 2>/dev/null || true; }
trap cleanup_swarm EXIT
trap 'trap - EXIT; cleanup_swarm; exit 130' INT
trap 'trap - EXIT; cleanup_swarm; exit 143' TERM

sleep 6
# Root script = `ciphernode:admin-add` (registers + bonds), what tests/integration uses.
cd "$ROOT"
for addr in "${ADDRS[@]}"; do
  pnpm ciphernode:add --ciphernode-address "$addr" --network localhost
done

echo 1 > "$READY_FILE"
echo "CIPHERNODES HAVE BEEN ADDED."
wait
