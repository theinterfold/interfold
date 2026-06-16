#!/usr/bin/env bash
# =============================================================================
# Called by the VS Code "Deploy + Setup" task.
# Waits for Anvil, deploys contracts, sets up wallets/noir/ciphernodes,
# starts the swarm daemon, and signals readiness for node/client tasks.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRISP_ROOT="$REPO_ROOT/examples/CRISP"
SIGNAL_FILE="/tmp/crisp-dev-daemon-ready"
READYFILE="$CRISP_ROOT/.interfold/ready"

# ── Node config (must match start.sh) ──────────────────────────────────────
NODE_IDS=(cn1 cn2 cn3 cn4 cn5)
NODE_KEYS=(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
)
NODE_ADDRS=(
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
    "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"
)

# ── Clean previous state ────────────────────────────────────────────────────
echo "[deploy+setup] Cleaning previous state..."
rm -rf "$CRISP_ROOT/.interfold/data" "$CRISP_ROOT/.interfold/config"
rm -rf "$CRISP_ROOT/server/database"
rm -f "$READYFILE" "$SIGNAL_FILE"

echo "[deploy+setup] Waiting for Anvil (port 8545)..."
until curl -s http://localhost:8545 >/dev/null 2>&1; do sleep 1; done
echo "[deploy+setup] Anvil is ready."

echo "[deploy+setup] Deploying contracts..."
cd "$CRISP_ROOT"
bash scripts/crisp_deploy.sh

echo "[deploy+setup] Importing wallets..."
for i in "${!NODE_IDS[@]}"; do
    interfold wallet set --name "${NODE_IDS[$i]}" --private-key "${NODE_KEYS[$i]}"
done

echo "[deploy+setup] Running interfold noir setup..."
interfold noir setup

echo "[deploy+setup] Registering ciphernodes..."
for i in "${!NODE_IDS[@]}"; do
    pnpm ciphernode:add --ciphernode-address "${NODE_ADDRS[$i]}" --network "localhost"
done
echo 1 > "$READYFILE"

echo "[deploy+setup] Done. Signaling readiness."
touch "$SIGNAL_FILE"
echo "[deploy+setup] Signal file created: $SIGNAL_FILE — nodes can now start."
