#!/usr/bin/env bash

set -euo pipefail

echo "Waiting for local evm node..."
pnpm wait-on tcp:localhost:8545

echo "Waiting for program runner..."
pnpm wait-on http://localhost:13151/health

# The allowlist gate is deployed with the program; print-env does not know it, so read it from the deployment record.
ALLOWLIST_GATE_ADDRESS=$(node -p "require('./deployed_contracts.json').localhost?.MerkleAllowlistGate?.address ?? ''")

# print-env exports the contract addresses and the RPC URL; the local chain is anvil, whose fee token anyone may mint.
# The server (relayed bids) listens on 8080 in `pnpm dev:server`.
cd client && (export VITE_CHAIN_ID=31337 VITE_ENABLE_TEST_TOKEN_MINT=true VITE_SERVER_URL=http://127.0.0.1:8080 VITE_ALLOWLIST_GATE_ADDRESS="$ALLOWLIST_GATE_ADDRESS" $(interfold print-env --vite --chain localhost) && pnpm dev)
