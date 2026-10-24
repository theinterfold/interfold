#!/usr/bin/env bash

set -euo pipefail

echo "Waiting for local evm node..."
pnpm wait-on tcp:localhost:8545

echo "Waiting for program runner..."
pnpm wait-on http://localhost:13151/health

# The deploy script records every contract in deployed_contracts.json. Read the allowlist gate, the
# mock tokens and the block of the program deployment from it; print-env does not know them.
deployed() {
  node -p "const d = require('./deployed_contracts.json').localhost ?? {}; const e = d['$1']; e ? e.$2 : ''"
}
ALLOWLIST_GATE_ADDRESS=$(deployed MerkleAllowlistGate address)
SALE_TOKEN_ADDRESS=$(deployed MockSaleToken address)
PAYMENT_TOKEN_ADDRESS=$(deployed MockPaymentToken address)
DEPLOY_BLOCK=$(deployed SealedCcaProgram blockNumber)

# print-env exports the contract addresses and the RPC URL; the local chain is anvil, whose fee token anyone may mint.
# The server (relayed bids and deposits) listens on 8080 in `pnpm dev:server`.
cd client && (export VITE_CHAIN_ID=31337 VITE_ENABLE_TEST_TOKEN_MINT=true VITE_SERVER_URL=http://127.0.0.1:8080 \
  VITE_ALLOWLIST_GATE_ADDRESS="$ALLOWLIST_GATE_ADDRESS" VITE_SALE_TOKEN_ADDRESS="$SALE_TOKEN_ADDRESS" \
  VITE_PAYMENT_TOKEN_ADDRESS="$PAYMENT_TOKEN_ADDRESS" VITE_DEPLOY_BLOCK="${DEPLOY_BLOCK:-0}" \
  $(interfold print-env --vite --chain localhost) && pnpm dev)
