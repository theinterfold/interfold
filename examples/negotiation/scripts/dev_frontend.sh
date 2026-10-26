#!/usr/bin/env bash

set -euo pipefail

echo "Waiting for local evm node..."
pnpm wait-on tcp:localhost:8545

echo "Waiting for program runner..."
pnpm wait-on http://localhost:13151/health

# The deploy script records every contract in deployed_contracts.json. Read the block of the
# program deployment from it; print-env does not know it.
deployed() {
  node -p "const d = require('./deployed_contracts.json').localhost ?? {}; const e = d['$1']; e ? e.$2 : ''"
}
DEPLOY_BLOCK=$(deployed NegotiationProgram blockNumber)

# print-env exports the contract addresses and the RPC URL; the local chain is anvil, whose fee token anyone may mint.
# The server (relayed offers) listens on 8080 in `pnpm dev:server`.
cd client && (export VITE_CHAIN_ID=31337 VITE_ENABLE_TEST_TOKEN_MINT=true VITE_SERVER_URL=http://127.0.0.1:8080 \
  VITE_DEPLOY_BLOCK="${DEPLOY_BLOCK:-0}" \
  $(interfold print-env --vite --chain localhost) && pnpm dev)
