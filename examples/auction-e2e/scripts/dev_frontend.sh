#!/usr/bin/env bash

set -euo pipefail

echo "Waiting for local evm node..."
pnpm wait-on tcp:localhost:8545

echo "Waiting for program runner..."
pnpm wait-on http://localhost:13151/health

# print-env exports the contract addresses and the RPC URL; the local chain is anvil, whose fee token anyone may mint.
cd client && (export VITE_CHAIN_ID=31337 VITE_ENABLE_TEST_TOKEN_MINT=true $(interfold print-env --vite --chain localhost) && pnpm dev)
