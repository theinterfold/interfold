#!/usr/bin/env bash
# Starts the local stack and runs `tests/integration.spec.ts` against it. The test reads these variables:
#   SELLER_STEP, BUYER_STEP   The private price steps (levels 0-15) of the first negotiation. Default 2 and 12.
#                             The grid starts at the price 48 and has a step of 1, so the prices are 50 and 60.
#   NEGOTIATIONS=n            Run n negotiations in one stack run. The first has SELLER_STEP and BUYER_STEP.
#                             The other n-1 have random steps.
#   NEGOTIATION_CASES         An explicit list, for example "2:12,5:3" (seller step:buyer step). It replaces the
#                             variables above.
#   PROOF_CONCURRENCY=n       Offer proofs that run at the same time. Default 2.
#   NEGOTIATION_SERVER_URL    The coordination server. Default http://localhost:8080.
#
# Example: NEGOTIATIONS=4 pnpm test:integration

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/lib/dev_config.sh"
load_template_dev_config

# Proof aggregation stays on. The template skips it in CI, but the l-BFV public-key aggregator has
# no skip path: it publishes the committee key only with a real DkgAggregatorV2 proof, so with
# SKIP_PROOF_AGGREGATION the key is never published
# (crates/aggregator/src/public_key_aggregation/effects/publish_result.rs).
export E3_PROGRAM__DEV=true
export TEMPLATE_UNPROVED_TEST=1

passed_message() {
  echo ""
  echo "------------------------"
  echo "  ✅ Test has passed!   "
  echo "------------------------"
  echo ""
}

failed_message() {
  echo ""
  echo "------------------------"
  echo "  ❌ Test failed  "
  echo "------------------------"
  echo ""
  exit 1
}

# The test waits at most 10 minutes for the nodes, the EVM node and the program server to start, which
# take about 2 minutes in CI, and at most 5 seconds for one health request.
(pnpm concurrently \
  --names "TEST,EVM,MINE,CIPHER,SERVER,PROGRAM" \
  --prefix-colors "blue,cyan,gray,magenta,yellow,green" \
  --kill-others \
  --success command-TEST \
  "wait-on --timeout 600000 --httpTimeout 5000 file:/tmp/interfold_ciphernodes_ready tcp:localhost:8545 http://localhost:13151/health && export \$(interfold print-env --chain localhost) && pnpm vitest run ./tests/integration.spec.ts" \
  "anvil --host 0.0.0.0 --chain-id 31337 --block-time 1  --mnemonic 'test test test test test test test test test test test junk' --silent" \
  "wait-on tcp:localhost:8545 && node ./scripts/anvil-automine.mjs" \
  "pnpm dev:ciphernodes" \
  "pnpm dev:server" \
  "pnpm dev:program" && passed_message) || failed_message
