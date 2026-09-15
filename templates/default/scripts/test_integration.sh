#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/lib/dev_config.sh"
load_template_dev_config

# The skip below is only honoured by an interfold binary carrying the
# `test-only-skip-proof-aggregation` Cargo feature. `pnpm dev:setup` builds one from the monorepo;
# released binaries (releases.yml builds `--bin interfold` with no features) do not have it, and
# every ciphernode would exit at startup. Fail here rather than let the `wait-on` below block until
# the CI timeout.
#
# Probe the binary on PATH, not the checkout: the feature is compiled in, so a monorepo checkout
# alongside a stale or release-profile install passes a checkout test and still fails at startup,
# while a standalone checkout with a correctly built CLI is rejected for no reason.
if ! template_cli_has_feature test-only-skip-proof-aggregation; then
  echo "ERROR: this integration test needs an interfold built with" >&2
  echo "'--features test-only-skip-proof-aggregation'." >&2
  echo "The interfold on PATH does not report that feature, so every ciphernode would exit at" >&2
  echo "startup." >&2
  if template_monorepo_build_available; then
    echo "Run 'pnpm dev:setup' to reinstall the CLI from ${INTERFOLD_REPO_ROOT}." >&2
  else
    echo "No interfold checkout found at ${INTERFOLD_REPO_ROOT}. Install the CLI from an interfold" >&2
    echo "checkout with '--features test-only-skip-proof-aggregation'." >&2
  fi
  exit 1
fi

# The template integration deploys mock proof verifiers. Keep recursive proof
# aggregation enabled by default for users, but skip it in this bounded CI test.
export E3_NODES__CN1__SKIP_PROOF_AGGREGATION=true
export E3_NODES__CN2__SKIP_PROOF_AGGREGATION=true
export E3_NODES__CN3__SKIP_PROOF_AGGREGATION=true
export E3_NODES__CN4__SKIP_PROOF_AGGREGATION=true
export E3_NODES__CN5__SKIP_PROOF_AGGREGATION=true

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

(pnpm concurrently \
  --names "TEST,EVM,MINE,CIPHER,SERVER,PROGRAM" \
  --prefix-colors "blue,cyan,gray,magenta,yellow,green" \
  --kill-others \
  --success command-TEST \
  "wait-on file:/tmp/interfold_ciphernodes_ready tcp:localhost:8545 http://localhost:13151/health && export \$(interfold print-env --chain localhost) && pnpm vitest run ./tests/integration.spec.ts" \
  "anvil --host 0.0.0.0 --chain-id 31337 --block-time 1  --mnemonic 'test test test test test test test test test test test junk' --silent" \
  "wait-on tcp:localhost:8545 && node ./scripts/anvil-automine.mjs" \
  "pnpm dev:ciphernodes" \
  "TEST_MODE=1 pnpm dev:server" \
  "pnpm dev:program" && passed_message) || failed_message
