#!/usr/bin/env bash

set -e

export CARGO_INCREMENTAL=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/dev_config.sh"

load_crisp_dev_config

echo "SETUP..."
echo "pnpm install"
(cd "${REPO_ROOT}" && pnpm install --frozen-lockfile)
(cd "${REPO_ROOT}" && pnpm build:ts)
echo "sdk"
(pnpm build:sdk)
build_interfold_circuits_at_setup
echo "evm"
(cd "${REPO_ROOT}/packages/interfold-contracts" && pnpm compile:contracts)
(pnpm compile:contracts)
echo "server"
(cd ./server && [[ ! -f .env ]] && cp .env.example .env; cargo build --locked --bin cli && cargo build --locked --bin server)
apply_crisp_dev_config_to_server_env
echo "client"
(cd ./client && if [[ ! -f .env ]]; then cp .env.example .env; fi)
echo "ciphernode"
# `load_crisp_dev_config` exports E3_NODES__CN*__SKIP_PROOF_AGGREGATION from this profile.
# The node rejects that setting unless the binary carries the matching Cargo feature, so the
# feature selection has to follow the profile or every ciphernode exits on startup.
INTERFOLD_FEATURES=""
if [[ "$CRISP_SKIP_PROOF_AGGREGATION" == "true" ]]; then
  INTERFOLD_FEATURES="--features test-only-skip-proof-aggregation"
fi
echo "Building and installing interfold CLI (${INTERFOLD_FEATURES:-no extra features})..."
# Always reinstall: `cargo install --path` rebuilds and replaces in place, so a stale binary
# from an earlier checkout (or an earlier profile) cannot silently survive.
# shellcheck disable=SC2086
(cd "${REPO_ROOT}" && cargo install --locked --path crates/cli $INTERFOLD_FEATURES)

print_crisp_dev_config_summary
