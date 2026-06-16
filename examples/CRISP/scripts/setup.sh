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
if [[ ! -f ~/.cargo/bin/interfold ]]; then
  echo "Building and installing interfold CLI..."
  (cd "${REPO_ROOT}" && cargo build --locked -p e3-cli && cargo install --locked --path crates/cli)
else
  echo "interfold CLI already installed, skipping build"
fi

print_crisp_dev_config_summary
