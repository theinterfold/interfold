#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/dev_config.sh"

load_template_dev_config
cd "${TEMPLATE_ROOT}"

echo "Installing dependencies..."
pnpm install --frozen-lockfile

echo "Installing Cargo dependencies..."
cargo build

echo "Compiling guest program..."
if [[ ! -f './.interfold/generated/contracts/ImageID.sol' ]]; then
  interfold program compile
fi

build_interfold_circuits_at_setup

echo "Compiling contracts..."
pnpm compile

if [[ ! -f ~/.cargo/bin/interfold ]]; then
  echo "Building and installing interfold CLI..."
  (cd "${INTERFOLD_REPO_ROOT}" && cargo build --locked -p e3-cli && cargo install --locked --path crates/cli)
else
  echo "interfold CLI already installed, skipping build"
fi

echo "Running interfold noir setup..."
interfold noir setup

echo "Template setup complete."
