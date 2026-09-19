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

echo "Compiling the configured program service..."
interfold program compile

build_interfold_circuits_at_setup

echo "Compiling contracts..."
pnpm compile

# `test-only-skip-proof-aggregation` is compiled in unconditionally: it only lets the node honour
# the opt-in `skip_proof_aggregation` setting, and with that setting unset the binary behaves
# identically. `scripts/test_integration.sh` exports E3_NODES__CN*__SKIP_PROOF_AGGREGATION=true,
# and without the feature every ciphernode exits at startup (crates/entrypoint/src/start/start.rs).
# Proof aggregation stays enabled by default for template users - that is the runtime setting, not
# this build flag. Matches how CI builds the binary the template tests run against (ci.yml).
#
# Only the in-monorepo checkout can build it. A standalone template gets its binary from a release
# install, so there is nothing to build from here - the old `[[ ! -f ~/.cargo/bin/interfold ]]`
# guard was doing double duty for that case.
if template_monorepo_build_available; then
  echo "Building and installing interfold CLI..."
  # Always reinstall so a stale binary from an earlier checkout cannot silently survive.
  (cd "${INTERFOLD_REPO_ROOT}" &&
    cargo install --locked --path crates/cli --bin interfold -f \
      --features test-only-skip-proof-aggregation)
elif [[ ! -f ~/.cargo/bin/interfold ]] && ! command -v interfold >/dev/null 2>&1; then
  echo "interfold CLI not found and this is a standalone template (no monorepo at" >&2
  echo "${INTERFOLD_REPO_ROOT}). Install it first, then re-run setup." >&2
  exit 1
else
  echo "Standalone template: using the already-installed interfold CLI."
fi

echo "Running interfold noir setup..."
interfold noir setup

echo "Template setup complete."
