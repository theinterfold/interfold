#!/usr/bin/env bash
set -euo pipefail
: "${OPENVM_PROVER_BIN:?Set OPENVM_PROVER_BIN}"
: "${OPENVM_PROVER_CONFIG:?Set OPENVM_PROVER_CONFIG}"
exec cargo run --locked --release --manifest-path /app/crates/support/Cargo.toml -p e3-support-app -- "$@"
