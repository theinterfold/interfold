#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# OpenVM tasks for this repository. A project made with `interfold init` uses
# `interfold program compile` and `interfold program start` instead.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command="${1:-}"
shift || true
case "$command" in
  cli-build)
    exec cargo build --locked --release --manifest-path "$ROOT/Cargo.toml" -p e3-cli --bin interfold "$@"
    ;;
  service-test)
    exec cargo test --locked --manifest-path "$ROOT/Cargo.toml" -p e3-openvm-types -p e3-openvm-host -p e3-compute-provider -p e3-program-server -p e3-program-runner "$@"
    ;;
  prover-build|prover-test|prover-check)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/prover}"
    exec cargo "${command#prover-}" --locked --release --manifest-path "$ROOT/crates/openvm-prover/Cargo.toml" "$@"
    ;;
  prover)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/prover}"
    exec cargo run --locked --release --manifest-path "$ROOT/crates/openvm-prover/Cargo.toml" -- "$@"
    ;;
  *) echo 'Usage: pnpm openvm cli-build|service-test|prover-build|prover-test|prover-check|prover [arguments]' >&2; exit 2 ;;
esac
