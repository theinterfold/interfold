#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command="${1:-}"
shift || true
case "$command" in
  setup) exec node "$ROOT/scripts/setup-crisp-fhe.mjs" "$@" ;;
  baseline|optimized)
    variant="risc0-$command"
    CARGO_TARGET_DIR="$ROOT/target/crisp-risc0" exec cargo run --locked --release \
      --manifest-path "$ROOT/examples/CRISP/prover/$variant/Cargo.toml" \
      -p "crisp-$variant" -- "$@"
    ;;
  build)
    CARGO_TARGET_DIR="$ROOT/target/crisp-risc0" exec cargo build --locked --release \
      --manifest-path "$ROOT/examples/CRISP/prover/risc0-optimized/Cargo.toml" \
      -p crisp-risc0-optimized "$@"
    ;;
  *) echo 'Usage: pnpm crisp:risc0 setup|build|baseline|optimized [arguments]' >&2; exit 2 ;;
esac
