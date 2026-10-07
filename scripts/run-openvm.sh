#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command="${1:-}"
shift || true
case "$command" in
  setup-fhe) exec node "$ROOT/scripts/setup-openvm-fhe.mjs" "$@" ;;
  cli-build)
    exec cargo build --locked --release --manifest-path "$ROOT/Cargo.toml" -p e3-cli --bin interfold "$@"
    ;;
  fixture)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/crisp-server}"
    exec cargo run --locked --release --manifest-path "$ROOT/examples/CRISP/Cargo.toml" -p e3-user-program --example openvm_fixture -- "$@"
    ;;
  crisp-server-build|crisp-server-test)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/crisp-server}"
    exec cargo "${command#crisp-server-}" --locked --manifest-path "$ROOT/examples/CRISP/Cargo.toml" -p crisp "$@"
    ;;
  service-build|service-test|service-check)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/service}"
    exec cargo "${command#service-}" --locked --manifest-path "$ROOT/crates/support/Cargo.toml" "$@"
    ;;
  service-start)
    : "${OPENVM_PROVER_BIN:?Set OPENVM_PROVER_BIN}"
    : "${OPENVM_PROVER_CONFIG:?Set OPENVM_PROVER_CONFIG}"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/service}"
    exec cargo run --locked --release --manifest-path "$ROOT/crates/support/Cargo.toml" -p e3-support-app -- "$@"
    ;;
  prover-build|prover-test|prover-check)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/prover}"
    exec cargo "${command#prover-}" --locked --release --manifest-path "$ROOT/crates/support/openvm/prover/Cargo.toml" "$@"
    ;;
  prover)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/prover}"
    exec cargo run --locked --release --manifest-path "$ROOT/crates/support/openvm/prover/Cargo.toml" -- "$@"
    ;;
  guest)
    export CARGO_TARGET_DIR="$ROOT/target/openvm/guest"
    export RUSTFLAGS="${RUSTFLAGS:-} --cfg crisp_openvm --cfg crisp_fhe_optimized"
    export OPENVM_BUILD_LOCKED=1
    cd "$ROOT/crates/support/openvm/guest"
    exec cargo openvm "$@"
    ;;
  contract-test)
    exec pnpm --filter @crisp-e3/contracts test --network default tests/openvm-receipt.test.ts tests/crisp.journal.test.ts "$@"
    ;;
  proof-test)
    OPENVM_REQUIRE_PROOF_TEST=1 exec pnpm --filter @crisp-e3/contracts test --network default tests/openvm-proof.test.ts "$@"
    ;;
  service-e2e)
    OPENVM_E2E_ENABLED=1 exec pnpm --filter @crisp-e3/contracts test --network localhost tests/openvm-service.test.ts "$@"
    ;;
  *) echo 'Usage: pnpm openvm setup-fhe|cli-build|fixture|crisp-server-build|crisp-server-test|service-build|service-test|service-check|service-start|prover-build|prover-test|prover-check|prover|guest|contract-test|proof-test|service-e2e [arguments]' >&2; exit 2 ;;
esac
