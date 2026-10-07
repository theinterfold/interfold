#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# OpenVM tasks for this repository. The CRISP tasks run in examples/CRISP; a project made with
# `interfold init` uses `interfold program compile` and `interfold program start` instead.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRISP="$ROOT/examples/CRISP"
command="${1:-}"
shift || true
case "$command" in
  cli-build)
    exec cargo build --locked --release --manifest-path "$ROOT/Cargo.toml" -p e3-cli --bin interfold "$@"
    ;;
  fixture)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/crisp-server}"
    exec cargo run --locked --release --manifest-path "$CRISP/Cargo.toml" -p e3-user-program --example openvm_fixture -- "$@"
    ;;
  crisp-server-build|crisp-server-test)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/crisp-server}"
    exec cargo "${command#crisp-server-}" --locked --manifest-path "$CRISP/Cargo.toml" -p crisp "$@"
    ;;
  # CRISP's proving service: examples/CRISP/.interfold/support/openvm/service.
  service-build|service-check)
    exec cargo "${command#service-}" --locked --manifest-path "$CRISP/Cargo.toml" -p e3-support-scripts-openvm "$@"
    ;;
  service-test)
    exec cargo test --locked --manifest-path "$ROOT/Cargo.toml" -p e3-openvm-types -p e3-openvm-host -p e3-compute-provider -p e3-program-server "$@"
    ;;
  # Builds CRISP's guest, keys, receipt identity, worker configuration and service. Takes the same
  # OPENVM_* environment as `interfold program compile`.
  compile)
    cd "$CRISP"
    exec bash .interfold/support/openvm/compile "$@"
    ;;
  service-start)
    cd "$CRISP"
    exec bash .interfold/support/openvm/start "$@"
    ;;
  prover-build|prover-test|prover-check)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/prover}"
    exec cargo "${command#prover-}" --locked --release --manifest-path "$ROOT/crates/openvm-prover/Cargo.toml" "$@"
    ;;
  prover)
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/openvm/prover}"
    exec cargo run --locked --release --manifest-path "$ROOT/crates/openvm-prover/Cargo.toml" -- "$@"
    ;;
  # Builds CRISP's guest and runs it, without proving, on a fixture made by `fixture`, then checks
  # that it reveals the SHA-256 digest of the journal the native host computed.
  guest-parity)
    fixture="${1:?Usage: pnpm openvm guest-parity <fixture-directory>}"
    out="$ROOT/target/openvm/guest-parity"
    export OPENVM_BUILD_LOCKED=1
    RUSTFLAGS="${RUSTFLAGS:-} --cfg crisp_openvm --cfg crisp_fhe_optimized" \
      cargo openvm build --manifest-path "$CRISP/guest/Cargo.toml" --target-dir "$out/target" --output-dir "$out"
    revealed="$(cargo openvm run --manifest-path "$CRISP/guest/Cargo.toml" --exe "$out/e3-openvm-guest.vmexe" \
      --input "$fixture/execute/input.json" | sed -n 's/^Execution output: //p')"
    expected="$(python3 -c 'import hashlib, sys; print(list(hashlib.sha256(open(sys.argv[1], "rb").read()).digest()))' \
      "$fixture/execute/journal.bin")"
    if [ "$revealed" != "$expected" ]; then
      echo "The guest revealed ${revealed:-nothing}; the host journal hashes to $expected" >&2
      exit 1
    fi
    echo "The guest revealed the digest of the host's journal"
    ;;
  # `cargo openvm <arguments>` in CRISP's guest, with the guest's configuration flags.
  guest)
    export RUSTFLAGS="${RUSTFLAGS:-} --cfg crisp_openvm --cfg crisp_fhe_optimized"
    export OPENVM_BUILD_LOCKED=1
    cd "$CRISP/guest"
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
  *) echo 'Usage: pnpm openvm cli-build|fixture|crisp-server-build|crisp-server-test|service-build|service-check|service-test|compile|service-start|prover-build|prover-test|prover-check|prover|guest-parity|guest|contract-test|proof-test|service-e2e [arguments]' >&2; exit 2 ;;
esac
