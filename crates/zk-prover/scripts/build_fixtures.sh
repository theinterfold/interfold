#!/usr/bin/env bash

set -e


cd "$(git rev-parse --show-toplevel)"

# Fixture regeneration requires Nargo.
if ! command -v nargo &> /dev/null; then
    exit 0
fi

# In a clean checkout, build the circuit artifacts used by integration tests.
# Check every artifact the tests actually open, not merely that some JSON exists:
# a stale, partial, or different-preset tree would otherwise skip the build and
# leave the tests reading artifacts that do not match the current toolchain.
required_artifacts=(
    ./circuits/bin/.active-preset.json
    ./circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json
    ./circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json
    ./circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json
)

missing_artifacts=()
for artifact in "${required_artifacts[@]}"; do
    [[ -f "$artifact" ]] || missing_artifacts+=("$artifact")
done

if (( ${#missing_artifacts[@]} > 0 )); then
    if ! command -v bb &> /dev/null; then
        exit 0
    fi
    echo "Building circuits (missing: ${missing_artifacts[*]})..."
    pnpm install
    # This script runs from crates/zk-prover/build.rs, i.e. inside an outer
    # `cargo build`/`cargo test` process that holds target/release/.cargo-lock.
    # `build:circuits`'s default behavior of splicing a nested
    # `cargo run --release --bin generate_parity_matrices` here would deadlock
    # on that lock (a nested cargo cannot be invoked from inside an outer
    # cargo process). Skip the parity-matrices regen: the committed matrices
    # under `circuits/lib/src/configs/committee/<committee>/parity_{insecure,secure}.nr`
    # are source of truth and the authoritative input for the fixtures we are
    # about to compile. If a developer changes the BFV constants the parity
    # generator reads, rerun `pnpm build:circuits --committee <name>` from
    # OUTSIDE cargo to refresh those matrices and commit the result.
    pnpm build:circuits --skip-regen-parity
fi

# Keep the integration-test fixture in sync with the current Noir serialization format.
dummy_package="./crates/zk-prover/tests/fixtures/dummy"
dummy_artifact="$dummy_package/target/dummy.json"
fixture="./crates/zk-prover/tests/fixtures/dummy.json"
normalize_compiled_circuit_paths() {
  # Noir emits machine-local absolute paths in file_map; keep fixtures stable.
  jq '
    if .file_map then
      .file_map |= with_entries(
        .value |= if (.path | type) == "string" then
          .path |= (
            if test("^/") and test("circuits/") then
              sub("^.*?circuits/"; "circuits/")
            elif test("^/") and test("crates/zk-prover/tests/fixtures/dummy/") then
              sub("^.*?crates/zk-prover/tests/fixtures/dummy/"; "crates/zk-prover/tests/fixtures/dummy/")
            else .
            end
          )
        else .
        end
      )
    else .
    end
  '
}

(cd "$dummy_package" && nargo compile)
normalize_compiled_circuit_paths <"$dummy_artifact" >"$fixture"
