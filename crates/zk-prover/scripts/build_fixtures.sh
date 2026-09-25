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
    pnpm install --frozen-lockfile
    # build:circuits runs Cargo. This script can run inside a Cargo build script, which holds the
    # target-directory lock, so use a separate target directory.
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}/e3-zk-prover-fixtures" pnpm build:circuits
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
