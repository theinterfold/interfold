#!/usr/bin/env bash

set -e


cd "$(git rev-parse --show-toplevel)"

# Fixture regeneration requires Nargo.
if ! command -v nargo &> /dev/null; then
    exit 0
fi

# Build or repair the circuit artifacts the integration tests open. `--skip-if-built` reuses
# `circuits/bin` only when it is stamped for the current sources and holds every artifact in
# `crates/zk/prover/required-artifacts.json`; otherwise it hydrates it from a current
# `dist/circuits`, or builds the pair.
if command -v bb &> /dev/null; then
    # Only a rebuild needs the Node dependencies (it renders the verifiers with tsx).
    [[ -d node_modules ]] || pnpm install --frozen-lockfile
    # build:circuits runs Cargo. This script can run inside a Cargo build script, which holds the
    # target-directory lock, so use a separate target directory.
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}/e3-zk-prover-fixtures" \
        pnpm build:circuits --skip-if-built
fi

# Keep the integration-test fixture in sync with the current Noir serialization format.
dummy_package="./crates/zk/prover/tests/fixtures/dummy"
dummy_artifact="$dummy_package/target/dummy.json"
fixture="./crates/zk/prover/tests/fixtures/dummy.json"
normalize_compiled_circuit_paths() {
  # Noir emits machine-local absolute paths in file_map; keep fixtures stable.
  jq '
    if .file_map then
      .file_map |= with_entries(
        .value |= if (.path | type) == "string" then
          .path |= (
            if test("^/") and test("circuits/") then
              sub("^.*?circuits/"; "circuits/")
            elif test("^/") and test("crates/zk/prover/tests/fixtures/dummy/") then
              sub("^.*?crates/zk/prover/tests/fixtures/dummy/"; "crates/zk/prover/tests/fixtures/dummy/")
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
