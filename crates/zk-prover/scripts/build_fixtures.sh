#!/usr/bin/env bash

set -e


cd "$(git rev-parse --show-toplevel)"

# if this is a clean checkout we need to have some artifacts to test against
if find ./circuits/bin -name '*.json' -print -quit | grep -q .; then
  exit 0
fi

# if we are in CI where circuits have been built ignore
if ! command -v nargo &> /dev/null; then
    exit 0
fi

if ! command -v bb &> /dev/null; then
    exit 0
fi

echo "Building circuits..."

pnpm install && pnpm build:circuits

# Keep integration-test fixture in sync when the dummy circuit is built.
dummy_artifact="./circuits/bin/dummy/dummy.json"
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

if [ -f "$dummy_artifact" ]; then
  mkdir -p "$(dirname "$fixture")"
  normalize_compiled_circuit_paths <"$dummy_artifact" >"$fixture"
fi
