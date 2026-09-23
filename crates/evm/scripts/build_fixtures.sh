#!/usr/bin/env bash

set -euo pipefail

echo "Building fixtures..."

solc --combined-json abi,bin tests/fixtures/emit_logs.sol |
  jq '.contracts["tests/fixtures/emit_logs.sol:EmitLogs"] | {abi, bin}' > tests/fixtures/emit_logs.json
