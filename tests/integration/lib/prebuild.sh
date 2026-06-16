#!/usr/bin/env bash
set -eu  # Exit immediately if a command exits with a non-zero status

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INTEGRATION_NOIR="${INTEGRATION_DIR}/.interfold/noir"
VERSIONS_JSON="${ROOT_DIR}/crates/zk-prover/versions.json"

echo ""
echo "PREBUILDING BINARIES..."
echo ""
(cd "$ROOT_DIR/crates" && cargo build --bin fake_encrypt --bin pack_e3_params)
echo ""
echo "FINISHED PREBUILDING BINARIES"
echo ""

if [[ "${PROOF_AGGREGATION_ENABLED:-false}" == "true" ]]; then
  echo ""
  echo "BUILDING ZK CIRCUITS + ON-CHAIN VERIFIERS (proof aggregation enabled)..."
  echo ""

  # Nodes must prove with the same VKs as deployed Honk verifiers. `interfold noir setup`
  # otherwise installs the release tarball (crates/zk-prover/versions.json), which can
  # disagree with locally rebuilt circuits/verifiers after `build:circuits`.
  rm -rf "${INTEGRATION_NOIR}/circuits"
  mkdir -p "${INTEGRATION_NOIR}/circuits"

  (cd "$ROOT_DIR" && pnpm build:circuits --preset insecure-512 -o "${INTEGRATION_NOIR}/circuits")
  # `--check`: verify the committed Honk Solidity verifiers in
  # packages/interfold-contracts/contracts/verifiers/bfv/honk/ match the
  # freshly-built circuits' recursive VKs. Fails loudly on drift instead of
  # silently rewriting committed contracts mid-test. If this errors, run
  # `pnpm generate:verifiers --write` and commit the diff.
  (cd "$ROOT_DIR" && pnpm generate:verifiers --check --no-compile --no-clean-targets)

  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required to pin noir/version.json for integration ZK fixtures" >&2
    exit 1
  fi
  REQUIRED_BB="$(jq -r '.required_bb_version' "$VERSIONS_JSON")"
  REQUIRED_CIRCUITS="$(jq -r '.required_circuits_version' "$VERSIONS_JSON")"
  jq -n \
    --arg bb "$REQUIRED_BB" \
    --arg circuits "$REQUIRED_CIRCUITS" \
    '{bb_version: $bb, circuits_version: $circuits}' \
    > "${INTEGRATION_NOIR}/version.json"

  echo "Staged circuits under ${INTEGRATION_NOIR}/circuits/insecure-512"
  echo "Pinned noir version.json (bb=${REQUIRED_BB}, circuits=${REQUIRED_CIRCUITS})"
  echo ""
  echo "FINISHED BUILDING ZK CIRCUITS + VERIFIERS"
  echo ""
fi
