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
(cd "$ROOT_DIR/crates" && cargo build --bin fake_encrypt --bin pack_e3_params --bin ckks_encrypt --bin pack_ckks_params --bin ckks_auction_eval)
echo ""
echo "FINISHED PREBUILDING BINARIES"
echo ""

echo ""
echo "BUILDING SOURCE-ALIGNED ZK CIRCUITS..."
echo ""

# The ciphernode always generates leaf proofs, even when recursive aggregation
# is skipped. Never let integration tests combine current Rust witnesses with
# a stale circuit ABI.
rm -rf "${INTEGRATION_NOIR}/circuits"
mkdir -p "${INTEGRATION_NOIR}/circuits" "${INTEGRATION_NOIR}/bin"

if [[ "${FULL_PROOF_AGGREGATION:-false}" == "true" ]]; then
  (cd "$ROOT_DIR" && pnpm build:circuits --preset insecure-512 -o "${INTEGRATION_NOIR}/circuits")
  # `--check`: verify the committed Honk Solidity verifiers in
  # packages/interfold-contracts/contracts/verifiers/bfv/honk/ match the
  # freshly-built circuits' recursive VKs. Fails loudly on drift instead of
  # silently rewriting committed contracts mid-test. If this errors, run
  # `pnpm generate:verifiers --write` and commit the diff.
  (cd "$ROOT_DIR" && pnpm generate:verifiers --check --no-compile --no-clean-targets)
else
  # C5/C7 final aggregation is skipped, but DKG and decryption leaf proofs
  # still execute. Build only those two source groups for the fast CI profile.
  (cd "$ROOT_DIR" && pnpm build:circuits --preset insecure-512 --group dkg,threshold -o "${INTEGRATION_NOIR}/circuits")
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to pin noir/version.json for integration ZK fixtures" >&2
  exit 1
fi
if ! command -v bb >/dev/null 2>&1; then
  echo "bb is required to build source-aligned integration circuits" >&2
  exit 1
fi

REQUIRED_BB="$(jq -r '.required_bb_version' "$VERSIONS_JSON")"
REQUIRED_CIRCUITS="$(jq -r '.required_circuits_version' "$VERSIONS_JSON")"
jq -n \
  --arg bb "$REQUIRED_BB" \
  --arg circuits "$REQUIRED_CIRCUITS" \
  '{bb_version: $bb, circuits_version: $circuits}' \
  > "${INTEGRATION_NOIR}/version.json"
cp "$(command -v bb)" "${INTEGRATION_NOIR}/bin/bb"
chmod +x "${INTEGRATION_NOIR}/bin/bb"

echo "Staged circuits under ${INTEGRATION_NOIR}/circuits/insecure-512"
echo "Pinned noir version.json (bb=${REQUIRED_BB}, circuits=${REQUIRED_CIRCUITS})"
echo ""
echo "FINISHED BUILDING SOURCE-ALIGNED ZK CIRCUITS"
echo ""
