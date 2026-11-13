#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INTEGRATION_NOIR="${INTEGRATION_DIR}/.interfold/noir"
VERSIONS_JSON="${ROOT_DIR}/crates/zk/prover/versions.json"

echo ""
echo "PREBUILDING BINARIES..."
echo ""
(cd "$ROOT_DIR" && cargo build --locked -p e3-tests --bin fake_encrypt --bin pack_e3_params)
echo ""
echo "FINISHED PREBUILDING BINARIES"
echo ""

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
# Nodes treat a bb that reports another version as not installed and download the pinned one,
# which replaces this fixture's noir folder. Circuits built with another bb do not match either.
LOCAL_BB="$(bb --version)"
if [[ "$LOCAL_BB" != "$REQUIRED_BB" ]]; then
  echo "bb on PATH is ${LOCAL_BB}, integration fixtures need ${REQUIRED_BB} ($(command -v bb))" >&2
  exit 1
fi

echo ""
echo "PREPARING ZK CIRCUITS..."
echo ""

# The ciphernode generates leaf proofs even when recursive aggregation is skipped.
# Full-proof runs reuse source-matched artifacts or build them; other runs compile selected groups.
rm -rf "${INTEGRATION_NOIR}/circuits"
mkdir -p "${INTEGRATION_NOIR}/circuits" "${INTEGRATION_NOIR}/bin"

if [[ "${FULL_PROOF_AGGREGATION:-false}" == "true" ]]; then
  # A PR can change the VK catalogue before its artifacts are published. Never substitute the
  # branch tip: build this tree instead, retaining the catalogue/verifier checks below.
  built_matrix=false
  if ! (cd "$ROOT_DIR" && pnpm store:circuits pull); then
    echo "No matching published artifacts available; building the source-aligned matrix"
    (cd "$ROOT_DIR" && pnpm build:circuits --preset all --committee all --skip-if-built)
    built_matrix=true
  fi
  (cd "$ROOT_DIR" && pnpm build:circuits \
    --preset insecure-64 \
    --committee minimum \
    --skip-if-built \
    --no-clean-targets)
  if [[ "$built_matrix" == "true" ]]; then
    # Matrix builds switch shared selectors and generated bounds; restore the default sources.
    (cd "$ROOT_DIR" && pnpm generate:crypto-config)
  fi
  (cd "$ROOT_DIR" && pnpm build:circuits prepare-vk-commitments)
  (cd "$ROOT_DIR" && pnpm check:crypto-config --full)
  for preset in insecure-64 secure-8192; do
    mkdir -p "${INTEGRATION_NOIR}/circuits/${preset}"
    cp -R "${ROOT_DIR}/dist/circuits/${preset}/minimum" \
      "${INTEGRATION_NOIR}/circuits/${preset}/"
  done
  # `--check`: verify the committed Honk Solidity verifiers in
  # packages/interfold-contracts/contracts/verifiers/bfv/honk/ match the
  # freshly-built circuits' recursive VKs. Fails loudly on drift instead of
  # silently rewriting committed contracts mid-test. If this errors, run
  # `pnpm generate:verifiers --write` and commit the diff.
  (cd "$ROOT_DIR" && pnpm generate:verifiers --check --no-compile --no-clean-targets)
else
  # C5/C7 final aggregation is skipped, but DKG and decryption leaf proofs
  # still execute. Build only those two source groups for the fast CI profile.
  (cd "$ROOT_DIR" && pnpm build:circuits --preset insecure-64 --group dkg,threshold -o "${INTEGRATION_NOIR}/circuits")
fi

source "$SCRIPT_DIR/utils.sh"
(cd "$ROOT_DIR" && pnpm store:circuits checksums --dir "${INTEGRATION_NOIR}/circuits")
CIRCUITS_MAP="$(jq '.files | with_entries(.value = {file: .key, checksum: .value})' \
  "${INTEGRATION_NOIR}/circuits/checksums.json")"
if [[ "$(jq 'length' <<<"$CIRCUITS_MAP")" -eq 0 ]]; then
  echo "no circuit artifacts found for integration ZK fixtures" >&2
  exit 1
fi
jq -n \
  --arg bb "$REQUIRED_BB" \
  --arg circuits "$REQUIRED_CIRCUITS" \
  --argjson circuit_files "$CIRCUITS_MAP" \
  '{bb_version: $bb, circuits_version: $circuits, circuits: $circuit_files}' \
  > "${INTEGRATION_NOIR}/version.json"
cp "$(command -v bb)" "${INTEGRATION_NOIR}/bin/bb"
chmod +x "${INTEGRATION_NOIR}/bin/bb"

# The upgrade reset scenario keeps this output for the candidate. The stamp lets it refuse a noir
# folder that a released binary's setup replaced.
noir_digest "$INTEGRATION_NOIR" >"${INTEGRATION_DIR}/.interfold/prebuild-noir.sha256"

echo "Staged source-aligned integration circuits under ${INTEGRATION_NOIR}/circuits"
echo "Pinned noir version.json (bb=${REQUIRED_BB}, circuits=${REQUIRED_CIRCUITS})"
echo ""
echo "FINISHED BUILDING SOURCE-ALIGNED ZK CIRCUITS"
echo ""
