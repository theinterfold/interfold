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
(cd "$ROOT_DIR" && cargo build --locked -p e3-tests --bin fake_encrypt)
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

# The proof jobs use the published artifacts without requiring a local source-hash match.
rm -rf "${INTEGRATION_NOIR}/circuits"
mkdir -p "${INTEGRATION_NOIR}/circuits" "${INTEGRATION_NOIR}/bin"
(cd "$ROOT_DIR" && pnpm store:circuits pull --latest)
(cd "$ROOT_DIR" && pnpm build:circuits \
  --preset insecure-64 \
  --committee minimum \
  --hydrate-bin-only \
  --no-clean-targets)
(cd "$ROOT_DIR" && pnpm build:circuits prepare-vk-commitments)
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

echo "Staged source-aligned integration circuits under ${INTEGRATION_NOIR}/circuits"
echo "Pinned noir version.json (bb=${REQUIRED_BB}, circuits=${REQUIRED_CIRCUITS})"
echo ""
echo "FINISHED BUILDING SOURCE-ALIGNED ZK CIRCUITS"
echo ""
