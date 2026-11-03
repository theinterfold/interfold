#!/usr/bin/env bash
# Time one client-side user-data encryption proof for a preset, on native bb and on WASM.
#
# Usage: scripts/benchmark-user-data-encryption.sh <SDK preset> [runs]
#   e.g. scripts/benchmark-user-data-encryption.sh SECURE_THRESHOLD_16384
#
# It builds the preset's encryption circuits (minimum committee, as the SDK uses), runs
# tests/integration/user-data-encryption-benchmark.test.ts once with native bb and once on WASM,
# then rebuilds the circuits that were active before. The SDK's default preset is not changed.
# Needs the pinned bb on PATH (`required_bb_version` in crates/zk-prover/versions.json); BB_NATIVE overrides
# the native binary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SDK_DIR}/../.." && pwd)"
SDK_PRESET="${1:?usage: $0 <SDK preset> [runs]}"
RUNS="${2:-2}"

# The l-BFV presets prove with the chunked tree; the trBFV presets with one circuit.
case "${SDK_PRESET}" in
  INSECURE_THRESHOLD) CIRCUIT_PRESET=insecure CHUNKED=false ;;
  INSECURE_THRESHOLD_LBFV) CIRCUIT_PRESET=insecure CHUNKED=true ;;
  SECURE_THRESHOLD_8192) CIRCUIT_PRESET=secure-8192 CHUNKED=false ;;
  SECURE_THRESHOLD_16384) CIRCUIT_PRESET=secure-16384 CHUNKED=true ;;
  *)
    echo "Unknown SDK preset: ${SDK_PRESET}" >&2
    exit 1
    ;;
esac

TREE_CIRCUITS=(
  ct0_chunk_main ct0_pk_ct_commit ct0_eval_chunk_identity user_data_encryption_ct0_chunked
  ct1_chunk_main ct1_pk_ct_commit ct1_eval_chunk_identity user_data_encryption_ct1_chunked
)
if [[ "${CHUNKED}" == true ]]; then
  CIRCUITS=("${TREE_CIRCUITS[@]}" user_data_encryption_chunked)
else
  CIRCUITS=(user_data_encryption)
fi

ACTIVE="${REPO_ROOT}/circuits/bin/.active-preset.json"
read -r ACTIVE_PRESET ACTIVE_COMMITTEE < <(node -e '
  const a = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))
  console.log(a.preset, a.committee)' "${ACTIVE}")

restore() {
  echo "Restoring the ${ACTIVE_PRESET}/${ACTIVE_COMMITTEE} circuits"
  pnpm -C "${REPO_ROOT}" build:circuits --preset "${ACTIVE_PRESET}" --committee "${ACTIVE_COMMITTEE}" > /dev/null
}
trap restore EXIT

CIRCUIT_ARGS=()
for circuit in "${CIRCUITS[@]}"; do CIRCUIT_ARGS+=(--circuit "${circuit}"); done
echo "Building the ${CIRCUIT_PRESET} encryption circuits"
pnpm -C "${REPO_ROOT}" build:circuits --preset "${CIRCUIT_PRESET}" --committee minimum --group threshold \
  "${CIRCUIT_ARGS[@]}" --skip-checksums --no-clean-targets > /dev/null

TARGET="${REPO_ROOT}/circuits/bin/threshold/target"
if [[ "${CHUNKED}" == true ]]; then
  # The test imports the SDK's staged bundle, as scripts/compile-circuits.sh stages it.
  DIST="${SDK_DIR}/circuits/dist/${CIRCUIT_PRESET}"
  mkdir -p "${DIST}"
  for circuit in "${CIRCUITS[@]}"; do cp "${TARGET}/${circuit}.json" "${DIST}/${circuit}.json"; done
  for circuit in "${TREE_CIRCUITS[@]}"; do cp "${TARGET}/${circuit}.vk_recursive.json" "${DIST}/${circuit}.vk.json"; done
fi

NATIVE="${BB_NATIVE:-$(command -v bb)}"
cd "${SDK_DIR}"
# bb.js uses the native binary named by BB_BINARY_PATH and falls back to WASM when it is missing.
for bb in "${NATIVE}" /nonexistent/bb; do
  BB_BINARY_PATH="${bb}" UDE_BENCH_PRESET="${SDK_PRESET}" UDE_BENCH_RUNS="${RUNS}" \
    pnpm exec vitest --run --config vitest.proofs.config.ts tests/integration/user-data-encryption-benchmark.test.ts \
    | grep -E 'UDE_BENCH|FAIL|Error'
done
