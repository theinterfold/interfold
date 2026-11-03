#!/usr/bin/env bash
# Compile and stage the threshold user-data encryption circuits for the SDK.
# Default committee is minimum (matches DEFAULT_E3_CONFIG.committeeSize = CommitteeSize.Minimum).
# l-BFV keys use the chunked proof tree staged per preset under circuits/dist. trBFV keys use the
# single `user_data_encryption` circuit, compiled last so circuits/bin/threshold/target holds it. It
# needs no verification key: the SDK returns the proof, and nothing it does verifies it inside
# another circuit.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMITTEE="${CIRCUIT_COMMITTEE:-minimum}"
case "${COMMITTEE}" in
  minimum) ;;
    *)
    echo "Error: SDK proof bundles require the minimum committee (got: ${COMMITTEE})" >&2
    exit 1
    ;;
esac

TARGET="${REPO_ROOT}/circuits/bin/threshold/target"
DIST="${SCRIPT_DIR}/../circuits/dist"
PRESETS=(secure-8192 secure-16384 insecure)
# The proof tree: the prover also imports each one's recursive key (`<circuit>.vk.json`).
TREE_ARTIFACTS=(
  ct0_chunk_main
  ct0_pk_ct_commit
  ct0_eval_chunk_identity
  ct1_chunk_main
  ct1_pk_ct_commit
  ct1_eval_chunk_identity
  user_data_encryption_ct0_chunked
  user_data_encryption_ct1_chunked
)
ARTIFACTS=("${TREE_ARTIFACTS[@]}" user_data_encryption_chunked)

rm -rf "${DIST}"
for PRESET in "${PRESETS[@]}"; do
  BUILD_COMMITTEE="${COMMITTEE}"
  # Secure-16384 currently has a verifier route only for the minimum committee.
  if [[ "${PRESET}" == "secure-16384" ]]; then
    BUILD_COMMITTEE="minimum"
  fi

  CIRCUIT_ARGS=()
  for CIRCUIT in "${ARTIFACTS[@]}"; do
    CIRCUIT_ARGS+=(--circuit "${CIRCUIT}")
  done

  pnpm -C "${REPO_ROOT}" build:circuits \
    --preset "${PRESET}" \
    --committee "${BUILD_COMMITTEE}" \
    --group threshold \
    "${CIRCUIT_ARGS[@]}" \
    --output "${DIST}/threshold-build" \
    --skip-checksums \
    --no-clean-targets

  PRESET_DIST="${DIST}/${PRESET}"
  mkdir -p "${PRESET_DIST}"
  for CIRCUIT in "${ARTIFACTS[@]}"; do
    cp "${TARGET}/${CIRCUIT}.json" "${PRESET_DIST}/${CIRCUIT}.json"
  done
  # The build writes the key next to the bytecode it just compiled and deletes it on each recompile,
  # so a missing key fails here instead of shipping one from an older build.
  for CIRCUIT in "${TREE_ARTIFACTS[@]}"; do
    cp "${TARGET}/${CIRCUIT}.vk_recursive.json" "${PRESET_DIST}/${CIRCUIT}.vk.json"
  done

  case "${PRESET}" in
    insecure) EXPECTED_DEGREE=128 ;;
    secure-8192) EXPECTED_DEGREE=8192 ;;
    secure-16384) EXPECTED_DEGREE=16384 ;;
  esac
  node --input-type=module - "${PRESET_DIST}/ct0_pk_ct_commit.json" "${EXPECTED_DEGREE}" <<'NODE'
import { readFileSync } from 'node:fs'

const [artifactPath, expectedDegreeText] = process.argv.slice(2)
const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'))
const ct0is = artifact.abi.parameters.find(({ name }) => name === 'ct0is')
const degree = ct0is?.type?.type?.fields?.find(({ name }) => name === 'coefficients')?.type?.length
const expectedDegree = Number(expectedDegreeText)
if (degree !== expectedDegree) {
  throw new Error(`${artifactPath} has polynomial degree ${degree}; expected ${expectedDegree}.`)
}
NODE
done

# The SDK's trBFV presets are INSECURE_THRESHOLD_64 (on-chain set 0, the `insecure-64` circuit
# preset) and SECURE_THRESHOLD_8192; the default proves at degree 64.
pnpm -C "${REPO_ROOT}" build:circuits \
  --preset insecure-64 \
  --committee "${COMMITTEE}" \
  --group threshold \
  --circuit user_data_encryption \
  --skip-vk \
  --skip-checksums \
  --no-clean-targets
