#!/usr/bin/env bash
# Compile and stage each threshold user-data encryption preset for the SDK.
# Default committee is minimum (matches DEFAULT_E3_CONFIG.committeeSize = CommitteeSize.Minimum).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMITTEE="${CIRCUIT_COMMITTEE:-minimum}"
case "${COMMITTEE}" in
  minimum|micro|small) ;;
    *)
    echo "Error: CIRCUIT_COMMITTEE must be minimum|micro|small (got: ${COMMITTEE})" >&2
    exit 1
    ;;
esac

TARGET="${REPO_ROOT}/circuits/bin/threshold/target"
DIST="${SCRIPT_DIR}/../circuits/dist"
PRESETS=(secure-8192 secure-16384 insecure)
ARTIFACTS=(
  ct0_chunk_main
  ct0_chunk_main_root
  ct0_pk_ct_commit
  ct0_chunk_gamma
  ct0_eval_chunk_main
  ct0_eval_chunk_main_root
  ct0_eval_pk_ct
  ct0_eval_chunk_identity
  ct1_chunk_main
  ct1_chunk_main_root
  ct1_pk_ct_commit
  ct1_chunk_gamma
  ct1_eval_chunk_main
  ct1_eval_chunk_main_root
  ct1_eval_pk_ct
  ct1_eval_chunk_identity
  user_data_encryption
  user_data_encryption_ct0
  user_data_encryption_ct1
)

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
    --skip-vk \
    --skip-checksums \
    --no-clean-targets

  PRESET_DIST="${DIST}/${PRESET}"
  mkdir -p "${PRESET_DIST}"
  for CIRCUIT in "${ARTIFACTS[@]}"; do
    cp "${TARGET}/${CIRCUIT}.json" "${PRESET_DIST}/${CIRCUIT}.json"
  done

  case "${PRESET}" in
    insecure) EXPECTED_DEGREE=512 ;;
    secure-8192) EXPECTED_DEGREE=8192 ;;
    secure-16384) EXPECTED_DEGREE=16384 ;;
  esac
  node --input-type=module - "${PRESET_DIST}/ct0_pk_ct_commit.json" "${EXPECTED_DEGREE}" <<'NODE'
import { readFileSync } from 'node:fs'

const [artifactPath, expectedDegreeText] = process.argv.slice(2)
const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'))
const pk0is = artifact.abi.parameters.find(({ name }) => name === 'pk0is')
const degree = pk0is?.type?.type?.fields?.find(({ name }) => name === 'coefficients')?.type?.length
const expectedDegree = Number(expectedDegreeText)
if (degree !== expectedDegree) {
  throw new Error(`${artifactPath} has polynomial degree ${degree}; expected ${expectedDegree}.`)
}
NODE
done
