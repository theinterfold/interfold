#!/usr/bin/env bash
# Compile and stage the threshold user-data encryption circuits for the SDK.
# Default committee is minimum (matches DEFAULT_E3_CONFIG.committeeSize = CommitteeSize.Minimum).
# l-BFV keys use the chunked proof tree staged per preset under circuits/dist; it is always built for
# the minimum committee, the one the SDK requires (assert-minimum-circuits.ts), and CIRCUIT_COMMITTEE
# applies to the trBFV circuit only. trBFV keys use the single `user_data_encryption` circuit,
# compiled last so circuits/bin/threshold/target holds it. It needs no verification key: the SDK
# returns the proof, and nothing it does verifies it inside another circuit.
#
# Needs `nargo` and the pinned `bb` (`required_bb_version` in crates/zk/prover/versions.json) on PATH:
# the l-BFV tree builds write each circuit's recursive verification key, which the prover ships.
# `pnpm run` finds the `bb` that @aztec-foundation/bb.js installs.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMITTEE="${CIRCUIT_COMMITTEE:-minimum}"
case "${COMMITTEE}" in
  minimum|micro|small|large) ;;
    *)
    echo "Error: CIRCUIT_COMMITTEE must be minimum|micro|small|large (got: ${COMMITTEE})" >&2
    exit 1
    ;;
esac

if ! command -v bb > /dev/null 2>&1; then
  echo "Error: bb must be on PATH (run this through pnpm, or install the version in crates/zk/prover/versions.json)" >&2
  exit 1
fi

# The chunked proof tree lives in the l-BFV threshold workspace, whose `target` holds its artifacts.
TARGET="${REPO_ROOT}/circuits/bin/lbfv/threshold/target"
DIST="${SCRIPT_DIR}/../circuits/dist"
PRESETS=(secure-16384 insecure-lbfv)
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

# The builds write each circuit's JSON three times (evm, default, recursive), and only the staged
# copies below are read, so they go to a scratch directory instead of circuits/dist.
BUILD_OUTPUT="$(mktemp -d)"
# The builds switch circuits/lib/src/configs/default to the preset they build. On failure, rebuild
# the pair that was active so the checkout is not left on an l-BFV preset.
ACTIVE="${REPO_ROOT}/circuits/bin/.active-preset.json"
ACTIVE_PRESET=""
ACTIVE_COMMITTEE=""
if [[ -f "${ACTIVE}" ]]; then
  read -r ACTIVE_PRESET ACTIVE_COMMITTEE < <(node -e '
    const a = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))
    console.log(a.preset, a.committee)' "${ACTIVE}")
fi
cleanup() {
  local status=$?
  rm -rf "${BUILD_OUTPUT}"
  if [[ ${status} -ne 0 && -n "${ACTIVE_PRESET}" ]]; then
    echo "Restoring the ${ACTIVE_PRESET}/${ACTIVE_COMMITTEE} circuits" >&2
    pnpm -C "${REPO_ROOT}" build:circuits --preset "${ACTIVE_PRESET}" --committee "${ACTIVE_COMMITTEE}" > /dev/null || true
  fi
}
trap cleanup EXIT

rm -rf "${DIST}"
for PRESET in "${PRESETS[@]}"; do
  CIRCUIT_ARGS=()
  for CIRCUIT in "${ARTIFACTS[@]}"; do
    CIRCUIT_ARGS+=(--circuit "${CIRCUIT}")
  done

  pnpm -C "${REPO_ROOT}" build:circuits \
    --preset "${PRESET}" \
    --committee minimum \
    --group threshold \
    "${CIRCUIT_ARGS[@]}" \
    --output "${BUILD_OUTPUT}" \
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
    insecure-lbfv) EXPECTED_DEGREE=128 ;;
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

# The SDK's trBFV presets are INSECURE_THRESHOLD_64 (on-chain set 4, the `insecure-64` circuit
# preset) and SECURE_THRESHOLD_8192; the default proves at degree 64.
pnpm -C "${REPO_ROOT}" build:circuits \
  --preset insecure-64 \
  --committee "${COMMITTEE}" \
  --group threshold \
  --circuit user_data_encryption \
  --skip-vk \
  --skip-checksums \
  --no-clean-targets
