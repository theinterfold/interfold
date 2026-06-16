#!/usr/bin/env bash
# Sync packages/interfold-contracts/test/fixtures/bfv_vk_binding/folded_artifacts.json
# from circuits/benchmarks/results_insecure_minimum/integration_summary.json (.folded_artifacts).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

INTEGRATION_JSON="${1:-${REPO_ROOT}/circuits/benchmarks/results_insecure_minimum/integration_summary.json}"
FIXTURE="${REPO_ROOT}/packages/interfold-contracts/test/fixtures/bfv_vk_binding/folded_artifacts.json"

if [ ! -f "${INTEGRATION_JSON}" ]; then
    echo "Skipping BFV VK binding fixture sync: ${INTEGRATION_JSON} not found"
    exit 0
fi

if ! jq -e '
    .folded_artifacts.dkg_aggregator.proof_hex
    and .folded_artifacts.dkg_aggregator.public_inputs_hex
    and .folded_artifacts.decryption_aggregator.proof_hex
    and .folded_artifacts.decryption_aggregator.public_inputs_hex
' "${INTEGRATION_JSON}" >/dev/null 2>&1; then
    echo "Skipping BFV VK binding fixture sync: no valid .folded_artifacts in ${INTEGRATION_JSON}"
    exit 0
fi

mkdir -p "$(dirname "${FIXTURE}")"
jq '.folded_artifacts' "${INTEGRATION_JSON}" >"${FIXTURE}.tmp"
mv "${FIXTURE}.tmp" "${FIXTURE}"
echo "✓ Synced BFV VK binding fixture: ${FIXTURE}"
