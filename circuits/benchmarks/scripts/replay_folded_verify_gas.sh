#!/usr/bin/env bash
# Replay DkgAggregatorVerifier / DecryptionAggregatorVerifier estimateGas using folded proofs from an
# integration summary JSON (BENCHMARK_SUMMARY_OUTPUT shape: .folded_artifacts.{dkg_aggregator,...})
# and merge verify_gas.dkg / verify_gas.dec into an existing crisp_verify_gas.json.
#
# Usage (from repo root):
#   ./circuits/benchmarks/scripts/replay_folded_verify_gas.sh \
#     --summary /tmp/summary_secure.json \
#     --gas-json ./circuits/benchmarks/results_secure_minimum/crisp_verify_gas.json \
#     --build secure-8192
#
# Use --build <preset> when Hardhat reverts with SumcheckFailed (verifier VKs must match the
# preset used to generate the folded proofs, e.g. secure-8192 for SecureThreshold8192).

set -e

SUMMARY_JSON=""
GAS_JSON=""
BUILD_PRESET=""
COMMITTEE=""
FORCE_BUILD=false
SKIP_BUILD=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
INTERFOLD_CONTRACTS="${REPO_ROOT}/packages/interfold-contracts"

while [[ $# -gt 0 ]]; do
    case $1 in
        --summary) SUMMARY_JSON="$2"; shift 2 ;;
        --gas-json) GAS_JSON="$2"; shift 2 ;;
        --build)
            BUILD_PRESET="$2"
            shift 2
            ;;
        --committee)
            COMMITTEE="$2"
            case "$COMMITTEE" in
                minimum|micro|small) ;;
                *)
                    echo "Error: --committee must be minimum|micro|small (got: $COMMITTEE)"
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --force-build)
            FORCE_BUILD=true
            shift
            ;;
        --skip-build|--no-build)
            SKIP_BUILD=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --summary <integration_summary.json> --gas-json <crisp_verify_gas.json> [--build <nargo-preset>]"
            exit 1
            ;;
    esac
done

if [ -z "$SUMMARY_JSON" ] || [ -z "$GAS_JSON" ]; then
    echo "Usage: $0 --summary <integration_summary.json> --gas-json <crisp_verify_gas.json> [--build <nargo-preset>]"
    exit 1
fi
if [ ! -f "$SUMMARY_JSON" ]; then
    echo "Error: summary file not found: $SUMMARY_JSON"
    exit 1
fi
if [ ! -f "$GAS_JSON" ]; then
    echo "Error: gas JSON not found: $GAS_JSON"
    exit 1
fi

if ! jq -e '.folded_artifacts.dkg_aggregator.proof_hex and .folded_artifacts.decryption_aggregator.proof_hex' "$SUMMARY_JSON" >/dev/null 2>&1; then
    echo "Error: $SUMMARY_JSON must contain .folded_artifacts with dkg_aggregator and decryption_aggregator proof_hex"
    exit 1
fi

RAW_DIR="$(cd "$(dirname "$GAS_JSON")" && pwd)/raw"
if [ ! -d "$RAW_DIR" ]; then
    echo "Error: expected raw benchmark dir next to gas JSON: $RAW_DIR"
    exit 1
fi

TMP_FOLDED="$(mktemp)"
TMP_GAS_PARTIAL="$(mktemp)"
trap 'rm -f "$TMP_FOLDED" "$TMP_GAS_PARTIAL"' EXIT

jq -c '.folded_artifacts' "$SUMMARY_JSON" >"$TMP_FOLDED"

if [ -n "$BUILD_PRESET" ]; then
    if [ "$SKIP_BUILD" = true ]; then
        echo "  [replay-gas] Skipping circuit build (--skip-build)."
        "${SCRIPT_DIR}/check_circuit_preset_artifacts.sh" "$BUILD_PRESET"
    else
        ENSURE_ARGS=("$BUILD_PRESET")
        if [ -n "$COMMITTEE" ]; then
            ENSURE_ARGS+=(--committee "$COMMITTEE")
        fi
        if [ "$FORCE_BUILD" = true ]; then
            ENSURE_ARGS+=(--force-build)
        fi
        "${SCRIPT_DIR}/ensure_circuit_preset_built.sh" "${ENSURE_ARGS[@]}"
        echo "  [replay-gas] Verifying preset '${BUILD_PRESET}' (dist stamp + circuits/bin)..."
        (cd "$REPO_ROOT" && pnpm generate:verifiers --check --no-compile --preset "$BUILD_PRESET")
    fi
fi

echo "  [replay-gas] Running Hardhat benchmarkGasFromRaw.ts (folded proofs)..."
(
    cd "$INTERFOLD_CONTRACTS" && \
    BENCHMARK_RAW_DIR="$RAW_DIR" \
    BENCHMARK_GAS_OUTPUT="$TMP_GAS_PARTIAL" \
    BENCHMARK_FOLDED_JSON="$TMP_FOLDED" \
    BENCHMARK_PRESET="${BUILD_PRESET:-insecure-512}" \
    pnpm hardhat run scripts/benchmarkGasFromRaw.ts --network hardhat
)

if ! jq -e '.verify_gas.dkg and .verify_gas.dec' "$TMP_GAS_PARTIAL" >/dev/null 2>&1; then
    echo "Error: partial gas output missing verify_gas.dkg/dec: $TMP_GAS_PARTIAL"
    cat "$TMP_GAS_PARTIAL"
    exit 1
fi

TMP_OUT="$(mktemp)"
jq --slurpfile patch "$TMP_GAS_PARTIAL" \
    '.verify_gas.dkg = $patch[0].verify_gas.dkg | .verify_gas.dec = $patch[0].verify_gas.dec' \
    "$GAS_JSON" >"$TMP_OUT"
mv "$TMP_OUT" "$GAS_JSON"
trap - EXIT
rm -f "$TMP_FOLDED" "$TMP_GAS_PARTIAL"

echo "  [replay-gas] Updated verify_gas.dkg and verify_gas.dec in: $GAS_JSON"
echo "  [replay-gas] Regenerate the report with generate_report.sh (and --integration-summary if you still use it for timings)."
