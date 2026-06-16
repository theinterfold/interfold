#!/bin/bash

# extract_crisp_verify_gas.sh - Runs CRISP verifier test with gas reporter and emits JSON.
# Usage: ./extract_crisp_verify_gas.sh --output <json_file> [--mode insecure|secure]
#        [--committee minimum|micro|small] [--verbose] [--skip-build] [--force-build]
#
# Integration test env (also set by run_benchmarks.sh):
#   BENCHMARK_PROOF_AGGREGATION=true        — always enabled in the benchmark harness
#   BENCHMARK_MULTITHREAD_JOBS=N            — Rayon concurrent ZK jobs (default: 1)
#   BENCHMARK_DKG_FOLD_ATTESTATION_VERIFIER — EIP-712 verifying contract for fold attestations

set -e

OUTPUT_JSON=""
MODE="insecure"
COMMITTEE=""
VERBOSE=false
SKIP_BUILD=false
FORCE_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --output)
            OUTPUT_JSON="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
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
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --skip-build|--no-build)
            SKIP_BUILD=true
            shift
            ;;
        --force-build)
            FORCE_BUILD=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --output <json_file> [--mode insecure|secure] [--committee minimum|micro|small] [--verbose] [--skip-build] [--force-build]"
            exit 1
            ;;
    esac
done

if [ -z "$OUTPUT_JSON" ]; then
    echo "Usage: $0 --output <json_file> [--mode insecure|secure] [--committee minimum|micro|small] [--verbose] [--skip-build] [--force-build]"
    exit 1
fi
if [ "$SKIP_BUILD" = true ] && [ "$FORCE_BUILD" = true ]; then
    echo "Error: --skip-build and --force-build are mutually exclusive"
    exit 1
fi
if [ "$MODE" != "insecure" ] && [ "$MODE" != "secure" ]; then
    echo "Error: mode must be 'insecure' or 'secure'"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
# shellcheck source=load_default_committee.sh
source "${SCRIPT_DIR}/load_default_committee.sh"
if [ -z "$COMMITTEE" ]; then
    load_default_committee "" "$REPO_ROOT"
    COMMITTEE="$COMMITTEE_NAME"
fi
CRISP_CONTRACTS_DIR="${REPO_ROOT}/examples/CRISP/packages/crisp-contracts"
TMP_LOG_CRISP="$(mktemp)"
TMP_LOG_FOLDED="$(mktemp)"
TMP_LOG_INTERFOLD="$(mktemp)"
TMP_JSON_INTERFOLD="$(mktemp)"
TMP_JSON_FOLDED="$(mktemp)"
TMP_JSON_SUMMARY="$(mktemp)"

cleanup_tmp_files() {
    rm -f "$TMP_LOG_CRISP" "$TMP_LOG_FOLDED" "$TMP_LOG_INTERFOLD" "$TMP_JSON_INTERFOLD" "$TMP_JSON_FOLDED" "$TMP_JSON_SUMMARY"
}
trap cleanup_tmp_files EXIT

if [ ! -d "$CRISP_CONTRACTS_DIR" ]; then
    cat > "$OUTPUT_JSON" <<EOF
{
  "verify_gas": null,
  "source": "crisp_verify_test",
  "note": "CRISP contracts directory not found"
}
EOF
    exit 0
fi

INTERFOLD_CONTRACTS_DIR="${REPO_ROOT}/packages/interfold-contracts"
OUTPUT_DIR="$(cd "$(dirname "$OUTPUT_JSON")" && pwd)"
RAW_DIR="${OUTPUT_DIR}/raw"

# Ensure recursive/noir VK variants exist for integration-based folded-proof export.
# This populates target artifacts required by `test_trbfv_actor`.
if [ "$MODE" = "secure" ]; then
    PRESET_NAME="secure-8192"
else
    PRESET_NAME="insecure-512"
fi

require_preset_artifacts() {
    if ! "${SCRIPT_DIR}/check_circuit_preset_artifacts.sh" "$PRESET_NAME" --committee "$COMMITTEE"; then
        exit 1
    fi
}

if [ "$SKIP_BUILD" = true ]; then
    echo "  [gas] Skipping circuit build and Honk verifier generation (--skip-build)."
    require_preset_artifacts
else
    ENSURE_ARGS=("$PRESET_NAME" --committee "$COMMITTEE")
    if [ "$FORCE_BUILD" = true ]; then
        ENSURE_ARGS+=(--force-build)
    fi
    if [ "$VERBOSE" = true ]; then
        ENSURE_ARGS+=(--verbose)
    fi
    "${SCRIPT_DIR}/ensure_circuit_preset_built.sh" "${ENSURE_ARGS[@]}"
    echo "  [gas] Build artifacts ready."

    # Align circuits/bin with PRESET_NAME, then verify preset artifacts.
    # insecure: also diff committed Honk .sol (pinned to insecure-512).
    # secure:   committed .sol stay insecure-only; gas replay deploys fresh verifiers from bin.
    echo "  [gas] Verifying circuit preset '${PRESET_NAME}' (dist stamp + circuits/bin)..."
    if [ "$VERBOSE" = true ]; then
        echo "  [gas] [verbose] Running: pnpm generate:verifiers --check --no-compile --preset ${PRESET_NAME}"
        (
          cd "$REPO_ROOT" && \
          pnpm generate:verifiers --check --no-compile --preset "$PRESET_NAME"
        )
    else
        (
          cd "$REPO_ROOT" && \
          pnpm generate:verifiers --check --no-compile --preset "$PRESET_NAME"
        )
    fi
    echo "  [gas] Preset '${PRESET_NAME}' artifacts ready for integration + gas replay."
    require_preset_artifacts
fi

set +e
echo "  [gas] Running CRISP verifier test for Pi_user gas..."
(
  cd "$CRISP_CONTRACTS_DIR" && \
  pnpm hardhat test mocha --grep "should verify the proof correctly with the crisp verifier"
) 2>&1 | tee "$TMP_LOG_CRISP"
CRISP_TEST_EXIT_CODE=${PIPESTATUS[0]}
echo "  [gas] CRISP test completed (exit=${CRISP_TEST_EXIT_CODE})."
require_preset_artifacts
BENCHMARK_PROOF_AGGREGATION=true
echo "  [gas] Running integration test (test_trbfv_actor); proof_aggregation=true, multithread_jobs=${BENCHMARK_MULTITHREAD_JOBS:-1}, profile=release..."
(
  cd "$REPO_ROOT" && \
  BENCHMARK_MODE="$MODE" \
  BENCHMARK_PROOF_AGGREGATION=true \
  BENCHMARK_FOLDED_OUTPUT="$TMP_JSON_FOLDED" \
  BENCHMARK_SUMMARY_OUTPUT="$TMP_JSON_SUMMARY" \
  cargo test --release -p e3-tests test_trbfv_actor -- --nocapture
) 2>&1 | tee "$TMP_LOG_FOLDED"
FOLDED_TEST_EXIT_CODE=${PIPESTATUS[0]}
echo "  [gas] Integration export completed (exit=${FOLDED_TEST_EXIT_CODE})."
INTERFOLD_TEST_EXIT_CODE=0
if [ "$FOLDED_TEST_EXIT_CODE" -ne 0 ]; then
    echo "  [gas] Skipping EVM replay: test_trbfv_actor failed (exit=${FOLDED_TEST_EXIT_CODE})."
    echo '{}' >"$TMP_JSON_INTERFOLD"
elif [ ! -s "$TMP_JSON_FOLDED" ] || ! jq -e '(.dkg_aggregator.proof_hex != "") and (.decryption_aggregator.proof_hex != "")' "$TMP_JSON_FOLDED" >/dev/null 2>&1; then
    echo "  [gas] Skipping EVM replay: folded proof export missing or empty."
    echo '{}' >"$TMP_JSON_INTERFOLD"
else
    echo "  [gas] Replaying folded artifacts on EVM verifiers for Pi_DKG/Pi_dec gas..."
    (
      cd "$INTERFOLD_CONTRACTS_DIR" && \
      BENCHMARK_RAW_DIR="$RAW_DIR" BENCHMARK_GAS_OUTPUT="$TMP_JSON_INTERFOLD" BENCHMARK_FOLDED_JSON="$TMP_JSON_FOLDED" \
      BENCHMARK_PRESET="$PRESET_NAME" \
      pnpm hardhat run scripts/benchmarkGasFromRaw.ts --network hardhat
    ) 2>&1 | tee "$TMP_LOG_INTERFOLD"
    INTERFOLD_TEST_EXIT_CODE=${PIPESTATUS[0]}
    echo "  [gas] EVM replay completed (exit=${INTERFOLD_TEST_EXIT_CODE})."
fi
set -e

parse_marker() {
    local marker="$1"
    local file_path="$2"
    python3 - "$marker" "$file_path" <<'PY'
import re
import sys

marker = sys.argv[1]
path = sys.argv[2]
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    text = f.read()

m = re.search(rf"\[bench-gas\]\s+{re.escape(marker)}=(\d+)", text)
if m:
    print(m.group(1))
PY
}

hex_len_bytes() {
    local hex="${1:-}"
    python3 - "$hex" <<'PY'
import sys
h = sys.argv[1] or ""
if h.startswith("0x"):
    h = h[2:]
if len(h) % 2 != 0:
    print("")
else:
    print(len(h) // 2)
PY
}

calldata_gas_from_hex() {
    local hex="${1:-}"
    python3 - "$hex" <<'PY'
import sys
h = sys.argv[1] or ""
if h.startswith("0x"):
    h = h[2:]
if len(h) % 2 != 0:
    print("")
    raise SystemExit(0)
gas = 0
for i in range(0, len(h), 2):
    b = h[i:i+2]
    gas += 4 if b == "00" else 16
print(gas)
PY
}

USER_VERIFY_GAS=$(parse_marker "crisp_user_verify" "$TMP_LOG_CRISP")
DKG_VERIFY_GAS=$(jq -r '.verify_gas.dkg // empty' "$TMP_JSON_INTERFOLD" 2>/dev/null || true)
DEC_VERIFY_GAS=$(jq -r '.verify_gas.dec // empty' "$TMP_JSON_INTERFOLD" 2>/dev/null || true)

DKG_PROOF_HEX=$(jq -r '.dkg_aggregator.proof_hex // empty' "$TMP_JSON_FOLDED" 2>/dev/null || true)
DKG_PUBLIC_HEX=$(jq -r '.dkg_aggregator.public_inputs_hex // empty' "$TMP_JSON_FOLDED" 2>/dev/null || true)
DEC_PROOF_HEX=$(jq -r '.decryption_aggregator.proof_hex // empty' "$TMP_JSON_FOLDED" 2>/dev/null || true)
DEC_PUBLIC_HEX=$(jq -r '.decryption_aggregator.public_inputs_hex // empty' "$TMP_JSON_FOLDED" 2>/dev/null || true)

DKG_PROOF_SIZE_BYTES=$(hex_len_bytes "$DKG_PROOF_HEX")
DKG_PUBLIC_SIZE_BYTES=$(hex_len_bytes "$DKG_PUBLIC_HEX")
DEC_PROOF_SIZE_BYTES=$(hex_len_bytes "$DEC_PROOF_HEX")
DEC_PUBLIC_SIZE_BYTES=$(hex_len_bytes "$DEC_PUBLIC_HEX")

DKG_PROOF_CALLDATA_GAS=$(calldata_gas_from_hex "$DKG_PROOF_HEX")
DKG_PUBLIC_CALLDATA_GAS=$(calldata_gas_from_hex "$DKG_PUBLIC_HEX")
DEC_PROOF_CALLDATA_GAS=$(calldata_gas_from_hex "$DEC_PROOF_HEX")
DEC_PUBLIC_CALLDATA_GAS=$(calldata_gas_from_hex "$DEC_PUBLIC_HEX")

[ -z "$USER_VERIFY_GAS" ] && USER_VERIFY_GAS="null"
[ -z "$DKG_VERIFY_GAS" ] && DKG_VERIFY_GAS="null"
[ -z "$DEC_VERIFY_GAS" ] && DEC_VERIFY_GAS="null"
[ -z "$DKG_PROOF_SIZE_BYTES" ] && DKG_PROOF_SIZE_BYTES="null"
[ -z "$DKG_PUBLIC_SIZE_BYTES" ] && DKG_PUBLIC_SIZE_BYTES="null"
[ -z "$DEC_PROOF_SIZE_BYTES" ] && DEC_PROOF_SIZE_BYTES="null"
[ -z "$DEC_PUBLIC_SIZE_BYTES" ] && DEC_PUBLIC_SIZE_BYTES="null"
[ -z "$DKG_PROOF_CALLDATA_GAS" ] && DKG_PROOF_CALLDATA_GAS="null"
[ -z "$DKG_PUBLIC_CALLDATA_GAS" ] && DKG_PUBLIC_CALLDATA_GAS="null"
[ -z "$DEC_PROOF_CALLDATA_GAS" ] && DEC_PROOF_CALLDATA_GAS="null"
[ -z "$DEC_PUBLIC_CALLDATA_GAS" ] && DEC_PUBLIC_CALLDATA_GAS="null"
INTEGRATION_SUMMARY_JSON=$(jq -c . "$TMP_JSON_SUMMARY" 2>/dev/null || true)
if [ -z "$INTEGRATION_SUMMARY_JSON" ] || ! printf '%s' "$INTEGRATION_SUMMARY_JSON" | jq -e . >/dev/null 2>&1; then
    INTEGRATION_SUMMARY_JSON="null"
fi

cat > "$OUTPUT_JSON" <<EOF
{
  "verify_gas": {
    "dkg": ${DKG_VERIFY_GAS},
    "user": ${USER_VERIFY_GAS},
    "dec": ${DEC_VERIFY_GAS}
  },
  "source": "folded_proof_export_plus_crisp_verify_test",
  "artifact_sizes_bytes": {
    "dkg": {
      "proof": ${DKG_PROOF_SIZE_BYTES},
      "public_inputs": ${DKG_PUBLIC_SIZE_BYTES}
    },
    "dec": {
      "proof": ${DEC_PROOF_SIZE_BYTES},
      "public_inputs": ${DEC_PUBLIC_SIZE_BYTES}
    }
  },
  "calldata_gas": {
    "dkg": {
      "proof": ${DKG_PROOF_CALLDATA_GAS},
      "public_inputs": ${DKG_PUBLIC_CALLDATA_GAS},
      "total": $(
        if [ "$DKG_PROOF_CALLDATA_GAS" = "null" ] || [ "$DKG_PUBLIC_CALLDATA_GAS" = "null" ]; then
            echo "null"
        else
            echo $((DKG_PROOF_CALLDATA_GAS + DKG_PUBLIC_CALLDATA_GAS))
        fi
      )
    },
    "dec": {
      "proof": ${DEC_PROOF_CALLDATA_GAS},
      "public_inputs": ${DEC_PUBLIC_CALLDATA_GAS},
      "total": $(
        if [ "$DEC_PROOF_CALLDATA_GAS" = "null" ] || [ "$DEC_PUBLIC_CALLDATA_GAS" = "null" ]; then
            echo "null"
        else
            echo $((DEC_PROOF_CALLDATA_GAS + DEC_PUBLIC_CALLDATA_GAS))
        fi
      )
    }
  },
  "integration_summary": ${INTEGRATION_SUMMARY_JSON},
  "test_exit_code": {
    "crisp": ${CRISP_TEST_EXIT_CODE},
    "folded_export": ${FOLDED_TEST_EXIT_CODE},
    "interfold_contracts": ${INTERFOLD_TEST_EXIT_CODE}
  }
}
EOF
echo "  [gas] Wrote gas/integration summary JSON: $OUTPUT_JSON"
if [ "$FOLDED_TEST_EXIT_CODE" -ne 0 ]; then
    echo "  [gas] ERROR: test_trbfv_actor failed — Pi_DKG/Pi_dec verify gas and integration timings will be incomplete."
    echo "  [gas]        Re-run after a successful integration export (no Anvil required)."
fi
if [ "$CRISP_TEST_EXIT_CODE" -ne 0 ] || [ "$FOLDED_TEST_EXIT_CODE" -ne 0 ] || [ "$INTERFOLD_TEST_EXIT_CODE" -ne 0 ]; then
    exit 1
fi
