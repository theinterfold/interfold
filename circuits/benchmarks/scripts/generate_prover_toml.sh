#!/bin/bash

# generate_prover_toml.sh - Generates Prover.toml (and configs.nr) for a circuit via zk_cli
# Usage: ./generate_prover_toml.sh <circuit_path> <mode> <repo_root>
#   circuit_path: e.g. "dkg/pk" or "threshold/share_decryption"
#   mode: "insecure" or "secure"; set BENCHMARK_PRESET for the exact BFV preset
#   repo_root: absolute path to repository root (where Cargo.toml and circuits/ live)

set -e

CIRCUIT_PATH="$1"
MODE="$2"
REPO_ROOT="$3"

if [ -z "$CIRCUIT_PATH" ] || [ -z "$MODE" ] || [ -z "$REPO_ROOT" ]; then
    echo "Usage: $0 <circuit_path> <mode> <repo_root>"
    echo "  circuit_path: e.g. dkg/pk, threshold/share_decryption"
    echo "  mode: insecure or secure"
    echo "  repo_root: absolute path to repo root"
    exit 1
fi

if [ "$MODE" != "insecure" ] && [ "$MODE" != "secure" ]; then
    echo "Error: mode must be 'insecure' or 'secure'"
    exit 1
fi

PRESET="INSECURE_THRESHOLD"
if [ "${BENCHMARK_PRESET:-}" = "secure-8192" ]; then
    PRESET="SECURE_THRESHOLD_8192"
elif [ "${BENCHMARK_PRESET:-}" = "secure-16384" ]; then
    PRESET="SECURE_THRESHOLD_16384"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=load_default_committee.sh
source "${SCRIPT_DIR}/load_default_committee.sh"
DEFAULT_MOD_NR="${REPO_ROOT}/circuits/lib/src/configs/default/mod.nr"
# Generate Prover.toml using the benchmark run's committee (set by run_benchmarks.sh when invoked
# from the suite; otherwise falls back to the on-disk active committee).
if [ -z "${BENCHMARK_COMMITTEE:-}" ]; then
    load_default_committee "$DEFAULT_MOD_NR" "$REPO_ROOT"
else
    load_committee_by_name "$BENCHMARK_COMMITTEE" "$REPO_ROOT"
fi

if [ -z "$COMMITTEE_NAME" ]; then
    echo "Error: COMMITTEE_NAME not set by load_default_committee.sh"
    exit 1
fi

OUTPUT_DIR="${REPO_ROOT}/circuits/bin/${CIRCUIT_PATH}"

# Map circuit path to zk_cli --circuit and optional --inputs
# DKG circuits that need --inputs: share-computation, share-encryption, share-decryption
# config has no witness inputs (verifies constants only), so skip zk_cli
# shellcheck source=zk_cli_helpers.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/zk_cli_helpers.sh"

ZK_ARGS=($(get_zk_args "$CIRCUIT_PATH"))
ZK_CIRCUIT="${ZK_ARGS[0]}"
ZK_INPUTS="${ZK_ARGS[1]:-}"

cd "$REPO_ROOT"

generate_raw_toml() {
    local output_dir="$1"
    local cmd=(cargo run -p e3-zk-helpers --bin zk_cli -- --circuit "$ZK_CIRCUIT" --preset "$PRESET" --committee "$COMMITTEE_NAME" --output "$output_dir" --toml --no-configs)
    if [ -n "$ZK_INPUTS" ]; then
        cmd+=(--inputs "$ZK_INPUTS")
    fi
    "${cmd[@]}"
}

if [ "$CIRCUIT_PATH" = "threshold/user_data_encryption_ct0" ] || [ "$CIRCUIT_PATH" = "threshold/user_data_encryption_ct1" ]; then
    TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/interfold-ude-benchmark.XXXXXX")
    trap 'rm -rf "$TEMP_DIR"' EXIT
    echo "  Generating the user-data encryption witness and recursive child proofs..."
    generate_raw_toml "$TEMP_DIR"
    python3 - "$TEMP_DIR/Prover.toml" "$TEMP_DIR/inputs.json" <<'PY'
import json
import sys
import tomllib

def stringify_integers(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return [stringify_integers(item) for item in value]
    if isinstance(value, dict):
        return {key: stringify_integers(item) for key, item in value.items()}
    return value

with open(sys.argv[1], "rb") as source:
    witness = tomllib.load(source)
with open(sys.argv[2], "w", encoding="utf-8") as target:
    json.dump(stringify_integers(witness), target, separators=(",", ":"))
PY
    NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=24576}" pnpm --filter @interfold/user-data-encryption-prover exec tsx \
        src/generate-benchmark-toml.ts \
        --input "$TEMP_DIR/inputs.json" \
        --preset "${BENCHMARK_PRESET:-insecure}" \
        --committee "$COMMITTEE_NAME" \
        --output-root "$REPO_ROOT/circuits/bin/threshold"
    exit 0
fi

if [ "$CIRCUIT_PATH" = "dkg/sk_share_computation_chunk" ] || [ "$CIRCUIT_PATH" = "dkg/esm_share_computation_chunk" ]; then
    TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/interfold-c2-benchmark.XXXXXX")
    trap 'rm -rf "$TEMP_DIR"' EXIT
    echo "  Generating a representative C2 chunk witness..."
    generate_raw_toml "$TEMP_DIR"
    CHUNK_SIZE=512
    if [ "${BENCHMARK_PRESET:-insecure}" = "insecure" ]; then
        CHUNK_SIZE=128
    fi
    python3 "${SCRIPT_DIR}/extract_share_computation_chunk.py" \
        "$TEMP_DIR/Prover.toml" "$OUTPUT_DIR/Prover.toml" "$CIRCUIT_PATH" "$CHUNK_SIZE"
    exit 0
fi

if [ "$ZK_CIRCUIT" = "_no_zk_cli" ]; then
    echo "  No Prover.toml needed (config circuit has no witness inputs)"
    # Ensure empty Prover.toml so nargo execute can run
    mkdir -p "$OUTPUT_DIR"
    : > "$OUTPUT_DIR/Prover.toml"
    exit 0
fi

echo "  Generating Prover.toml: zk_cli --circuit $ZK_CIRCUIT --preset $PRESET --committee $COMMITTEE_NAME ${ZK_INPUTS:+--inputs $ZK_INPUTS}"
if ! generate_raw_toml "$OUTPUT_DIR" 2>&1; then
    echo "Error: zk_cli failed for $CIRCUIT_PATH"
    exit 1
fi
