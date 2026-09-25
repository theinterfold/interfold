#!/bin/bash

# benchmark_circuit.sh - Benchmarks a single Noir circuit
# Usage: ./benchmark_circuit.sh <circuit_path> <oracle_type> <output_json> [mode] [--skip-compile]

set -e

CIRCUIT_PATH="$1"
ORACLE_TYPE="$2"  # "default" or "keccak"
OUTPUT_JSON="$3"
MODE="insecure"  # Default mode
SKIP_COMPILE=false

if [ -z "$CIRCUIT_PATH" ] || [ -z "$ORACLE_TYPE" ] || [ -z "$OUTPUT_JSON" ]; then
    echo "Usage: $0 <circuit_path> <oracle_type> <output_json> [mode] [--skip-compile]"
    exit 1
fi

# Parse optional arguments (mode and flags)
shift 3  # Remove first 3 positional args
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-compile|--no-compile)
            SKIP_COMPILE=true
            shift
            ;;
        *)
            # If it's not a flag, assume it's the mode (for backward compatibility)
            if [[ "$1" != --* ]]; then
                MODE="$1"
            else
                echo "Warning: Unknown option '$1', ignoring"
            fi
            shift
            ;;
    esac
done

# Get circuit name from Nargo.toml
CIRCUIT_NAME=$(grep "^name = " "$CIRCUIT_PATH/Nargo.toml" | sed 's/name = "\(.*\)"/\1/')
if [ -z "$CIRCUIT_NAME" ]; then
    CIRCUIT_NAME=$(basename "$CIRCUIT_PATH")
fi

# Clean up circuit path for report (relative from repo: circuits/bin/... or bin/...)
if [[ "$CIRCUIT_PATH" == *"/circuits/bin/"* ]]; then
    CIRCUIT_PATH_CLEAN=$(echo "$CIRCUIT_PATH" | sed 's|.*/circuits/\(bin/.*\)|circuits/\1|')
elif [[ "$CIRCUIT_PATH" == *"/bin/"* ]]; then
    CIRCUIT_PATH_CLEAN=$(echo "$CIRCUIT_PATH" | sed 's|.*\(bin/.*\)|\1|')
else
    CIRCUIT_PATH_CLEAN="circuits/bin/${MODE}/$(basename "$CIRCUIT_PATH")"
fi

# Portable high-resolution timestamp (fractional seconds) for timing.
# macOS date does not support %N; use gdate, Python, or Perl fallback.
get_timestamp() {
    local t
    # GNU date (Linux): date +%s.%N
    t=$(date +%s.%N 2>/dev/null)
    if [[ -n "$t" && "$t" =~ ^[0-9]+\.[0-9]+$ ]]; then
        echo "$t"
        return
    fi
    # GNU date on macOS (e.g. brew install coreutils -> gdate)
    if command -v gdate >/dev/null 2>&1; then
        t=$(gdate +%s.%N 2>/dev/null)
        if [[ -n "$t" && "$t" =~ ^[0-9]+\.[0-9]+$ ]]; then
            echo "$t"
            return
        fi
    fi
    # Python (python3 or python) - high resolution
    if command -v python3 >/dev/null 2>&1; then
        t=$(python3 -c 'import time; print("%.9f" % time.time())' 2>/dev/null)
        [[ -n "$t" ]] && echo "$t" && return
    fi
    if command -v python >/dev/null 2>&1; then
        t=$(python -c 'import time; print("%.9f" % time.time())' 2>/dev/null)
        [[ -n "$t" ]] && echo "$t" && return
    fi
    # Perl with Time::HiRes
    if t=$(perl -MTime::HiRes -e 'printf "%.9f\n", Time::HiRes::time()' 2>/dev/null); then
        if [[ "$t" =~ ^[0-9]+\.[0-9]+$ ]]; then
            echo "$t"
            return
        fi
    fi
    # Fallback: integer seconds (POSIX)
    echo "$(date +%s).000000000"
}

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=================================================="
echo "Benchmarking: $CIRCUIT_NAME"
echo "Mode: $MODE"
echo "Oracle: $ORACLE_TYPE"
echo "Skip Compile: $SKIP_COMPILE"
echo "=================================================="

cd "$CIRCUIT_PATH"

# Determine target directory location
# Check if we're in a workspace (target at parent level) or standalone (target in current dir)
TARGET_DIR="target"
WORKSPACE_ROOT="$(pwd)"

# Check if parent directory has a workspace Nargo.toml
# This handles workspace setups (e.g. circuits/bin/dkg with parent Nargo.toml)
if [ -f "../Nargo.toml" ]; then
    if grep -q "^\[workspace\]" "../Nargo.toml" 2>/dev/null; then
        # We're in a workspace, target is at workspace root
        TARGET_DIR="../target"
        WORKSPACE_ROOT="$(cd .. && pwd)"
        echo "Detected workspace setup: target directory at ${TARGET_DIR}"
    fi
else
    # Standalone project, target is in current directory
    echo "Detected standalone project: target directory at ${TARGET_DIR}"
fi

# Ensure target directory exists
mkdir -p "${TARGET_DIR}"

# Note: We don't clean workspace-level targets to avoid affecting other circuits
# Only clean if it's a local target directory
if [ "$TARGET_DIR" = "target" ]; then
    rm -rf target/
    mkdir -p target/
fi

# Prepare nargo command with oracle flag
NARGO_COMPILE_CMD="nargo compile"
NARGO_EXECUTE_CMD="nargo execute"
BB_GATES_CMD="bb gates"
BB_WRITE_VK_CMD="bb write_vk"
BB_PROVE_CMD="bb prove"
BB_VERIFY_CMD="bb verify"

# Initialize results
COMPILE_TIME=0
COMPILE_SUCCESS="false"
EXECUTE_TIME=0
EXECUTE_SUCCESS="false"
CIRCUIT_SIZE=0
WITNESS_SIZE=0
GATES_OUTPUT=""
TOTAL_GATES=0
ACIR_OPCODES=0
VK_GEN_TIME=0
VK_GEN_SUCCESS="false"
VK_SIZE=0
PROVE_TIME=0
PROVE_SUCCESS="false"
PROOF_SIZE=0
VERIFY_TIME=0
VERIFY_SUCCESS="false"
PUBLIC_INPUT_SIZE=0
PROOF_CALLDATA_GAS=0
PUBLIC_INPUT_CALLDATA_GAS=0
TOTAL_CALLDATA_GAS=0
PROOF_HEX="0x"
PUBLIC_INPUTS_HEX="0x"
ERROR_MSG=""

calculate_calldata_gas() {
    local file_path="$1"
    if [ ! -f "$file_path" ]; then
        echo "0"
        return
    fi
    python3 - "$file_path" <<'PY'
import sys

path = sys.argv[1]
with open(path, "rb") as f:
    data = f.read()

zero = data.count(0)
non_zero = len(data) - zero
print((zero * 4) + (non_zero * 16))
PY
}

# 1. COMPILE
if [ "$SKIP_COMPILE" = true ]; then
    echo ""
    echo "[1/6] Skipping compilation (using existing artifacts)..."
    # Check if compiled circuit exists
    if [ -f "${TARGET_DIR}/${CIRCUIT_NAME}.json" ]; then
        COMPILE_SUCCESS="true"
        COMPILE_TIME=0
        CIRCUIT_SIZE=$(wc -c < "${TARGET_DIR}/${CIRCUIT_NAME}.json" | tr -d ' ')
        echo "✓ Found existing compiled circuit (${CIRCUIT_SIZE} bytes)"
    else
        COMPILE_SUCCESS="false"
        COMPILE_TIME=0
        ERROR_MSG="Compilation skipped but circuit JSON not found at ${TARGET_DIR}/${CIRCUIT_NAME}.json"
        echo "✗ Compilation skipped but circuit not found"
        echo "  Expected: ${TARGET_DIR}/${CIRCUIT_NAME}.json"
    fi
else
    echo ""
    echo "[1/6] Compiling circuit..."
    START=$(get_timestamp)
    if $NARGO_COMPILE_CMD > /tmp/compile_output.txt 2>&1; then
        END=$(get_timestamp)
        COMPILE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        COMPILE_SUCCESS="true"
        echo "✓ Compilation successful (${COMPILE_TIME}s)"
        
        # Get circuit size
        if [ -f "${TARGET_DIR}/${CIRCUIT_NAME}.json" ]; then
            CIRCUIT_SIZE=$(wc -c < "${TARGET_DIR}/${CIRCUIT_NAME}.json" | tr -d ' ')
        fi
    else
        END=$(get_timestamp)
        COMPILE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        ERROR_MSG="Compilation failed. Check compilation logs."
        echo "✗ Compilation failed"
        cat /tmp/compile_output.txt
    fi
fi

# 2. EXECUTE
if [ "$COMPILE_SUCCESS" = "true" ]; then
    echo ""
    echo "[2/6] Executing circuit..."
    START=$(get_timestamp)
    if $NARGO_EXECUTE_CMD > /tmp/execute_output.txt 2>&1; then
        END=$(get_timestamp)
        EXECUTE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        EXECUTE_SUCCESS="true"
        echo "✓ Execution successful (${EXECUTE_TIME}s)"
        
        # Get witness size
        if [ -f "${TARGET_DIR}/${CIRCUIT_NAME}.gz" ]; then
            WITNESS_SIZE=$(wc -c < "${TARGET_DIR}/${CIRCUIT_NAME}.gz" | tr -d ' ')
        fi
    else
        END=$(get_timestamp)
        EXECUTE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        ERROR_MSG="Execution failed. Check execution logs."
        echo "✗ Execution failed"
        cat /tmp/execute_output.txt
    fi
fi

# 3. GATE COUNT
if [ "$EXECUTE_SUCCESS" = "true" ]; then
    echo ""
    echo "[3/6] Counting gates..."
    if GATES_OUTPUT=$($BB_GATES_CMD -b "${TARGET_DIR}/${CIRCUIT_NAME}.json" 2>&1); then
        echo "✓ Gate count retrieved"
        echo "$GATES_OUTPUT"
        # Extract circuit_size and acir_opcodes from JSON output (bb gates returns JSON)
        TOTAL_GATES=$(echo "$GATES_OUTPUT" | grep -o '"circuit_size":[[:space:]]*[0-9]*' | grep -o '[0-9]*$' | head -1)
        if [ -z "$TOTAL_GATES" ]; then
            TOTAL_GATES=0
        fi
        ACIR_OPCODES=$(echo "$GATES_OUTPUT" | grep -o '"acir_opcodes":[[:space:]]*[0-9]*' | grep -o '[0-9]*$' | head -1)
        if [ -z "$ACIR_OPCODES" ]; then
            ACIR_OPCODES=0
        fi
    else
        echo "✗ Gate count failed"
        GATES_OUTPUT="Gate count failed"
        TOTAL_GATES=0
        ACIR_OPCODES=0
    fi
fi

# 4. GENERATE VK
if [ "$EXECUTE_SUCCESS" = "true" ]; then
    echo ""
    echo "[4/6] Generating verification key..."
    START=$(get_timestamp)
    if $BB_WRITE_VK_CMD -b "${TARGET_DIR}/${CIRCUIT_NAME}.json" -o "${TARGET_DIR}" > /tmp/vk_output.txt 2>&1; then
        END=$(get_timestamp)
        VK_GEN_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        VK_GEN_SUCCESS="true"
        echo "✓ VK generation successful (${VK_GEN_TIME}s)"
        
        # Get VK size (bb creates vk file directly in target directory)
        if [ -f "${TARGET_DIR}/vk" ]; then
            VK_SIZE=$(wc -c < "${TARGET_DIR}/vk" | tr -d ' ')
        fi
    else
        END=$(get_timestamp)
        VK_GEN_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        echo "✗ VK generation failed"
        cat /tmp/vk_output.txt
    fi
fi

# 5. GENERATE PROOF
if [ "$VK_GEN_SUCCESS" = "true" ]; then
    echo ""
    echo "[5/6] Generating proof..."
    START=$(get_timestamp)
    if $BB_PROVE_CMD -b "${TARGET_DIR}/${CIRCUIT_NAME}.json" -w "${TARGET_DIR}/${CIRCUIT_NAME}.gz" -k "${TARGET_DIR}/vk" -o "${TARGET_DIR}" > /tmp/prove_output.txt 2>&1; then
        END=$(get_timestamp)
        PROVE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        PROVE_SUCCESS="true"
        echo "✓ Proof generation successful (${PROVE_TIME}s)"
        
        # Get proof size (bb creates proof file directly in target directory)
        if [ -f "${TARGET_DIR}/proof" ]; then
            PROOF_SIZE=$(wc -c < "${TARGET_DIR}/proof" | tr -d ' ')
            PROOF_CALLDATA_GAS=$(calculate_calldata_gas "${TARGET_DIR}/proof")
            PROOF_HEX=$(python3 - "${TARGET_DIR}/proof" <<'PY'
import binascii
import pathlib
import sys
data = pathlib.Path(sys.argv[1]).read_bytes()
print("0x" + binascii.hexlify(data).decode())
PY
)
        fi
    else
        END=$(get_timestamp)
        PROVE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        echo "✗ Proof generation failed"
        cat /tmp/prove_output.txt
    fi
fi

# 6. VERIFY PROOF
if [ "$PROVE_SUCCESS" = "true" ]; then
    echo ""
    echo "[6/6] Verifying proof..."
    START=$(get_timestamp)
    # bb verify expects paths to vk, proof, and public inputs (all directly in target directory)
    if $BB_VERIFY_CMD -k "${TARGET_DIR}/vk" -p "${TARGET_DIR}/proof" -i "${TARGET_DIR}/public_inputs" > /tmp/verify_output.txt 2>&1; then
        END=$(get_timestamp)
        VERIFY_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        VERIFY_SUCCESS="true"
        echo "✓ Verification successful (${VERIFY_TIME}s)"
        if [ -f "${TARGET_DIR}/public_inputs" ]; then
            PUBLIC_INPUT_SIZE=$(wc -c < "${TARGET_DIR}/public_inputs" | tr -d ' ')
            PUBLIC_INPUT_CALLDATA_GAS=$(calculate_calldata_gas "${TARGET_DIR}/public_inputs")
            PUBLIC_INPUTS_HEX=$(python3 - "${TARGET_DIR}/public_inputs" <<'PY'
import binascii
import pathlib
import sys
data = pathlib.Path(sys.argv[1]).read_bytes()
print("0x" + binascii.hexlify(data).decode())
PY
)
        fi
        TOTAL_CALLDATA_GAS=$((PROOF_CALLDATA_GAS + PUBLIC_INPUT_CALLDATA_GAS))
    else
        END=$(get_timestamp)
        VERIFY_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        echo "✗ Verification failed"
        cat /tmp/verify_output.txt
    fi
fi

# Get system info (escape for JSON)
NARGO_VERSION=$(nargo --version 2>/dev/null | tr '\n' ' ' || echo "unknown")
BB_VERSION=$(bb --version 2>/dev/null | tr '\n' ' ' || echo "unknown")
OS_INFO=$(uname -s)
ARCH_INFO=$(uname -m)

# Get hardware info
if [ "$(uname -s)" = "Darwin" ]; then
    # macOS
    CPU_MODEL=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
    CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
    RAM_GB=$(echo "scale=2; $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824" | bc)
    [ "$RAM_GB" = "0" ] && RAM_GB="unknown"
elif [ "$(uname -s)" = "Linux" ]; then
    # Linux
    CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "unknown")
    CPU_CORES=$(nproc 2>/dev/null || grep -c processor /proc/cpuinfo 2>/dev/null || echo "unknown")
    RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    RAM_GB=$(echo "scale=2; $RAM_KB / 1048576" | bc)
    [ "$RAM_GB" = "0" ] && RAM_GB="unknown"
else
    CPU_MODEL="unknown"
    CPU_CORES="unknown"
    RAM_GB="unknown"
fi

# JSON-escape string fields to ensure valid output
CIRCUIT_NAME_JSON=$(printf '%s' "$CIRCUIT_NAME" | jq -Rs .)
CIRCUIT_PATH_CLEAN_JSON=$(printf '%s' "$CIRCUIT_PATH_CLEAN" | jq -Rs .)
MODE_JSON=$(printf '%s' "$MODE" | jq -Rs .)
ORACLE_TYPE_JSON=$(printf '%s' "$ORACLE_TYPE" | jq -Rs .)
TIMESTAMP_JSON=$(printf '%s' "$TIMESTAMP" | jq -Rs .)
OS_INFO_JSON=$(printf '%s' "$OS_INFO" | jq -Rs .)
ARCH_INFO_JSON=$(printf '%s' "$ARCH_INFO" | jq -Rs .)
CPU_MODEL_JSON=$(printf '%s' "$CPU_MODEL" | jq -Rs .)
CPU_CORES_JSON=$(printf '%s' "$CPU_CORES" | jq -Rs .)
RAM_GB_JSON=$(printf '%s' "$RAM_GB" | jq -Rs .)
NARGO_VERSION_JSON=$(printf '%s' "$NARGO_VERSION" | jq -Rs .)
BB_VERSION_JSON=$(printf '%s' "$BB_VERSION" | jq -Rs .)

# Create JSON output
cat > "$OUTPUT_JSON" <<EOF
{
  "circuit_name": $CIRCUIT_NAME_JSON,
  "circuit_path": $CIRCUIT_PATH_CLEAN_JSON,
  "mode": $MODE_JSON,
  "oracle_type": $ORACLE_TYPE_JSON,
  "timestamp": $TIMESTAMP_JSON,
  "system_info": {
    "os": $OS_INFO_JSON,
    "arch": $ARCH_INFO_JSON,
    "cpu_model": $CPU_MODEL_JSON,
    "cpu_cores": $CPU_CORES_JSON,
    "ram_gb": $RAM_GB_JSON,
    "nargo_version": $NARGO_VERSION_JSON,
    "bb_version": $BB_VERSION_JSON
  },
  "compilation": {
    "time_seconds": ${COMPILE_TIME:-0},
    "success": $COMPILE_SUCCESS,
    "circuit_size_bytes": ${CIRCUIT_SIZE:-0}
  },
  "execution": {
    "time_seconds": ${EXECUTE_TIME:-0},
    "success": $EXECUTE_SUCCESS,
    "witness_size_bytes": ${WITNESS_SIZE:-0}
  },
  "gates": {
    "total_gates": ${TOTAL_GATES:-0},
    "acir_opcodes": ${ACIR_OPCODES:-0},
    "raw_output": $(echo "$GATES_OUTPUT" | jq -Rs .)
  },
  "vk_generation": {
    "time_seconds": ${VK_GEN_TIME:-0},
    "success": $VK_GEN_SUCCESS,
    "vk_size_bytes": ${VK_SIZE:-0}
  },
  "proof_generation": {
    "time_seconds": ${PROVE_TIME:-0},
    "success": $PROVE_SUCCESS,
    "proof_size_bytes": ${PROOF_SIZE:-0},
    "proof_hex": $(printf '%s' "$PROOF_HEX" | jq -Rs .)
  },
  "verification": {
    "time_seconds": ${VERIFY_TIME:-0},
    "success": $VERIFY_SUCCESS,
    "public_inputs_hex": $(printf '%s' "$PUBLIC_INPUTS_HEX" | jq -Rs .),
    "public_inputs_size_bytes": ${PUBLIC_INPUT_SIZE:-0},
    "calldata_gas_proof": ${PROOF_CALLDATA_GAS:-0},
    "calldata_gas_public_inputs": ${PUBLIC_INPUT_CALLDATA_GAS:-0},
    "calldata_gas_total": ${TOTAL_CALLDATA_GAS:-0}
  },
  "error": $(echo "$ERROR_MSG" | jq -Rs .)
}
EOF

echo ""
echo "=================================================="
echo "Benchmark complete!"
echo "Results saved to: $OUTPUT_JSON"
echo "=================================================="
