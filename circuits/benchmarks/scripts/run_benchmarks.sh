#!/bin/bash

# run_benchmarks.sh - Main orchestration script for benchmarking circuits
# Usage: ./run_benchmarks.sh [--config <config_file>] [--mode insecure|secure]
#   [--committee minimum|micro|small] [--circuit <path>]
#   [--skip-compile] [--bench-compile] [--clean] [--verbose]
#   [--multithread-jobs N]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARKS_DIR="$(dirname "$SCRIPT_DIR")"
# shellcheck source=benchmark_output_dir.sh
source "${SCRIPT_DIR}/benchmark_output_dir.sh"
CONFIG_FILE="${BENCHMARKS_DIR}/config.json"
CLEAN_ARTIFACTS=false
MODE_OVERRIDE=""
COMMITTEE_OVERRIDE=""
SKIP_COMPILE=false
BENCH_COMPILE=false
CIRCUIT_FILTER=""
VERBOSE=false
PRESET_ARTIFACTS_READY=false
MULTITHREAD_JOBS="${BENCHMARK_MULTITHREAD_JOBS:-}"
export BENCHMARK_PROOF_AGGREGATION=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --mode)
            MODE_OVERRIDE="$2"
            if [ "$MODE_OVERRIDE" != "insecure" ] && [ "$MODE_OVERRIDE" != "secure" ]; then
                echo "Error: Mode must be 'insecure' or 'secure'"
                exit 1
            fi
            shift 2
            ;;
        --committee)
            COMMITTEE_OVERRIDE="$2"
            case "$COMMITTEE_OVERRIDE" in
                minimum|micro|small) ;;
                *)
                    echo "Error: --committee must be minimum|micro|small (got: $COMMITTEE_OVERRIDE)"
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --circuit)
            CIRCUIT_FILTER="$2"
            shift 2
            ;;
        --skip-compile|--no-compile)
            SKIP_COMPILE=true
            shift
            ;;
        --bench-compile)
            BENCH_COMPILE=true
            shift
            ;;
        --clean)
            CLEAN_ARTIFACTS=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --multithread-jobs)
            MULTITHREAD_JOBS="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--config <config_file>] [--mode insecure|secure] [--committee minimum|micro|small] [--circuit <path>] [--skip-compile] [--bench-compile] [--clean] [--verbose] [--multithread-jobs N]"
            exit 1
            ;;
    esac
done

if [ -n "$MULTITHREAD_JOBS" ]; then
    if ! [[ "$MULTITHREAD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
        echo "Error: --multithread-jobs must be a positive integer (got: $MULTITHREAD_JOBS)"
        exit 1
    fi
    export BENCHMARK_MULTITHREAD_JOBS="$MULTITHREAD_JOBS"
elif [ -n "${BENCHMARK_MULTITHREAD_JOBS:-}" ]; then
    echo "  Using BENCHMARK_MULTITHREAD_JOBS from environment: $BENCHMARK_MULTITHREAD_JOBS"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

echo "╔════════════════════════════════════════════════╗"
echo "║       Interfold ZK Circuit Benchmark Suite       ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Read configuration (circuits may be strings or {name, modes[]}; see config.json)
ALL_CIRCUITS=$(jq -r '.circuits[] | (if type == "string" then . else .name end)' "$CONFIG_FILE")
ORACLES=$(jq -r '.oracles[]' "$CONFIG_FILE")
OUTPUT_DIR_BASE=$(jq -r '.output_dir // "results"' "$CONFIG_FILE")
BIN_DIR=$(jq -r '.bin_dir // "../bin"' "$CONFIG_FILE")
MODE=$(jq -r '.mode // "insecure"' "$CONFIG_FILE")

# Restrict to one circuit if --circuit was given
if [ -n "$CIRCUIT_FILTER" ]; then
    CIRCUITS="$CIRCUIT_FILTER"
    if ! echo "$ALL_CIRCUITS" | grep -qx "$CIRCUIT_FILTER" 2>/dev/null; then
        echo "Note: --circuit $CIRCUIT_FILTER is not in config.json; running anyway if path exists."
    fi
else
    CIRCUITS="$ALL_CIRCUITS"
fi

# Override mode if provided via command line
if [ -n "$MODE_OVERRIDE" ]; then
    MODE="$MODE_OVERRIDE"
fi

# Validate mode
if [ "$MODE" != "insecure" ] && [ "$MODE" != "secure" ]; then
    echo "Error: Invalid mode '$MODE'. Must be 'insecure' or 'secure'"
    exit 1
fi

# Monorepo root (benchmarks live in circuits/benchmarks, so go up two levels)
REPO_ROOT="$(cd "${BENCHMARKS_DIR}/../.." && pwd)"
# Circuits live under circuits/bin (bin_dir is relative to benchmarks dir, e.g. ../bin)
CIRCUITS_BASE_DIR="$(cd "${BENCHMARKS_DIR}/${BIN_DIR}" && pwd)"

# Resolve the committee for the output dir name. Explicit --committee wins; otherwise we
# read what's currently on disk (the build step below will respect that selection). Sourced
# here so OUTPUT_DIR can include the committee axis (`results_<mode>_<name>`).
# shellcheck source=load_default_committee.sh
source "${SCRIPT_DIR}/load_default_committee.sh"

assert_skip_compile_committee_matches_disk() {
    load_default_committee "" "$REPO_ROOT"
    if [ "$COMMITTEE_NAME" != "$OUTPUT_COMMITTEE" ]; then
        echo "Error: --skip-compile with --committee $OUTPUT_COMMITTEE but on-disk circuits are built for committee '$COMMITTEE_NAME'."
        echo "  Rebuild: pnpm build:circuits --committee $OUTPUT_COMMITTEE"
        echo "  Or omit --committee to benchmark the on-disk selection."
        exit 1
    fi
}

if [ -n "$COMMITTEE_OVERRIDE" ]; then
    OUTPUT_COMMITTEE="$COMMITTEE_OVERRIDE"
else
    load_default_committee "" "$REPO_ROOT"
    OUTPUT_COMMITTEE="$COMMITTEE_NAME"
fi

if [ "$SKIP_COMPILE" = true ] && [ -n "$COMMITTEE_OVERRIDE" ]; then
    assert_skip_compile_committee_matches_disk
fi

# results_<mode>_<committee> (see benchmark_output_dir.sh)
BENCHMARK_OUTPUT_DIR_BASE="$OUTPUT_DIR_BASE"
OUTPUT_DIR="$(benchmark_results_dir_basename "$MODE" "$OUTPUT_COMMITTEE")"
mkdir -p "${BENCHMARKS_DIR}/${OUTPUT_DIR}/raw"

# For secure mode, patch lib to use secure configs (restored at end)
DEFAULT_MOD_NR="${REPO_ROOT}/circuits/lib/src/configs/default/mod.nr"
DEFAULT_MOD_BACKUP=""
if [ "$MODE" = "secure" ] && [ -f "$DEFAULT_MOD_NR" ]; then
    DEFAULT_MOD_BACKUP="${DEFAULT_MOD_NR}.benchmark_backup"
    cp "$DEFAULT_MOD_NR" "$DEFAULT_MOD_BACKUP"
    if sed --version 2>/dev/null | grep -q GNU; then
        sed -i 's|super::insecure::|super::secure::|g' "$DEFAULT_MOD_NR"
    else
        sed -i '' 's|super::insecure::|super::secure::|g' "$DEFAULT_MOD_NR"
    fi
    echo "  Patched lib configs to secure (will restore)"
fi

# Store git info
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

load_committee_by_name "$OUTPUT_COMMITTEE" "$REPO_ROOT"

echo "Configuration:"
echo "  Mode: $MODE"
echo "  Committee: $OUTPUT_COMMITTEE (N=$COMMITTEE_N, T=$COMMITTEE_T, H=$COMMITTEE_H)"
if [ -n "$CIRCUIT_FILTER" ]; then
    echo "  Circuit: $CIRCUIT_FILTER (single)"
fi
if [ "$SKIP_COMPILE" = true ]; then
    echo "  Skip Compilation: Yes (using existing artifacts)"
elif [ "$BENCH_COMPILE" = true ]; then
    echo "  Per-circuit compile: Yes (--bench-compile)"
elif [ "$PRESET_ARTIFACTS_READY" = true ]; then
    echo "  Per-circuit compile: No (preset artifacts ready; use --bench-compile to measure compile time)"
fi
if [ "$VERBOSE" = true ]; then
    echo "  Verbose Logging: Yes"
fi
echo "  Proof aggregation (integration): enabled (always on in benchmarks)"
if [ -n "$BENCHMARK_MULTITHREAD_JOBS" ]; then
    echo "  Multithread concurrent jobs: $BENCHMARK_MULTITHREAD_JOBS"
fi
echo "  Git Branch: $GIT_BRANCH"
echo "  Git Commit: $GIT_COMMIT"
echo "  Circuits: $(echo $CIRCUITS | wc -w | tr -d ' ')"
echo "  Oracles: $(echo $ORACLES)"
echo "  Base Directory: $CIRCUITS_BASE_DIR"
echo "  Output Directory: ${OUTPUT_DIR}"
echo ""

# Preflight build for selected preset so raw benches and integration stages
# use consistent, freshly-generated circuit artifacts.
if [ "$SKIP_COMPILE" = false ]; then
    if [ "$MODE" = "secure" ]; then
        PRESET_NAME="secure-8192"
    else
        PRESET_NAME="insecure-512"
    fi
    ENSURE_ARGS=("$PRESET_NAME" --committee "$OUTPUT_COMMITTEE")
    if [ "$VERBOSE" = true ]; then
        ENSURE_ARGS+=(--verbose)
    fi
    "${SCRIPT_DIR}/ensure_circuit_preset_built.sh" "${ENSURE_ARGS[@]}"
    if "${SCRIPT_DIR}/check_circuit_preset_artifacts.sh" "$PRESET_NAME" --committee "$OUTPUT_COMMITTEE"; then
        PRESET_ARTIFACTS_READY=true
    fi
    echo "Preflight build complete."
    echo ""
fi

# Circuit-specific modes come from config.json (e.g. "config" has "modes": ["secure"]); see circuits/benchmarks/config.json
RUN_CIRCUITS=""
CIRCUIT_MODES=$(jq -r '.circuits[] | (if type == "string" then . else .name end) as $path | (if type == "object" and (.modes != null) then (.modes | join(",")) else "insecure,secure" end) | "\($path)\t\(.)"' "$CONFIG_FILE")
while IFS= read -r line; do
    [ -z "$line" ] && continue
    c="${line%%	*}"
    modes="${line#*	}"
    # If --circuit filter is set, we iterate over CIRCUITS (one path) and may not have entry in CIRCUIT_MODES; then run it
    if [ -n "$CIRCUIT_FILTER" ]; then
        [ "$c" != "$CIRCUIT_FILTER" ] && continue
    fi
    # Skip if this circuit is restricted to other mode(s) (see config.json "modes" field)
    if [ -n "$modes" ] && [ "${modes}" != "insecure,secure" ]; then
        if [[ ",${modes}," != *",${MODE},"* ]]; then
            echo "  Skipping $c (config.json restricts to mode(s): $modes; current mode: $MODE)"
            continue
        fi
    fi
    RUN_CIRCUITS="${RUN_CIRCUITS} ${c}"
done <<< "$CIRCUIT_MODES"
# When --circuit was given but not in config.json, no line matched; run it anyway if path exists (see note above)
if [ -n "$CIRCUIT_FILTER" ] && [ -z "$RUN_CIRCUITS" ] && ! echo "$ALL_CIRCUITS" | grep -qx "$CIRCUIT_FILTER" 2>/dev/null; then
    RUN_CIRCUITS="$CIRCUIT_FILTER"
fi
RUN_CIRCUITS=$(echo "$RUN_CIRCUITS" | xargs)
echo ""

TOTAL_BENCHMARKS=$(($(echo $RUN_CIRCUITS | wc -w | tr -d ' ') * $(echo $ORACLES | wc -w | tr -d ' ')))
CURRENT=0

# Restore lib config on exit (if we patched for secure)
restore_default_mod() {
    if [ -n "$DEFAULT_MOD_BACKUP" ] && [ -f "$DEFAULT_MOD_BACKUP" ]; then
        cp "$DEFAULT_MOD_BACKUP" "$DEFAULT_MOD_NR"
        rm -f "$DEFAULT_MOD_BACKUP"
        echo "  Restored lib configs/default to insecure"
    fi
}
trap restore_default_mod EXIT

# Run benchmarks
for CIRCUIT in $RUN_CIRCUITS; do
    CIRCUIT_PATH="${CIRCUITS_BASE_DIR}/${CIRCUIT}"
    
    if [ ! -d "$CIRCUIT_PATH" ]; then
        echo "⚠️  Warning: Circuit directory not found: $CIRCUIT_PATH"
        echo "    Skipping..."
        echo ""
        continue
    fi
    
    for ORACLE in $ORACLES; do
        CURRENT=$((CURRENT + 1))
        CIRCUIT_SLUG="$(echo "$CIRCUIT" | tr '/' '_')"
        OUTPUT_FILE="${BENCHMARKS_DIR}/${OUTPUT_DIR}/raw/${CIRCUIT_SLUG}_${ORACLE}.json"
        
        echo "────────────────────────────────────────────────"
        echo "Benchmark [$CURRENT/$TOTAL_BENCHMARKS]: ${CIRCUIT} (${MODE}) with ${ORACLE} oracle"
        echo "────────────────────────────────────────────────"
        
        # Generate Prover.toml (and configs.nr) via zk_cli so nargo execute has witness
        echo "  Generating Prover.toml..."
        if ! BENCHMARK_COMMITTEE="$OUTPUT_COMMITTEE" "${SCRIPT_DIR}/generate_prover_toml.sh" "$CIRCUIT" "$MODE" "$REPO_ROOT" 2>&1; then
            echo "⚠️  Prover.toml generation failed for $CIRCUIT, skipping benchmark"
            echo ""
            continue
        fi
        
        # Run benchmark
        BENCHMARK_ARGS=("$CIRCUIT_PATH" "$ORACLE" "$OUTPUT_FILE" "$MODE")
        if [ "$BENCH_COMPILE" != true ]; then
            if [ "$SKIP_COMPILE" = true ] || [ "$PRESET_ARTIFACTS_READY" = true ]; then
                BENCHMARK_ARGS+=("--skip-compile")
            fi
        fi
        "${SCRIPT_DIR}/benchmark_circuit.sh" "${BENCHMARK_ARGS[@]}"
        
        echo ""
    done
done

echo "╔════════════════════════════════════════════════╗"
echo "║       Generating Report...                     ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Stage 1/3: Running gas extraction pipeline (CRISP test + integration + EVM replay)..."

# Try to retrieve verifier gas from the existing CRISP verify test path.
GAS_JSON_FILE="${BENCHMARKS_DIR}/${OUTPUT_DIR}/crisp_verify_gas.json"
# Remove any previous gas artifact so failures cannot leak stale values.
rm -f "${GAS_JSON_FILE}"
EXTRACT_ARGS=(--output "${GAS_JSON_FILE}" --mode "$MODE" --committee "$OUTPUT_COMMITTEE")
if [ "$VERBOSE" = true ]; then
    EXTRACT_ARGS+=(--verbose)
fi
# Benches already validated preset+committee artifacts; gas stage only checks + runs tests.
if [ "$SKIP_COMPILE" = true ] || [ "$PRESET_ARTIFACTS_READY" = true ]; then
    EXTRACT_ARGS+=(--skip-build)
fi
if "${SCRIPT_DIR}/extract_crisp_verify_gas.sh" "${EXTRACT_ARGS[@]}"; then
    echo "✓ CRISP verify gas extracted: ${GAS_JSON_FILE}"
else
    echo "⚠️  Could not extract CRISP verify gas; report will show N/A for verify gas"
fi

# Persist CLI flags for report regeneration (see generate_report.sh → Run configuration).
RUN_META_FILE="${BENCHMARKS_DIR}/${OUTPUT_DIR}/benchmark_run_meta.json"
MT_JOBS_JSON="${BENCHMARK_MULTITHREAD_JOBS:-1}"
load_committee_by_name "$OUTPUT_COMMITTEE" "$REPO_ROOT"
jq -n \
    --arg mode "$MODE" \
    --arg preset "$([ "$MODE" = "secure" ] && echo "secure-8192" || echo "insecure-512")" \
    --arg committee "$OUTPUT_COMMITTEE" \
    --argjson proof_agg true \
    --argjson multithread_jobs "$MT_JOBS_JSON" \
    --argjson verbose "$([ "$VERBOSE" = true ] && echo true || echo false)" \
    --argjson committee_size_n "$COMMITTEE_N" \
    --argjson committee_size_h "$COMMITTEE_H" \
    --argjson committee_threshold_t "$COMMITTEE_T" \
    '{
      benchmark_mode: $mode,
      bfv_preset_subdir: $preset,
      committee: $committee,
      proof_aggregation: $proof_agg,
      multithread_jobs: $multithread_jobs,
      verbose: $verbose,
      nodes_spawned: 20,
      committee_size_n: $committee_size_n,
      committee_size_h: $committee_size_h,
      committee_threshold_t: $committee_threshold_t,
      network_model: "in_process_bus",
      testmode_harness: true
    }' > "${RUN_META_FILE}"

# Extract integration summary from the fresh gas JSON before rendering the report so
# generate_report.sh always sees up-to-date lambda / timings (not a stale on-disk snapshot).
INTEGRATION_SNAPSHOT="${BENCHMARKS_DIR}/${OUTPUT_DIR}/integration_summary.json"
if [ -f "${GAS_JSON_FILE}" ] && jq -e '.integration_summary != null' "${GAS_JSON_FILE}" >/dev/null 2>&1; then
    jq '.integration_summary' "${GAS_JSON_FILE}" > "${INTEGRATION_SNAPSHOT}"
    echo "✓ Wrote integration summary snapshot: ${INTEGRATION_SNAPSHOT}"
fi

# Generate markdown report
echo "Stage 2/3: Rendering markdown report from benchmarks + gas summary..."
REPORT_FILE="${BENCHMARKS_DIR}/${OUTPUT_DIR}/report.md"
REPORT_ARGS=(
    --input-dir "${BENCHMARKS_DIR}/${OUTPUT_DIR}/raw"
    --output "${REPORT_FILE}"
    --git-commit "$GIT_COMMIT"
    --git-branch "$GIT_BRANCH"
    --gas-json "${GAS_JSON_FILE}"
    --benchmark-mode "$MODE"
    --run-meta "${RUN_META_FILE}"
)
if [ -f "${INTEGRATION_SNAPSHOT}" ]; then
    REPORT_ARGS+=(--integration-summary "${INTEGRATION_SNAPSHOT}")
fi
"${SCRIPT_DIR}/generate_report.sh" "${REPORT_ARGS[@]}"

if [[ "${OUTPUT_DIR}" =~ ^results_insecure_ ]] && [ -f "${INTEGRATION_SNAPSHOT}" ]; then
    "${SCRIPT_DIR}/sync_bfv_vk_binding_fixture.sh" "${INTEGRATION_SNAPSHOT}"
fi

echo "Stage 3/3: Finalizing outputs..."
echo "✓ Report generated: ${REPORT_FILE}"
echo ""

# Keep raw/ so that a later run with --circuit only overwrites that circuit's JSON and the
# report is regenerated from the full set (existing + updated). Delete results_<mode>/raw
# manually if you want a clean slate for the next full run.

# Clean artifacts if requested
if [ "$CLEAN_ARTIFACTS" = true ]; then
    echo "Cleaning circuit artifacts..."
    for CIRCUIT in $RUN_CIRCUITS; do
        CIRCUIT_PATH="${CIRCUITS_BASE_DIR}/${CIRCUIT}"
        if [ -d "$CIRCUIT_PATH/target" ]; then
            rm -rf "$CIRCUIT_PATH/target"
            echo "  ✓ Cleaned: $CIRCUIT (${MODE})"
        else
            echo "  ⊘ No target dir: $CIRCUIT (${MODE})"
        fi
    done
    echo ""
fi

echo "╔════════════════════════════════════════════════╗"
echo "║       Benchmark Complete!                      ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Results:"
echo "  Report: ${REPORT_FILE}"
echo ""
echo "To view the report:"
echo "  cat ${REPORT_FILE}"
echo "  # or"
echo "  open ${REPORT_FILE}  # (macOS)"
