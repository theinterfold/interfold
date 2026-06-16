#!/bin/bash
# Shared output directory naming for benchmark runs.
# Sourced by run_benchmarks.sh and regenerate_report.sh.
#
# Layout (under circuits/benchmarks/):
#   results_<mode>_<committee>
#
# Examples:
#   results_insecure_minimum
#   results_insecure_micro
#   results_secure_small
#
# Proof aggregation is always enabled in the benchmark harness. Committee sizes are
# minimum, micro, or small.

# Args: <insecure|secure> [committee]
benchmark_results_dir_basename() {
    local mode="$1"
    local committee="${2:-minimum}"
    local base="${BENCHMARK_OUTPUT_DIR_BASE:-results}"
    echo "${base}_${mode}_${committee}"
}

# Full path under BENCHMARKS_DIR (set by caller).
benchmark_results_dir_path() {
    local benchmarks_dir="$1"
    local mode="$2"
    local committee="${3:-minimum}"
    echo "${benchmarks_dir}/$(benchmark_results_dir_basename "$mode" "$committee")"
}

# Legacy basenames the regenerator falls back to when the current layout is missing.
# Returns each candidate on its own line (newest-first); callers pick the first that exists.
benchmark_results_dir_legacy_basenames() {
    local mode="$1"
    local committee="${2:-minimum}"
    local base="${BENCHMARK_OUTPUT_DIR_BASE:-results}"
    echo "${base}_${mode}_agg_${committee}"
    echo "${base}_${mode}_no_agg_${committee}"
    echo "${base}_${mode}_agg"
    echo "${base}_${mode}_no_agg"
    echo "${base}_${mode}"
}

# Backward compat: single-string version (oldest legacy only). Kept so older external scripts
# that source this file don't break.
benchmark_results_dir_legacy_basename() {
    local mode="$1"
    local base="${BENCHMARK_OUTPUT_DIR_BASE:-results}"
    echo "${base}_${mode}"
}
