#!/usr/bin/env bash
#
# Per-task circuit cost report: gates, compile time, and peak memory for every circuit in one
# protocol task, multiplied by how many times that circuit runs.
#
# Default mode measures circuits only and needs no witnesses, so it covers the recursive terminals
# and folds that `run_benchmarks.sh` skips.
#
# --prove adds a per-circuit witness and proving pass: `zk_cli` builds the Prover.toml (which
# exercises the zk-helper witness code), then nargo executes and bb proves and verifies. Recursive
# circuits are reported as gate-only, because `zk_cli` refuses to fabricate their proof inputs.
# This is per circuit, not a folded chain - one proof each, at the lowest level.
#
# Usage:
#   ./task_costs.sh --list
#   ./task_costs.sh --task pk-generation
#   ./task_costs.sh --task pk-generation --rebuild
#   ./task_costs.sh --task pk-generation --prove
#
# Instance counts below are for secure-16384 / minimum: GADGET_DIM = L = 5 gives 25 limbs and
# 5 rows per party, and H = 2. Pass --instances to override a count when comparing presets.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BIN_DIR="${REPO_ROOT}/circuits/bin"

TASK=""
REBUILD="false"
PROVE="false"
COMMITTEE="minimum"

# task -> "circuit:group:instances,..."
# `group` is the directory under circuits/bin; `instances` is how many proofs one party produces.
task_circuits() {
    case "$1" in
        pk-generation)
            echo "lbfv_party_secrets:threshold:1,lbfv_pk_generation_limb:threshold:25,lbfv_pk_generation:threshold:5"
            ;;
        pk-aggregation)
            echo "lbfv_pk_aggregation:threshold:5"
            ;;
        rlk-generation)
            echo "rlk_generation_limb:threshold:25,rlk_generation:threshold:5"
            ;;
        rlk-aggregation)
            echo "rlk_aggregation:threshold:5"
            ;;
        pk-fold)
            # Measurement-only: folds the public-key rows alone. Not in the protocol chain.
            echo "lbfv_pk_fold_kernel:recursive_aggregation:1,lbfv_pk_fold:recursive_aggregation:4"
            ;;
        generation-fold)
            echo "lbfv_generation_fold_kernel:recursive_aggregation:1,lbfv_generation_fold:recursive_aggregation:4"
            ;;
        aggregation-fold)
            echo "lbfv_aggregation_fold_kernel:recursive_aggregation:1,lbfv_aggregation_fold:recursive_aggregation:4"
            ;;
        trbfv-pk-generation)
            echo "pk_generation:threshold:1,pk_aggregation:threshold:1"
            ;;
        share-encryption)
            echo "share_encryption:dkg:1"
            ;;
        share-decryption)
            echo "share_decryption:dkg:1,share_decryption:threshold:1"
            ;;
        user-data-encryption)
            echo "user_data_encryption_ct0:threshold:1,user_data_encryption_ct1:threshold:1"
            ;;
        *)
            return 1
            ;;
    esac
}

ALL_TASKS="pk-generation pk-fold pk-aggregation rlk-generation rlk-aggregation generation-fold aggregation-fold trbfv-pk-generation share-encryption share-decryption user-data-encryption"

while [ $# -gt 0 ]; do
    case "$1" in
        --task) TASK="$2"; shift 2 ;;
        --rebuild) REBUILD="true"; shift ;;
        --prove) PROVE="true"; shift ;;
        --committee) COMMITTEE="$2"; shift 2 ;;
        --list)
            echo "Tasks:"
            for t in $ALL_TASKS; do
                printf "  %-22s %s\n" "$t" "$(task_circuits "$t")"
            done
            exit 0
            ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$TASK" ]; then
    echo "error: --task is required (see --list)" >&2
    exit 1
fi

CIRCUITS="$(task_circuits "$TASK")" || { echo "error: unknown task '$TASK' (see --list)" >&2; exit 1; }

command -v nargo >/dev/null || { echo "error: nargo not on PATH" >&2; exit 1; }
command -v bb >/dev/null || { echo "error: bb not on PATH" >&2; exit 1; }

# Peak resident set of a command, in bytes. macOS `/usr/bin/time -l` reports this; GNU `time -v`
# reports kilobytes, so normalize.
peak_rss_bytes() {
    local out
    out="$( { /usr/bin/time -l "$@" >/dev/null; } 2>&1 || true )"
    local mac
    mac="$(printf '%s\n' "$out" | awk '/maximum resident set size/ {print $1; exit}')"
    if [ -n "$mac" ]; then
        echo "$mac"
        return
    fi
    local gnu
    gnu="$(printf '%s\n' "$out" | awk -F': ' '/Maximum resident set size/ {print $2; exit}')"
    if [ -n "$gnu" ]; then
        echo $((gnu * 1024))
        return
    fi
    echo 0
}

# shellcheck source=zk_cli_helpers.sh
. "${SCRIPT_DIR}/zk_cli_helpers.sh"

# Build Prover.toml through zk_cli (this is the zk-helper witness path), then execute and prove.
# Prints "witness_s prove_s verify_s peak_bytes" or "- - - 0" when the circuit has no generator.
witness_and_prove() {
    local name="$1" group="$2" pkg_dir="$3" json="$4"
    local zk_args
    zk_args="$(get_zk_args "${group}/${name}" 2>/dev/null || echo "")"
    if [ -z "$zk_args" ] || [ "$zk_args" = "_no_zk_cli" ]; then
        echo "- - - 0"
        return
    fi

    local target_dir
    target_dir="$(dirname "$json")"

    # zk_cli writes Prover.toml next to the package. A recursive circuit refuses here, which is
    # what distinguishes "no generator" from a real failure.
    if ! (cd "$REPO_ROOT" && cargo run -q -p e3-zk-helpers --bin zk_cli -- \
            --circuit "$(echo "$zk_args" | awk '{print $1}')" \
            --preset "$(preset_label)" --committee "$COMMITTEE" \
            --output "$pkg_dir" --toml --no-configs >/dev/null 2>&1); then
        echo "SKIP SKIP SKIP 0"
        return
    fi

    local t0 t1 w_s p_s v_s peak
    t0=$(date +%s)
    (cd "$pkg_dir" && nargo execute >/dev/null 2>&1) || { echo "FAIL FAIL FAIL 0"; return; }
    t1=$(date +%s); w_s=$((t1 - t0))

    bb write_vk -b "$json" -o "$target_dir" >/dev/null 2>&1 || { echo "$w_s FAIL FAIL 0"; return; }

    t0=$(date +%s)
    peak=$(peak_rss_bytes bb prove -b "$json" -w "${target_dir}/${name}.gz" \
        -k "${target_dir}/vk" -o "$target_dir")
    t1=$(date +%s); p_s=$((t1 - t0))

    t0=$(date +%s)
    bb verify -k "${target_dir}/vk" -p "${target_dir}/proof" \
        -i "${target_dir}/public_inputs" >/dev/null 2>&1 || { echo "$w_s $p_s FAIL $peak"; return; }
    t1=$(date +%s); v_s=$((t1 - t0))

    echo "$w_s $p_s $v_s $peak"
}

preset_label() {
    grep -m1 'for preset:' "${REPO_ROOT}/circuits/lib/src/configs/default/mod.nr" \
        | sed 's/.*for preset: //' || echo "unknown"
}

printf '\n=== task: %s   preset: %s ===\n\n' "$TASK" "$(preset_label)"
if [ "$PROVE" = "true" ]; then
    printf '%-28s %12s %8s %8s %8s %9s %5s %13s\n' \
        CIRCUIT GATES WIT_S PROVE_S VERIFY_S PROVE_GB RUNS TASK_PROVE_S
    printf '%.0s-' {1..98}; printf '\n'
else
    printf '%-30s %12s %14s %10s %10s %6s %14s\n' \
        CIRCUIT GATES ACIR_OPCODES COMPILE_S PEAK_GB RUNS TASK_GATES
    printf '%.0s-' {1..102}; printf '\n'
fi

total_gates=0
total_runs=0
total_prove=0
peak_overall=0

IFS=',' read -ra ENTRIES <<< "$CIRCUITS"
for entry in "${ENTRIES[@]}"; do
    name="${entry%%:*}"
    rest="${entry#*:}"
    group="${rest%%:*}"
    runs="${rest##*:}"
    pkg_dir="${BIN_DIR}/${group}/${name}"

    if [ ! -d "$pkg_dir" ]; then
        printf '%-30s %12s %14s %10s %10s %6s %14s\n' "$name" "-" "-" "-" "-" "$runs" "MISSING"
        continue
    fi

    # Workspace builds land in <group>/target; a standalone build lands in <pkg>/target.
    json=""
    for candidate in "${BIN_DIR}/${group}/target/${name}.json" "${pkg_dir}/target/${name}.json"; do
        [ -f "$candidate" ] && json="$candidate" && break
    done

    compile_s="cached"
    peak_gb="-"
    if [ "$REBUILD" = "true" ] || [ -z "$json" ]; then
        start=$(date +%s)
        peak=$(cd "$pkg_dir" && peak_rss_bytes nargo compile)
        compile_s=$(( $(date +%s) - start ))
        peak_gb=$(awk -v b="$peak" 'BEGIN { printf "%.2f", b / 1073741824 }')
        [ "$peak" -gt "$peak_overall" ] && peak_overall="$peak"
        for candidate in "${BIN_DIR}/${group}/target/${name}.json" "${pkg_dir}/target/${name}.json"; do
            [ -f "$candidate" ] && json="$candidate" && break
        done
    fi

    if [ -z "$json" ]; then
        printf '%-30s %12s %14s %10s %10s %6s %14s\n' "$name" "-" "-" "$compile_s" "$peak_gb" "$runs" "NO ARTIFACT"
        continue
    fi

    gates_json="$(bb gates -b "$json" 2>/dev/null || true)"
    gates="$(printf '%s' "$gates_json" | grep -o '"circuit_size":[[:space:]]*[0-9]*' | grep -o '[0-9]*$' | head -1)"
    opcodes="$(printf '%s' "$gates_json" | grep -o '"acir_opcodes":[[:space:]]*[0-9]*' | grep -o '[0-9]*$' | head -1)"
    gates="${gates:-0}"
    opcodes="${opcodes:-0}"

    task_gates=$((gates * runs))
    total_gates=$((total_gates + task_gates))
    total_runs=$((total_runs + runs))

    if [ "$PROVE" = "true" ]; then
        read -r w_s p_s v_s prove_peak <<< "$(witness_and_prove "$name" "$group" "$pkg_dir" "$json")"
        prove_gb="-"
        [ "$prove_peak" -gt 0 ] 2>/dev/null && \
            prove_gb=$(awk -v b="$prove_peak" 'BEGIN { printf "%.2f", b / 1073741824 }')
        task_prove="-"
        if [ "$p_s" -eq "$p_s" ] 2>/dev/null; then
            task_prove=$((p_s * runs))
            total_prove=$((total_prove + task_prove))
        fi
        printf '%-28s %12s %8s %8s %8s %9s %5s %13s\n' \
            "$name" "$gates" "$w_s" "$p_s" "$v_s" "$prove_gb" "$runs" "$task_prove"
    else
        printf "%-30s %12s %14s %10s %10s %6s %14s\n" \
            "$name" "$gates" "$opcodes" "$compile_s" "$peak_gb" "$runs" "$task_gates"
    fi
done

if [ "$PROVE" = "true" ]; then
    printf '%.0s-' {1..98}; printf '\n'
    printf '%-28s %12s %8s %8s %8s %9s %5s %13s\n' \
        "TOTAL" "$total_gates" "" "" "" "" "$total_runs" "$total_prove"
else
    printf '%.0s-' {1..102}; printf '\n'
    printf '%-30s %12s %14s %10s %10s %6s %14s\n' "TOTAL" "" "" "" "" "$total_runs" "$total_gates"
fi

if [ "$peak_overall" -gt 0 ]; then
    printf '\nlargest single-circuit compile: %.2f GB\n' \
        "$(awk -v b="$peak_overall" 'BEGIN { print b / 1073741824 }')"
fi
if [ "$PROVE" = "true" ]; then
cat <<'EOF'

WIT_S covers zk_cli building Prover.toml (the zk-helper witness path) plus `nargo execute`.
PROVE_S and PROVE_GB are one `bb prove` for one instance; TASK_PROVE_S multiplies by RUNS, so it is
the serial proving time one party spends on this task. A `-` means the circuit is recursive and
zk_cli will not fabricate its proof inputs; measure those through the chained measurement tests.
EOF
else
cat <<'EOF'

GATES is the proving-relevant size (bb `circuit_size`), not ACIR opcodes: the two diverge widely
because wide range checks are one opcode but many gates. RUNS is proofs per party, so TASK_GATES is
the proving work one party does for this task. COMPILE_S and PEAK_GB are compile-time only and
appear as `cached` unless --rebuild is passed. Add --prove for witness and proving measurements.
EOF
fi
