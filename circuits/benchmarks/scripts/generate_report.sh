#!/bin/bash

set -e

INPUT_DIR=""
OUTPUT_FILE=""
GIT_COMMIT="unknown"
GIT_BRANCH="unknown"
GAS_JSON=""
# Optional JSON from `BENCHMARK_SUMMARY_OUTPUT` (same schema as embedded `integration_summary` in
# crisp_verify_gas.json). Used when gas JSON has null/broken integration_summary but timings exist
# on disk (e.g. long secure run wrote /tmp/summary_secure.json separately).
INTEGRATION_SUMMARY_FILE=""
RUN_META_FILE=""
BENCHMARK_MODE_OVERRIDE=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARKS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "${BENCHMARKS_DIR}/../.." && pwd)"

while [[ $# -gt 0 ]]; do
    case $1 in
        --input-dir) INPUT_DIR="$2"; shift 2 ;;
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        --git-commit) GIT_COMMIT="$2"; shift 2 ;;
        --git-branch) GIT_BRANCH="$2"; shift 2 ;;
        --gas-json) GAS_JSON="$2"; shift 2 ;;
        --integration-summary) INTEGRATION_SUMMARY_FILE="$2"; shift 2 ;;
        --run-meta) RUN_META_FILE="$2"; shift 2 ;;
        --benchmark-mode) BENCHMARK_MODE_OVERRIDE="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$INPUT_DIR" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 --input-dir <dir> --output <file> [--git-commit <hash>] [--git-branch <branch>] [--gas-json <file>] [--integration-summary <timings.json>]"
    exit 1
fi

format_s() { awk -v v="$1" 'BEGIN{printf "%.2f", v}'; }
format_ms() { echo "$1 * 1000" | bc -l | awk '{printf "%.2f", $0}'; }
format_kb() { echo "$1 / 1024" | bc -l | awk '{printf "%.2f", $0}'; }

hex_len_bytes() {
    local hex="${1:-}"
    python3 - "$hex" <<'PY'
import sys
h = sys.argv[1] or ""
if h.startswith("0x"):
    h = h[2:]
if len(h) % 2 != 0:
    print("0")
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
    print("0")
    raise SystemExit(0)
gas = 0
for i in range(0, len(h), 2):
    b = h[i : i + 2]
    gas += 4 if b == "00" else 16
print(gas)
PY
}

find_json_by_path_fragment() {
    local frag="$1"
    for json_file in "$INPUT_DIR"/*.json; do
        [ -f "$json_file" ] || continue
        local circuit_path
        circuit_path=$(jq -r '.circuit_path // ""' "$json_file")
        if [[ "$circuit_path" == *"$frag"* ]]; then
            echo "$json_file"
            return
        fi
    done
    echo ""
}

emit_circuit_row() {
    local label="$1"
    local path_fragment="$2"
    local json_file
    json_file=$(find_json_by_path_fragment "$path_fragment")
    if [ -z "$json_file" ]; then
        echo "| $label | N/A | N/A | N/A | N/A |" >> "$OUTPUT_FILE"
        return
    fi
    local constraints prove verify proof_size
    constraints=$(jq -r '.gates.total_gates // 0' "$json_file")
    prove=$(jq -r '.proof_generation.time_seconds // 0' "$json_file")
    verify=$(jq -r '.verification.time_seconds // 0' "$json_file")
    proof_size=$(jq -r '.proof_generation.proof_size_bytes // 0' "$json_file")
    echo "| $label | $constraints | $(format_s "$prove") | $(format_ms "$verify") | $(format_kb "$proof_size") |" >> "$OUTPUT_FILE"
}

emit_user_data_enc_row() {
    local wrapper ct0 ct1
    wrapper=$(find_json_by_path_fragment "/threshold/user_data_encryption")
    ct0=$(find_json_by_path_fragment "/threshold/user_data_encryption_ct0")
    ct1=$(find_json_by_path_fragment "/threshold/user_data_encryption_ct1")

    if [ -n "$wrapper" ]; then
        local constraints prove verify proof_size
        constraints=$(jq -r '.gates.total_gates // 0' "$wrapper")
        prove=$(jq -r '.proof_generation.time_seconds // 0' "$wrapper")
        verify=$(jq -r '.verification.time_seconds // 0' "$wrapper")
        proof_size=$(jq -r '.proof_generation.proof_size_bytes // 0' "$wrapper")
        if [ "$proof_size" -gt 0 ]; then
            echo "| user_data_encryption | $constraints | $(format_s "$prove") | $(format_ms "$verify") | $(format_kb "$proof_size") |" >> "$OUTPUT_FILE"
            return
        fi
    fi

    if [ -n "$ct0" ] && [ -n "$ct1" ]; then
        local constraints prove verify proof_size
        constraints=$(echo "$(jq -r '.gates.total_gates // 0' "$ct0") + $(jq -r '.gates.total_gates // 0' "$ct1")" | bc)
        prove=$(echo "$(jq -r '.proof_generation.time_seconds // 0' "$ct0") + $(jq -r '.proof_generation.time_seconds // 0' "$ct1")" | bc -l)
        verify=$(echo "$(jq -r '.verification.time_seconds // 0' "$ct0") + $(jq -r '.verification.time_seconds // 0' "$ct1")" | bc -l)
        proof_size=$(echo "$(jq -r '.proof_generation.proof_size_bytes // 0' "$ct0") + $(jq -r '.proof_generation.proof_size_bytes // 0' "$ct1")" | bc)
        echo "| user_data_encryption | $constraints | $(format_s "$prove") | $(format_ms "$verify") | $(format_kb "$proof_size") |" >> "$OUTPUT_FILE"
        return
    fi

    echo "| user_data_encryption | N/A | N/A | N/A | N/A |" >> "$OUTPUT_FILE"
}

verify_gas_for_artifact() {
    local artifact="$1"
    [ -f "$GAS_JSON" ] || { echo "N/A"; return; }
    local key=""
    case "$artifact" in
        Π_DKG) key="dkg" ;;
        Π_user) key="user" ;;
        Π_dec) key="dec" ;;
        *) echo "N/A"; return ;;
    esac
    local value
    value=$(jq -r ".verify_gas.${key} // empty" "$GAS_JSON")
    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo "N/A"
    else
        echo "$value"
    fi
}

artifact_metrics() {
    local name="$1"
    local label="$2"
    local verify_gas="$3"
    local artifact_key=""
    case "$name" in
        Π_DKG) artifact_key="dkg" ;;
        Π_dec) artifact_key="dec" ;;
    esac

    if [ "$label" = "user_data_encryption" ]; then
        local wrapper
        wrapper=$(find_json_by_path_fragment "/threshold/user_data_encryption")
        local proof_size public_size calldata total

        # Prefer the wrapper artifact when available; it matches what is posted/verified on-chain.
        if [ -n "$wrapper" ]; then
            proof_size=$(jq -r '.proof_generation.proof_size_bytes // 0' "$wrapper")
            public_size=$(jq -r '.verification.public_inputs_size_bytes // 0' "$wrapper")
            calldata=$(jq -r '.verification.calldata_gas_total // 0' "$wrapper")
            total="N/A"
            if [ "$verify_gas" != "N/A" ]; then total=$((verify_gas + calldata)); fi
            echo "| $name | $(format_kb "$proof_size") KB | $(format_kb "$public_size") KB | $verify_gas | $calldata | $total |" >> "$OUTPUT_FILE"
            return
        fi

        echo "| $name | N/A | N/A | $verify_gas | N/A | N/A |" >> "$OUTPUT_FILE"
        return
    fi

    # Prefer folded artifact sizes/calldata (when present) so table aligns with folded verify gas.
    if [ -n "$artifact_key" ] && [ -f "$GAS_JSON" ]; then
        local folded_proof_size folded_public_size folded_calldata
        folded_proof_size=$(jq -r ".artifact_sizes_bytes.${artifact_key}.proof // empty" "$GAS_JSON")
        folded_public_size=$(jq -r ".artifact_sizes_bytes.${artifact_key}.public_inputs // empty" "$GAS_JSON")
        folded_calldata=$(jq -r ".calldata_gas.${artifact_key}.total // empty" "$GAS_JSON")
        if [ -n "$folded_proof_size" ] && [ "$folded_proof_size" != "null" ] && [ "$folded_proof_size" != "0" ] \
            && [ -n "$folded_public_size" ] && [ "$folded_public_size" != "null" ] && [ "$folded_public_size" != "0" ] \
            && [ -n "$folded_calldata" ] && [ "$folded_calldata" != "null" ] && [ "$folded_calldata" != "0" ]; then
            local folded_total="N/A"
            if [ "$verify_gas" != "N/A" ]; then folded_total=$((verify_gas + folded_calldata)); fi
            echo "| $name | $(format_kb "$folded_proof_size") KB | $(format_kb "$folded_public_size") KB | $verify_gas | $folded_calldata | $folded_total |" >> "$OUTPUT_FILE"
            return
        fi
    fi

    # Sizes + calldata from integration summary folded hex (when gas JSON has no folded export).
    if [ -n "$artifact_key" ] && [ -n "$INTEGRATION_SUMMARY_FILE" ] && [ -f "$INTEGRATION_SUMMARY_FILE" ]; then
        local pfx ph pubh pb pubb cdp cdc folded_total
        case "$artifact_key" in
            dkg) pfx=".folded_artifacts.dkg_aggregator" ;;
            dec) pfx=".folded_artifacts.decryption_aggregator" ;;
            *) pfx="" ;;
        esac
        if [ -n "$pfx" ]; then
            ph=$(jq -r "${pfx}.proof_hex // empty" "$INTEGRATION_SUMMARY_FILE" 2>/dev/null || true)
            pubh=$(jq -r "${pfx}.public_inputs_hex // empty" "$INTEGRATION_SUMMARY_FILE" 2>/dev/null || true)
            if [ -n "$ph" ] && [ "$ph" != "null" ] && [ -n "$pubh" ] && [ "$pubh" != "null" ]; then
                pb=$(hex_len_bytes "$ph")
                pubb=$(hex_len_bytes "$pubh")
                cdp=$(calldata_gas_from_hex "$ph")
                cdc=$(calldata_gas_from_hex "$pubh")
                folded_calldata=$((cdp + cdc))
                folded_total="N/A"
                if [ "$verify_gas" != "N/A" ]; then folded_total=$((verify_gas + folded_calldata)); fi
                echo "| $name | $(format_kb "$pb") KB | $(format_kb "$pubb") KB | $verify_gas | $folded_calldata | $folded_total |" >> "$OUTPUT_FILE"
                return
            fi
        fi
    fi

    local json_file
    json_file=$(find_json_by_path_fragment "$label")
    if [ -z "$json_file" ]; then
        echo "| $name | N/A | N/A | $verify_gas | N/A | N/A |" >> "$OUTPUT_FILE"
        return
    fi
    local proof_size public_size calldata total
    proof_size=$(jq -r '.proof_generation.proof_size_bytes // 0' "$json_file")
    public_size=$(jq -r '.verification.public_inputs_size_bytes // 0' "$json_file")
    calldata=$(jq -r '.verification.calldata_gas_total // 0' "$json_file")
    total="N/A"
    if [ "$verify_gas" != "N/A" ]; then total=$((verify_gas + calldata)); fi
    echo "| $name | $(format_kb "$proof_size") KB | $(format_kb "$public_size") KB | $verify_gas | $calldata | $total |" >> "$OUTPUT_FILE"
}

sum_phase_metrics() {
    local labels="$1"
    local prove_sum="0"
    local proof_sum="0"
    local bandwidth_sum="0"
    local count=0
    for label in $labels; do
        local jf
        jf=$(find_json_by_path_fragment "$label")
        [ -n "$jf" ] || continue
        local p ps pub
        p=$(jq -r '.proof_generation.time_seconds // 0' "$jf")
        ps=$(jq -r '.proof_generation.proof_size_bytes // 0' "$jf")
        pub=$(jq -r '.verification.public_inputs_size_bytes // 0' "$jf")
        prove_sum=$(echo "$prove_sum + $p" | bc -l)
        proof_sum=$(echo "$proof_sum + $ps" | bc -l)
        bandwidth_sum=$(echo "$bandwidth_sum + $ps + $pub" | bc -l)
        count=$((count + 1))
    done
    if [ "$count" -eq 0 ]; then echo "N/A|N/A|N/A"; return; fi
    echo "$(format_s "$prove_sum") s|$(format_kb "$proof_sum") KB|$(format_kb "$bandwidth_sum") KB"
}

integration_phase_seconds() {
    local label="$1"
    local blob="${2:-}"
    [ -n "$blob" ] || return 1
    jq -r --arg label "$label" '
      (.phase_timings // .timings_seconds // [])[]
      | select(.label == $label)
      | if type == "object" then .seconds else . end
    ' <<<"$blob" 2>/dev/null | head -1
}

integration_timing_seconds() {
    local label="$1"
    local val=""
    local f blob
    if [ -n "${2:-}" ]; then
        val=$(integration_phase_seconds "$label" "$2")
        [ -n "$val" ] && [ "$val" != "null" ] && echo "$val" && return
    fi
    for f in "$INTEGRATION_SUMMARY_FILE" "$GAS_JSON"; do
        [ -n "$f" ] && [ -f "$f" ] || continue
        blob=$(jq -c 'if (.integration_summary != null) then .integration_summary elif has("integration_test") then . else empty end' "$f" 2>/dev/null || true)
        [ -z "$blob" ] || [ "$blob" = "null" ] && continue
        val=$(integration_phase_seconds "$label" "$blob")
        if [ -n "$val" ] && [ "$val" != "null" ]; then
            echo "$val"
            return
        fi
    done
    echo ""
}

emit_audit_warnings() {
    local missing=0
    local v
    {
        echo "## Audit status"
        echo ""
    } >> "$OUTPUT_FILE"
    for art in "Π_DKG" "Π_user" "Π_dec"; do
        v=$(verify_gas_for_artifact "$art")
        if [ "$v" = "N/A" ]; then
            missing=$((missing + 1))
        fi
    done
    if [ "$missing" -gt 0 ]; then
        cat >> "$OUTPUT_FILE" <<EOF
> **Incomplete on-chain verify gas:** $missing of 3 artifact verify-gas values are **N/A**. Re-run \`./run_benchmarks.sh\` and ensure \`extract_crisp_verify_gas.sh\` completes (CRISP test + \`test_trbfv_actor\` + EVM replay). Calldata gas alone is not sufficient for audit sign-off.

EOF
    else
        echo "On-chain verify gas: **complete** (CRISP Π_user + Interfold Π_DKG / Π_dec replay)." >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
    if [ -z "$INTEGRATION_BLOB" ]; then
        cat >> "$OUTPUT_FILE" <<EOF
> **No integration summary:** Role/phase **wall-clock** rows and multithread job tables require \`integration_summary.json\` or embedded \`integration_summary\` in \`crisp_verify_gas.json\`.

EOF
    fi
    echo "---" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

emit_measurement_methodology() {
    cat >> "$OUTPUT_FILE" <<'EOF'
## Measurement methodology

| Metric kind | Source | Meaning | Do **not** use for |
|-------------|--------|---------|-------------------|
| **wall_clock** | `test_trbfv_actor` phase timers / HLC event span | End-to-end wait in the in-process test harness | Production WAN latency; per-node deployment cost |
| **isolated_nargo** | `benchmark_circuit.sh` per circuit | Single `bb prove` on oracle witness, one circuit at a time | Full protocol pipeline (different witness path) |
| **tracked_job_wall** | `MultithreadReport` per `ComputeRequest` | Wall time of each job on the shared Rayon pool (≤ `BENCHMARK_MULTITHREAD_JOBS` concurrent) | End-to-end time — **sums exceed wall clock** when jobs overlap |

**Harness limits (integration):** all ciphernodes share one process and bus (`network_model: in_process_bus`); sortition registers extra nodes; `testmode_*` enabled; proof aggregation always enabled. Compare runs only with the same `benchmark_mode`, committee, `BENCHMARK_MULTITHREAD_JOBS`, commit, and hardware.

---
EOF
}

# Normalized integration summary object: either `results_*/integration_summary.json` or
# `crisp_verify_gas.json` → `.integration_summary` (see `BENCHMARK_SUMMARY_OUTPUT` in e3-tests).
integration_blob_from_inputs() {
    local f blob sibling
    if [ -z "$INTEGRATION_SUMMARY_FILE" ] && [ -n "$GAS_JSON" ] && [ -f "$GAS_JSON" ]; then
        sibling="$(dirname "$GAS_JSON")/integration_summary.json"
        if [ -f "$sibling" ]; then
            INTEGRATION_SUMMARY_FILE="$sibling"
        fi
    fi
    for f in "$INTEGRATION_SUMMARY_FILE" "$GAS_JSON"; do
        [ -n "$f" ] && [ -f "$f" ] || continue
        blob=$(jq -c 'if (.integration_summary != null) and (.integration_summary | type == "object") then .integration_summary elif has("integration_test") then . else empty end' "$f" 2>/dev/null || true)
        if [ -n "$blob" ] && [ "$blob" != "null" ]; then
            echo "$blob"
            return 0
        fi
    done
    return 1
}

artifact_size_pair_from_gas() {
    local key="$1"
    local proof public bandwidth
    if [ -f "$GAS_JSON" ]; then
        proof=$(jq -r ".artifact_sizes_bytes.${key}.proof // empty" "$GAS_JSON" 2>/dev/null)
        public=$(jq -r ".artifact_sizes_bytes.${key}.public_inputs // empty" "$GAS_JSON" 2>/dev/null)
        if [ -n "$proof" ] && [ "$proof" != "null" ] && [ -n "$public" ] && [ "$public" != "null" ] \
            && [ "$proof" != "0" ] && [ "$public" != "0" ]; then
            bandwidth=$(echo "$proof + $public" | bc)
            echo "$(format_kb "$proof") KB|$(format_kb "$bandwidth") KB"
            return
        fi
    fi
    # Fallback: folded hex from integration summary export (test `BENCHMARK_SUMMARY_OUTPUT`).
    local blob
    blob="$(integration_blob_from_inputs 2>/dev/null || true)"
    if [ -n "$blob" ]; then
        local pfx ph pubh
        case "$key" in
            dkg) pfx=".folded_artifacts.dkg_aggregator" ;;
            dec) pfx=".folded_artifacts.decryption_aggregator" ;;
            *) echo ""; return ;;
        esac
        ph=$(jq -r "${pfx}.proof_hex // empty" <<<"$blob" 2>/dev/null || true)
        pubh=$(jq -r "${pfx}.public_inputs_hex // empty" <<<"$blob" 2>/dev/null || true)
        if [ -n "$ph" ] && [ "$ph" != "null" ] && [ -n "$pubh" ] && [ "$pubh" != "null" ]; then
            proof=$(hex_len_bytes "$ph")
            public=$(hex_len_bytes "$pubh")
            if [ "$proof" != "0" ] || [ "$public" != "0" ]; then
                bandwidth=$(echo "$proof + $public" | bc)
                echo "$(format_kb "$proof") KB|$(format_kb "$bandwidth") KB"
                return
            fi
        fi
    fi
    echo ""
}

load_protocol_params() {
    # shellcheck source=load_default_committee.sh
    source "${SCRIPT_DIR}/load_default_committee.sh"
    load_default_committee "${REPO_ROOT}/circuits/lib/src/configs/default/mod.nr" "${REPO_ROOT}"
    echo "${COMMITTEE_H}|${COMMITTEE_N}|${COMMITTEE_T}"
}

load_system_info_from_raw() {
    local first_json
    first_json=$(ls "$INPUT_DIR"/*.json 2>/dev/null | head -1)
    [ -n "$first_json" ] || return 1
    CPU_MODEL=$(jq -r '.system_info.cpu_model // "unknown"' "$first_json")
    CPU_CORES=$(jq -r '.system_info.cpu_cores // "unknown"' "$first_json")
    RAM_GB=$(jq -r '.system_info.ram_gb // "unknown"' "$first_json")
    SYS_OS=$(jq -r '.system_info.os // "unknown"' "$first_json")
    SYS_ARCH=$(jq -r '.system_info.arch // "unknown"' "$first_json")
    NARGO_VER=$(jq -r '.system_info.nargo_version // "unknown"' "$first_json")
    BB_VER=$(jq -r '.system_info.bb_version // "unknown"' "$first_json")
}

resolve_run_meta_file() {
    if [ -n "$RUN_META_FILE" ] && [ -f "$RUN_META_FILE" ]; then
        echo "$RUN_META_FILE"
        return 0
    fi
    local candidate
    for candidate in \
        "$(dirname "$INPUT_DIR")/benchmark_run_meta.json" \
        "$(dirname "$GAS_JSON")/benchmark_run_meta.json"; do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

emit_run_configuration_section() {
    local blob="${1:-}"
    local meta_file
    meta_file="$(resolve_run_meta_file 2>/dev/null || true)"

    local bench_mode bench_preset bench_preset_name bench_lambda
    local proof_agg multithread_jobs rayon_threads cores_avail fold_verifier
    local entire_test_sec verbose_flag integration_test_name

    bench_mode="$BENCHMARK_MODE_OVERRIDE"
    bench_preset=""
    bench_preset_name=""
    bench_lambda=""
    proof_agg=""
    multithread_jobs=""
    rayon_threads=""
    cores_avail=""
    fold_verifier=""
    entire_test_sec=""
    integration_test_name="test_trbfv_actor"
    verbose_flag=""

    if [ -n "$blob" ]; then
        bench_mode=$(jq -r '.benchmark_config.mode // empty' <<<"$blob")
        bench_preset=$(jq -r '.benchmark_config.bfv_preset_subdir // empty' <<<"$blob")
        bench_preset_name=$(jq -r '.benchmark_config.bfv_preset // empty' <<<"$blob")
        bench_lambda=$(jq -r '.benchmark_config.lambda // empty' <<<"$blob")
        # NOTE: cannot use `//` here — jq's alt-operator treats `false` as null
        # and would fall through, dropping the legitimate `false` value.
        proof_agg=$(jq -r '
            if .benchmark_config.proof_aggregation_enabled != null then
              .benchmark_config.proof_aggregation_enabled
            elif .proof_aggregation_enabled != null then
              .proof_aggregation_enabled
            else
              empty
            end
        ' <<<"$blob")
        multithread_jobs=$(jq -r '.benchmark_config.multithread_concurrent_jobs // .multithread.max_simultaneous_rayon_tasks // empty' <<<"$blob")
        rayon_threads=$(jq -r '.multithread.rayon_threads // empty' <<<"$blob")
        cores_avail=$(jq -r '.multithread.cores_available // empty' <<<"$blob")
        fold_verifier=$(jq -r '.dkg_fold_attestation_verifier // empty' <<<"$blob")
        entire_test_sec=$(jq -r '.timings_seconds[]? | select(.label == "Entire Test") | .seconds' <<<"$blob" | head -1)
        integration_test_name=$(jq -r '.integration_test // "test_trbfv_actor"' <<<"$blob")
    fi

    if [ -n "$meta_file" ]; then
        [ -z "$bench_mode" ] || [ "$bench_mode" = "null" ] && bench_mode=$(jq -r '.benchmark_mode // empty' "$meta_file")
        [ -z "$bench_preset" ] || [ "$bench_preset" = "null" ] && bench_preset=$(jq -r '.bfv_preset_subdir // empty' "$meta_file")
        [ -z "$proof_agg" ] || [ "$proof_agg" = "null" ] && proof_agg=$(jq -r 'if .proof_aggregation != null then .proof_aggregation else empty end' "$meta_file")
        [ -z "$multithread_jobs" ] || [ "$multithread_jobs" = "null" ] && multithread_jobs=$(jq -r '.multithread_jobs // empty' "$meta_file")
        verbose_flag=$(jq -r 'if .verbose != null then .verbose else empty end' "$meta_file")
    fi

    [ -z "$bench_mode" ] || [ "$bench_mode" = "null" ] && bench_mode="unknown"
    [ -z "$bench_preset" ] || [ "$bench_preset" = "null" ] && bench_preset="(see circuit artifacts)"
    [ -z "$proof_agg" ] || [ "$proof_agg" = "null" ] && proof_agg="unknown"
    [ -z "$multithread_jobs" ] || [ "$multithread_jobs" = "null" ] && multithread_jobs="1 (default)"
    [ -z "$rayon_threads" ] || [ "$rayon_threads" = "null" ] && rayon_threads="N/A"
    [ -z "$cores_avail" ] || [ "$cores_avail" = "null" ] && cores_avail="N/A"

    load_system_info_from_raw 2>/dev/null || true
    CPU_MODEL="${CPU_MODEL:-unknown}"
    CPU_CORES="${CPU_CORES:-unknown}"
    RAM_GB="${RAM_GB:-unknown}"
    SYS_OS="${SYS_OS:-unknown}"
    SYS_ARCH="${SYS_ARCH:-unknown}"
    NARGO_VER="${NARGO_VER:-unknown}"
    BB_VER="${BB_VER:-unknown}"

    {
        echo "## Run configuration"
        echo ""
        echo "Settings for this benchmark run (integration test + Nargo circuit benches on the same host)."
        echo ""
        echo "### Integration test (\`$integration_test_name\`)"
        echo ""
        echo "| Setting | Value |"
        echo "|---------|-------|"
        echo "| Benchmark mode | \`$bench_mode\` |"
        echo "| BFV preset (artifacts) | \`$bench_preset\` |"
        if [ -n "$bench_preset_name" ] && [ "$bench_preset_name" != "null" ]; then
            echo "| BFV preset (enum) | \`$bench_preset_name\` |"
        fi
        if [ -n "$bench_lambda" ] && [ "$bench_lambda" != "null" ]; then
            echo "| λ (smudging / error) | $bench_lambda |"
        fi
        local nodes_spawned network_model testmode_harness
        nodes_spawned=$(jq -r '.benchmark_config.nodes_spawned // empty' <<<"$blob")
        network_model=$(jq -r '.benchmark_config.network_model // empty' <<<"$blob")
        testmode_harness=$(jq -r 'if .benchmark_config.testmode_harness != null then .benchmark_config.testmode_harness else empty end' <<<"$blob")
        if [ -n "$nodes_spawned" ] && [ "$nodes_spawned" != "null" ]; then
            echo "| Nodes spawned (builder) | $nodes_spawned |"
        fi
        if [ -n "$network_model" ] && [ "$network_model" != "null" ]; then
            echo "| Network model | \`$network_model\` |"
        fi
        if [ -n "$testmode_harness" ] && [ "$testmode_harness" != "null" ]; then
            echo "| Testmode harness | $testmode_harness |"
        fi
        echo "| \`proof_aggregation_enabled\` | $proof_agg |"
        echo "| \`BENCHMARK_MULTITHREAD_JOBS\` (max concurrent ZK jobs) | $multithread_jobs |"
        echo "| Rayon worker threads | $rayon_threads |"
        echo "| CPU cores (host) | $cores_avail |"
        if [ -n "$fold_verifier" ] && [ "$fold_verifier" != "null" ]; then
            echo "| \`dkg_fold_attestation_verifier\` (EIP-712) | \`$fold_verifier\` |"
        fi
        if [ -n "$entire_test_sec" ] && [ "$entire_test_sec" != "null" ]; then
            echo "| Integration wall clock (\`Entire Test\`) | $(format_s "$entire_test_sec") s |"
        fi
        if [ -n "$verbose_flag" ] && [ "$verbose_flag" != "null" ]; then
            echo "| Verbose logging (\`run_benchmarks.sh --verbose\`) | $verbose_flag |"
        fi
        echo ""
        echo "### Hardware & software (Nargo / Barretenberg host)"
        echo ""
        echo "| | |"
        echo "|--|--|"
        echo "| **CPU** | $CPU_MODEL |"
        echo "| **CPU cores** | $CPU_CORES |"
        echo "| **RAM** | ${RAM_GB} GB |"
        echo "| **OS** | $SYS_OS |"
        echo "| **Architecture** | $SYS_ARCH |"
        echo "| **Nargo** | $NARGO_VER |"
        echo "| **Barretenberg** | $BB_VER |"
        echo ""
        echo "---"
        echo ""
    } >> "$OUTPUT_FILE"
}

integration_op_total_seconds() {
    local pattern="$1"
    local blob="${2:-}"
    [ -z "$blob" ] && return 1
    jq -r --arg p "$pattern" '
      [.operation_timings[]?
       | select(.name | test($p))
       | .total_seconds]
      | add // empty
    ' <<<"$blob" 2>/dev/null || true
}

TIMESTAMP=$(date -u "+%Y-%m-%d %H:%M:%S UTC")
IFS='|' read -r PROTOCOL_H PROTOCOL_N PROTOCOL_T <<< "$(load_protocol_params)"
INTEGRATION_BLOB="$(integration_blob_from_inputs || true)"

cat > "$OUTPUT_FILE" <<EOF
# Interfold ZK Circuit Benchmarks

**Generated:** ${TIMESTAMP}

**Git Branch:** \`${GIT_BRANCH}\`  
**Git Commit:** \`${GIT_COMMIT}\`

**Committee Size:** \`H=${PROTOCOL_H}\`, \`N=${PROTOCOL_N}\`, \`T=${PROTOCOL_T}\`

EOF

emit_run_configuration_section "$INTEGRATION_BLOB"
emit_audit_warnings
emit_measurement_methodology

if [ -f "$GAS_JSON" ]; then
    fold_exit=$(jq -r '.test_exit_code.folded_export // empty' "$GAS_JSON" 2>/dev/null || true)
    if [ "$fold_exit" != "" ] && [ "$fold_exit" != "null" ] && [ "$fold_exit" != "0" ]; then
        cat >> "$OUTPUT_FILE" <<EOF
> **Warning:** \`test_trbfv_actor\` failed during gas extraction (exit ${fold_exit}). Π_DKG / Π_dec verify gas and phase rows below may reflect **Nargo-only** estimates or stale data. Re-run \`./run_benchmarks.sh\` after a successful integration export.

EOF
    fi
fi

cat >> "$OUTPUT_FILE" <<EOF
## Protocol Summary

### Circuit Benchmarks (isolated Nargo + Barretenberg)

Single-circuit \`bb prove\` on the benchmark oracle witness (not the integration actor pipeline).

| Circuit | Constraints | Prove (s) | Verify (ms) | Proof (KB) |
|---------|-------------|-----------|-------------|------------|
EOF

emit_circuit_row "C0" "/dkg/pk"
emit_circuit_row "C1" "/threshold/pk_generation"
emit_circuit_row "C2a" "/dkg/sk_share_computation"
emit_circuit_row "C2b" "/dkg/e_sm_share_computation"
emit_circuit_row "C3a" "/dkg/share_encryption"
emit_circuit_row "C3b" "/dkg/share_encryption"
emit_circuit_row "C4a" "/dkg/share_decryption"
emit_circuit_row "C4b" "/dkg/share_decryption"
emit_circuit_row "C5" "/threshold/pk_aggregation"
emit_user_data_enc_row
emit_circuit_row "C6" "/threshold/share_decryption"
emit_circuit_row "C7" "/threshold/decrypted_shares_aggregation"

cat >> "$OUTPUT_FILE" <<EOF

### Artifacts

| Artifact | Proof size | Public input size | Verify gas | Calldata gas | Total gas |
|----------|------------|-------------------|------------|--------------|-----------|
EOF

artifact_metrics "Π_DKG" "/threshold/pk_aggregation" "$(verify_gas_for_artifact Π_DKG)"
artifact_metrics "Π_user" "user_data_encryption" "$(verify_gas_for_artifact Π_user)"
artifact_metrics "Π_dec" "/threshold/decrypted_shares_aggregation" "$(verify_gas_for_artifact Π_dec)"

p1=$(sum_phase_metrics "/dkg/pk /threshold/pk_generation /dkg/sk_share_computation /dkg/e_sm_share_computation /dkg/share_encryption /dkg/share_encryption /dkg/share_decryption /dkg/share_decryption /recursive_aggregation/c2ab_fold /recursive_aggregation/c3ab_fold /recursive_aggregation/c4ab_fold /recursive_aggregation/node_fold")
p2=$(sum_phase_metrics "/threshold/pk_aggregation")
p3=$(sum_phase_metrics "/threshold/user_data_encryption_ct0 /threshold/user_data_encryption_ct1")
p4n=$(sum_phase_metrics "/threshold/share_decryption")
p4a=$(sum_phase_metrics "/threshold/decrypted_shares_aggregation")
IFS='|' read -r p1t p1s p1b <<< "$p1"
IFS='|' read -r p2t p2s p2b <<< "$p2"
IFS='|' read -r p3t p3s p3b <<< "$p3"
IFS='|' read -r p4nt p4ns p4nb <<< "$p4n"
IFS='|' read -r p4at p4as p4ab <<< "$p4a"

p1_metric="wall_clock"
p2_metric="wall_clock"
p3_metric="isolated_nargo"
p4n_metric="isolated_nargo"
p4a_metric="wall_clock"

p1_integration=$(integration_timing_seconds "ThresholdShares -> PublicKeyAggregated" "$INTEGRATION_BLOB")
if [ -n "$p1_integration" ] && [ "$p1_integration" != "null" ]; then
    p1t="$(format_s "$p1_integration") s"
else
    p1t="N/A"
    p1_metric="—"
fi

p2_integration=$(integration_timing_seconds "Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall)" "$INTEGRATION_BLOB")
if [ -n "$p2_integration" ] && [ "$p2_integration" != "null" ]; then
    p2t="$(format_s "$p2_integration") s"
else
    p2t="N/A"
    p2_metric="—"
fi

p4a_integration=$(integration_timing_seconds "Ciphertext published -> PlaintextAggregated" "$INTEGRATION_BLOB")
if [ -n "$p4a_integration" ] && [ "$p4a_integration" != "null" ]; then
    p4at="$(format_s "$p4a_integration") s"
else
    p4at="N/A"
    p4a_metric="—"
fi

p4_sub_integration=$(integration_timing_seconds "Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)" "$INTEGRATION_BLOB")
p4_sub_metric=""
p4_sub_t=""
if [ -n "$p4_sub_integration" ] && [ "$p4_sub_integration" != "null" ]; then
    p4_sub_t="$(format_s "$p4_sub_integration") s"
    p4_sub_metric="wall_clock"
fi

# Keep role-phase rows aligned with artifact outputs when folded artifact sizes are available.
p2_artifact=$(artifact_size_pair_from_gas "dkg")
if [ -n "$p2_artifact" ]; then
    IFS='|' read -r p2s p2b <<< "$p2_artifact"
fi
wrapper_json=$(find_json_by_path_fragment "/threshold/user_data_encryption")
if [ -n "$wrapper_json" ]; then
    p3_proof_bytes=$(jq -r '.proof_generation.proof_size_bytes // 0' "$wrapper_json")
    p3_public_bytes=$(jq -r '.verification.public_inputs_size_bytes // 0' "$wrapper_json")
    p3_bandwidth_bytes=$(echo "$p3_proof_bytes + $p3_public_bytes" | bc)
    p3s="$(format_kb "$p3_proof_bytes") KB"
    p3b="$(format_kb "$p3_bandwidth_bytes") KB"
fi
p4a_artifact=$(artifact_size_pair_from_gas "dec")
if [ -n "$p4a_artifact" ]; then
    IFS='|' read -r p4as p4ab <<< "$p4a_artifact"
fi

cat >> "$OUTPUT_FILE" <<EOF

### Role / Phase / Activity

| Role | Phase | Activity | Metric | Duration | Proof size | Bandwidth |
|------|-------|----------|--------|----------|------------|-----------|
| Each ciphernode | P1 | one-time DKG participation (test harness) | $p1_metric | $p1t | $p1s | $p1b |
| Aggregator | P2 | C5 + Π_DKG fold (aggregator span) | $p2_metric | $p2t | $p2s | $p2b |
| User | P3 | per user input | $p3_metric | $p3t | $p3s | $p3b |
| Each ciphernode | P4 | per computation output (C6) | $p4n_metric | $p4nt | $p4ns | $p4nb |
| Aggregator | P4 | C7 + Π_dec fold (full publish→aggregate) | $p4a_metric | $p4at | $p4as | $p4ab |
EOF
if [ -n "$p4_sub_t" ]; then
    echo "| Aggregator | P4 | C7 + fold only (pending→plaintext span) | $p4_sub_metric | $p4_sub_t | $p4as | $p4ab |" >> "$OUTPUT_FILE"
fi
if [ -n "$INTEGRATION_BLOB" ]; then
    p2_tracked=$(integration_op_total_seconds "^(ZkDkgAggregation|ZkPkAggregation)" "$INTEGRATION_BLOB")
    if [ -n "$p2_tracked" ] && [ "$p2_tracked" != "null" ]; then
        echo "" >> "$OUTPUT_FILE"
        echo "_P2 **tracked_job_wall** sum (ZkDkgAggregation + ZkPkAggregation, parallelizable): **$(format_s "$p2_tracked") s** — not comparable to P2 wall_clock row above._" >> "$OUTPUT_FILE"
    fi
fi

if [ -n "$INTEGRATION_BLOB" ]; then
    it_name=$(jq -r '.integration_test // "test_trbfv_actor"' <<<"$INTEGRATION_BLOB")
    {
        echo ""
        echo "## Integration test (\`$it_name\`)"
        echo ""
        echo "### End-to-end phase timings (integration test)"
        echo ""
        echo "| Phase | Metric | Duration (s) |"
        echo "|-------|--------|---------------|"
    } >> "$OUTPUT_FILE"
    while IFS=$'\t' read -r label metric sec; do
        [ -z "$label" ] && continue
        [ -z "$metric" ] || [ "$metric" = "null" ] && metric="wall_clock"
        echo "| $label | \`$metric\` | $(format_s "$sec") |" >> "$OUTPUT_FILE"
    done < <(jq -r '
      (.phase_timings // .timings_seconds // [])[]
      | if type == "object" then [.label, (.metric // "wall_clock"), .seconds]
        else [.label, "wall_clock", .] end
      | @tsv
    ' <<<"$INTEGRATION_BLOB")

    if jq -e '(.operation_timings | type == "array") and (.operation_timings | length > 0)' <<<"$INTEGRATION_BLOB" >/dev/null 2>&1; then
        {
            echo ""
            echo "### Multithread job timings (\`tracked_job_wall\`)"
            echo ""
            echo "| Name | Avg (s) | Runs | Total (s) |"
            echo "|------|---------|------|-----------|"
        } >> "$OUTPUT_FILE"
        while IFS=$'\t' read -r name avgr runs tot; do
            [ -z "$name" ] && continue
            echo "| $name | $(format_s "$avgr") | $runs | $(format_s "$tot") |" >> "$OUTPUT_FILE"
        done < <(jq -r '.operation_timings[]? | [.name, .avg_seconds, .runs, .total_seconds] | @tsv' <<<"$INTEGRATION_BLOB")
        ott=$(jq -r '.operation_timings_total_seconds // empty' <<<"$INTEGRATION_BLOB")
        if [ -n "$ott" ] && [ "$ott" != "null" ]; then
            echo "" >> "$OUTPUT_FILE"
            echo "Sum of tracked job wall time: **$(format_s "$ott") s** — **not** end-to-end latency (jobs run in parallel up to \`BENCHMARK_MULTITHREAD_JOBS\`)." >> "$OUTPUT_FILE"
        fi
        fold_rows=$(
            jq -r '
              .operation_timings[]?
              | select(.name | startswith("NodeDkgFold/"))
              | [.name, .avg_seconds, .runs, .total_seconds]
              | @tsv
            ' <<<"$INTEGRATION_BLOB"
        )
        if [ -n "$fold_rows" ]; then
            {
                echo ""
                echo "### NodeDkgFold sub-steps (\`tracked_job_wall\`, per fold prove)"
                echo ""
                echo "| Step | Avg (s) | Runs | Total (s) |"
                echo "|------|---------|------|-----------|"
            } >> "$OUTPUT_FILE"
            while IFS=$'\t' read -r name avgr runs tot; do
                [ -z "$name" ] && continue
                step="${name#NodeDkgFold/}"
                echo "| $step | $(format_s "$avgr") | $runs | $(format_s "$tot") |" >> "$OUTPUT_FILE"
            done <<<"$fold_rows"
        fi
    fi

    if jq -e '(.operation_timings | type == "array") and (.operation_timings | length > 0)' <<<"$INTEGRATION_BLOB" >/dev/null 2>&1; then
        agg_rows=$(
            jq -r '
              .operation_timings[]?
              | select(
                  .name
                  | test("^(ZkNodeDkgFold|ZkDkgAggregation|ZkDecryptionAggregation|ZkPkAggregation|ZkDecryptedSharesAggregation|ZkNodesFold)$")
                )
              | [.name, .avg_seconds, .runs, .total_seconds]
              | @tsv
            ' <<<"$INTEGRATION_BLOB"
        )
        if [ -n "$agg_rows" ]; then
            {
                echo ""
                echo "### Aggregation jobs (\`tracked_job_wall\`)"
                echo ""
                echo "| Operation | Avg (s) | Runs | Total (s) |"
                echo "|-----------|---------|------|-----------|"
            } >> "$OUTPUT_FILE"
            while IFS=$'\t' read -r name avgr runs tot; do
                [ -z "$name" ] && continue
                echo "| $name | $(format_s "$avgr") | $runs | $(format_s "$tot") |" >> "$OUTPUT_FILE"
            done <<<"$agg_rows"
            agg_total=$(
                jq -r '
                  [.operation_timings[]?
                   | select(
                       .name
                       | test("^(ZkNodeDkgFold|ZkDkgAggregation|ZkDecryptionAggregation|ZkPkAggregation|ZkDecryptedSharesAggregation|ZkNodesFold)$")
                     )
                   | .total_seconds]
                  | add // 0
                ' <<<"$INTEGRATION_BLOB"
            )
            if [ -n "$agg_total" ] && [ "$agg_total" != "null" ]; then
                echo "" >> "$OUTPUT_FILE"
                echo "Sum of aggregation job tracked time: **$(format_s "$agg_total") s** (parallel CPU work; not P1/P2 wall clock)." >> "$OUTPUT_FILE"
            fi
        fi
    fi

    if jq -e '.folded_artifacts != null' <<<"$INTEGRATION_BLOB" >/dev/null 2>&1; then
        {
            echo ""
            echo "### Folded on-chain artifacts (exported for Π_DKG / Π_dec gas)"
            echo ""
            echo "| Artifact | Proof (bytes) | Public inputs (bytes) |"
            echo "|----------|---------------|------------------------|"
        } >> "$OUTPUT_FILE"
        for key in dkg_aggregator decryption_aggregator; do
            pb=$(jq -r ".folded_artifacts.${key}.proof_hex // empty" <<<"$INTEGRATION_BLOB")
            pubb=$(jq -r ".folded_artifacts.${key}.public_inputs_hex // empty" <<<"$INTEGRATION_BLOB")
            if [ -n "$pb" ] && [ ${#pb} -gt 2 ]; then
                proof_bytes=$(( (${#pb} - 2) / 2 ))
                pub_bytes=$(( (${#pubb} - 2) / 2 ))
                echo "| $key | $proof_bytes | $pub_bytes |" >> "$OUTPUT_FILE"
            fi
        done
    elif [ "$agg_enabled" = "true" ]; then
        echo "" >> "$OUTPUT_FILE"
        echo "_No \`folded_artifacts\` in integration summary (export failed or test exited early)._" >> "$OUTPUT_FILE"
    fi
fi

{
    echo ""
    echo "## Raw circuit benchmark JSON (Nargo)"
    echo ""
} >> "$OUTPUT_FILE"
shopt -s nullglob
raw_files=("$INPUT_DIR"/*.json)
if [ ${#raw_files[@]} -eq 0 ]; then
    echo "_No \`.json\` files in this input directory._" >> "$OUTPUT_FILE"
else
    echo "Source files for the **Circuit Benchmarks** table. Persist this directory with \`crisp_verify_gas.json\` (and optional \`integration_summary.json\`) to regenerate the report without re-running the integration test." >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "| File |" >> "$OUTPUT_FILE"
    echo "|------|" >> "$OUTPUT_FILE"
    for jf in "${raw_files[@]}"; do
        echo "| \`$(basename "$jf")\` |" >> "$OUTPUT_FILE"
    done
fi
shopt -u nullglob

cat >> "$OUTPUT_FILE" <<EOF

## Notes

- All nodes are executed on the same machine in this benchmark run, so inter-node network latency is effectively 0.
EOF

echo "✓ Report generated successfully: $OUTPUT_FILE"
