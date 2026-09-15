#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Batch-driven deterministic zk_cli codegen for every (preset x committee) x circuit.
#
# Produces per-circuit `configs.nr` + `Prover.toml` under:
#     dist/circuit-codegen/<preset>/<committee>/<circuit_path>/
# for all three BFV presets (insecure, secure-8192, secure-16384) and all
# committees (minimum, micro, small).
#
# This is a convenience batch wrapper: it drives the same per-circuit `zk_cli codegen`
# path as `circuits/benchmarks/scripts/generate_prover_toml.sh`, but for the full
# matrix at once and including configs (not just Prover.toml), so operators do not
# need to repeat zk_cli runs manually.
#
# Augments — does not replace — `zk_cli`. `zk_cli` remains the on-demand single-circuit
# path; this script is the deterministic matrix sweep.
#
# Usage:
#   ./scripts/generate-circuit-configs.sh [--preset insecure|secure-8192|secure-16384|all] [--committee minimum|micro|small|all] [--circuits <comma-separated paths>] [--output <dir>] [--allow-failures]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=circuits/benchmarks/scripts/zk_cli_helpers.sh
ZK_CLI_HELPERS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../circuits/benchmarks/scripts" && pwd)/zk_cli_helpers.sh"
source "$ZK_CLI_HELPERS"

ALL_PRESETS=("insecure" "secure-8192" "secure-16384")
ALL_COMMITTEES=("minimum" "micro" "small")
DEFAULT_OUTPUT="$REPO_ROOT/dist/circuit-codegen"

# Canonical circuit list. Mirrors `circuits/benchmarks/config.json`; entries are either
# a plain path string (`"dkg/pk"`) or a `{name, modes}` object (`config`).
CONFIG_JSON="$REPO_ROOT/circuits/benchmarks/config.json"
ALL_CIRCUITS=()
while IFS= read -r circuit; do
    ALL_CIRCUITS+=("$circuit")
done < <(jq -r '.circuits[] | if type == "object" then .name else . end' "$CONFIG_JSON")

SELECT_PRESETS=()
SELECT_COMMITTEES=()
SELECT_CIRCUITS=()
OUTPUT="$DEFAULT_OUTPUT"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --preset|--committee|--circuits|--output)
            if [[ $# -lt 2 ]]; then
                echo "Missing value for $1" >&2
                exit 1
            fi
            case "$1" in
                --preset)
                    if [[ "$2" == "all" ]]; then
                        SELECT_PRESETS=("${ALL_PRESETS[@]}")
                    else
                        SELECT_PRESETS+=("$2")
                    fi
                    ;;
                --committee)
                    if [[ "$2" == "all" ]]; then
                        SELECT_COMMITTEES=("${ALL_COMMITTEES[@]}")
                    else
                        SELECT_COMMITTEES+=("$2")
                    fi
                    ;;
                --circuits)
                    IFS=',' read -r -a SELECT_CIRCUITS <<< "$2"
                    ;;
                --output)
                    OUTPUT="$2"
                    ;;
            esac
            shift 2
            ;;
        --allow-failures)
            ALLOW_FAILURES=1
            shift
            ;;
        --strict)
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--preset insecure|secure-8192|secure-16384|all] [--committee minimum|micro|small|all] [--circuits <csv>] [--output <dir>] [--allow-failures]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Defaults when the flags were not given: use everything.
[[ ${#SELECT_PRESETS[@]} -eq 0 ]] && SELECT_PRESETS=("${ALL_PRESETS[@]}")
[[ ${#SELECT_COMMITTEES[@]} -eq 0 ]] && SELECT_COMMITTEES=("${ALL_COMMITTEES[@]}")
[[ ${#SELECT_CIRCUITS[@]} -eq 0 ]] && SELECT_CIRCUITS=("${ALL_CIRCUITS[@]}")

# map circuit path -> exact zk_cli preset name (BfvPreset::name, e.g. SECURE_THRESHOLD_16384)
preset_to_zk_name() {
    case "$1" in
        insecure) echo "INSECURE_THRESHOLD_512" ;;
        secure-8192) echo "SECURE_THRESHOLD_8192" ;;
        secure-16384) echo "SECURE_THRESHOLD_16384" ;;
        *) echo "Error: unknown preset $1" >&2; return 1 ;;
    esac
}

echo "🔮 Generating circuit configs: presets=[${SELECT_PRESETS[*]}] committees=[${SELECT_COMMITTEES[*]}]"
echo "   circuits=$(( ${#SELECT_CIRCUITS[@]} ))  output=$OUTPUT"

mkdir -p "$OUTPUT"

ALLOW_FAILURES="${ALLOW_FAILURES:-0}"
MANIFEST=()
FAILURES=()

for preset in "${SELECT_PRESETS[@]}"; do
    zk_preset="$(preset_to_zk_name "$preset")"
    for committee in "${SELECT_COMMITTEES[@]}"; do
        for circuit_path in "${SELECT_CIRCUITS[@]}"; do
            out_dir="$OUTPUT/$preset/$committee/$circuit_path"
            mkdir -p "$out_dir"
            printf -v man "%s\t%s\t%s" "$preset" "$committee" "$circuit_path"
            MANIFEST+=("$man")

            zk_args="$(get_zk_args "$circuit_path" || true)"
            zk_circuit="${zk_args%% *}"
            if [[ "$zk_args" == *" "* ]]; then
                zk_inputs="${zk_args#* }"
            else
                zk_inputs=""
            fi

            if [[ "$zk_circuit" == "_no_zk_cli" ]]; then
                # `config` circuit has no witness inputs; emit an empty Prover.toml so nargo runs.
                touch "$out_dir/Prover.toml"
                echo "  . $preset/$committee/$circuit_path  (no zk_cli)"
                continue
            fi

            cmd=(cargo run -q -p e3-zk-helpers --bin zk_cli --
                --circuit "$zk_circuit"
                --preset "$zk_preset"
                --committee "$committee"
                --output "$out_dir"
                --toml)
            if [[ -n "$zk_inputs" ]]; then
                cmd+=(--inputs "$zk_inputs")
            fi

            echo "  → $preset/$committee/$circuit_path  (zk_cli --circuit $zk_circuit --preset $zk_preset --committee $committee)"
            if "${cmd[@]}"; then
                : # success
            else
                printf -v fail "%s\t%s\t%s\t(zk_cli %s %s failed)" "$preset" "$committee" "$circuit_path" "$zk_circuit" "$zk_inputs"
                FAILURES+=("$fail")
                if [[ "$ALLOW_FAILURES" != "1" ]]; then
                    echo "  ✗ $preset/$committee/$circuit_path failed (strict mode) — aborting" >&2
                    exit 1
                fi
                echo "  ✗ $preset/$committee/$circuit_path failed (recorded; --allow-failures)" >&2
            fi
        done
    done
done

printf '%s\n' "${MANIFEST[@]}" > "$OUTPUT/manifest.txt"
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    printf '%s\n' "${FAILURES[@]}" > "$OUTPUT/failures.txt"
    echo "⚠ ${#FAILURES[@]} infeasible/invalid combination(s); see $OUTPUT/failures.txt"
else
    rm -f "$OUTPUT/failures.txt"
fi
echo "✔ Wrote $(wc -l < "$OUTPUT/manifest.txt") entries + manifest to $OUTPUT"
