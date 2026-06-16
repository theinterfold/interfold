#!/usr/bin/env bash
# Ensure Noir circuit artifacts exist for a benchmark preset (insecure-512 | secure-8192).
#
# Usage (from repo root):
#   ./circuits/benchmarks/scripts/ensure_circuit_preset_built.sh <preset> [--committee minimum|micro|small] [--force-build] [--verbose]
#
# Default: pnpm build:circuits --skip-if-built --no-clean --no-clean-targets (fast re-runs).
# --force-build: full rebuild (wipes dist/circuits and circuits/bin targets via build:circuits).

set -e

PRESET=""
COMMITTEE=""
FORCE_BUILD=false
VERBOSE=false

usage() {
    echo "Usage: $0 <insecure-512|secure-8192> [--committee minimum|micro|small] [--force-build] [--verbose]"
}

require_arg_value() {
    local flag="$1"
    local value="${2:-}"
    if [ -z "$value" ] || [[ "$value" == -* ]]; then
        echo "Error: $flag requires a value"
        usage
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --committee)
            require_arg_value "$1" "${2:-}"
            COMMITTEE="$2"
            case "$COMMITTEE" in
                minimum|micro|small) ;;
                *)
                    echo "Error: --committee must be minimum|micro|small (got: $COMMITTEE)"
                    usage
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --force-build)
            FORCE_BUILD=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            if [ -z "$PRESET" ]; then
                PRESET="$1"
            else
                echo "Unexpected argument: $1"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -z "$PRESET" ]; then
    usage
    exit 1
fi
if [ "$PRESET" != "insecure-512" ] && [ "$PRESET" != "secure-8192" ]; then
    echo "Error: preset must be insecure-512 or secure-8192"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

if [ -z "$COMMITTEE" ]; then
    # shellcheck source=load_default_committee.sh
    source "${SCRIPT_DIR}/load_default_committee.sh"
    load_default_committee "" "$REPO_ROOT"
    COMMITTEE="$COMMITTEE_NAME"
fi

BUILD_ARGS=(--preset "$PRESET" --committee "$COMMITTEE")
if [ "$FORCE_BUILD" = true ]; then
    echo "  [circuits] Full rebuild: pnpm build:circuits ${BUILD_ARGS[*]}"
else
    # Committee changes invalidate the source hash, so --skip-if-built still recompiles
    # when the committee changed since the last build.
    BUILD_ARGS+=(--skip-if-built --no-clean --no-clean-targets)
    echo "  [circuits] Ensuring (${PRESET}${COMMITTEE:+, committee=$COMMITTEE}) (skip-if-built; use --force-build to recompile)..."
fi

if [ "$VERBOSE" = true ]; then
    echo "  [circuits] Running: pnpm build:circuits ${BUILD_ARGS[*]}"
    (cd "$REPO_ROOT" && pnpm build:circuits "${BUILD_ARGS[@]}")
else
    (cd "$REPO_ROOT" && pnpm build:circuits "${BUILD_ARGS[@]}" >/dev/null)
fi
