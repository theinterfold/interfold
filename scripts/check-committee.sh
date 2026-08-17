#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Asserts that the committee selection is internally consistent across the five files
# that encode it independently:
#
#   1. circuits/lib/src/configs/committee/active.nr  (Noir-side active committee)
#   2. circuits/bin/.active-preset.json              (last `pnpm build:circuits` stamp)
#   3. packages/interfold-contracts/scripts/utils.ts   (BFV_DKG_H / BFV_THRESHOLD_T)
#   4. crates/zk-helpers/src/ciphernodes_committee.rs (committee enum values, single source)
#   5. packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol
#
# A drift between any two means the next `pnpm build:circuits` would silently produce
# verifiers / proofs against the wrong committee. Run from .husky/pre-push (or CI).
#
# Exit 0 on consistency, 1 on drift. The stamp is optional (skipped when absent — common
# in fresh clones before `pnpm build:circuits`).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ACTIVE_NR="circuits/lib/src/configs/committee/active.nr"
STAMP="circuits/bin/.active-preset.json"
UTILS_TS="packages/interfold-contracts/scripts/utils.ts"
COMMITTEE_RS="crates/zk-helpers/src/ciphernodes_committee.rs"
ACTIVE_SOL="packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol"
RAN_STAMP_CHECK=false
RAN_PARITY_CHECK=false

fail() {
  echo "❌ check:committee: $*" >&2
  exit 1
}

# 1. Extract committee name from active.nr (matches "crate::configs::committee::<name>::N_PARTIES").
if [[ ! -f "$ACTIVE_NR" ]]; then
  fail "missing $ACTIVE_NR"
fi
ACTIVE_COMMITTEE=$(grep -oE 'crate::configs::committee::(minimum|micro|small)::N_PARTIES' "$ACTIVE_NR" \
  | head -n1 \
  | sed -E 's|.*committee::([a-z]+)::N_PARTIES|\1|')
if [[ -z "${ACTIVE_COMMITTEE:-}" ]]; then
  fail "could not infer committee from $ACTIVE_NR (regex match failed)"
fi

# 2. Extract (H, T) from utils.ts.
if [[ ! -f "$UTILS_TS" ]]; then
  fail "missing $UTILS_TS"
fi
UTILS_H=$(grep -E '^export const BFV_DKG_H = [0-9]+' "$UTILS_TS" | grep -oE '[0-9]+' | head -n1)
UTILS_T=$(grep -E '^export const BFV_THRESHOLD_T = [0-9]+' "$UTILS_TS" | grep -oE '[0-9]+' | head -n1)
if [[ -z "${UTILS_H:-}" || -z "${UTILS_T:-}" ]]; then
  fail "could not parse BFV_DKG_H / BFV_THRESHOLD_T from $UTILS_TS"
fi

# 3. Expected (H, T) for the active committee — parsed from the leaf `mod.nr` (same source
#    as `load_default_committee.sh`; avoids duplicating numbers in this script).
COMMITTEE_MOD="circuits/lib/src/configs/committee/${ACTIVE_COMMITTEE}/mod.nr"
if [[ ! -f "$COMMITTEE_MOD" ]]; then
  fail "missing $COMMITTEE_MOD (no Noir module for committee '$ACTIVE_COMMITTEE')"
fi
EXPECTED_H=$(grep -E 'pub global H: u32 = [0-9]+' "$COMMITTEE_MOD" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
EXPECTED_T=$(grep -E 'pub global T: u32 = [0-9]+' "$COMMITTEE_MOD" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
EXPECTED_N=$(grep -E 'pub global N_PARTIES: u32 = [0-9]+' "$COMMITTEE_MOD" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
if [[ -z "${EXPECTED_H:-}" || -z "${EXPECTED_T:-}" || -z "${EXPECTED_N:-}" ]]; then
  fail "could not parse H / T / N from $COMMITTEE_MOD"
fi

if [[ "$UTILS_H" != "$EXPECTED_H" || "$UTILS_T" != "$EXPECTED_T" ]]; then
  fail "drift: $ACTIVE_NR says committee=$ACTIVE_COMMITTEE (expects H=$EXPECTED_H, T=$EXPECTED_T) \
but $UTILS_TS has BFV_DKG_H=$UTILS_H, BFV_THRESHOLD_T=$UTILS_T. \
Run: pnpm build:circuits --committee $ACTIVE_COMMITTEE"
fi

# 4. The Solidity constants must select the same active circuit shape.
[[ -f "$ACTIVE_SOL" ]] || fail "missing $ACTIVE_SOL"
SOL_H=$(grep -E 'uint32 internal constant H = [0-9]+' "$ACTIVE_SOL" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
SOL_T=$(grep -E 'uint32 internal constant T = [0-9]+' "$ACTIVE_SOL" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
SOL_N=$(grep -E 'uint32 internal constant N = [0-9]+' "$ACTIVE_SOL" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
SOL_SIZE=$(grep -E 'uint8 internal constant COMMITTEE_SIZE = [0-9]+' "$ACTIVE_SOL" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
case "$ACTIVE_COMMITTEE" in
  minimum) EXPECTED_SIZE=0 ;;
  micro) EXPECTED_SIZE=1 ;;
  small) EXPECTED_SIZE=2 ;;
  *) fail "unknown committee '$ACTIVE_COMMITTEE' in $ACTIVE_NR" ;;
esac
if [[ "$SOL_H" != "$EXPECTED_H" || "$SOL_T" != "$EXPECTED_T" || "$SOL_N" != "$EXPECTED_N" || "$SOL_SIZE" != "$EXPECTED_SIZE" ]]; then
  fail "drift: $ACTIVE_SOL has (size=$SOL_SIZE, N=$SOL_N, T=$SOL_T, H=$SOL_H), expected (size=$EXPECTED_SIZE, N=$EXPECTED_N, T=$EXPECTED_T, H=$EXPECTED_H)"
fi

# 5. Optional stamp cross-check (when circuits have been built locally).
if [[ -f "$STAMP" ]]; then
  # Older stamps (written before build-circuits.ts learned about committees) lack the field;
  # treat that as "no cross-check" rather than failing the whole script.
  STAMP_COMMITTEE=$(grep -oE '"committee"\s*:\s*"[a-z]+"' "$STAMP" 2>/dev/null | grep -oE '"[a-z]+"$' | tr -d '"' || true)
  if [[ -n "${STAMP_COMMITTEE:-}" ]]; then
    RAN_STAMP_CHECK=true
    if [[ "$STAMP_COMMITTEE" != "$ACTIVE_COMMITTEE" ]]; then
      fail "drift: $ACTIVE_NR says committee=$ACTIVE_COMMITTEE but $STAMP says committee=$STAMP_COMMITTEE. \
Either rebuild circuits with the current selection or revert active.nr to match the stamp."
    fi
  fi
fi

# 6. Check every Rust enum row against its Noir committee module.
if [[ ! -f "$COMMITTEE_RS" ]]; then
  fail "missing $COMMITTEE_RS"
fi
for committee in minimum micro small; do
  mod_file="circuits/lib/src/configs/committee/$committee/mod.nr"
  [[ -f "$mod_file" ]] || fail "missing $mod_file"

  noir_n=$(grep -E 'pub global N_PARTIES: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  noir_h=$(grep -E 'pub global H: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  noir_t=$(grep -E 'pub global T: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  capitalized="$(echo "$committee" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
  rust_block="$(
    awk -v marker="CiphernodesCommitteeSize::$capitalized => CiphernodesCommittee {" '
      index($0, marker) { found = 1 }
      found { print }
      found && /^[[:space:]]*},[[:space:]]*$/ { exit }
    ' "$COMMITTEE_RS"
  )"
  rust_n=$(grep -E '^[[:space:]]*n: [0-9]+,' <<<"$rust_block" | grep -oE '[0-9]+' | head -n1)
  rust_h=$(grep -E '^[[:space:]]*h: [0-9]+,' <<<"$rust_block" | grep -oE '[0-9]+' | head -n1)
  rust_t=$(grep -E '^[[:space:]]*threshold: [0-9]+,' <<<"$rust_block" | grep -oE '[0-9]+' | head -n1)

  if [[ -z "$rust_n" || -z "$rust_h" || -z "$rust_t" ]]; then
    fail "could not parse CiphernodesCommitteeSize::$capitalized from $COMMITTEE_RS"
  fi
  if [[ "$rust_n" != "$noir_n" || "$rust_h" != "$noir_h" || "$rust_t" != "$noir_t" ]]; then
    fail "drift: $mod_file has (N=$noir_n, T=$noir_t, H=$noir_h) but \
$COMMITTEE_RS has (N=$rust_n, T=$rust_t, H=$rust_h) for $capitalized"
  fi
done

# 7. Derived Noir artifacts for every committee must match what `generate_parity_matrices` would
#    write right now. Hand-edits would slip past every other check, so verify them by
#    regenerating into a tempdir and diffing. On-disk files are kept `nargo fmt`-clean
#    (see `scripts/lint-circuits.sh`), so we format the generator output before comparing.
#    Skipped when the binary is unavailable (fresh clone before `cargo build`); the build step
#    will re-emit them anyway.
GEN_BIN="target/release/generate_parity_matrices"
NOIR_LIB="circuits/lib"
for c in minimum micro small; do
  for artifact in parity_insecure.nr parity_secure.nr smudging.nr; do
    [[ -f "$NOIR_LIB/src/configs/committee/$c/$artifact" ]] || fail "missing generated committee artifact: $c/$artifact"
  done
done

format_committee_artifacts() {
  local committee="$1"
  local tmp="$2"
  local variant live fresh backup formatted
  local -a swapped_live=()
  local -a swapped_backup=()

  _restore_swapped_committee_live() {
    local i
    for i in "${!swapped_live[@]}"; do
      if [[ -f "${swapped_backup[$i]}" ]]; then
        cp "${swapped_backup[$i]}" "${swapped_live[$i]}"
      fi
    done
  }

  trap '_restore_swapped_committee_live' ERR

  for variant in insecure secure; do
    live="$NOIR_LIB/src/configs/committee/$committee/parity_${variant}.nr"
    fresh="$tmp/$committee/parity_${variant}.nr"
    [[ -f "$live" && -f "$fresh" ]] || continue
    backup="$tmp/$committee/parity_${variant}.live.bak"
    formatted="$tmp/$committee/parity_${variant}.formatted.nr"
    cp "$live" "$backup"
    cp "$fresh" "$live"
    swapped_live+=("$live")
    swapped_backup+=("$backup")
  done

  live="$NOIR_LIB/src/configs/committee/$committee/smudging.nr"
  fresh="$tmp/$committee/smudging.nr"
  if [[ -f "$live" && -f "$fresh" ]]; then
    backup="$tmp/$committee/smudging.live.bak"
    cp "$live" "$backup"
    cp "$fresh" "$live"
    swapped_live+=("$live")
    swapped_backup+=("$backup")
  fi

  if ((${#swapped_live[@]} == 0)); then
    trap - ERR
    return 0
  fi

  if ! (cd "$NOIR_LIB" && nargo fmt) >/dev/null; then
    _restore_swapped_committee_live
    trap - ERR
    return 1
  fi

  for variant in insecure secure; do
    live="$NOIR_LIB/src/configs/committee/$committee/parity_${variant}.nr"
    fresh="$tmp/$committee/parity_${variant}.nr"
    backup="$tmp/$committee/parity_${variant}.live.bak"
    formatted="$tmp/$committee/parity_${variant}.formatted.nr"
    [[ -f "$backup" ]] || continue
    cp "$live" "$formatted"
    cp "$backup" "$live"
    cp "$formatted" "$fresh"
  done
  live="$NOIR_LIB/src/configs/committee/$committee/smudging.nr"
  fresh="$tmp/$committee/smudging.nr"
  backup="$tmp/$committee/smudging.live.bak"
  formatted="$tmp/$committee/smudging.formatted.nr"
  if [[ -f "$backup" ]]; then
    cp "$live" "$formatted"
    cp "$backup" "$live"
    cp "$formatted" "$fresh"
  fi

  trap - ERR
}

command -v nargo >/dev/null 2>&1 || fail "nargo is required to verify generated committee artifacts"
cargo build --quiet --release -p e3-zk-helpers --bin generate_parity_matrices
RAN_PARITY_CHECK=true
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# Mirror the committee dir layout so the bin can write into <tmp>/<committee>/.
for c in minimum micro small; do
  if [[ -d "circuits/lib/src/configs/committee/$c" ]]; then
    mkdir -p "$TMP/$c"
  fi
done
for c in minimum micro small; do
  [[ -d "$TMP/$c" ]] || continue
  "$GEN_BIN" --committee "$c" --output-root "$TMP" >/dev/null
  format_committee_artifacts "$c" "$TMP"
  for variant in insecure secure; do
    live="circuits/lib/src/configs/committee/$c/parity_${variant}.nr"
    fresh="$TMP/$c/parity_${variant}.nr"
    [[ -f "$fresh" ]] || fail "$GEN_BIN did not generate $fresh"
    if ! diff -q "$live" "$fresh" >/dev/null; then
      fail "$live drift vs generator output. Run: pnpm build:circuits --committee $c"
    fi
  done
  live="circuits/lib/src/configs/committee/$c/smudging.nr"
  fresh="$TMP/$c/smudging.nr"
  [[ -f "$fresh" ]] || fail "$GEN_BIN did not generate $fresh"
  if ! diff -q "$live" "$fresh" >/dev/null; then
    fail "$live drift vs generator output. Run: pnpm build:circuits --committee $c"
  fi
done

echo "✓ check:committee: $ACTIVE_COMMITTEE (H=$EXPECTED_H, T=$EXPECTED_T) consistent across active.nr, ActiveCryptoConfig.sol, utils.ts, Rust committee rows$([ "$RAN_STAMP_CHECK" = true ] && echo ', .active-preset.json')$([ "$RAN_PARITY_CHECK" = true ] && echo ', generated committee artifacts')"
