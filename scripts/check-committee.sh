#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Asserts that the BFV parameters and committee selection are internally consistent across
# the files that encode them independently:
#
#   1. packages/interfold-contracts/scripts/protocol/constants.ts (deployment parameters)
#   2. crates/fhe-params/src/constants.rs (ciphernode parameters)
#   3. circuits/lib/src/configs/{insecure,secure_8192,secure_16384}/threshold.nr (circuit parameters)
#   4. circuits/lib/src/configs/committee/active.nr (Noir-side active committee)
#   5. packages/interfold-contracts/scripts/utils.ts (deployment hashes and committee values)
#   6. crates/zk-helpers/src/ciphernodes_committee.rs (committee enum values)
#   7. packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol
#
# `circuits/bin/.active-preset.json` is only a local hydrated cache. It can point at Sepolia's
# fast insecure-minimum artifacts while the checked-in production config points at secure-small.
#
# A drift between any two means the next `pnpm build:circuits` would silently produce
# verifiers / proofs against the wrong committee. Run from .husky/pre-push (or CI).
#
# Exit 0 on consistency, 1 on drift.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ACTIVE_NR="circuits/lib/src/configs/committee/active.nr"
STAMP="circuits/bin/.active-preset.json"
UTILS_TS="packages/interfold-contracts/scripts/utils.ts"
PROTOCOL_CONSTANTS_TS="packages/interfold-contracts/scripts/protocol/constants.ts"
FHE_CONSTANTS_RS="crates/fhe-params/src/constants.rs"
COMMITTEE_RS="crates/zk-helpers/src/ciphernodes_committee.rs"
ACTIVE_SOL="packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol"
TASKS_TS="packages/interfold-contracts/tasks/interfold.ts"
SDK_UTILS_TS="packages/interfold-sdk/src/utils.ts"
EVM_HELPERS_RS="crates/evm-helpers/src/contracts.rs"
EVM_EVENTS_RS="crates/evm/src/interfold/events.rs"
INDEXER_RS="crates/indexer/src/indexer.rs"
FIXTURE_CONSTANTS_TS="packages/interfold-contracts/test/fixtures/constants.ts"
RAN_STAMP_CHECK=false
RAN_PARITY_CHECK=false

fail() {
  echo "❌ check:committee: $*" >&2
  exit 1
}

for required_file in \
  "$PROTOCOL_CONSTANTS_TS" \
  "$FHE_CONSTANTS_RS" \
  "$ACTIVE_SOL" \
  "$TASKS_TS" \
  "$SDK_UTILS_TS" \
  "$EVM_HELPERS_RS" \
  "$EVM_EVENTS_RS" \
  "$INDEXER_RS" \
  "$FIXTURE_CONSTANTS_TS"; do
  [[ -f "$required_file" ]] || fail "missing $required_file"
done

for committee in minimum micro small; do
  for artifact in parity_insecure.nr parity_secure_8192.nr parity_secure_16384.nr smudging.nr; do
    [[ -f "circuits/lib/src/configs/committee/$committee/$artifact" ]] \
      || fail "missing generated committee artifact: $committee/$artifact"
  done
done

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

# 4. The Solidity constants must include each supported on-chain committee shape.
[[ -f "$ACTIVE_SOL" ]] || fail "missing $ACTIVE_SOL"
sol_u32() {
  local name="$1"
  grep -E "uint32 internal constant $name = [0-9]+" "$ACTIVE_SOL" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1
}
sol_u8() {
  local name="$1"
  grep -E "uint8 internal constant $name = [0-9]+" "$ACTIVE_SOL" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1
}
check_sol_committee() {
  local committee="$1"
  local prefix="$2"
  local size="$3"
  local mod_file="circuits/lib/src/configs/committee/$committee/mod.nr"
  local noir_n noir_h noir_t sol_size sol_n sol_h sol_t
  noir_n=$(grep -E 'pub global N_PARTIES: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  noir_h=$(grep -E 'pub global H: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  noir_t=$(grep -E 'pub global T: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  sol_size=$(sol_u8 "${prefix}_COMMITTEE_SIZE")
  sol_n=$(sol_u32 "${prefix}_N")
  sol_h=$(sol_u32 "${prefix}_H")
  sol_t=$(sol_u32 "${prefix}_T")
  if [[ "$sol_size" != "$size" || "$sol_n" != "$noir_n" || "$sol_h" != "$noir_h" || "$sol_t" != "$noir_t" ]]; then
    fail "drift: $ACTIVE_SOL ${prefix} has (size=$sol_size, N=$sol_n, T=$sol_t, H=$sol_h), expected (size=$size, N=$noir_n, T=$noir_t, H=$noir_h)"
  fi
}
check_sol_committee minimum MINIMUM 0
check_sol_committee micro MICRO 1
check_sol_committee small SMALL 2

# 5. The complete threshold parameter tuple must match across deployment tooling, ciphernodes,
#    and Noir. The error variance is represented in Noir by the generated encryption bound.
hex_csv_to_decimal() {
  local input="$1"
  local output=""
  local item decimal
  local -a items
  IFS=',' read -r -a items <<< "$input"
  for item in "${items[@]}"; do
    decimal=$(printf '%u' "$((item))")
    output="${output}${output:+,}${decimal}"
  done
  printf '%s' "$output"
}

error_bound_for_variance() {
  node -e '
const variance = BigInt(process.argv[1]);
if (variance <= 16n) {
  process.stdout.write((2n * variance).toString());
} else {
  const target = 3n * variance;
  let bound = target;
  let next = (bound + target / bound) / 2n;
  while (next < bound) {
    bound = next;
    next = (bound + target / bound) / 2n;
  }
  while (bound * (bound + 1n) < target) bound += 1n;
  while (bound > 0n && (bound - 1n) * bound >= target) bound -= 1n;
  process.stdout.write(bound.toString());
}
' "$1"
}

check_bfv_preset() {
  local label="$1"
  local ts_name="$2"
  local rust_name="$3"
  local noir_name="$4"
  local ts_block rust_block rust_threshold noir_file
  local ts_degree ts_plaintext ts_moduli ts_error
  local rust_degree rust_plaintext rust_moduli rust_error
  local noir_degree noir_plaintext noir_moduli noir_error_bound expected_error_bound

  ts_block=$(awk -v marker="  ${ts_name}: {" '
    $0 == marker { found = 1 }
    found { print }
    found && /^  },/ { exit }
  ' "$PROTOCOL_CONSTANTS_TS")
  rust_block=$(awk -v marker="pub mod ${rust_name} {" '
    $0 == marker { found = 1 }
    found { print }
    found && /^}/ { exit }
  ' "$FHE_CONSTANTS_RS")
  rust_threshold=$(awk '
    /^    pub mod threshold \{/ { found = 1 }
    found { print }
    found && /^    }/ { exit }
  ' <<< "$rust_block")
  noir_file="circuits/lib/src/configs/${noir_name}/threshold.nr"

  [[ -n "$ts_block" && -n "$rust_threshold" && -f "$noir_file" ]] \
    || fail "could not read the ${label} BFV parameter sources"

  ts_degree=$(grep -E '^[[:space:]]*degree: [0-9]+n,' <<< "$ts_block" | sed -E 's/.*degree: ([0-9]+)n,.*/\1/')
  ts_plaintext=$(grep -E '^[[:space:]]*plaintextModulus: [0-9]+n,' <<< "$ts_block" | sed -E 's/.*plaintextModulus: ([0-9]+)n,.*/\1/')
  ts_moduli=$(grep -oE '0x[0-9a-fA-F]+n' <<< "$ts_block" | tr -d 'n' | tr '[:upper:]' '[:lower:]' | paste -sd, -)
  ts_error=$(grep -E '^[[:space:]]*error1Variance: "[0-9]+",' <<< "$ts_block" | sed -E 's/.*"([0-9]+)".*/\1/')

  rust_degree=$(grep -E '^[[:space:]]*pub const DEGREE: usize = [0-9]+;' <<< "$rust_block" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  rust_plaintext=$(grep -E 'PLAINTEXT_MODULUS: u64 = [0-9]+;' <<< "$rust_threshold" | sed -E 's/.*= ([0-9]+);/\1/')
  rust_moduli=$(grep -oE '0x[0-9a-fA-F_]+' <<< "$rust_threshold" | tr -d '_' | tr '[:upper:]' '[:lower:]' | paste -sd, -)
  rust_error=$(grep -E 'ERROR1_VARIANCE: &str = "[0-9]+";' <<< "$rust_threshold" | sed -E 's/.*"([0-9]+)".*/\1/')

  if [[ "$ts_degree" != "$rust_degree" || "$ts_plaintext" != "$rust_plaintext" || \
        "$ts_moduli" != "$rust_moduli" || "$ts_error" != "$rust_error" ]]; then
    fail "drift: ${label} BFV parameters differ between $PROTOCOL_CONSTANTS_TS and $FHE_CONSTANTS_RS"
  fi

  noir_degree=$(grep -E '^pub global N: u32 = [0-9]+;' "$noir_file" | sed -E 's/.*= ([0-9]+);/\1/')
  noir_plaintext=$(grep -E '^pub global PLAINTEXT_MODULUS: Field = [0-9]+;' "$noir_file" | sed -E 's/.*= ([0-9]+);/\1/')
  noir_moduli=$(awk '/^pub global QIS:/,/];/ { gsub(/[^0-9,]/, ""); if ($0 != "") { printf "%s%s", sep, $0; sep = "," } }' "$noir_file")
  noir_error_bound=$(grep -E '^pub global PK_GENERATION_B_ENC: Field = [0-9]+;' "$noir_file" | sed -E 's/.*= ([0-9]+);/\1/')
  expected_error_bound=$(error_bound_for_variance "$ts_error")

  if [[ "$ts_degree" != "$noir_degree" || "$ts_plaintext" != "$noir_plaintext" || \
        "$(hex_csv_to_decimal "$ts_moduli")" != "$noir_moduli" || \
        "$expected_error_bound" != "$noir_error_bound" ]]; then
    fail "drift: ${label} BFV parameters differ between $PROTOCOL_CONSTANTS_TS and $noir_file"
  fi
}

check_bfv_preset insecure insecure insecure insecure
check_bfv_preset secure-8192 secure8192 secure_8192 secure_8192
check_bfv_preset secure-16384 secure16384 secure_16384 secure_16384

# 6. Every chain-supported route in utils.ts must match the Noir committee shape and the
#    parameter/configuration hashes compiled into ActiveCryptoConfig.sol. Keep this check
#    dependency-free because the Agent Harness runs it before Node dependencies are installed.
CIRCUIT_VERSION_LABEL=$(grep -E 'bytes32 internal constant CIRCUIT_VERSION = keccak256\("[^\"]+"\);' "$ACTIVE_SOL" \
  | sed -E 's/.*keccak256\("([^\"]+)"\).*/\1/' \
  | head -n1)
[[ "$CIRCUIT_VERSION_LABEL" == "interfold-bfv-v2" ]] \
  || fail "$ACTIVE_SOL must use circuit identity interfold-bfv-v2; got ${CIRCUIT_VERSION_LABEL:-missing}"
grep -Fq 'export const CIRCUIT_VERSION = ethers.id("interfold-bfv-v2");' "$FIXTURE_CONSTANTS_TS" \
  || fail "$FIXTURE_CONSTANTS_TS must derive configuration IDs from interfold-bfv-v2"
grep -Fq 'b"interfold-bfv-v2"' "$EVM_EVENTS_RS" \
  || fail "$EVM_EVENTS_RS must derive configuration IDs from interfold-bfv-v2"
grep -Fq 'b"interfold-bfv-v2"' "$INDEXER_RS" \
  || fail "$INDEXER_RS must derive configuration IDs from interfold-bfv-v2"

sol_bytes32() {
  local name="$1"
  grep -A1 -E "bytes32 internal constant $name" "$ACTIVE_SOL" \
    | grep -oE '0x[0-9a-fA-F]+' \
    | head -n1
}

ts_bytes32() {
  local name="$1"
  grep -A1 -E "^const $name" "$UTILS_TS" \
    | grep -oE '0x[0-9a-fA-F]+' \
    | head -n1
}

for prefix in INSECURE SECURE SECURE_16384; do
  utils_param_hash=$(ts_bytes32 "${prefix}_PARAM_SET_HASH")
  utils_config_id=$(ts_bytes32 "${prefix}_CONFIG_ID")
  sol_param_hash=$(sol_bytes32 "${prefix}_PARAM_SET_HASH")
  sol_config_id=$(sol_bytes32 "${prefix}_CONFIG_ID")
  if [[ "$utils_param_hash" != "$sol_param_hash" || "$utils_config_id" != "$sol_config_id" ]]; then
    fail "drift: $UTILS_TS ${prefix} hashes do not match $ACTIVE_SOL"
  fi
done

extract_ts_config_id() {
  local file="$1"
  local param_set="$2"
  sed -n '/function cryptoConfigIdForParamSet/,/^}/p' "$file" \
    | grep -A2 "paramSet === ${param_set}" \
    | grep -oE '0x[0-9a-fA-F]{64}' \
    | head -n1
}

extract_rust_config_id() {
  local file="$1"
  local param_set="$2"
  sed -n '/^fn crypto_config_id_for_param_set/,/^}/p' "$file" \
    | grep -E "^[[:space:]]*${param_set} =>" \
    | grep -oE '0x[0-9a-fA-F]{64}' \
    | head -n1
}

for prefix_and_param_set in INSECURE:0 SECURE:1 SECURE_16384:2; do
  prefix="${prefix_and_param_set%%:*}"
  param_set="${prefix_and_param_set##*:}"
  expected_id=$(sol_bytes32 "${prefix}_CONFIG_ID")
  task_id=$(extract_ts_config_id "$TASKS_TS" "$param_set")
  sdk_id=$(extract_ts_config_id "$SDK_UTILS_TS" "$param_set")
  evm_helper_id=$(extract_rust_config_id "$EVM_HELPERS_RS" "$param_set")
  if [[ "$task_id" != "$expected_id" || "$sdk_id" != "$expected_id" || "$evm_helper_id" != "$expected_id" ]]; then
    fail "drift: paramSet=${param_set} config ID must match $ACTIVE_SOL in tasks, SDK, and EVM helpers"
  fi
  grep -Fq "$expected_id" "$EVM_EVENTS_RS" \
    || fail "drift: paramSet=${param_set} config ID must match $ACTIVE_SOL in the Rust EVM compatibility test"
done

ORIGIN_V1_INSECURE_CONFIG_ID="0x04f3677e73b0f5066d6caf5cbd92e3fb2e38338edaf5cfc971ab28f7b684da78"
[[ "$(sol_bytes32 INSECURE_CONFIG_ID)" != "$ORIGIN_V1_INSECURE_CONFIG_ID" ]] \
  || fail "$ACTIVE_SOL insecure configuration ID must differ from the origin interfold-bfv-v1 ID"

check_utils_route() {
  local symbol="$1"
  local preset="$2"
  local committee="$3"
  local expected_size="$4"
  local block mod_file noir_n noir_h noir_t expected_shape
  block=$(sed -n "/^export const ${symbol}_BFV_CONFIG:/,/^);/p" "$UTILS_TS")
  [[ -n "$block" ]] || fail "missing ${symbol}_BFV_CONFIG in $UTILS_TS"
  mod_file="circuits/lib/src/configs/committee/$committee/mod.nr"
  noir_n=$(grep -E 'pub global N_PARTIES: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  noir_h=$(grep -E 'pub global H: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  noir_t=$(grep -E 'pub global T: u32 = [0-9]+' "$mod_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  expected_shape="{ committeeSize: $expected_size, h: $noir_h, t: $noir_t, n: $noir_n },"
  if ! grep -Fq "\"$preset\"" <<< "$block" || \
     ! grep -Fq "\"$committee\"" <<< "$block" || \
     ! grep -Fq "$expected_shape" <<< "$block"; then
    fail "drift: ${symbol}_BFV_CONFIG must define $preset/$committee with $expected_shape"
  fi
}

check_utils_route INSECURE_MINIMUM insecure minimum 0
check_utils_route INSECURE_MICRO insecure micro 1
check_utils_route INSECURE_SMALL insecure small 2
check_utils_route SECURE_MINIMUM secure-8192 minimum 0
check_utils_route SECURE_MICRO secure-8192 micro 1
check_utils_route SECURE_SMALL secure-8192 small 2
check_utils_route SECURE_16384_MINIMUM secure-16384 minimum 0

route_list() {
  local array_name="$1"
  sed -n "/^export const ${array_name}:.*= \[/,/^\] as const;/p" "$UTILS_TS" \
    | grep -oE '(INSECURE|SECURE(_16384)?)_(MINIMUM|MICRO|SMALL)_BFV_CONFIG' \
    | paste -sd, -
}

TESTNET_ROUTES=$(route_list TESTNET_BFV_CONFIGS)
EXPECTED_TESTNET_ROUTES="INSECURE_MINIMUM_BFV_CONFIG,INSECURE_MICRO_BFV_CONFIG,INSECURE_SMALL_BFV_CONFIG,SECURE_MINIMUM_BFV_CONFIG,SECURE_MICRO_BFV_CONFIG,SECURE_SMALL_BFV_CONFIG,SECURE_16384_MINIMUM_BFV_CONFIG"
[[ "$TESTNET_ROUTES" == "$EXPECTED_TESTNET_ROUTES" ]] \
  || fail "$UTILS_TS testnet routes must contain the exact supported-pair matrix; got $TESTNET_ROUTES"

MAINNET_ROUTES=$(route_list MAINNET_BFV_CONFIGS)
EXPECTED_MAINNET_ROUTES="SECURE_SMALL_BFV_CONFIG,SECURE_MICRO_BFV_CONFIG,SECURE_MINIMUM_BFV_CONFIG"
[[ "$MAINNET_ROUTES" == "$EXPECTED_MAINNET_ROUTES" ]] \
  || fail "$UTILS_TS mainnet routes must be secure-only small, micro, minimum; got $MAINNET_ROUTES"

# 7. Optional local-cache note (when circuits have been built locally).
if [[ -f "$STAMP" ]]; then
  # Older stamps (written before build-circuits.ts learned about committees) lack the field.
  STAMP_COMMITTEE=$(grep -oE '"committee"\s*:\s*"[a-z]+"' "$STAMP" 2>/dev/null | grep -oE '"[a-z]+"$' | tr -d '"' || true)
  if [[ -n "${STAMP_COMMITTEE:-}" ]]; then
    if [[ "$STAMP_COMMITTEE" != "$ACTIVE_COMMITTEE" ]]; then
      echo "  (local circuits/bin cache is hydrated for committee=$STAMP_COMMITTEE; production active.nr is committee=$ACTIVE_COMMITTEE)" >&2
    else
      RAN_STAMP_CHECK=true
    fi
  fi
fi

# 8. Check every Rust enum row against its Noir committee module.
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

# 9. Parity matrices for every committee must match what `generate_parity_matrices` would
#    write right now. Hand-edits to parity_*.nr would slip past every other check, so verify
#    them by regenerating into a tempdir and diffing. On-disk files are kept `nargo fmt`-clean
#    (see `scripts/lint-circuits.sh`), so we format the generator output before comparing.
#    Skipped when the binary is unavailable (fresh clone before `cargo build`); the build step
#    will re-emit them anyway.
GEN_BIN="target/release/generate_parity_matrices"
NOIR_LIB="circuits/lib"
format_parity_matrices_for_committee() {
  local committee="$1"
  local tmp="$2"
  local variant live fresh backup formatted
  local -a swapped_live=()
  local -a swapped_backup=()

  _restore_swapped_parity_live() {
    local i
    for i in "${!swapped_live[@]}"; do
      if [[ -f "${swapped_backup[$i]}" ]]; then
        cp "${swapped_backup[$i]}" "${swapped_live[$i]}"
      fi
    done
  }

  trap '_restore_swapped_parity_live' ERR

  for variant in insecure secure_8192 secure_16384; do
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
    _restore_swapped_parity_live
    trap - ERR
    return 1
  fi

  for variant in insecure secure_8192 secure_16384; do
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

if [[ -x "$GEN_BIN" ]]; then
  if ! command -v nargo >/dev/null 2>&1; then
    echo "  (skipping parity-matrix drift check: nargo not found. Install nargo to enable formatted parity comparison.)" >&2
  else
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
      format_parity_matrices_for_committee "$c" "$TMP"
      for variant in insecure secure_8192 secure_16384; do
        live="circuits/lib/src/configs/committee/$c/parity_${variant}.nr"
        fresh="$TMP/$c/parity_${variant}.nr"
        if [[ -f "$live" && -f "$fresh" ]] && ! diff -q "$live" "$fresh" >/dev/null; then
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
  fi
else
  echo "  (skipping parity-matrix drift check: $GEN_BIN not built. Run \`cargo build -p e3-zk-helpers --bin generate_parity_matrices --release\` to enable.)" >&2
fi

echo "✓ check:committee: BFV tuples, interfold-bfv-v2 configuration IDs, all supported testnet routes, and local $ACTIVE_COMMITTEE (H=$EXPECTED_H, T=$EXPECTED_T) are consistent across TypeScript, Rust, Noir, and Solidity$([ "$RAN_STAMP_CHECK" = true ] && echo ', .active-preset.json')$([ "$RAN_PARITY_CHECK" = true ] && echo ', parity_*.nr')"
