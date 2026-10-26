#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Asserts that the BFV parameters and committee selection are internally consistent across
# the files that encode them independently:
#
#   1. packages/interfold-contracts/crypto-config.json (deployment parameter snapshot)
#   2. crates/fhe-params/src/constants.rs (ciphernode parameters)
#   3. circuits/lib/src/configs/{insecure,secure}/threshold.nr (circuit parameters)
#   4. circuits/lib/src/configs/committee/active.nr (Noir-side active committee)
#   5. packages/interfold-contracts/scripts/utils.ts (deployment hashes and committee values)
#   6. crates/committee/src/lib.rs (committee enum values)
#   7. packages/interfold-contracts/contracts/lib/BfvProtocol.sol
#
# `circuits/bin/.active-preset.json` is only a local hydrated cache. It can point at Sepolia's
# fast insecure-minimum artifacts while the checked-in production config points at secure-small.
#
# A drift between any two means the next `pnpm build:circuits` would silently produce
# verifiers / proofs against the wrong committee. Run from .husky/pre-push (or CI).
#
# Exit 0 on consistency, 1 on drift.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ACTIVE_NR="circuits/lib/src/configs/committee/active.nr"
STAMP="circuits/bin/.active-preset.json"
UTILS_TS="packages/interfold-contracts/scripts/utils.ts"
PROTOCOL_CONSTANTS_TS="packages/interfold-contracts/scripts/protocol/constants.ts"
CRYPTO_CONFIG_JSON="packages/interfold-contracts/crypto-config.json"
FHE_CONSTANTS_RS="crates/fhe-params/src/constants.rs"
COMMITTEE_RS="crates/committee/src/lib.rs"
PROTOCOL_SOL="packages/interfold-contracts/contracts/lib/BfvProtocol.sol"
TASKS_TS="packages/interfold-contracts/tasks/interfold.ts"
SDK_UTILS_TS="packages/interfold-sdk/src/utils.ts"
EVM_HELPERS_RS="crates/evm-helpers/src/contracts.rs"
RAN_STAMP_CHECK=false
RAN_PARITY_CHECK=false

fail() {
  echo "❌ check:committee: $*" >&2
  exit 1
}

for required_file in \
  "$PROTOCOL_CONSTANTS_TS" \
  "$CRYPTO_CONFIG_JSON" \
  "$FHE_CONSTANTS_RS" \
  "$PROTOCOL_SOL" \
  "$TASKS_TS" \
  "$SDK_UTILS_TS" \
  "$EVM_HELPERS_RS"; do
  [[ -f "$required_file" ]] || fail "missing $required_file"
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

# 2. Read the selected committee's dimensions from the shared snapshot.
if [[ ! -f "$UTILS_TS" ]]; then
  fail "missing $UTILS_TS"
fi
UTILS_COMMITTEE=$(grep -E '^export const ACTIVE_BFV_COMMITTEE:' "$UTILS_TS" | sed -E 's/.*= "([a-z]+)";.*/\1/')
[[ "$UTILS_COMMITTEE" == "$ACTIVE_COMMITTEE" ]] || fail "$UTILS_TS selects committee=$UTILS_COMMITTEE, but $ACTIVE_NR selects $ACTIVE_COMMITTEE"
IFS=';' read -r UTILS_H UTILS_T < <(node --input-type=module - "$CRYPTO_CONFIG_JSON" "$UTILS_COMMITTEE" <<'NODE'
import { readFileSync } from 'node:fs';
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const committee = config.committees.find(committee => committee.name === process.argv[3]);
if (!committee) throw new Error(`Missing committee: ${process.argv[3]}`);
process.stdout.write(`${committee.h};${committee.t}\n`);
NODE
)
if [[ -z "${UTILS_H:-}" || -z "${UTILS_T:-}" ]]; then
  fail "could not parse BFV_DKG_H / BFV_THRESHOLD_T from $UTILS_TS"
fi

# 3. Read expected (H, T) from the active committee's leaf module; do not copy its numbers.
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
[[ -f "$PROTOCOL_SOL" ]] || fail "missing $PROTOCOL_SOL"
sol_u32() {
  local name="$1"
  grep -E "uint32 internal constant $name = [0-9]+" "$PROTOCOL_SOL" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1
}
sol_u8() {
  local name="$1"
  grep -E "uint8 internal constant $name = [0-9]+" "$PROTOCOL_SOL" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1
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
    fail "drift: $PROTOCOL_SOL ${prefix} has (size=$sol_size, N=$sol_n, T=$sol_t, H=$sol_h), expected (size=$size, N=$noir_n, T=$noir_t, H=$noir_h)"
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
if (variance < 16n) {
  process.stdout.write((2n * variance).toString());
  process.exit(0);
}
const value = 3n * variance;
if (value < 2n) {
  process.stdout.write(value.toString());
} else {
  let current = value;
  let next = (current + value / current) / 2n;
  while (next < current) {
    current = next;
    next = (current + value / current) / 2n;
  }
  process.stdout.write(current.toString());
}
' "$1"
}

check_bfv_preset() {
  local label="$1"
  local rust_name="$2"
  local noir_name="$3"
  local ts_values rust_block rust_threshold noir_file
  local ts_degree ts_plaintext ts_moduli ts_error
  local rust_degree rust_plaintext rust_moduli rust_error
  local noir_degree noir_plaintext noir_moduli noir_error_bound expected_error_bound
  local noir_q_mod_t noir_q_inverse_mod_t expected_q_mod_t expected_q_inverse_mod_t

  ts_values=$(node --input-type=module - "$CRYPTO_CONFIG_JSON" "$label" <<'NODE'
import { readFileSync } from 'node:fs';
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const preset = config.bfv.presets.find(preset => preset.preset === process.argv[3]);
if (!preset) throw new Error(`Missing BFV preset: ${process.argv[3]}`);
const p = preset.threshold;
process.stdout.write([p.degree, p.plaintextModulus, p.moduli.map(value => `0x${BigInt(value).toString(16)}`).join(','), p.error1Variance].join(';'));
NODE
  )
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

  [[ -n "$ts_values" && -n "$rust_threshold" && -f "$noir_file" ]] \
    || fail "could not read the ${label} BFV parameter sources"

  IFS=';' read -r ts_degree ts_plaintext ts_moduli ts_error <<< "$ts_values"

  rust_degree=$(grep -E '^[[:space:]]*pub const DEGREE: usize = [0-9]+;' <<< "$rust_block" | sed -E 's/.*= ([0-9]+);/\1/' | head -n1)
  rust_plaintext=$(grep -E 'PLAINTEXT_MODULUS: u64 = [0-9]+;' <<< "$rust_threshold" | sed -E 's/.*= ([0-9]+);/\1/')
  rust_moduli=$(grep -oE '0x[0-9a-fA-F]+' <<< "$rust_threshold" | tr '[:upper:]' '[:lower:]' | paste -sd, -)
  rust_error=$(grep -E 'ERROR1_VARIANCE: &str = "[0-9]+";' <<< "$rust_threshold" | sed -E 's/.*"([0-9]+)".*/\1/')

  if [[ "$ts_degree" != "$rust_degree" || "$ts_plaintext" != "$rust_plaintext" || \
        "$(hex_csv_to_decimal "$ts_moduli")" != "$(hex_csv_to_decimal "$rust_moduli")" || "$ts_error" != "$rust_error" ]]; then
    fail "drift: ${label} BFV parameters differ between $CRYPTO_CONFIG_JSON and $FHE_CONSTANTS_RS"
  fi

  noir_degree=$(grep -E '^pub global N: u32 = [0-9]+;' "$noir_file" | sed -E 's/.*= ([0-9]+);/\1/')
  noir_plaintext=$(grep -E '^pub global PLAINTEXT_MODULUS: Field = [0-9]+;' "$noir_file" | sed -E 's/.*= ([0-9]+);/\1/')
  noir_moduli=$(grep -E '^pub global QIS:' "$noir_file" | sed -E 's/.*= \[([^]]+)\];/\1/' | tr -d ' ')
  noir_error_bound=$(grep -E '^pub global PK_GENERATION_B_ENC: Field = [0-9]+;' "$noir_file" | sed -E 's/.*= ([0-9]+);/\1/')
  noir_q_mod_t=$(grep -E '^pub global Q_MOD_T: Field = [0-9]+;' "$noir_file" | sed -E 's/.*= ([0-9]+);/\1/')
  noir_q_inverse_mod_t=$(grep -E '^pub global Q_INVERSE_MOD_T: Field = [0-9]+;' "$noir_file" | sed -E 's/.*= ([0-9]+);/\1/')
  expected_error_bound=$(error_bound_for_variance "$ts_error")

  if [[ "$ts_degree" != "$noir_degree" || "$ts_plaintext" != "$noir_plaintext" || \
        "$(hex_csv_to_decimal "$ts_moduli")" != "$noir_moduli" || \
        "$expected_error_bound" != "$noir_error_bound" ]]; then
    fail "drift: ${label} BFV parameters differ between $CRYPTO_CONFIG_JSON and $noir_file"
  fi

  # C7 decoding uses the inverse of the product of the threshold CRT primes modulo t.
  IFS=, read -r expected_q_mod_t expected_q_inverse_mod_t < <(node -e '
const moduli = process.argv[1].split(",").map(BigInt);
const t = BigInt(process.argv[2]);
const qModT = moduli.reduce((product, modulus) => product * modulus, 1n) % t;
let [a, b, x, y] = [qModT, t, 1n, 0n];
while (b !== 0n) {
  const quotient = a / b;
  [a, b] = [b, a - quotient * b];
  [x, y] = [y, x - quotient * y];
}
if (a !== 1n) process.exit(1);
process.stdout.write(`${qModT},${(x % t + t) % t}\n`);
' "$noir_moduli" "$noir_plaintext")
  if [[ "$noir_q_mod_t" != "$expected_q_mod_t" || "$noir_q_inverse_mod_t" != "$expected_q_inverse_mod_t" ]]; then
    fail "drift: ${label} C7 Q_MOD_T/Q_INVERSE_MOD_T in $noir_file must be $expected_q_mod_t/$expected_q_inverse_mod_t"
  fi
}

check_bfv_preset insecure-64 insecure_64 insecure
check_bfv_preset secure-8192 secure_8192 secure

# 6. Every chain-supported route in utils.ts must match the Noir committee shape and the
#    parameter/configuration hashes in BfvProtocol.sol. Keep this check
#    dependency-free because Repository Checks runs it before Node dependencies are installed.
sol_bytes32() {
  local name="$1"
  grep -A1 -E "bytes32 internal constant $name" "$PROTOCOL_SOL" \
    | grep -oE '0x[0-9a-fA-F]+' \
    | head -n1
}

for prefix_and_preset in INSECURE:insecure-64 SECURE:secure-8192; do
  prefix="${prefix_and_preset%%:*}"
  preset="${prefix_and_preset#*:}"
  IFS=';' read -r utils_param_hash utils_config_id < <(node --input-type=module - "$CRYPTO_CONFIG_JSON" "$preset" <<'NODE'
import { readFileSync } from 'node:fs';
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const preset = config.bfv.presets.find(preset => preset.preset === process.argv[3]);
if (!preset) throw new Error(`Missing preset: ${process.argv[3]}`);
process.stdout.write(`${preset.parameterHash};${preset.cryptoConfigId}\n`);
NODE
  )
  sol_param_hash=$(sol_bytes32 "${prefix}_PARAM_SET_HASH")
  sol_config_id=$(sol_bytes32 "${prefix}_CONFIG_ID")
  if [[ "$utils_param_hash" != "$sol_param_hash" || "$utils_config_id" != "$sol_config_id" ]]; then
    fail "drift: $UTILS_TS ${prefix} hashes do not match $PROTOCOL_SOL"
  fi
done

binding_config_id() {
  node --input-type=module - "$CRYPTO_CONFIG_JSON" "$1" <<'NODE'
import { readFileSync } from 'node:fs';
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const preset = config.bfv.presets.find(preset => preset.paramSet === Number(process.argv[3]));
if (!preset) throw new Error(`Unsupported BFV parameter set: ${process.argv[3]}`);
process.stdout.write(preset.cryptoConfigId);
NODE
}

node --input-type=module - "$TASKS_TS" "$SDK_UTILS_TS" "$UTILS_TS" "$EVM_HELPERS_RS" <<'NODE'
import { readFileSync } from 'node:fs';
for (const [index, file] of process.argv.slice(2, 4).entries()) {
  const source = readFileSync(file, 'utf8');
  const imported = /import\s*\{[^}]*\bbfvPresetForParamSet\b[^}]*\}\s*from\s*["']([^"']+)["']/.exec(source);
  const expected = index === 0 ? '../bfv.js' : '@interfold/contracts/bfv';
  if (imported?.[1] !== expected) {
    throw new Error(`${file} must import the shared BFV preset lookup`);
  }
  if (/0x[0-9a-fA-F]{64}/.test(source)) {
    throw new Error(`${file} contains an independent configuration-ID literal`);
  }
}
const utils = readFileSync(process.argv[4], 'utf8');
for (const imported of ['BFV_PRESETS', 'COMMITTEES']) {
  if (!new RegExp(`import\\s*\\{[^}]*\\b${imported}\\b[^}]*\\}\\s*from\\s*["']\\.\\./bfv\\.js["']`).test(utils)) {
    throw new Error(`Deployment utils must import ${imported} from the shared binding`);
  }
}
for (const [name, field] of [['BFV_DKG_H', 'h'], ['BFV_THRESHOLD_T', 't'], ['ACTIVE_BFV_PARAM_SET', 'paramSet'], ['ACTIVE_BFV_COMMITTEE_SIZE', 'committeeSize'], ['ACTIVE_BFV_COMMITTEE_N', 'n']]) {
  if (!new RegExp(`export const ${name} = ACTIVE_BFV_CONFIG\\.${field};`).test(utils)) {
    throw new Error(`${name} must follow the selected shared configuration`);
  }
}
if (/0x[0-9a-fA-F]{64}/.test(utils)) throw new Error('Deployment utils contain an independent protocol hash');
const projection = /function bfvConfig\([\s\S]*?^}/m.exec(utils)?.[0] ?? '';
for (const expected of [
  'const parameters = BFV_PRESETS[preset]', 'const members = COMMITTEES[committee]',
  'paramSet: parameters.paramSet', 'paramSetHash: parameters.paramSetHash', 'configId: parameters.configId',
  'committeeSize: members.committeeSize', 'h: members.h', 't: members.t', 'n: members.n',
]) {
  if (!projection.includes(expected)) throw new Error(`Deployment configuration must use ${expected}`);
}
const rust = readFileSync(process.argv[5], 'utf8');
if (/0x[0-9a-fA-F]{64}/.test(rust) || !rust.includes('BfvPreset::from_on_chain_param_set(param_set)') || !rust.includes('current_bfv_crypto_config_id(&encode_bfv_params(&threshold))')) {
  throw new Error('EVM request helpers must derive configuration IDs from the BFV owner');
}
NODE

for prefix_and_param_set in INSECURE:0 SECURE:2; do
  prefix="${prefix_and_param_set%%:*}"
  param_set="${prefix_and_param_set##*:}"
  expected_id=$(sol_bytes32 "${prefix}_CONFIG_ID")
  binding_id=$(binding_config_id "$param_set")
  if [[ "$binding_id" != "$expected_id" ]]; then
    fail "drift: paramSet=${param_set} config ID must match $PROTOCOL_SOL in shared bindings"
  fi
done

check_utils_route() {
  local symbol="$1"
  local preset="$2"
  local committee="$3"
  local block expected_call
  block=$(sed -n "/^export const ${symbol}_BFV_CONFIG:/,/^);/p" "$UTILS_TS")
  [[ -n "$block" ]] || fail "missing ${symbol}_BFV_CONFIG in $UTILS_TS"
  expected_call="exportconst${symbol}_BFV_CONFIG:ActiveBfvConfig=bfvConfig(\"$preset\",\"$committee\");"
  if [[ "$(tr -d '[:space:]' <<< "$block" | sed 's/,);/);/')" != "$expected_call" ]]; then
    fail "drift: ${symbol}_BFV_CONFIG must select $preset/$committee from the shared binding"
  fi
}

check_utils_route INSECURE_MINIMUM insecure-64 minimum
check_utils_route INSECURE_MICRO insecure-64 micro
check_utils_route INSECURE_SMALL insecure-64 small
check_utils_route SECURE_MINIMUM secure-8192 minimum
check_utils_route SECURE_MICRO secure-8192 micro
check_utils_route SECURE_SMALL secure-8192 small

route_list() {
  local array_name="$1"
  sed -n "/^export const ${array_name}:.*= \[/,/^\] as const;/p" "$UTILS_TS" \
    | grep -oE '(INSECURE|SECURE)_(MINIMUM|MICRO|SMALL)_BFV_CONFIG' \
    | paste -sd, -
}

TESTNET_ROUTES=$(route_list TESTNET_BFV_CONFIGS)
EXPECTED_TESTNET_ROUTES="INSECURE_MINIMUM_BFV_CONFIG,INSECURE_MICRO_BFV_CONFIG,INSECURE_SMALL_BFV_CONFIG,SECURE_MINIMUM_BFV_CONFIG,SECURE_MICRO_BFV_CONFIG,SECURE_SMALL_BFV_CONFIG"
[[ "$TESTNET_ROUTES" == "$EXPECTED_TESTNET_ROUTES" ]] \
  || fail "$UTILS_TS testnet routes must contain the exact six-pair matrix; got $TESTNET_ROUTES"

MAINNET_ROUTES=$(route_list MAINNET_BFV_CONFIGS)
EXPECTED_MAINNET_ROUTES="SECURE_SMALL_BFV_CONFIG,SECURE_MICRO_BFV_CONFIG,SECURE_MINIMUM_BFV_CONFIG"
[[ "$MAINNET_ROUTES" == "$EXPECTED_MAINNET_ROUTES" ]] \
  || fail "$UTILS_TS mainnet routes must be secure-only small, micro, minimum; got $MAINNET_ROUTES"

# 7. Optional local-cache note (when circuits have been built locally).
if [[ -f "$STAMP" ]]; then
  # A stamp without a committee field cannot identify the artifact pair.
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

# 9. The Rust build owner renders and formats a temporary library copy, without swapping live files.
if command -v nargo >/dev/null 2>&1; then
  pnpm --silent build:circuits check --committee all || fail "generated committee configuration differs from the Rust build owner"
  RAN_PARITY_CHECK=true
else
  echo "  (skipping generated committee check: nargo not found.)" >&2
fi

echo "✓ check:committee: BFV tuples, configuration IDs, all six routes, and local $ACTIVE_COMMITTEE (H=$EXPECTED_H, T=$EXPECTED_T) are consistent across TypeScript, Rust, Noir, and Solidity$([ "$RAN_STAMP_CHECK" = true ] && echo ', .active-preset.json')$([ "$RAN_PARITY_CHECK" = true ] && echo ', parity_*.nr')"
