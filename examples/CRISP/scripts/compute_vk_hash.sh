#!/usr/bin/env bash
# Fold public key_hash = compute_vk_hash(ude, crisp, ct0_vk_chain, ct1_vk_chain).
# Needs pnpm compile:circuits.
#
# Prints one hash per ballot stack. Each belongs in the matching fold circuit:
#   crisp         -> circuits/bin/fold/src/main.nr         CRISP_FOLD_EXPECTED_KEY_HASH_*
#   crisp_onchain -> circuits/bin/fold_onchain/src/main.nr CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_*
#
# The `crisp` hash changes whenever the crisp circuit changes, not only when a new stack is added.
#
# ct0 and ct1 are each a tree of chunk circuits, so the fold cannot anchor them with one key hash.
# The user_data_encryption wrapper outputs one VK chain per leg instead, and this script computes the
# same values:
#   manifest = compute_vk_hash(gamma, root, leaf, pk_ct, identity, eval_root, eval_leaf, eval_pk_ct)
#   chain    = compute_vk_hash(top_level, manifest)
# The order must match `compute_ude_vk_manifest` in
# circuits/lib/src/core/threshold/user_data_encryption_chunk.nr. Circuits that their parent verifies
# with ZK (leaves, pk/ct, and the ct0 top level that contains `k1`) use the `noir-recursive` hash.
# Every other circuit uses the `noir-recursive-no-zk` hash.
set -euo pipefail

CRISP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$CRISP/../.." && pwd)"
T="$REPO/circuits/bin/threshold/target"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

need() {
  for f in "$@"; do
    [[ -f "$f" ]] || { echo "missing $f (run pnpm compile:circuits in examples/CRISP)" >&2; exit 1; }
  done
}

vk_hash() {
  (cd "$REPO" && cargo run -q -p e3-zk-helpers --bin compute-vk-hash -- "$@")
}

# Write a 0x-prefixed field element as the 32-byte big-endian file compute-vk-hash reads.
to_file() {
  local hex="${1#0x}"
  printf '%064s' "$hex" | tr ' ' '0' | xxd -r -p >"$2"
}

# Print the VK chain for one leg (ct0 or ct1).
leg_chain() {
  local ct="$1"
  local manifest_files=(
    "$T/${ct}_chunk_gamma.vk_recursive_hash"
    "$T/${ct}_chunk_main_root.vk_recursive_hash"
    "$T/${ct}_chunk_main.vk_noir_hash"
    "$T/${ct}_pk_ct_commit.vk_noir_hash"
    "$T/${ct}_eval_chunk_identity.vk_recursive_hash"
    "$T/${ct}_eval_chunk_main_root.vk_recursive_hash"
    "$T/${ct}_eval_chunk_main.vk_noir_hash"
    "$T/${ct}_eval_pk_ct.vk_noir_hash"
  )
  local top_hash="$T/user_data_encryption_${ct}.vk_recursive_hash"
  if [[ "$ct" == "ct0" ]]; then
    top_hash="$T/user_data_encryption_${ct}.vk_noir_hash"
  fi
  need "${manifest_files[@]}" "$top_hash"
  local manifest_hash
  manifest_hash="$(vk_hash "${manifest_files[@]}")" || return 1
  to_file "$manifest_hash" "$TMP/${ct}_manifest"
  vk_hash "$top_hash" "$TMP/${ct}_manifest"
}

ct0_chain="$(leg_chain ct0)" || exit 1
ct1_chain="$(leg_chain ct1)" || exit 1
to_file "$ct0_chain" "$TMP/ct0_vk_chain"
to_file "$ct1_chain" "$TMP/ct1_vk_chain"

for name in crisp crisp_onchain; do
  VK=(
    "$T/user_data_encryption.vk_recursive_hash"
    "$CRISP/circuits/bin/${name}/target/${name}.vk_recursive_hash"
    "$TMP/ct0_vk_chain"
    "$TMP/ct1_vk_chain"
  )
  need "${VK[@]}"
  printf '%s: ' "$name"
  vk_hash "${VK[@]}"
done
