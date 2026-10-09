#!/usr/bin/env bash
# Fold public key_hash = compute_vk_hash(ude, crisp, ct0, ct1). Needs pnpm compile:circuits.
#
# Prints one hash per ballot stack. Each belongs in the matching fold circuit:
#   crisp         -> circuits/bin/fold/src/main.nr         CRISP_FOLD_EXPECTED_KEY_HASH_*
#   crisp_onchain -> circuits/bin/fold_onchain/src/main.nr CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_*
#
# The `crisp` hash changes whenever the crisp circuit changes, not only when a new stack is added.
set -euo pipefail

CRISP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$CRISP/../.." && pwd)"
T="$REPO/circuits/bin/threshold/target"

for name in crisp crisp_onchain; do
  VK=(
    "$T/user_data_encryption.vk_recursive_hash"
    "$CRISP/circuits/bin/${name}/target/${name}.vk_recursive_hash"
    "$T/user_data_encryption_ct0.vk_recursive_hash"
    "$T/user_data_encryption_ct1.vk_recursive_hash"
  )
  for f in "${VK[@]}"; do
    [[ -f "$f" ]] || { echo "missing $f (run pnpm compile:circuits in examples/CRISP)" >&2; exit 1; }
  done
  printf '%s: ' "$name"
  (cd "$REPO" && cargo run --quiet --locked --release -p e3-zk-helpers --bin zk-cli -- vk-hash "${VK[@]}")
done
