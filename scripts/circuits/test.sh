#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ACTIVE_COMMITTEE="$REPO_ROOT/circuits/lib/src/configs/committee/active.nr"
ACTIVE_PRESET="$REPO_ROOT/circuits/lib/src/configs/default/mod.nr"
BACKUP_DIR=$(mktemp -d)

restore_active_config() {
  cp "$BACKUP_DIR/active.nr" "$ACTIVE_COMMITTEE"
  cp "$BACKUP_DIR/default.nr" "$ACTIVE_PRESET"
  rm -rf "$BACKUP_DIR"
}

cp "$ACTIVE_COMMITTEE" "$BACKUP_DIR/active.nr"
cp "$ACTIVE_PRESET" "$BACKUP_DIR/default.nr"
trap restore_active_config EXIT

# Every binary package with Noir tests is listed below, in exactly one group. The check that
# follows fails when a package gains tests without being added, so no package is skipped silently.
ACTIVE_PACKAGES=(
  recursive_aggregation/decryption_aggregator
)
# These read the full preset (generated bounds, smudging and l-BFV row counts). The generated bounds
# belong to the committed committee, so they run on it, once for each l-BFV-capable preset.
LBFV_PACKAGES=(
  dkg/esm_share_computation_chunk
  recursive_aggregation/c3_fold_chunked
  recursive_aggregation/dkg_aggregator_v2
  recursive_aggregation/lbfv_aggregation_fold
  recursive_aggregation/lbfv_aggregation_fold_kernel
  recursive_aggregation/lbfv_generation_fold
  recursive_aggregation/lbfv_generation_fold_kernel
  recursive_aggregation/node_fold_chunked
  recursive_aggregation/node_fold_v2
  recursive_aggregation/nodes_fold_v2
  recursive_aggregation/nodes_fold_v2_kernel
)
# These read only H, N_PARTIES and L_THRESHOLD, and run on the committee matrix at the end.
MATRIX_PACKAGES=(
  recursive_aggregation/dkg_aggregator
  recursive_aggregation/node_fold
)

unlisted=$(cd "$REPO_ROOT/circuits/bin" && grep -rl --include='*.nr' '#\[test' . | sed 's|^\./||' | cut -d/ -f1,2 | sort -u |
  grep -vxF -f <(printf '%s\n' "${ACTIVE_PACKAGES[@]}" "${LBFV_PACKAGES[@]}" "${MATRIX_PACKAGES[@]}") || true)
if [ -n "$unlisted" ]; then
  echo "Packages with Noir tests that scripts/circuits/test.sh does not run:" >&2
  echo "$unlisted" >&2
  exit 1
fi

# select_preset PRESET: point the default config at one preset (insecure_64, insecure, secure_8192, secure_16384).
select_preset() {
  sed -E \
    -e "s/preset: (insecure-64|insecure-simd|insecure|secure-8192|secure-16384)/preset: ${1//_/-}/g" \
    -e "s/super::(insecure_64|insecure_simd|insecure|secure_8192|secure_16384)::/super::$1::/g" \
    "$BACKUP_DIR/default.nr" > "$ACTIVE_PRESET"
}

(cd "$REPO_ROOT/circuits/lib" && nargo test)
for package in "${ACTIVE_PACKAGES[@]}"; do
  (cd "$REPO_ROOT/circuits/bin/$package" && nargo test)
done
for preset in insecure secure_16384; do
  select_preset "$preset"
  echo "Testing the l-BFV packages for ${preset//_/-}"
  for package in "${LBFV_PACKAGES[@]}"; do
    (cd "$REPO_ROOT/circuits/bin/$package" && nargo test)
  done
done
cp "$BACKUP_DIR/default.nr" "$ACTIVE_PRESET"

# The config circuit re-derives the committed secure parameters and bounds for the committed
# committee. It runs before the loop below rewrites the committee selection.
(cd "$REPO_ROOT/circuits/bin/config" && nargo execute)

# These packages read H, N_PARTIES, and L_THRESHOLD. Cover each committee on both trBFV presets.
for committee in minimum micro small; do
  sed -E \
    -e "s/committee: (minimum|micro|small)/committee: $committee/g" \
    -e "s/committee::(minimum|micro|small)/committee::$committee/g" \
    "$BACKUP_DIR/active.nr" > "$ACTIVE_COMMITTEE"

  for preset in insecure_64 secure_8192; do
    select_preset "$preset"
    echo "Testing DKG aggregation for ${preset//_/-}/$committee"
    # node_fold's recipient-key constraints are indexed by N_PARTIES and L_THRESHOLD, the same
    # values these pairs cover.
    for package in "${MATRIX_PACKAGES[@]}"; do
      (cd "$REPO_ROOT/circuits/bin/$package" && nargo test)
    done
  done
done

echo "Noir circuits tested successfully"
