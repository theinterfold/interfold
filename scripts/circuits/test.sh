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
  chonk/c3_chonk_app_chunked
  lbfv/dkg/esm_share_computation_chunk
  lbfv/recursive_aggregation/dkg_aggregator_v2
  lbfv/recursive_aggregation/lbfv_aggregation_fold
  lbfv/recursive_aggregation/lbfv_aggregation_fold_kernel
  lbfv/recursive_aggregation/lbfv_generation_fold
  lbfv/recursive_aggregation/lbfv_generation_fold_kernel
  lbfv/recursive_aggregation/node_fold_chunked
  lbfv/recursive_aggregation/node_fold_v2
  lbfv/recursive_aggregation/nodes_fold_v2
  lbfv/recursive_aggregation/nodes_fold_v2_kernel
)
# These read only H, N_PARTIES and L_THRESHOLD, and run on the committee matrix at the end.
MATRIX_PACKAGES=(
  recursive_aggregation/dkg_aggregator
  recursive_aggregation/node_fold
)

unlisted=$(cd "$REPO_ROOT/circuits/bin" && grep -rl --include='*.nr' '#\[test' . | sed -E 's|^\./||; s|^((lbfv/)?[^/]+/[^/]+)/.*|\1|' | sort -u |
  grep -vxF -f <(printf '%s\n' "${ACTIVE_PACKAGES[@]}" "${LBFV_PACKAGES[@]}" "${MATRIX_PACKAGES[@]}") || true)
if [ -n "$unlisted" ]; then
  echo "Packages with Noir tests that scripts/circuits/test.sh does not run:" >&2
  echo "$unlisted" >&2
  exit 1
fi

# select_preset MODULE: point the default config at one preset module (insecure, insecure_lbfv,
# secure, secure_16384) and its artifact label.
select_preset() {
  local label
  case "$1" in
    insecure) label=insecure-64 ;;
    insecure_lbfv) label=insecure-lbfv ;;
    secure) label=secure-8192 ;;
    secure_16384) label=secure-16384 ;;
    *) echo "Unknown preset module: $1" >&2; exit 1 ;;
  esac
  sed -E \
    -e "s/preset: (insecure-64|insecure-lbfv|secure-8192|secure-16384)$/preset: $label/g" \
    -e "s/super::(insecure|insecure_lbfv|secure|secure_16384)::/super::$1::/g" \
    "$BACKUP_DIR/default.nr" > "$ACTIVE_PRESET"
}

(cd "$REPO_ROOT/circuits/lib" && nargo test)
for package in "${ACTIVE_PACKAGES[@]}"; do
  (cd "$REPO_ROOT/circuits/bin/$package" && nargo test)
done
for preset in insecure_lbfv secure_16384; do
  select_preset "$preset"
  echo "Testing the l-BFV packages for $preset"
  for package in "${LBFV_PACKAGES[@]}"; do
    (cd "$REPO_ROOT/circuits/bin/$package" && nargo test)
  done
done
cp "$BACKUP_DIR/default.nr" "$ACTIVE_PRESET"

# The config circuit re-derives the committed secure parameters and bounds for the committed
# committee. It runs before the loop below rewrites the committee selection.
(cd "$REPO_ROOT/circuits/bin/config" && nargo execute)

# The dkg_aggregator and node_fold tests read only H, N_PARTIES, and L_THRESHOLD. Both trBFV presets
# have L_THRESHOLD = 3. These pairs run each committee once and each trBFV preset at least once; the
# l-BFV presets run their own packages above.
for pair in minimum:insecure micro:secure small:secure large:insecure; do
  committee="${pair%%:*}"
  preset="${pair##*:}"
  sed -E \
    -e "s/committee: (minimum|micro|small|large)/committee: $committee/g" \
    -e "s/committee::(minimum|micro|small|large)/committee::$committee/g" \
    "$BACKUP_DIR/active.nr" > "$ACTIVE_COMMITTEE"

  select_preset "$preset"
  echo "Testing DKG aggregation for $preset/$committee"
  # node_fold's recipient-key constraints are indexed by N_PARTIES and L_THRESHOLD, the same
  # values these pairs cover.
  for package in "${MATRIX_PACKAGES[@]}"; do
    (cd "$REPO_ROOT/circuits/bin/$package" && nargo test)
  done
done

echo "Noir circuits tested successfully"
