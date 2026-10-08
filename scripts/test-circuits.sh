#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
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

(cd "$REPO_ROOT/circuits/lib" && nargo test)
(cd "$REPO_ROOT/circuits/bin/recursive_aggregation/decryption_aggregator" && nargo test)

# The config circuit re-derives the committed secure parameters and bounds for the committed
# committee. It runs before the loop below rewrites the committee selection.
(cd "$REPO_ROOT/circuits/bin/config" && nargo execute)

# The dkg_aggregator and node_fold tests read only H, N_PARTIES, and L_THRESHOLD, and the preset
# changes only L_THRESHOLD (insecure 2, secure 3). These pairs run each committee once and cover
# both values.
for pair in minimum:insecure micro:secure small:secure; do
  committee="${pair%%:*}"
  preset="${pair##*:}"
  sed -E \
    -e "s/committee: (minimum|micro|small)/committee: $committee/g" \
    -e "s/committee::(minimum|micro|small)/committee::$committee/g" \
    "$BACKUP_DIR/active.nr" > "$ACTIVE_COMMITTEE"

  preset_name="${preset}-512"
  if [[ "$preset" == "secure" ]]; then
    preset_name="secure-8192"
  fi
  sed -E \
    -e "s/preset: (insecure-512|secure-8192)/preset: $preset_name/g" \
    -e "s/super::(insecure|secure)::/super::$preset::/g" \
    "$BACKUP_DIR/default.nr" > "$ACTIVE_PRESET"
  echo "Testing DKG aggregation for $preset_name/$committee"
  (cd "$REPO_ROOT/circuits/bin/recursive_aggregation/dkg_aggregator" && nargo test)
  # node_fold's recipient-key constraints are indexed by N_PARTIES and L_THRESHOLD, the same
  # values these pairs cover.
  (cd "$REPO_ROOT/circuits/bin/recursive_aggregation/node_fold" && nargo test)
done

echo "Noir circuits tested successfully"
