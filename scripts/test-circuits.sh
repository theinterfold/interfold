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

for committee in minimum micro small; do
  sed -E \
    -e "s/committee: (minimum|micro|small)/committee: $committee/g" \
    -e "s/committee::(minimum|micro|small)/committee::$committee/g" \
    "$BACKUP_DIR/active.nr" > "$ACTIVE_COMMITTEE"

  for preset in insecure secure_8192; do
    preset_name="${preset//_/-}"
    sed -E \
      -e "s/preset: (insecure|secure-8192)/preset: $preset_name/g" \
      -e "s/super::(insecure|secure_8192)::/super::$preset::/g" \
      "$BACKUP_DIR/default.nr" > "$ACTIVE_PRESET"
    echo "Testing DKG aggregation for $preset_name/$committee"
    (cd "$REPO_ROOT/circuits/bin/recursive_aggregation/dkg_aggregator" && nargo test)
  done
done

echo "Noir circuits tested successfully"
