#!/usr/bin/env bash
# r130 v3: synchronous RAN verification of the r127 n2 nested-cargo deadlock fix.
# Sync (no internal backgrounding) so a one-shot runner keeps it alive. The
# 600-s foreground cap of the calling tool is the watchdog; a fresh-cargo hang
# (r127 RAN signature: 45+ min flat) cannot fit in 600 s and will be surfaced.
set -u
REPO=/home/dev/interfold-research/interfold
P3=/home/dev/interfold-research/poc/r130
cd "$REPO"
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"

echo "=== T0=$(date -u +%FT%TZ) v3 start ==="
/usr/bin/time -v cargo build --release -p e3-zk-prover 2> "$P3/v3_time.log" | tee "$P3/v3_cargo.log"
RC=${PIPESTATUS[0]}
echo "=== R130v3 cargo build RC=$RC  T1=$(date -u +%FT%TZ) ==="

{
  echo "=== POST-STATE (T1=$(date -u +%FT%TZ)) ==="
  for p in \
    circuits/bin/.active-preset.json \
    circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json \
    circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json \
    circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json; do
    if [[ -f "$REPO/$p" ]]; then
      sha=$(sha256sum "$REPO/$p" | awk '{print $1}')
      sz=$(stat -c '%s' "$REPO/$p")
      echo "$p | sha256=$sha | size=$sz"
    else
      echo "$p | ABSENT"
    fi
  done
} > "$P3/v3_post_state.txt"

# evidence: did the pnpm branch fire? (the "Building circuits" + "Set Noir config" lines
# are emitted ONLY when the missing-artifacts branch is taken)
grep -n "Building circuits (\|Set Noir config to:\|skip-regen-parity\|Building Noir circuits" \
  "$P3/v3_cargo.log" > "$P3/v3_branch_fired_grep.txt" 2>/dev/null || true
echo "DONE_RC=$RC"