#!/usr/bin/env bash
# r130: RAN verification of the build.rs<->build_fixtures.sh nested-cargo deadlock fix.
#
# Shape (matches r127 n2's RAN deadlock signature exactly):
#   outer `cargo build --release -p e3-zk-prover` holds target/release/.cargo-lock
#     -> build.rs runs crates/zk-prover/scripts/build_fixtures.sh
#        -> the 4 required artifacts are MISSING (deleted) -> pnpm branch enters
#           -> build:circuits must regenerate them WITHOUT a nested cargo call
#              (the --skip-regen-parity flag added this round)
#
# Success = cargo exits 0 within the watchdog window AND all 4 artifacts
# re-exist AND the 3 fold JSONs + .active-preset.json are byte-identical
# to their pre-delete SHAs (deterministic nargo/bb per the r111/r117 class).
#
# Watchdog: r127's hang was observed RAN at 45+ min with wchan=locks_lock_inode_wait.
# 40 min cap here is 3x the realistic build wall (r111's insecure-512/min nargo is ~3 min),
# so any stall will reliably trip the watchdog.
set -u
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"
REPO=/home/dev/interfold-research/interfold
P3=/home/dev/interfold-research/poc/r130
cd "$REPO"

echo "=== T0=$(date -u +%FT%TZ) RAN watchdog start ==="
(
  # watchdog background: kill after 40 min if the cargo process is still up
  ( sleep 2400 && pgrep -f "cargo build --release -p e3-zk-prover" 2>/dev/null && echo "WATCHDOG_TIMEOUT at $(date -u +%FT%TZ)" ) &
  WD=$!
  # foreground: the actual test
  /usr/bin/time -v cargo build --release -p e3-zk-prover 2>&1 | tee "$P3/r130_full.log"
  RC=${PIPESTATUS[0]}
  kill "$WD" 2>/dev/null; wait "$WD" 2>/dev/null
  echo "=== R130 cargo build RC=$RC ==="
  # post-state
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
  } > "$P3/post_state_r130.txt"
  echo "=== r130 marker done ==="
) > "$P3/watcher_full.log" 2>&1
echo "=== T_done=$(date -u +%FT%TZ) watcher exited ==="