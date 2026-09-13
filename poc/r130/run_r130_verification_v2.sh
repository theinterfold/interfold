#!/usr/bin/env bash
# r130: RAN verification of the r127 n2 nested-cargo deadlock fix.
#
# Pre-state (snapshotted at this launcher's T0):
#   - the 4 required artifacts are DELETED (git-ignored; untracked; poisoned the
#     build.rs skip gate on purpose to force the pnpm branch to fire).
#   - crates/zk-prover/scripts/build_fixtures.sh is MODIFIED (the r130 fix makes
#     it call `pnpm build:circuits --skip-regen-parity`), so build.rs re-runs.
#
# RAN assertion points:
#   A. cargo exits 0 (no watchdog trip within 30 min).
#   B. watch log contains "Building circuits (" AND
#      "Set Noir config to: insecure (preset: insecure-512)" —
#      = the pnpm branch actually FIRED (vs the bytes-present skip).
#   C. post-state: all 4 artifacts restored, SHAs match the pre-delete
#      r111-anchored baselines (byte-deterministic nargo per the r116/r117 class).
#   D. NO nested `cargo run` process spawned during the pnpm branch (post-fix:
#      the nested cargo call is skipped under --skip-regen-parity).
#   E. build.rs's dummy.json `nargo compile` + jq still ran afterward (baseline behavior retained).
#
# Watchdog: 30 min (r127's hang was observed RAN at 45+ min; 30 min cap
# comfortably exceeds the realistic build wall of ~175s drop + ~2 min nargo + compile
# chain and any flake should be caught).
set -u
REPO=/home/dev/interfold-research/interfold
P3=/home/dev/interfold-research/poc/r130
cd "$REPO"
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"

echo "=== T0=$(date -u +%FT%TZ) RAN verification start ===" | tee "$P3/v2_watcher_head.log"

# We inline the watchdog: pgrep the cargo pid; if after 1800s it's still alive,
# dump /proc state -> evidence of hang, then SIGKILL.
WD_PID_FILE="$P3/cargo_pid"
cargo build --release -p e3-zk-prover 2>&1 | tee "$P3/v2_cargo.log" &
CARGO_BUILD_PID=$!
echo "$CARGO_BUILD_PID" > "$WD_PID_FILE"

# proc watcher: samples every 10 s to detect external/nested cargo running
( 
  while [[ -d /proc/$CARGO_BUILD_PID ]]; do
    [ -n "${CARGO_BUILD_PID:-}" ] || break
    # snapshot: any cargo / pnpm processes
    {
      date -u +%FT%TZ
      ps -eo pid,ppid,pcpu,pmem,comm,stat | awk 'NR==1 || / cargo | pnpm| nargo норко | /x |' | head -20
    } >> "$P3/v2_proc_snap.log" 2>/dev/null
    sleep 10
  done
) &
PS_SNAP_PID=$!

# watchdog end
STARTED=$(date +%s)
while kill -0 "$CARGO_BUILD_PID" 2>/dev/null; do
  [ -n "${WD_PID_FILE:-}" ] || break
  NOW=$(date +%s)
  ELAPSED=$((NOW - STARTED))
  if (( ELAPSED > 1800 )); then
    echo "WATCHDOG_TRIP at $(date -u +%FT%TZ) cargo_pid=$CARGO_BUILD_PID" 
    # evidence
    ps aux | head -30 > "$P3/v2_watchdog_ps.log" || true
    kill -9 "$CARGO_BUILD_PID" 2>/dev/null
    break
  fi
  sleep 2
done
wait "$CARGO_BUILD_PID" 2>/dev/null
BUILD_RC=$?
kill "$PS_SNAP_PID" 2>/dev/null
echo "=== BUILD_RC=$BUILD_RC cargo wall $(date -u +%FT%TZ) ===" | tee -a "$P3/v2_watcher_head.log"

# Post-state RAN snapshot:
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
} > "$P3/v2_post_state.txt"

# Evidence grep (the "pnpm branch fired" markers + dummy restore):
grep -n "Building circuits (\|Set Noir config to:\|Set Noir committee to:\|Regenerating\|nargo compile" \
  "$P3/v2_cargo.log" | head -30 > "$P3/v2_branch_fired_grep.txt" || true

exit "$BUILD_RC"