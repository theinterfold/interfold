#!/usr/bin/env bash
# r130 RAN proof: run the FIXED in-cargo chain (what build.rs does) under a live
# outer cargo-lock, with the 3 fold artifacts missing (lean-checkout shape).
# Pre: clean state (verified beforehand). Post: SHAs of the 4 artifacts must match
# /tmp/r130_artifacts_baseline.txt.
set -u
REPO=/home/dev/interfold-research/interfold
P3=/home/dev/interfold-research/poc/r130
LOG="$P3/leg_r130.out"
BASE_ART=/tmp/r130_artifacts_baseline.txt
cd "$REPO"

# build hook binary
gcc -static -o "$P3/fd9hold" "$P3/fd9hold.c" || { echo FAIL_FD9HOLD; exit 90; }
echo "[0] fd9hold built"

# 1) rm the required artifacts (lean-checkout missing branch)
for p in \
  circuits/bin/.active-preset.json \
  circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json \
  circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json \
  circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json; do
  rm -f "$REPO/$p"
done
echo "[1] required 4 artifacts deleted (lean-checkout shape)"

# 2) start the nominal lock holder on target/release/.cargo-lock
"$P3/fd9hold" &
HOLD=$!
sleep 0.5
ps -p $HOLD >/dev/null && echo "[2] fd9hold pid=$HOLD (flock holder, replaces outer cargo)"

# 3) run the entry point build.rs calls
T0=$(date '+%s.%N')
timeout 1800 bash crates/zk-prover/scripts/build_fixtures.sh >"$LOG" 2>&1
RC=$?
T1=$(date '+%s.%N')
DT=$(echo "$T1 $T0" | awk '{printf "%.2f", $1-$2}')
echo "[3] build_fixtures.sh RC=$RC wall=${DT}s (had hung before fix ~45min+ in r127)"
kill $HOLD 2>/dev/null
wait $HOLD 2>/dev/null

# 4) post-state
echo "[4] post-state:"
for p in \
  circuits/bin/.active-preset.json \
  circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json \
  circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json \
  circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json; do
  if [[ -f "$REPO/$p" ]]; then
    sha=$(sha256sum "$REPO/$p" | awk '{print $1}')
    orig=$(grep "$p" "$BASE_ART" 2>/dev/null | awk '{print $1}')
    if [[ -n "$orig" && "$sha" == "$orig" ]]; then
      echo "  MATCH  $p"
    elif [[ -n "$orig" ]]; then
      echo "  DRIFT  $p sha=$sha (was $orig)"
    else
      echo "  NEW    $p sha=$sha"
    fi
  else
    echo "  ABSENT $p"
  fi
done

# 5) nested-cargo call detection: the pre-fix shape would call
# `cargo run generate_parity_matrices` from inside build:circuits; the fix
# short-circuits before that. Grep the log for the regen line: before the fix
# the log would show cargo invocations; with the fix we expect the
# skip-regen-parity short-circuit console.log to appear.
if grep -q "skip-regen-parity" "$LOG"; then
  echo "[5] FIX-ENGAGED: build:circuits took the --skip-regen-parity path"
else
  echo "[5] FIX-NOT-ENGAGED: no skip-regen-parity marker in log"
fi
# Also: did build:circuits print a regen line (which would imply it tried cargo)?
if grep -qE "Regenerated parity|cargo run --release --bin generate_parity_matrices" "$LOG"; then
  echo "[5b] WARNING: log shows parity regen activity (pre-fix shape!)"
else
  echo "[5b] no parity-regen activity in log (as expected with skip)"
fi
tail -30 "$LOG" | tee "$P3/leg_r130_last30.txt"
exit $RC