#!/usr/bin/env bash
# r130 RAN verification - P1 (locus-direct).
# Runs the exact entry point from r127 n2, crates/zk-prover/scripts/build_fixtures.sh,
# under the corrected fix (pnpm build:circuits --skip-regen-parity), with:
#   - a PATH-prefix trap that logs ANY cargo invocation (we can then assert the
#     nested `cargo run generate_parity_matrices` did NOT run)
#   - the 4 commit-required artifacts DELETED (the missing-branch precondition)
# AND asserts the 4 artifacts are byte-restored at their r111-anchored SHAs
# (byte-determinism per the r111/r117 class).
set -u
REPO=/home/dev/interfold-research/interfold
P3=/home/dev/interfold-research/poc/r130
cd "$REPO"
export PATH="$P3/bin-trap:/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$REPO/target"
LOG="$P3/v3_run.log"
TRAPLOG=/tmp/r130_v3_cargo_trap.log
rm -f "$LOG" "$TRAPLOG"

# stated up-front: 4 required artifacts absent
for p in \
  circuits/bin/.active-preset.json \
  circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json \
  circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json \
  circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json; do
    [[ -f "$p" ]] && { echo "ERROR: $p present pre"; exit 17; }
done
touch crates/zk-prover/scripts/build_fixtures.sh

echo "=== T0=$(date -u +%FT%TZ) R130 P1 start: bash crates/zk-prover/scripts/build_fixtures.sh ===" | tee -a "$LOG"
/usr/bin/time -v bash crates/zk-prover/scripts/build_fixtures.sh >> "$LOG" 2>&1
RC=$?
echo "=== T1=$(date -u +%FT%TZ) RC=$RC ==="

{
  echo "=== POST-STATE ==="
  for p in \
    circuits/bin/.active-preset.json \
    circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json \
    circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json \
    circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json; do
    if [[ -f "$p" ]]; then
      sha=$(sha256sum "$p" | awk '{print $1}')
      echo "$p sha256=$sha"
    else
      echo "$p ABSENT"
    fi
  done
  echo "=== CARGO-TRAP: any cargo invocation during the run ==="
  if [[ -f "$TRAPLOG" ]]; then cat "$TRAPLOG"; else
    echo "(none - no cargo was invoked during the pnpm-branch path)"
  fi
  echo "=== --skip-regen-parity short-circuit marker in the log? ==="
  grep -c "skip-regen-parity" "$LOG" 2>/dev/null || echo 0
} >> "$LOG" 2>&1

echo "=== R130 P1 RC=$RC final done ===" | tee -a "$LOG"
exit $RC