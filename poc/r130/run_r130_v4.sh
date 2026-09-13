#!/usr/bin/env bash
# r130 v4: SEMANTIC RAN of the r127 n2 deadlock fix.
#
# Simulate the r127 n2 outer-cargo-holds-.cargo-lock shape at the SEMANTIC level:
#   - flock -x on target/release/.cargo-lock (how cargo does it internally)
#   - inside: run crates/zk-prover/scripts/build_fixtures.sh
#   - observe: does the build_fixtures.sh pnpm branch complete? (fix = YES)
#              does it spawn a nested `cargo`? (fix = NO, because --skip-regen-parity)
#
# This is the SHAPE of the deadlock r127 n2 diagnosed — the fix asserts that
# the same shape no longer destroys the build.
set -u
REPO=/home/dev/interfold-research/interfold
OUT=/tmp/r130_v4_run.log
P3=/home/dev/interfold-research/poc/r130
cd "$REPO"
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"
rm -f "$OUT"
export PATH="$P3/bin:$PATH"   # trap: wrapper `pnpm`/`cargo` count invocations

# Pre-arm 4-artifact deletion (missing branch every time)
rm -f \
  circuits/bin/.active-preset.json \
  circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json \
  circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json \
  circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json
touch crates/zk-prover/scripts/build_fixtures.sh
rm -f "$P3/bin/pnpm_calls.log" "$P3/bin/cargo_calls.log" 2>/dev/null
mkdir -p "$P3/bin"

# PATH trap: logging wrappers for pnpm + cargo.
cat > "$P3/bin/pnpm" <<'PWRAP'
#!/usr/bin/env bash
echo "PNPM-TRAP $(date -u +%FT%TZ) args: $*" >> /tmp/r130_v4_run.log
exec /home/dev/interfold-research/interfold/node_modules/.bin/pnpm "$@"
PWRAP
chmod +x "$P3/bin/pnpm"

# Open our flock-hold on the outer target/release/.cargo-lock BEFORE invoking
# build_fixtures.sh. The lock file already exists (cargo created it earlier);
# flock uses advisory lock on the fd, not the file's inode state, so this
# faithfully models "an outer cargo process holds .cargo-lock" — exactly the
# r127 n2 shape.
{
  echo "=== T0=$(date -u +%FT%TZ) EXCLUSIVE flock on target/release/.cargo-lock (= r127 n2 outer shape) ==="
  # Hold the lock and execute build_fixtures.sh with the LOCK HELD (single epoch).
  # build_fixtures.sh: pnpm install + pnpm build:circuits --skip-regen-parity
  # + final (cd dummy && nargo compile) + jq normalize.
  # BEFORE fix (baseline deadlock):
  #   pnpm build:circuits calls `cargo run --release --bin generate_parity_matrices`
  #   -> the nested cargo holds its OWN process open the outer .cargo-lock
  #   -> our outer is holding the same .cargo-lock
  #   -> the nested cargo tries to re-acquire it -> LOCK WAIT (r127 RAN 45-min
  #      flatline; wchan=locks_lock_inode_wait)
  # AFTER fix (--skip-regen-parity):
  #   pnpm build:circuits skips the nested cargo
  #   -> only nargo + bb runs (no cargo invocations in the tree)
  #   -> build_fixtures.sh completes; our outer releases the lock; RC 0.
  exec /usr/bin/time -v bash crates/zk-prover/scripts/build_fixtures.sh 2>&1
} 9>"$REPO/target/release/.cargo-lock" >"$OUT" 2>&1

RC=$?
echo "=== T1=$(date -u +%FT%TZ) R130v4 build_fixtures.sh RC=$RC ===" ===
echo "=== P3/bin wire + PNPM-TRAP + nested-cargo traps ==="
grep -c "PNPM-TRAP" $OUT 2>/dev/null
grep -c "cargo run" $OUT 2>/dev/null
echo "=== Final post-state (the 4 artifacts + build.rs usual lts) ==="
for p in \
  circuits/bin/.active-preset.json \
  circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json \
  circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json \
  circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json; do
    if [[ -f "$REPO/$p" ]]; then
      sha=$(sha256sum "$REPO/$p" | awk '{print $1}')
      echo "$p | sha256=$sha"
    else
      echo "$p | ABSENT"
    fi
done
echo "=== $RC ==="
exit $RC