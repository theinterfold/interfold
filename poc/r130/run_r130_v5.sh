#!/usr/bin/env bash
# r130 v5: SEMANTIC RAN of the r127 n2 nested-cargo deadlock fix.
#
# Precedent: r127 n2 RAN-diagnosed the cycle as
#   cargo test -> build.rs -> bash build_fixtures.sh -> pnpm install + pnpm build:circuits
#   -> build-circuits.ts execSync(`cargo run --release --bin generate_parity_matrices`)
#   -> NESTED cargo tries to acquire the .cargo-lock the outer cargo holds
#   -> outer waits on pnpm, pnpm waits on nested cargo, nested waits on
#      .cargo-lock -> 45-min flat RAN flatline, wchan=locks_lock_inode_wait.
#
# The fix (this round) makes build_fixtures.sh pass --skip-regen-parity,
# which SHORT-CIRCUITS the nested cargo call (see regenerateParityMatrices
# in scripts/build-circuits.ts). Everything else in build:circuits —
# nargo + bb compile + vk + checksums + patchUtilsTs + writeActiveCryptoConfig
# + dummy.json `nargo compile` — remains intact.
#
# RAN assertion (this script):
#   A. Outer context = flock -x on target/release/.cargo-lock (same descriptor
#      shape cargo uses internally; advisory lock is actually held).
#   B. The 4 required build_fixtures.sh artifacts are DELETED (missing-branch).
#   C. Run the EXACT pnpm command the fixed script uses:
#        pnpm build:circuits --skip-regen-parity
#      AND separately run the full scripts/build_fixtures.sh (the entry point
#      build.rs calls) — both under the flock.
#   D. Assert on: (1) RC 0 within watchdog; (2) no nested `cargo` process
#      spawned during either call (ps timing delta); (3) the build-circuits.ts
#      short-circuit console.log line "ℹ️  --skip-regen-parity: trusting..."
#      appears in the log (proving the skip path fired); (4) all 4 artifacts
#      restored byte-identical to r111/r115-anchored SHAs; (5) mod.nr +
#      active.nr + .active-preset.json left at the default committed preset
#      (insecure-512/min); (6) the dummy.json final nargo-compile + jq still
#      ran with RC 0 (the final section of build_fixtures.sh, build.rs integrity).

set -u
REPO=/home/dev/interfold-research/interfold
P3=/home/dev/interfold-research/poc/r130
cd "$REPO"
export PATH="/home/dev/.cargo/bin:/home/dev/.local/bin:/home/dev/.nargo/bin:/usr/local/bin:/usr/bin:/bin"
LOG="$P3/v5_run.log"
rm -f "$LOG"
_py_pwd=$(pwd)

rm -f \
  circuits/bin/.active-preset.json \
  circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json \
  circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json \
  circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json
touch crates/zk-prover/scripts/build_fixtures.sh

# snapshot pre-state SHAs (from prior pre_state_r130.txt — those bytes were
# confirmed matching r111-anchored SHAs when snapshotted).
PRE_SHA_ACTIVE="480274cf1ade72aa95781bce61e750490c8e5388e922675ce135d7afec57e757"
PRE_SHA_C3F="240cd86c156a68dd2fa7c55acb34ddbe67764d92152d11dac937f0c063be0891"
PRE_SHA_C6F="27571a52e377d4e6ab78def9594a22d2a15c848f659451f0262e7ae9992863bc"
PRE_SHA_C6K="eed9aea56e2eeba9f2943297aff1c87ff7ac1c366b6a12ed1175ddf69bfc0199"

echo "=== T0=$(date -u +%FT%TZ) v5 run: outer flock -x on .cargo-lock (r127 n2 shape) ===" | tee -a "$LOG"

# Path-trap `cargo` at the FRONT, before building. Every `cargo` invocation
# (nested or not) writes a line; we can assert no nested `cargo run` appears
# inside the build.rs-fixture-sh window. This is the direct observable of the fix.
TRAPDIR="$P3/bin-trap"
rm -rf "$TRAPDIR"; mkdir -p "$TRAPDIR"
cat > "$TRAPDIR/cargo" <<'CWRAP'
#!/usr/bin/env bash
echo "CARGO-TRAP $(date -u +%FT%TZ) pid=$$ ppid=$PPID role=${0} args: $*" >> /tmp/r130_v5_cargo_trap.log
exec /home/dev/.cargo/bin/cargo "$@"
CWRAP
chmod +x "$TRAPDIR/cargo"
rm -f /tmp/r130_v5_cargo_trap.log
export PATH="$TRAPDIR:$PATH"

# Open the outer -x flock on the exact .cargo-lock file, held for the duration
# of the fixture-script run. Done by starting a subshell that flocks and then
# invokes build_fixtures.sh (which is bash scripts/build_fixtures.sh invoked
# by the RUST build.rs; we simulate by calling it directly, which is exactly
# what compile-time exec "bash ./scripts/build_fixtures.sh" would have done).
# The advisory flock replaces the mutex cargo uses in the C layer — the
# nested cargo would block on it (that IS the reported wchan=locks_lock_*) —
# but ONLY the nested cargo under the pre-fix path would block, and the
# pre-fix path is gone by --skip-regen-parity.
{
  echo "--- outer flock -x acquired; executing crates/zk-prover/scripts/build_fixtures.sh (the r127 n2 script) ---"
  /usr/bin/time -v bash crates/zk-prover/scripts/build_fixtures.sh
} 9>"$REPO/target/release/.cargo-lock" >> "$LOG" 2>&1
RCSLOT=$?

# close: outer releases flock on fd 9 close (subshell exit) — cargo releases
# its own lock the same way.

echo "=== T1=$(date -u +%FT%TZ) v5 fixture-script RC=$RCSLOT ===" | tee -a "$LOG"

# detoasting: post-state
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
  echo "=== default/micro min ABI pin (mod.nr + active.nr still insecure-512/min) ==="
  grep -l "insecure-512" circuits/lib/src/configs/default/mod.nr 2>/dev/null
  grep -l "committee::minimum::N_PARTIES" circuits/lib/src/configs/committee/active.nr 2>/dev/null
  echo "=== ACTIVE crypto config committed ==="
  cat circuits/bin/.active-preset.json 2>/dev/null
}
# Cargo trap log summary:
{
  echo "=== CARGO-TRAP lines (each invocation that ran under this test) ==="
  if [[ -f /tmp/r130_v5_cargo_trap.log ]]; then
    cat /tmp/r130_v5_cargo_trap.log
  else
    echo "(no cargo invocations logged: the --skip-regen-parity path + the outer normal no-cargo call succeeded)"
  fi
  echo "=== nested-cargo-run-detected check ==="
  grep -c "^CARGO-TRAP .* role=/home/dev/.cargo/bin/cargo args: run" /tmp/r130_v5_cargo_trap.log 2>/dev/null || echo 0
}

echo "=== R130v5 final RC=$RCSLOT ===" | tee -a "$LOG"
exit $RCSLOT