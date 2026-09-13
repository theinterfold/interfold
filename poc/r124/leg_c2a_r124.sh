#!/bin/bash
# r124 C2a (transition key-material leaf, the box-2 binding-constraint / highest-RAM
# heavy small-leaf) secure-8192/small COMPILE-to-completion leg on the re-provisioned
# 8c / 32 GiB box.
#
# Why this is the leg: r45 RAN-compiled C2a small-secure on an 8c box at 15.1 GiB
# high-water but it OOM'd at 15:35 CPU (the box CommitLimit was only 11.88 GiB) so it
# NEVER produced a final artifact -- hence C2a small-secure json is absent on-disk while
# its two siblings (C2b e_sm + C4) completed. This is the box-2 32 GiB card's
# binding-constraint leaf; completing it here RAN-anchors what every prior round only
# had DRAFT (r96 DRAFT-1 knife-edge 15.43 / r102 2-pt 4c RAN-anchored small@4c 12.01)
# or an OOM-killed 8c partial (r45 15.1 GiB).
#
# Method = the RAN single-process peak the app boxes always used: `time -v nargo compile`
# in the C2a package dir (compiles C2a + lib + bb_proof_verification git dep). Peak RSS
# ("Maximum resident set size") is the load-bearing number (matches r45/r99/r100/r101/r121).
# Config flip is self-restoring byte-exact (r121 recipe, git-checkout restore + porcelain
# assert + pre-leg sha). Lossy-transport-safe: the C2a dir/name are resolved at runtime
# via python, never typed as a literal (r92 protocol).
#
# CANARY-R124-C2A-LEG-9D4E7 (transport integrity marker).
set -uo pipefail

INTERFOLD=/home/dev/interfold-research/interfold
HERE="$INTERFOLD/poc/r124"
cd "$INTERFOLD" || { echo "LEG FAIL: cannot cd"; exit 1; }

TS0=$(date +%s)
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"

# Resolve the C2a package dir + name WITHOUT typing the (display-redacted) literal.
C2A_DIR=$(python3 -c "import os; d='circuits/bin/dkg'; p=[x for x in os.listdir(d) if x.startswith('sk_') and x not in ('share_encryption','share_decryption')][0]; print(d+'/'+p)")
C2A_NAME=$(basename "$C2A_DIR")
echo "R124-LEG C2a dir resolved: ${C2A_DIR}"
echo "R124-LEG starting $(date -u '+%Y-%m-%dT%H:%M:%SZ') epoch=$TS0"

COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
LEG_OUT="$HERE/c2a_leg_run.out"
TIMEV=$HERE/c2a_timev_r124.txt
GATES="$HERE/c2a_gates_r124.json"

# Pre-leg sha of the two config files (restore assert).
SHA_C_BEFORE=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_BEFORE=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)

# Box census (this leg).
{ echo "= r124 box census $(date -u +%H:%M:%S) ="; nproc; grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo; awk '/^btime/{print "btime",$2}' /proc/stat; cat /proc/loadavg; } > "$HERE/c2a_box_census_r124.txt" 2>&1

# ---- config flip (r121): committee min->small, preset insecure->secure ----
python3 - "$COMMITTEE" "$DEFAULTM" <<'PY' || { echo "LEG FAIL: config flip"; exit 94; }
import sys
c,s=sys.argv[1],sys.argv[2]
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert 'committee::small' in a2, 'committee did not flip to small'
assert 'super::secure::' in b2, 'preset did not flip to secure'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped: committee=small preset=secure')
PY

# ---- the measured compile (nargo must run INSIDE the C2a package dir) ----
J_OUT="$HERE/c2a_leg_j.out"; J_ERR="$HERE/c2a_leg_j.err"
rm -f "$INTERFOLD/$C2A_DIR/target/$C2A_NAME.json" 2>/dev/null
cd "$INTERFOLD/$C2A_DIR" || { echo "LEG FAIL: cannot cd into $C2A_DIR"; exit 96; }
echo "R124-LEG nargo compile cwd=$(pwd)"
{ /usr/bin/time -v nargo compile > "$J_OUT" 2> "$J_ERR"; } > /dev/null 2>&1
RC=$?
cd "$INTERFOLD" || true
# Consolidate record (nargo stdout+stderr + time -v).
cat "$J_OUT" "$J_ERR" > "$LEG_OUT" 2>/dev/null
grep -E 'Maximum resident set size|Elapsed \(wall clock|User time|System time|Percentage of CPU|Exit status' "$J_ERR" > "$TIMEV" 2>/dev/null
echo "R124-LEG nargo compile rc=$RC"
echo "==== time -v ===="; cat "$TIMEV"

if [ "$RC" -ne 0 ] || [ ! -f "$INTERFOLD/$C2A_DIR/target/$C2A_NAME.json" ]; then
  echo "R124-LEG nargo compile FAILED or no artifact (rc=$RC)"; 
fi

# ---- gates + sha of the fresh artifact (if present) ----
JN="$INTERFOLD/$C2A_DIR/target/$C2A_NAME.json"
if [ -f "$JN" ]; then
  SHA_NEW=$(sha256sum "$JN" | cut -c1-16)
  echo "R124-LEG C2a small-secure json sha16: $SHA_NEW"
  bb gates -b "$JN" -t noir-recursive-no-zk > "$GATES" 2>&1
  echo "R124-LEG bb gates rc=$? (raw in $GATES)"
else
  echo "R124-LEG NO C2a artifact; skipping gates+sha"
fi

# ---- byte-exact restore (git) + assert ----
git checkout -- "$COMMITTEE" "$DEFAULTM" || git -C "$INTERFOLD" checkout -- circuits/lib/src/configs/committee/active.nr circuits/lib/src/configs/default/mod.nr
SHA_C_AFTER=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_AFTER=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
PORC=$(git status --porcelain -- circuits/lib/src/configs/)
TS1=$(date +%s)
{
  echo "RESTORE pre_c=$SHA_C_BEFORE"
  echo "RESTORE post_c=$SHA_C_AFTER"
  echo "RESTORE pre_d=$SHA_D_BEFORE"
  echo "RESTORE post_d=$SHA_D_AFTER"
  echo "RESTORE porcelain_configs=[$PORC]"
  echo "wall_s=$((TS1-TS0))"
} > "$HERE/c2a_restore_r124.txt" 2>&1
if [ "$SHA_C_BEFORE" != "$SHA_C_AFTER" ] || [ "$SHA_D_BEFORE" != "$SHA_D_AFTER" ] || [ -n "$PORC" ]; then
  echo "R124-LEG RESTORE ASSERT FAILED (need in-round repair)"; exit 95
fi
echo "R124-LEG config byte-restored ASSERTED (porcelain 0) wall=$((TS1-TS0))s"
exit 0