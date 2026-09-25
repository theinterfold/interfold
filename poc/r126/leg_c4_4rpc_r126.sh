#!/bin/bash
# r126 C4 (share_decryption) secure-8192/small 4c-PINNED COMPILE-to-completion leg.
#
# Premise: r125's C4 leg at 8c full-parallel OOM-killed at 30.81 GiB peak on the
# 32 GiB box (kernel SIGKILL, artifact absent). r102's 2-pt RAN-anchored linear-in-gates
# model predicts C4 small@4c = 12.82 GiB from (r101 min@4c 4.17 GiB @1.746M g) +
# (r83 micro@4c 7.36 GiB @2.418M g). This leg RAN-runs the 4c-pinned corner to verify
# the SPEC A (16 GiB @4c-pinned) card's C4 piece — the last missing RAN datum.
#
# Method = r100/r101-shape 4c-pinned single-process peak. Taskset -c 0-3 + RAYON_NUM_THREADS=4
# pins to the SPEC A card's 4c shape (not the 8c-parallel r125 shape). Config flip is
# self-restoring byte-exact (r121 recipe, git-checkout + porcelain assert + pre-leg sha).
# CANARY-R126-C4-LEG-4RPC-9F3D1.
set -uo pipefail
INTERFOLD=/home/dev/interfold-research/interfold
HERE="$INTERFOLD/poc/r126"
cd "$INTERFOLD" || { echo "LEG FAIL: cannot cd"; exit 1; }
TS0=$(date +%s)
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
J_OUT="$HERE/c4_4rpc_j.out"; J_ERR="$HERE/c4_4rpc_j.err"; J_RUN="$HERE/c4_4rpc_leg_run.out"
TIMEV="$HERE/c4_4rpc_timev.txt"; GATES="$HERE/c4_4rpc_gates.json"
SHA_C_BEFORE=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_BEFORE=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
{
  echo "= r126 c4 4c-pinned box census $(date -u +%H:%M:%S) ="
  echo "nproc=$(nproc)"
  echo "taskset_cpus=0-3 (4c)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg
} > "$HERE/c4_4rpc_box_census.txt" 2>&1
# config flip min->small + insecure->secure
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
JN="$INTERFOLD/circuits/bin/dkg/target/share_decryption.json"
rm -f "$JN" 2>/dev/null
cd "$INTERFOLD/circuits/bin/dkg/share_decryption" || { echo "LEG FAIL: cannot cd into C4 leaf"; exit 96; }
echo "R126-LEG C4 4c-pinned nargo compile cwd=$(pwd) threads=4 cputaset=0-3" > "$J_RUN"
# 4c-pinned: taskset pins the whole subprocess tree to CPUs 0-3; RAYON_NUM_THREADS pins
# nargo's internal rayon pool to 4 threads (matching taskset arity, zero oversubscription).
{ taskset -c 0-3 env RAYON_NUM_THREADS=4 RAYON_RS_NUM_CPUS=4 /usr/bin/time -v nargo compile > "$J_OUT" 2> "$J_ERR"; } >> "$J_RUN" 2>&1
RC=$?
cd "$INTERFOLD" || true
echo "R126-LEG C4 rc=$RC" >> "$J_RUN"
grep -E 'Maximum resident set size|Elapsed \(wall clock|User time|System time|Percent of CPU|Exit status|Swaps' "$J_ERR" > "$TIMEV" 2>/dev/null
cat "$J_OUT" "$J_ERR" >> "$J_RUN" 2>/dev/null
# artifact + gates
if [ -f "$JN" ]; then
  SZ=$(stat -c '%s' "$JN")
  MTIME_Y=$(stat -c '%Y' "$JN")
  SHA16=$(sha256sum "$JN" | cut -c1-16)
  echo "R126-LEG C4 artifact present: $SZ bytes mtime=$MTIME_Y sha16=$SHA16" >> "$J_RUN"
  bb gates -b "$JN" -t noir-recursive-no-zk > "$GATES" 2>&1
  echo "bb gates rc=$?" >> "$J_RUN"
else
  echo "R126-LEG C4 NO artifact on disk (possible OOM or compile error — see J_ERR)" >> "$J_RUN"
fi
# restore configs
git -C "$INTERFOLD" checkout -- "$COMMITTEE" "$DEFAULTM"
SHA_C_AFTER=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_AFTER=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
PORC=$(git -C "$INTERFOLD" status --porcelain -- circuits/lib/src/configs/)
TS1=$(date +%s)
{
  echo "R126-LEG c4 4c-pinned results:"
  echo "pre_c=$SHA_C_BEFORE post_c=$SHA_C_AFTER"
  echo "pre_d=$SHA_D_BEFORE post_d=$SHA_D_AFTER"
  echo "porcelain_configs=[$PORC]"
  echo "wall_s=$((TS1-TS0))"
  echo "compile_rc=$RC"
} > "$HERE/c4_4rpc_restore_r126.txt" 2>&1
if [ "$SHA_C_BEFORE" != "$SHA_C_AFTER" ] || [ "$SHA_D_BEFORE" != "$SHA_D_AFTER" ] || [ -n "$PORC" ]; then
  echo "R126-LEG RESTORE ASSERT FAILED (need in-round repair)" | tee -a "$J_RUN"; exit 95
fi
echo "R126-LEG config byte-restored ASSERTED (porcelain 0) wall=$((TS1-TS0))s" | tee -a "$J_RUN"
exit 0
