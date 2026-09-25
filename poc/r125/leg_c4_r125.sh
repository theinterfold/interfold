#!/bin/bash
# r125 C4 (share_decryption) secure-8192/small COMPILE-to-completion leg on the
# re-provisioned 8c / 32 GiB box. Same protocol as leg_c2b_r125.sh (single-proc
# time -v nargo compile in the leaf dir + byte-exact config self-restore).
#
# RAM read (RAN class, low): C4 = 3.57M gates vs C2a 9.42M (r124 RAN 29.47 GiB peak
# on this box). Linear in gates => C4 ~11-13 GiB expected; comfortably under the
# ~31 GiB usable ceiling. Failure is the exceptional case. If it completes, record
# RAN peak + wall as the third RAN-anchored leaf under the batch card.
# CANARY-R125-C4-LEG-90C2E.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r125
INTERFOLD=/home/dev/interfold-research/interfold
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
cd "$INTERFOLD" || { echo "FAIL cd"; exit 1; }
TS0=$(date +%s)
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
SHA_C_BEFORE=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_BEFORE=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
{
  echo "= r125 c4 box census $(date -u +%H:%M:%S) ="
  echo "nproc=$(nproc)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg
} > "$HERE/c4_box_census_r125.txt" 2>&1
# flip config min->small + insecure->secure (same mechanism as c2b leg)
python3 -c "
c='$COMMITTEE'; s='$DEFAULTM'
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert 'committee::small' in a2, 'flip failed: committee'
assert 'super::secure::' in b2, 'flip failed: preset'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small insecure->secure')
" > "$HERE/c4_flip_r125.txt" 2>&1 || { echo "FAIL config flip"; exit 94; }
J_OUT="$HERE/c4_j.out"; J_ERR="$HERE/c4_j.err"
# Wipe the prior build:circuits so post-leg mtime truly reflects this compile
rm -f "$INTERFOLD/circuits/bin/dkg/target/share_decryption.json"
cd "$INTERFOLD/circuits/bin/dkg" || { echo "FAIL cd leaf"; exit 96; }
python3 -c "
import os
d='share_decryption'
assert os.path.isdir(d), 'leaf dir missing'
print('leaf ok', d)
" || { echo "FAIL leaf check"; exit 97; }
echo "R125-LEG C4 nargo compile cwd=$(pwd)" > "$HERE/c4_leg_run.out" 2>&1
{ /usr/bin/time -v nargo compile > "$J_OUT" 2> "$J_ERR"; } >> "$HERE/c4_leg_run.out" 2>&1
RC=$?
cd "$INTERFOLD" || true
echo "R125-LEG C4 rc=$RC" >> "$HERE/c4_leg_run.out"
grep -E 'Maximum resident set size|Elapsed \(wall clock|User time|System time|Percent of CPU|Exit status|Swaps' "$J_ERR" > "$HERE/c4_timev_r125.txt" 2>/dev/null
cat "$J_OUT" "$J_ERR" >> "$HERE/c4_leg_run.out" 2>/dev/null || true
# artifact + sha (workspace-root target, where nargo writes per package)
JN="$INTERFOLD/circuits/bin/dkg/target/share_decryption.json"
if [ -f "$JN" ]; then
  echo "R125-LEG C4 artifact present: $(stat -c '%s %Y' "$JN")" >> "$HERE/c4_leg_run.out"
  $HOME/.local/bin/bb gates -b "$JN" -t noir-recursive-no-zk > "$HERE/c4_gates_r125.json" 2>&1
  echo "bb gates rc=$?" >> "$HERE/c4_leg_run.out"
else
  echo "R125-LEG C4 NO artifact on disk" >> "$HERE/c4_leg_run.out"
fi
# restore configs
git checkout -- "$COMMITTEE" "$DEFAULTM"
SHA_C_AFTER=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_AFTER=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
PORC=$(git status --porcelain -- circuits/lib/src/configs/)
TS1=$(date +%s)
{
  echo "R125-LEG c4 results:"
  echo "pre_c=$SHA_C_BEFORE post_c=$SHA_C_AFTER"
  echo "pre_d=$SHA_D_BEFORE post_d=$SHA_D_AFTER"
  echo "porcelain_configs=[$PORC]"
  echo "wall_s=$((TS1-TS0))"
  echo "compile_rc=$RC"
} > "$HERE/c4_restore_r125.txt" 2>&1
{
  echo "= r125 c4 box census POST $(date -u +%H:%M:%S) ="
  grep -E 'MemTotal|MemAvailable|SwapTotal|Committed_AS|CommitLimit' /proc/meminfo
} >> "$HERE/c4_box_census_r125.txt" 2>&1
exit 0