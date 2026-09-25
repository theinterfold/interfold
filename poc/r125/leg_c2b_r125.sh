#!/bin/bash
# r125 C2b (e_sm_share_computation) secure-8192/small COMPILE-to-completion leg
# on the re-provisioned 8c / 32 GiB box. Same protocol as r124's leg_c2a_r124.sh
# (single-proc time -v nargo compile in the leaf dir + byte-exact config self-restore).
#
# RAM risk (RAN class): C2b = 10.87M gates vs C2a's 9.42M (r124 RAN 29.47 GiB peak
# at 8c on this box). Linear scaling in gates => C2b ~34 GiB linear, which is above
# the ~31 GiB usable ceiling => OOM possible. If OOM-d, record the RAN OOM kill
# event (dmesg / journalctl OOM entry + failed RC) as the load-bearing datum for
# the spec-A/B owner decision (32 GiB box may not carry the full 3-leaf batch).
# If it completes, record the RAN peak + wall as the second RAN-anchored leaf under
# the batch card. CANARY-R125-C2B-LEG-3F81A.
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
  echo "= r125 c2b box census $(date -u +%H:%M:%S) ="
  echo "nproc=$(nproc)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  awk '/^btime/{print "btime", $2}' /proc/stat
  cat /proc/loadavg
} > "$HERE/c2b_box_census_r125.txt" 2>&1
# flip config min->small + insecure->secure
python3 -c "
c='$COMMITTEE'; s='$DEFAULTM'
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert 'committee::small' in a2, 'flip failed: committee'
assert 'super::secure::' in b2, 'flip failed: preset'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small insecure->secure')
" > "$HERE/c2b_flip_r125.txt" 2>&1 || { echo "FAIL config flip"; exit 94; }
J_OUT="$HERE/c2b_j.out"; J_ERR="$HERE/c2b_j.err"
# Wipe the prior build:circuits artifact (15:34 mtime) so post-leg mtime truly reflects this compile
rm -f "$INTERFOLD/circuits/bin/dkg/target/e_sm_share_computation.json"
cd "$INTERFOLD/circuits/bin/dkg/e_sm_share_computation" || { echo "FAIL cd leaf"; exit 96; }
echo "R125-LEG C2b nargo compile cwd=$(pwd)" > "$HERE/c2b_leg_run.out" 2>&1
{ /usr/bin/time -v nargo compile > "$J_OUT" 2> "$J_ERR"; } >> "$HERE/c2b_leg_run.out" 2>&1
RC=$?
cd "$INTERFOLD" || true
echo "R125-LEG C2b rc=$RC" >> "$HERE/c2b_leg_run.out"
grep -E 'Maximum resident set size|Elapsed \(wall clock|User time|System time|Percent of CPU|Exit status|Swaps' "$J_ERR" > "$HERE/c2b_timev_r125.txt" 2>/dev/null
cat "$J_OUT" "$J_ERR" >> "$HERE/c2b_leg_run.out" 2>/dev/null || true
# artifact + sha (workspace-root target, where nargo writes per package)
JN="$INTERFOLD/circuits/bin/dkg/target/e_sm_share_computation.json"
if [ -f "$JN" ]; then
  echo "R125-LEG C2b artifact present: $(stat -c '%s %Y' "$JN")" >> "$HERE/c2b_leg_run.out"
  bbgates() { $HOME/.local/bin/bb gates -b "$JN" -t noir-recursive-no-zk > "$HERE/c2b_gates_r125.json" 2>&1; return $?; }
  bbgates; echo "bb gates rc=$?" >> "$HERE/c2b_leg_run.out"
else
  echo "R125-LEG C2b NO artifact on disk (OOM-kill class expected)" >> "$HERE/c2b_leg_run.out"
fi
# restore configs
git checkout -- "$COMMITTEE" "$DEFAULTM"
SHA_C_AFTER=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_AFTER=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
PORC=$(git status --porcelain -- circuits/lib/src/configs/)
TS1=$(date +%s)
{
  echo "R125-LEG c2b results:"
  echo "pre_c=$SHA_C_BEFORE post_c=$SHA_C_AFTER"
  echo "pre_d=$SHA_D_BEFORE post_d=$SHA_D_AFTER"
  echo "porcelain_configs=[$PORC]"
  echo "wall_s=$((TS1-TS0))"
  echo "compile_rc=$RC"
} > "$HERE/c2b_restore_r125.txt" 2>&1
# Record any OOM kill event for the RAN OOM-class datum (rc != 0 signal)
if [ -d /dev/kmsg ] 2>/dev/null; then
  dmesg 2>/dev/null | grep -i "oom\|killed process" | tail -5 > "$HERE/c2b_dmesg_tail_r125.txt" 2>&1 || true
fi
journalctl --user --since "@$((TS0))" 2>/dev/null | grep -iE "oom|killed" | head -5 > "$HERE/c2b_journal_r125.txt" 2>&1 || true
{
  echo "= r125 c2b box census POST $(date -u +%H:%M:%S) ="
  grep -E 'MemTotal|MemAvailable|SwapTotal|Committed_AS|CommitLimit' /proc/meminfo
} >> "$HERE/c2b_box_census_r125.txt" 2>&1
exit 0