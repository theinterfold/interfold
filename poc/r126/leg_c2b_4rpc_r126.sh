#!/bin/bash
# r126 C2b (e_sm_share_computation) secure-8192/small 4c-pinned leg.
# Same protocol as leg_c2a_4rpc_r126.sh; leaf = e_sm_share_computation; artifact at
# workspace-root target dir.
set -uo pipefail
HERE=/home/dev/interfold-research/interfold/poc/r126
INTERFOLD=/home/dev/interfold-research/interfold
restore() {
  git -C "$INTERFOLD" checkout -- circuits/lib/src/configs/committee/active.nr circuits/lib/src/configs/default/mod.nr 2>/dev/null || true
}
trap restore EXIT
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
cd "$INTERFOLD" || { echo "FAIL cd"; exit 1; }
TS0=$(date +%s)
{ echo "= r126 c2b box census PRE $(date -u +%H:%M:%S) ="
  echo "nproc=$(nproc)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg
} > "$HERE/c2b_box_census_r126.txt" 2>&1
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
SHA_C_BEFORE=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_BEFORE=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
python3 - <<'PY' > "$HERE/c2b_flip_r126.txt" 2>&1
c='circuits/lib/src/configs/committee/active.nr'; s='circuits/lib/src/configs/default/mod.nr'
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert (a!=a2) and (b!=b2), 'flip failed (config already flipped or pattern missing)?'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small, insecure->secure')
PY
[ -f "$HERE/c2b_flip_r126.txt" ]
rm -f "$INTERFOLD/circuits/bin/dkg/target/e_sm_share_computation.json"
cd "$INTERFOLD/circuits/bin/dkg/e_sm_share_computation" || { echo "FAIL cd leaf"; exit 92; }
J_OUT="$HERE/c2b_j.out"; J_ERR="$HERE/c2b_j.err"
echo "R126-LEG C2b 4c-pinned nargo compile cwd=$(pwd) threads=4 cputaset=0-3" > "$HERE/c2b_leg_run.out"
{ taskset -c 0-3 /usr/bin/time -v nargo compile > "$J_OUT" 2> "$J_ERR"; } >> "$HERE/c2b_leg_run.out" 2>&1
RC=$?
cd "$INTERFOLD" || true
echo "R126-LEG C2b rc=$RC" >> "$HERE/c2b_leg_run.out"
grep -E 'Maximum resident set size|Elapsed \(wall clock|Percent of CPU|Exit status|Swaps|Major faults|Minor faults' "$J_ERR" > "$HERE/c2b_timev_r126.txt" 2>/dev/null || true
cat "$J_OUT" "$J_ERR" >> "$HERE/c2b_leg_run.out" 2>/dev/null || true
JN="$INTERFOLD/circuits/bin/dkg/target/e_sm_share_computation.json"
if [ -f "$JN" ]; then
  echo "R126-LEG C2b artifact: $(stat -c '%s %Y' "$JN")" >> "$HERE/c2b_leg_run.out"
  shasum -a 256 "$JN" 2>/dev/null | cut -c1-16 | xargs -I{} echo "R126-LEG C2b artifact sha16={}" >> "$HERE/c2b_leg_run.out"
  bbgates() { $HOME/.local/bin/bb gates -b "$JN" -t noir-recursive-no-zk > "$HERE/c2b_gates.json" 2>&1; return $?; }
  bbgates; echo "bb gates rc=$?" >> "$HERE/c2b_leg_run.out"
else
  echo "R126-LEG C2b NO artifact (OOM class)" >> "$HERE/c2b_leg_run.out"
fi
git checkout -- "$COMMITTEE" "$DEFAULTM"
SHA_C_AFTER=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_AFTER=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
PORC=$(git status --porcelain -- circuits/lib/src/configs/)
TS1=$(date +%s)
{ echo "R126-LEG c2b results:"
  echo "pre_c=$SHA_C_BEFORE post_c=$SHA_C_AFTER"
  echo "pre_d=$SHA_D_BEFORE post_d=$SHA_D_AFTER"
  echo "porcelain_configs=[$PORC]"
  echo "wall_s=$((TS1-TS0))"
  echo "compile_rc=$RC"
} > "$HERE/c2b_restore_r126.txt" 2>&1
journalctl --user --since "@$TS0" 2>/dev/null | grep -iE "killed|oom" | head -5 > "$HERE/c2b_journal_r126.txt" 2>&1 || true
{ echo "= r126 c2b box census POST $(date -u +%H:%M:%S) ="
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
} >> "$HERE/c2b_box_census_r126.txt" 2>&1
exit 0