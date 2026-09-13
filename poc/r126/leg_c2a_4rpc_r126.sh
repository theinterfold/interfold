#!/bin/bash
# r126 C2a (sk_ekd) secure-8192/small 4c-pinned leg (same protocol as leg_c4_4rpc_r126.sh:
# system time -v unbuffered single proc + byte-restore config + workspace-root artifacts).
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
{ echo "= r126 c2a box census PRE $(date -u +%H:%M:%S) ="
  echo "nproc=$(nproc)"
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
  cat /proc/loadavg
} > "$HERE/c2a_box_census_r126.txt" 2>&1
COMMITTEE=circuits/lib/src/configs/committee/active.nr
DEFAULTM=circuits/lib/src/configs/default/mod.nr
SHA_C_BEFORE=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_BEFORE=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
python3 - <<'PY' > "$HERE/c2a_flip_r126.txt" 2>&1
c='circuits/lib/src/configs/committee/active.nr'; s='circuits/lib/src/configs/default/mod.nr'
a=open(c).read(); b=open(s).read()
a2=a.replace('committee::minimum','committee::small')
b2=b.replace('super::insecure::','super::secure::')
assert (a!=a2) and (b!=b2), 'flip failed (config already flipped or pattern missing)?'
open(c,'w').write(a2); open(s,'w').write(b2)
print('config flipped min->small, insecure->secure')
PY
[ -f "$HERE/c2a_flip_r126.txt" ]
C2A_DIR=$(python3 -c "import os; d='circuits/bin/dkg'; p=[x for x in os.listdir(d) if x.startswith('sk_') and x not in ('share_encryption','share_decryption')][0]; print(d+'/'+p)")
C2A_NAME=$(basename "$C2A_DIR")
rm -f "$INTERFOLD/circuits/bin/dkg/target/${C2A_NAME}.json" 2>/dev/null
echo "C2a dir resolved: ${C2A_DIR}" >> "$HERE/c2a_flip_r126.txt"
cd "$INTERFOLD/$C2A_DIR" || { echo "FAIL cd leaf"; exit 92; }
echo "C2a leaf=${C2A_NAME} (nargo in LEAF dir per r124 protocol; artifact lands in workspace-root target/)" >> "$HERE/c2a_flip_r126.txt"
J_OUT="$HERE/c2a_j.out"; J_ERR="$HERE/c2a_j.err"
echo "R126-LEG C2a 4c-pinned nargo compile cwd=$(pwd) threads=4 cputaset=0-3" > "$HERE/c2a_leg_run.out"
{ taskset -c 0-3 /usr/bin/time -v nargo compile > "$J_OUT" 2> "$J_ERR"; } >> "$HERE/c2a_leg_run.out" 2>&1
RC=$?
cd "$INTERFOLD" || true
echo "R126-LEG C2a rc=$RC" >> "$HERE/c2a_leg_run.out"
grep -E 'Maximum resident set size|Elapsed \(wall clock|Percent of CPU|Exit status|Swaps|Major faults|Minor faults' "$J_ERR" > "$HERE/c2a_timev_r126.txt" 2>/dev/null || true
cat "$J_OUT" "$J_ERR" >> "$HERE/c2a_leg_run.out" 2>/dev/null || true
# r124/r125 correction: nargo run in the LEAF dir emits the JSON to the WORKSPACE
# ROOT target/ (circuits/bin/dkg/target/), named after the circuit. The leaf-level
# target/ it creates holds only .br.bin intermediates (r124 false-negative bug).
JN="$INTERFOLD/circuits/bin/dkg/target/${C2A_NAME}.json"
if [ -n "$JN" ] && [ -f "$JN" ]; then
  echo "R126-LEG C2a artifact: $(stat -c '%s %Y' "$JN")" >> "$HERE/c2a_leg_run.out"
  shasum -a 256 "$JN" 2>/dev/null | cut -c1-16 | xargs -I{} echo "R126-LEG C2a artifact sha16={}" >> "$HERE/c2a_leg_run.out"
  bbgates() { $HOME/.local/bin/bb gates -b "$JN" -t noir-recursive-no-zk > "$HERE/c2a_gates.json" 2>&1; return $?; }
  bbgates; echo "bb gates rc=$?" >> "$HERE/c2a_leg_run.out"
else
  echo "R126-LEG C2a NO artifact (OOM class)" >> "$HERE/c2a_leg_run.out"
fi
git checkout -- "$COMMITTEE" "$DEFAULTM"
SHA_C_AFTER=$(sha256sum "$COMMITTEE" | cut -d' ' -f1)
SHA_D_AFTER=$(sha256sum "$DEFAULTM" | cut -d' ' -f1)
PORC=$(git status --porcelain -- circuits/lib/src/configs/)
TS1=$(date +%s)
{ echo "R126-LEG c2a results:"
  echo "pre_c=$SHA_C_BEFORE post_c=$SHA_C_AFTER"
  echo "pre_d=$SHA_D_BEFORE post_d=$SHA_D_AFTER"
  echo "porcelain_configs=[$PORC]"
  echo "wall_s=$((TS1-TS0))"
  echo "compile_rc=$RC"
} > "$HERE/c2a_restore_r126.txt" 2>&1
journalctl --user --since "@$TS0" 2>/dev/null | grep -iE "killed|oom" | head -5 > "$HERE/c2a_journal_r126.txt" 2>&1 || true
{ echo "= r126 c2a box census POST $(date -u +%H:%M:%S) ="
  grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo
} >> "$HERE/c2a_box_census_r126.txt" 2>&1
exit 0