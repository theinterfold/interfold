#!/usr/bin/env bash
# Round 117 - REGENERATE the C6 leaf (threshold/share_decryption) VK artifact set
# from the I14-patched share_decryption.json, per the CANONICAL build recipe
# (scripts/build-circuits.ts, base DKG/threshold branch): evm + noir-recursive-no-zk
# + noir-recursive VKs, each `bb write_vk -b <json> -o <targetDir> -t <target>`,
# then copy the transient <targetDir>/vk + /vk_hash onto the named
# <packageName>.vk* files and delete the transients (runWriteVk semantics).
#
# WHY: r115 (commit 678d0fd4) recompiled the C6 leaf .json in-place (nargo
# compile) WITHOUT re-running VK derivation, leaving share_decryption.json
# (2026-09-06 21:33) paired with six pre-patch VK artifacts (2026-09-02 19:50)
# => incoherent on-disk artifact tree; the proof-level fold-chain e2e
# (c6_fold_sequential_proves_and_verifies) RED-lit on it. Regenerating the VK
# set makes the tree coherent. target/ is gitignored build output: this script
# changes NO tracked file; it is the repair + the re-runnable recipe.
#
# Gate before running: configs must be at min/min (the on-disk
# share_decryption.json is the insecure-512/min post-patch artifact).
set -euo pipefail
export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
cd "$(dirname "$0")/../.."
T="circuits/bin/threshold/target"
J="$T/share_decryption.json"
P="share_decryption"

for f in circuits/lib/src/configs/committee/active.nr circuits/lib/src/configs/default/mod.nr; do
  if ! git diff --quiet -- "$f"; then echo "REFUSING: $f is modified (want min/min)"; exit 1; fi
done

for tgt in evm noir-recursive-no-zk noir-recursive; do
  case "$tgt" in
    evm) named="$P.vk" nhash="$P.vk_hash" ;;
    noir-recursive-no-zk) named="$P.vk_recursive" nhash="$P.vk_recursive_hash" ;;
    noir-recursive) named="$P.vk_noir" nhash="$P.vk_noir_hash" ;;
  esac
  echo "-> bb write_vk -t $tgt"
  bb write_vk -b "$J" -o "$T" -t "$tgt"
  cp "$T/vk" "$T/$named"
  cp "$T/vk_hash" "$T/$nhash"
  rm -f "$T/vk" "$T/vk_hash"
done

echo "regenerated VK set:"
python3 - <<'PY'
import os, time
for f in sorted(os.listdir("circuits/bin/threshold/target")):
    if f.startswith("share_decryption"):
        st = os.stat("circuits/bin/threshold/target/" + f)
        print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime)), f"{st.st_size:>8} B", f)
PY
echo "OK -- C6 leaf VK artifacts now derive from the I14-patched json (coherent tree)"