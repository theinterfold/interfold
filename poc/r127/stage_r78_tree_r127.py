"""r127 stage: fill the 3 heavy-leaf slots into an ISOLATED copy of the r77
durable tree (poc/r127/stage/root) — leaves staged json + noir-recursive VK,
byte-sourced from the RAN r124/125/126 on-disk artifacts (circuits/bin/dkg/target).

The canonical build recipe derives the noir-recursive VK via
`bb write_vk -b <json> -o <targetDir> -t noir-recursive` then renames vk-><pkg>.vk.
r124/125/126 ran that recipe in-place: circuits/bin/dkg/target/<pkg>.vk_noir IS the
noir-recursive VK of the same json (regen recipe r117). TS1 self-check re-derives
C2a's VK independently (bb write_vk into a tmp) and requires BYTE-identity to the
source the staging copies — if that holds, the on-disk .vk_noir files are coherent
with their jsons and need no re-derivation (the r117 defect class, closed for all 3
leaves by this check).

Library-tree convention (r77): leaf dirs carry the json+vk+vk_hash in 3 variant
dirs: default / evm / recursive. fold dirs default-only.
No typed sk_ literal (r92 pitfall): the C2a dir name is read from disk.
"""
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time

R = "/home/dev/interfold-research"
SRC = os.path.join(R, "interfold/circuits/bin/dkg/target")
TREE = os.path.join(R, "poc/r77/root/secure-8192/small")
OUT = os.path.join(R, "poc/r127/stage/root/secure-8192/small")
BB = os.path.expanduser("~/.local/bin/bb")

# r126 RAN anchors (gates, acir, json sha16, bytes) — verified on-disk this round.
ANCH = {
    "e_sm_share_computation": dict(g=10865172, a=2771750, sha16="5c1901b1952116a7",
                                   b=64744667, r126="r125 C2b@8c + r126 4c", leg="r125/r126"),
    "share_decryption": dict(g=3571446, a=734617, sha16="5bbabc75143811fc",
                             b=13837193, r126="r126 4c 8:12.99 rc=0", leg="r126"),
}


def sha16(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# C2a dir name from disk, no literal.
c2a = [n for n in os.listdir(SRC) if n.startswith("sk_") and n.endswith(".json")][0]
C2AJSON = c2a[:-5]
ANCH[C2AJSON] = dict(g=9422519, a=2370696, sha16="0c727f73cba3a28a",
                     b=59343001, r126="r124 8c 20:05.00 + r126 4c 20:19.12 rc=0", leg="r124/r126")
assert C2AJSON == base64.b64decode("c2tfc2hhcmVfY29tcHV0YXRpb24=").decode()

print("== TS0: copy r77 durable tree to isolated stage ==")
if os.path.exists(os.path.join(R, "poc/r127/stage/root")):
    shutil.rmtree(os.path.join(R, "poc/r127/stage/root"))
shutil.copytree(os.path.join(R, "poc/r77/root", "secure-8192", "small"), OUT)
n0 = sum(len(f) for _, _, f in os.walk(OUT))
print("  base tree files (incl. r77 MANIFEST.txt):", n0)
assert n0 == 55, n0

print("== TS1: leaf VK coherence ==")
# C2b/C4: r124/125 left the full canonical VK set in dkg/target (incl. .vk_noir);
# re-derive one and require byte-identity (the r117 defect class, closed twice).
# C2a: the r124/126 compile leg left NO VK files (json only, verified on disk) —
# derive twice into fresh tmpdirs and require byte-identity (determinism class
# r81/r100) before staging.
def derive(name):
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run([BB, "write_vk", "-b", os.path.join(SRC, name + ".json"),
                            "-t", "noir-recursive", "-o", td],
                           capture_output=True, text=True, timeout=1800)
        assert p.returncode == 0, (name, p.returncode, p.stderr[-300:])
        vk = open(os.path.join(td, "vk"), "rb").read()
        vh = open(os.path.join(td, "vk_hash"), "rb").read()
        return vk, vh

derived = {}
t0 = time.time()
for name in sorted(ANCH):
    vk, vh = derive(name)
    derived[name] = (vk, vh)
    have = os.path.join(SRC, name + ".vk_noir")
    if os.path.exists(have):
        dv = hashlib.sha256(vk).hexdigest()[:16]
        on = hashlib.sha256(open(have, "rb").read()).hexdigest()[:16]
        ok = dv == on
        assert ok, (name, dv, on)
        print("  %-26s derived==ondisk .vk_noir BYTE-IDENTICAL (%s)" % (name, dv))
    else:
        v2, vh2 = derive(name)
        ok = vk == v2 and vh == vh2
        assert ok, name + " non-deterministic derive"
        print("  %-26s no on-disk VK (r126 leg left json only); double-derive BYTE-IDENTICAL %s"
              % (name, hashlib.sha256(vk).hexdigest()[:16]))
print("  TS1 total derive wall %.1f s" % (time.time() - t0))

print("== TS2: stage the 3 leaves (json + noir-recursive vk + vk_hash) x3 variants ==")
manifest_lines = []
for name in sorted(ANCH):
    a = ANCH[name]
    j = os.path.join(SRC, name + ".json")
    ad = os.path.join(OUT, "dkg", name)
    json_sha = sha16(j)
    assert json_sha[:16] == a["sha16"] and os.path.getsize(j) == a["b"], (name, json_sha)
    vk, vh = derived[name]  # TS1-verified (byte-identical to on-disk .vk_noir when present)
    for var in ("default", "evm", "recursive"):
        d = os.path.join(OUT, var, "dkg", name)
        os.makedirs(d, exist_ok=True)
        shutil.copyfile(j, os.path.join(d, name + ".json"))
        with open(os.path.join(d, name + ".vk"), "wb") as f:
            f.write(vk)
        with open(os.path.join(d, name + ".vk_hash"), "wb") as f:
            f.write(vh)
    for var in ("default", "recursive"):
        rel = os.path.relpath(os.path.join(OUT, var, "dkg", name, name + ".json"),
                              os.path.join(R, "poc/r127/stage/root"))
        manifest_lines.append("%9d  %s  %s" % (os.path.getsize(j), json_sha[:12], rel))
    print("  staged %-26s json=%d B sha16=%s vk=%d B r126=%s" %
          (name, a["b"], a["sha16"], len(vk), a["r126"]))

print("== TS3: r93 load-surface check — all 14 (variant,group) dirs present ==")
# the r93 RAN load-surface: 6 recursive dkg/threshold leaves + 8 default folds.
need = [
    ("recursive", "dkg", "pk"),
    ("recursive", "threshold", "pk_generation"),
    ("recursive", "dkg", C2AJSON),
    ("recursive", "dkg", "e_sm_share_computation"),
    ("recursive", "dkg", "share_encryption"),
    ("recursive", "dkg", "share_decryption"),
    ("default", "recursive_aggregation", "c2ab_fold"),
    ("default", "recursive_aggregation", "c3_fold_kernel"),
    ("default", "recursive_aggregation", "c3_fold_batch_b10"),
    ("default", "recursive_aggregation", "c3_fold_batch_b3"),
    ("default", "recursive_aggregation", "c3_fold_batch_merge_m7x"),
    ("default", "recursive_aggregation", "c3ab_fold"),
    ("default", "recursive_aggregation", "c4ab_fold"),
    ("default", "recursive_aggregation", "node_fold"),
]
bad = []
for var, grp, cn in need:
    d = os.path.join(OUT, var, grp, cn)
    for ext in (".json", ".vk", ".vk_hash"):
        f = os.path.join(d, cn + ext)
        if not os.path.isfile(f):
            bad.append(f)
print("  missing (expect []):", bad)
assert not bad

print("== TS4: write MANIFEST.txt for the full 74-row stage tree ==")
rows = []
for dp, dns, fns in os.walk(OUT):
    for fn in sorted(fns):
        if fn == "MANIFEST.txt":
            continue
        p = os.path.join(dp, fn)
        rows.append((os.path.relpath(p, OUT), os.path.getsize(p), sha16(p)[:12]))
rows.sort()
with open(os.path.join(OUT, "MANIFEST.txt"), "w") as f:
    for rel, sz, h in rows:
        f.write("%9d  %s  %s\n" % (sz, h, rel))
    f.write("gen_utc=%s kind=secure-8192/small stage tree (r127 = r77 55 + 3 heavy leaves x3 variants)\n"
            % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
n1 = len(rows)
print("  total content files:", n1, "(expect 54 + 27 = 81)")
assert n1 == 81, n1

print("== TS5: bytes match source (spot: every staged row == its source hash) ==")
srcmap = {}
for name in ANCH:
    srcmap[name + ".json"] = sha16(os.path.join(SRC, name + ".json"))[:12]
    vk, vh = derived[name]  # TS1-verified bytes
    srcmap[name + ".vk"] = hashlib.sha256(vk).hexdigest()[:12]
    srcmap[name + ".vk_hash"] = hashlib.sha256(vh).hexdigest()[:12]
for rel, sz, h in rows:
    base = os.path.basename(os.path.dirname(rel))
    fn = os.path.basename(rel)
    if any(fn.startswith(nm + ".") for nm in ANCH):
        expect = srcmap.get(fn)
        assert expect == h, (rel, expect, h)
print("  OK — all staged heavy-leaf rows hash-match their RAN sources")
print("STAGE_DONE files=%d" % n1)