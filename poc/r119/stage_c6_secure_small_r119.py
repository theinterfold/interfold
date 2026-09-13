#!/usr/bin/env python3
"""Round 119 - compile + stage the C6 (threshold/share_decryption) leaf and the
c6_fold / c6_fold_kernel folds at the PRODUCTION field (secure-8192/small,
N=19/T=9/H=10, L=3) into a self-contained stage tree which the r119 proof-level
soundness test reads from.

WHY (the gap this fills): r117 RAN the C6 fold-chain soundness anchor ONLY at
InsecureThreshold512/Minimum (c6_fold_sequential_proves_and_verifies hard-codes
that preset/committee). r115's C6 I14 gate cut (commit 678d0fd4; -13.943 %
secure/small) + r117's C6 post-patch conformance both landed at the PRODUCTION
field. The C6 proof has only ever been COMPILED at secure/small (r115) and never
once PROVED-and-verified end-to-end there; and the C6 secure/small WITNESS layer
at T=9/L=3 (the r97 witness-risk class that was RAN for C1/C2/C4, NOT C6) had
never been RAN-exercised at the production committee. This round builds the
artifacts + runs the proof-level anchor at the production field.

Mechanism = the r115/r113/r117 self-restoring config swap. The 'threshold'
bin group has a SHARED workspace target dir (circuits/bin/threshold/target/ -
multiple circuits share it); the recursive_aggroup folds are per-package
targets. The on-disk MIN artifacts are snapshotted first and byte-restored
after (r117 pre-secure pattern; r115 restore-sha class) so the repo's target/
tree is byte-conserved through the round. RAM RAN-feasible: C6 2.56M g << the
C2a-micro 4.28M g class that peak-backed 7.09 GiB on this box (RAN r82); the
fold legs' 1.45M g class; each leg serial.

Command:
    python3 interfold/poc/r119/stage_c6_secure_small_r119.py
Stage tree root: interfold/poc/r119/root/secure-8192/small/
    recursive/threshold/share_decryption/{share_decryption.json,.vk,_vk_hash}
    default/recursive_aggregation/c6_fold/{c6_fold.json,.vk,_vk_hash}
    default/recursive_aggregation/c6_fold_kernel/{c6_fold_kernel.json,.vk,_vk_hash}
"""
import json, os, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))      # .../interfold/poc/r119
INTERFOLD = os.path.dirname(os.path.dirname(HERE))     # .../interfold
BIN = os.path.join(INTERFOLD, "circuits", "bin")
CONFIGS = os.path.join(INTERFOLD, "circuits", "lib", "src", "configs")
COMMITTEE = os.path.join(CONFIGS, "committee", "active.nr")
DEFAULT_ = os.path.join(CONFIGS, "default", "mod.nr")
OUT = os.path.join(HERE, "stage_c6_secure_small_r119.json")
ROOT = os.path.join(HERE, "root")
VKTMP = os.path.join(HERE, "vktmp")
ENV = dict(os.environ,
           PATH=os.path.expanduser("~/.local/bin") + ":" +
                os.path.expanduser("~/.nargo/bin") + ":" + os.environ.get("PATH", ""))

REC_SDIR = os.path.join(ROOT, "secure-8192", "small", "recursive", "threshold", "share_decryption")
D_C6F    = os.path.join(ROOT, "secure-8192", "small", "default", "recursive_aggregation", "c6_fold")
D_C6FK   = os.path.join(ROOT, "secure-8192", "small", "default", "recursive_aggregation", "c6_fold_kernel")
PRER = os.path.join(HERE, "pre-secure")   # min json snapshot dir (r117 pattern)

# (name, nargo compile cwd relative to BIN, on-disk json relative to BIN,
#  stage dir for the circuit, fold 'vk format' -t)
# The recursive-variant C6 leaf inner loads its .json at circuits_dir(Recursive)/
# threshold/share_decryption plus .vk + .vk_hash (load_vk_from_dir reads
# <circuit>.vk + <circuit>.vk_hash VERBATIM in that dir - we name our staged VK
# files that way, derived from the -t noir-recursive bb write_vk output).
# c6_fold / c6_fold_kernel loads at circuits_dir(Default)/recursive_aggregation/<name>/
# json + .vk + .vk_hash = the -t noir-recursive-no-zk write_vk output.
#
# VK VARIANT MAPPING (r78/r93/r118 RAN-verified + common/helpers.rs layout):
#   - C6 leaf proven at CircuitVariant::Recursive -> the recursive-stage tree uses
#     `.vk_noir` (bb -t noir-recursive), renamed onto share_decryption.vk + _hash.
#     (Recall the converter common/helpers.rs: "Use .vk_noir (noir-recursive) if
#     available, otherwise fall back to .vk_recursive, then .vk". The C6 leaf's
#     posterior transitive verify, r117, consumed the -t noir-recursive VK - and
#     r118's coherence sweep verifies the (json, -t noir-recursive vk) pair for
#     every threshold/dkg circuit. The min-of-C6 leaf in the r117+118-prep tree
#     carries six VK artifacts; the recursive/ staging uses .vk_noir.)
#   - c6_fold + c6_fold_kernel are non-ZK (bb -t noir-recursive-no-zk write_vk
#     per scripts/build-circuits.ts), staged under default/recursive_aggregation/<name>.
COMP = [
    ("c6",
     "threshold/share_decryption",
     "threshold/target/share_decryption.json",
     REC_SDIR, "noir-recursive"),
    ("c6_fold",
     "recursive_aggregation/c6_fold",
     "recursive_aggregation/c6_fold/target/c6_fold.json",
     D_C6F, "noir-recursive-no-zk"),
    ("c6_fold_kernel",
     "recursive_aggregation/c6_fold_kernel",
     "recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json",
     D_C6FK, "noir-recursive-no-zk"),
]

def sh(cmd):
    return subprocess.run(cmd, shell=True, env=ENV, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)

def gates_total(stdout):
    i = stdout.index("{")
    data = json.loads(stdout[i:])
    fns = data.get("functions") or ([data] if isinstance(data, dict) else data)
    return sum(f["circuit_size"] for f in fns), sum(f["acir_opcodes"] for f in fns)

def sha16(path):
    return json.load(open(path))["hash"][:16]

for required in (COMMITTEE, DEFAULT_):
    if not os.path.exists(required):
        print("SELF-CHECK FAIL: missing config " + required); sys.exit(1)

with open(COMMITTEE) as fh: c_bak = fh.read()
with open(DEFAULT_) as fh: d_bak = fh.read()

if os.path.exists(ROOT): shutil.rmtree(ROOT)
if os.path.exists(VKTMP): shutil.rmtree(VKTMP)
os.makedirs(VKTMP, exist_ok=True)
os.makedirs(PRER, exist_ok=True)

# 1) before swap: draw a snapshot of each on-disk min json byte-exact (for restore)
SNAP_MIN = {}  # name -> snapshot path
for (name, compdir, jsrel, sdir, vkfmt) in COMP:
    js = os.path.join(BIN, jsrel)
    if not os.path.exists(js):
        print("SELF-CHECK FAIL: missing on-disk min json", js); sys.exit(1)
    snap = os.path.join(PRER, name + ".min.json")
    shutil.copy2(js, snap)
    SNAP_MIN[name] = snap
    print("snapshotted min", name, "->", os.path.basename(snap))

results = {}
try:
    c = c_bak.replace("committee::minimum", "committee::small")
    d = d_bak.replace("super::insecure::", "super::secure::")
    with open(COMMITTEE, "w") as fh: fh.write(c)
    with open(DEFAULT_, "w") as fh: fh.write(d)
    if "committee::small" not in c or "super::secure::" not in d:
        raise SystemExit("config flip failed (assert tokens)")
    print("config swapped: committee=small, preset=secure")
    for (name, compdir, jsrel, sdir, vkfmt) in COMP:
        compdir_abs = os.path.join(BIN, compdir)
        js_abs      = os.path.join(BIN, jsrel)
        if not os.path.exists(compdir_abs):
            raise SystemExit("missing compile dir " + compdir_abs)
        line = {"compile_rc": -1, "writevk_rc": -1, "gates": None, "acir": None,
                "sha16": None, "compile_wall_s": None, "writevk_wall_s": None,
                "staged": False}
        t0 = time.time()
        r = sh("cd %s && nargo compile 2>&1" % compdir_abs)
        line["compile_wall_s"] = round(time.time() - t0, 2)
        line["compile_rc"] = r.returncode
        if r.returncode != 0:
            print(name, "COMPILE FAILED:", r.stdout.strip().splitlines()[-1:2:])
            results[name] = line
            continue
        t1 = time.time()
        vr = sh("bb write_vk -b %s -t %s -o %s 2>&1" % (js_abs, vkfmt, VKTMP))
        line["writevk_wall_s"] = round(time.time() - t1, 2)
        line["writevk_rc"] = vr.returncode
        if vr.returncode != 0:
            print(name, "WRITEVK FAILED:", vr.stdout.strip().splitlines()[-1:2:])
            results[name] = line
            continue
        g = sh("bb gates -b %s -t noir-recursive-no-zk 2>&1" % js_abs)
        if g.returncode == 0:
            line["gates"], line["acir"] = gates_total(g.stdout)
        line["sha16"] = sha16(js_abs)
        os.makedirs(sdir, exist_ok=True)
        shutil.copy2(js_abs, os.path.join(sdir, os.path.basename(jsrel)))
        # transient vanilla-name vk file (not <pkg>.vk) - rename into the stage dir
        vs  = os.path.join(VKTMP, "vk")
        vhs = os.path.join(VKTMP, "vk_hash")
        if os.path.exists(vs):
            shutil.copy2(vs, os.path.join(sdir, os.path.basename(jsrel).replace(".json", ".vk")))
        if os.path.exists(vhs):
            shutil.copy2(vhs, os.path.join(sdir, os.path.basename(jsrel).replace(".json", ".vk_hash")))
        for extra in ("vk", "vk_hash"):
            p = os.path.join(VKTMP, extra)
            if os.path.exists(p): os.remove(p)
        base = os.path.basename(jsrel).replace(".json", "")
        line["staged"] = (
            os.path.exists(os.path.join(sdir, base + ".json"))
            and os.path.exists(os.path.join(sdir, base + ".vk"))
            and os.path.exists(os.path.join(sdir, base + ".vk_hash"))
        )
        results[name] = line
        print(name, line)
finally:
    # 2) config byte-restore (asserted)
    with open(COMMITTEE, "w") as fh: fh.write(c_bak)
    with open(DEFAULT_, "w") as fh: fh.write(d_bak)
    if open(COMMITTEE).read() != c_bak: raise SystemExit("committee config restore drifted")
    if open(DEFAULT_).read() != d_bak:  raise SystemExit("default config restore drifted")
    print("config byte-restored (asserted)")
    # 3) min on-disk jsons byte-restore (asserted)
    for (name, compdir, jsrel, sdir, vkfmt) in COMP:
        snap = open(SNAP_MIN[name], "rb").read()
        js_abs = os.path.join(BIN, jsrel)
        with open(js_abs, "wb") as fh: fh.write(snap)
        if open(js_abs, "rb").read() != snap:
            raise SystemExit(name + ": min on-disk restore corrupted")
    print("min on-disk jsons byte-restored (asserted)")

with open(OUT, "w") as fh: json.dump(results, fh, indent=1)
print("records ->", OUT)
ok = all(v.get("compile_rc") == 0 and v.get("writevk_rc") == 0 and v.get("gates") is not None
         and v.get("staged") for v in results.values())
print("FULL SELF-CHECK", "OK" if ok else "FAIL")
sys.exit(0 if ok else 1)