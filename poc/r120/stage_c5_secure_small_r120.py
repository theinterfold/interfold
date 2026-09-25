#!/usr/bin/env python3
"""r120 - STAGE the C5 (threshold/pk_aggregation) artifact set for the
PRODUCTION FIELD (secure-8192/small, N=19/T=9/H=10, L=3) into the
E3_R120 stage tree, so the C5 leg (crates/zk-prover/tests/c5_secure_small_r120.rs)
can RAN-prove + verify C5 proofs at the production committee.

Mirrors r119's stage_c6_secure_small_r119.py exactly (config swap + fresh nargo
compile + bb write_vk + stage materialize + byte-restore asserts), adapted to the
C5 leaf (threshold group, Default variant VK = noir-recursive-no-zk per
scripts/build-circuits.ts recipes for base DKG/threshold circuits).

C5 = pk_aggregation = the LARGEST single circuit in the DKG DAG
(2,554,248 g secure-8192/small, r113/r39/r44 - the wall table's P2 aggregator
term + the r44 2.2M-cons class). r113's whole secure/small 3-arm gate split was
a GATE read (0 inners, 0 witness); r111/r112/r113 r110-class minimality told us
the source is minimal, which de-risks any future lever; but the PROVE WALL has
never been RAN at the production committee and the WITNESS layer (T=9/H=10
r97-class) has never been RAN-exercised for C5. This stage + its leg RAN-fills
both: the P2 span 400.03 s wall (r28-class bench, inherited from the M4 Pro/
main net benchmark, NOT RAN on box-1 at the production field) is now a box-1
RAN-anchored number.

Box-class RAN-feasibility (r119's C6 calibration, transfers to C5):
  C5  2,554,248 g  <<  C3-small 2,966,353 g (RAN-compiled 5.87 GiB r43)
                       and << C6-small 2,562,117 g (RAN-compiled 4.9 GiB r115,
                       RAN-proven 37.3-38.9 s each, 10 proves = 377.00 s total)
  => C5 is centrally safe on a 4c/7.8 GiB box (peak RSS expected below C3-small
     and below C6-small's compile ceiling); samples + serial proves do NOT stack.

Config pre-state gate: on-disk C5 json must be the min/min canonical
(insecure-512/minimum, circuits/bin/threshold/target/pk_aggregation.json);
the swap is self-restoring byte-exact + re-gate re-asserted (r119 protocol).

Command:
    python3 interfold/poc/r120/stage_c5_secure_small_r120.py
"""
import json, os, shutil, subprocess, sys, hashlib, time

HERE = os.path.dirname(os.path.abspath(__file__))                 # .../interfold/poc/r120
INTERFOLD = os.path.dirname(os.path.dirname(HERE))                # .../interfold
STAGE_ROOT = os.path.join(HERE, "root")

CONFIGS = os.path.join(INTERFOLD, "circuits", "lib", "src", "configs")
COMMITTEE = os.path.join(CONFIGS, "committee", "active.nr")
DEFAULT_  = os.path.join(CONFIGS, "default", "mod.nr")
C5_BIN    = os.path.join(INTERFOLD, "circuits", "bin", "threshold", "pk_aggregation")
C5_TARGET = os.path.join(INTERFOLD, "circuits", "bin", "threshold", "target")
C5_JSON   = os.path.join(C5_TARGET, "pk_aggregation.json")

ENV = dict(os.environ, PATH=os.path.expanduser("~/.local/bin") + ":" +
                         os.path.expanduser("~/.nargo/bin") + ":" + os.environ.get("PATH", ""))

def sh(cmd):
    return subprocess.run(cmd, shell=True, env=ENV, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)

def sha16(p):
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return h[:16]

def fail(m):
    print("STAGE FAIL:", m); sys.exit(1)

def ok():
    print("STAGE SELF-CHECK OK")
    sys.exit(0)

for f in (COMMITTEE, DEFAULT_, C5_JSON):
    if not os.path.exists(f):
        fail("missing " + f)

# Take snapshot of the min on-disk json before the swap (r119 protocol).
MIN_SNAP = os.path.join(HERE, "pre-secure")
os.makedirs(MIN_SNAP, exist_ok=True)
sha_before = sha16(C5_JSON)

with open(COMMITTEE) as f:
    c_bak = f.read()
with open(DEFAULT_) as f:
    d_bak = f.read()
try:
    c = c_bak.replace("committee::minimum", "committee::small")
    d = d_bak.replace("super::insecure::", "super::secure::")
    if "committee::small" not in c: fail("committee did not flip to small")
    if "super::secure::" not in d:   fail("preset did not flip to secure")
    with open(COMMITTEE, "w") as f: f.write(c)
    with open(DEFAULT_,  "w") as f: f.write(d)
    print("config swapped: committee=small, preset=secure")

    # Backup the min on-disk json so we can restore byte-exact.
    shutil.copy2(C5_JSON, os.path.join(MIN_SNAP, "pk_aggregation.json"))
    sha_snap = sha16(os.path.join(MIN_SNAP, "pk_aggregation.json"))
    print("min on-disk C5 json snapshot sha16:", sha_snap)

    # 1. Fresh nargo compile at secure/small.
    tgt = C5_TARGET
    # Force a clean re-compile by blowing the old ACIR (it was insecure/min).
    if os.path.exists(os.path.join(tgt, "pk_aggregation.json")):
        os.remove(os.path.join(tgt, "pk_aggregation.json"))
    t0 = time.time()
    r = sh("cd %s && nargo compile" % C5_BIN)
    wall = time.time() - t0
    if r.returncode != 0:
        fail("nargo compile C5 at secure/small (wall %.2f s)\n%s" % (wall, r.stdout[-3000:]))
    if not os.path.exists(C5_JSON):
        fail("no pk_aggregation.json after nargo compile")
    print("nargo compile secure/small C5 wall %.2f s" % wall)
    sha_new = sha16(C5_JSON)
    print("secure/small C5 json sha16:", sha_new)

    # 2. Gate measure (no recompile): bb gates on the fresh json.
    g = sh("bb gates -b %s -t noir-recursive-no-zk" % C5_JSON)
    if g.returncode != 0:
        fail("bb gates " + g.stdout[-2000:])
    out = g.stdout[g.stdout.index("{"):]
    data = json.loads(out)
    fns = data.get("functions") or ([data] if isinstance(data, dict) else data)
    G = sum(f["circuit_size"] for f in fns)
    AC = sum(f["acir_opcodes"] for f in fns)
    print("secure/small C5 gates = %d %d ACIR" % (G, AC))
    ANCHOR = 2554248  # r113/r39/r44 secure-8192/small C5 V0 gate anchor (full execute)
    if G != ANCHOR:
        print("STAGE WARNING: gate %d vs r113 anchor %d (if cone drifted, investigate)" % (G, ANCHOR))
    with open(os.path.join(HERE, "secure_gates_r120.json"), "w") as f:
        f.write(out)

    # 3. bb write_vk -t noir-recursive-no-zk (Default variant VK per recipes).
    tmp = os.path.join(HERE, "vktmp")
    if os.path.isdir(tmp): shutil.rmtree(tmp)
    os.makedirs(tmp, exist_ok=True)
    r2 = sh("bb write_vk -b %s -o %s -t noir-recursive-no-zk" % (C5_JSON, tmp))
    if r2.returncode != 0:
        fail("bb write_vk -t noir-recursive-no-zk " + r2.stdout[-2000:])
    if not os.path.exists(os.path.join(tmp, "vk")) or not os.path.exists(os.path.join(tmp, "vk_hash")):
        fail("missing transient vk/vk_hash after bb write_vk")

    # 4. Stage materialize.
    PRESET = os.path.join(STAGE_ROOT, "secure-8192", "small")
    STAGE_DIR = os.path.join(PRESET, "default", "threshold", "pk_aggregation")
    if os.path.isdir(STAGE_DIR): shutil.rmtree(STAGE_DIR)
    os.makedirs(STAGE_DIR, exist_ok=True)
    for src, dest in [
        (C5_JSON,           os.path.join(STAGE_DIR, "pk_aggregation.json")),
        (os.path.join(tmp, "vk"),      os.path.join(STAGE_DIR, "pk_aggregation.vk")),
        (os.path.join(tmp, "vk_hash"), os.path.join(STAGE_DIR, "pk_aggregation.vk_hash")),
    ]:
        shutil.copy2(src, dest)
    print("stage tree materialized: stages C5 json + noir-recursive-no-zk vk + vk_hash")
finally:
    # 5. Byte-exact config + min-json restore (r119 protocol, asserted).
    with open(COMMITTEE, "w") as f: f.write(c_bak)
    with open(DEFAULT_,  "w") as f: f.write(d_bak)
    if os.path.exists(os.path.join(MIN_SNAP, "pk_aggregation.json")):
        shutil.copy2(os.path.join(MIN_SNAP, "pk_aggregation.json"), C5_JSON)
    st_c = sh("git -C " + INTERFOLD + " status --porcelain -- circuits/lib/src/configs/committee/active.nr").stdout.strip()
    st_d = sh("git -C " + INTERFOLD + " status --porcelain -- circuits/lib/src/configs/default/mod.nr").stdout.strip()
    sha_after = None
    if os.path.exists(C5_JSON):
        sha_after = sha16(C5_JSON)
    if sha_before != sha_after:
        fail("min on-disk C5 json not byte-restored (before %s != after %s)" % (sha_before, sha_after))
    if st_c or st_d:
        fail("config git porcelain not empty after restore: %r %r" % (st_c, st_d))
    print("config + min on-disk C5 json byte-restored ASSERTED (sha %s; porcelain 0)" % sha_after)

ok()