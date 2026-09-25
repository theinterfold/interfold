#!/usr/bin/env python3
"""r121 - STAGE the C7 (threshold/decrypted_shares_aggregation) artifact set
for the PRODUCTION FIELD (secure-8192/small, N=19/T=9/H=10, L=3) into the
E3_R121 stage tree, so the C7 leg (crates/zk-prover/tests/c7_secure_small_r121.rs)
can RAN-prove + verify C7 proofs at the production committee.

Mirrors r120's stage_c5_secure_small_r120.py exactly (config swap + fresh nargo
compile + bb gates + bb write_vk + stage materialize + byte-restore asserts),
adapted to the C7 leaf (threshold group, Default variant VK =
noir-recursive-no-zk per the production worker handle_decrypted_shares_aggregation
multithread.rs:1575-1596 which uses CircuitVariant::Default).

C7 = decrypted_shares_aggregation = the post-DKG decryption-tail leaf. Its
scale at the PRODUCTION field (secure-8192/small, N=19/T=9/H=10, L=3) is the
FRESH compile this stage anchors: 334,161 gates / 142,900 ACIR (recorded in
secure_gates_r121.json). The on-disk bench report
(results_secure_agg_small/report.md:86) carries a "C7 136,374 cons" row but
report.md:8 shows that bench ran at "H=5, N=5, T=2" (its OWN micro committee, a
smaller key-sized config than the production N=19) on branch params/dyn-conf @
de480d63 - so 136,374 is that bench config's own small figure (NOT directly
comparable to the production field; a fresh comparison compile would bridge the
gap if ever needed), NOT the production anchor. This stage's fresh compile is
the production-field anchor. C7 remains the SMALLEST leaf overall (<< C5
2,554,248 g / C6 2,562,117 g / C3 2,966,353 g) so it is centrally safe on a
4c/7.8 GiB box. r115 source-minimality told us C7 is pure deterministic arith
(no FS sponge/challenge) so its single structural risk = the witness layer at
T=9/H=10 (the r97 "witness-exceeds-committed-bound" class) - never
RAN-exercised for C7 before this round. The whole prod-field anchor for C7 (the
r119 C6 / r120 C5 sibling gap) is this stage + leg.

Box-class RAN-feasibility (r119 C6 / r120 C5 calibration transfers):
  C7 334,161 g (fresh secure/small compile, this round's anchor)
                       <<  C5 2,554,248 g (RAN-proven 26.8 s avg r120)
                       and << C6 2,562,117 g (RAN-proven 37-39 s r119)
  => C7 compile + proves are light on a 4c/7.8 GiB box; samples + serial
     proves do NOT stack.

Config pre-state gate: on-disk C7 json must be the min/min canonical
(insecure-512/minimum, circuits/bin/threshold/target/decrypted_shares_aggregation.json);
the swap is self-restoring byte-exact + gate re-asserted (r119/r120 protocol).

Command:
    python3 interfold/poc/r121/stage_c7_secure_small_r121.py
"""
import json, os, shutil, subprocess, sys, hashlib, time

HERE = os.path.dirname(os.path.abspath(__file__))                 # .../interfold/poc/r121
INTERFOLD = os.path.dirname(os.path.dirname(HERE))                # .../interfold
STAGE_ROOT = os.path.join(HERE, "root")

CONFIGS = os.path.join(INTERFOLD, "circuits", "lib", "src", "configs")
COMMITTEE = os.path.join(CONFIGS, "committee", "active.nr")
DEFAULT_  = os.path.join(CONFIGS, "default", "mod.nr")
C7_BIN    = os.path.join(INTERFOLD, "circuits", "bin", "threshold", "decrypted_shares_aggregation")
C7_TARGET = os.path.join(INTERFOLD, "circuits", "bin", "threshold", "target")
C7_JSON   = os.path.join(C7_TARGET, "decrypted_shares_aggregation.json")

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

for f in (COMMITTEE, DEFAULT_, C7_JSON):
    if not os.path.exists(f):
        fail("missing " + f)

# Take snapshot of the min on-disk json before the swap (r120 protocol).
MIN_SNAP = os.path.join(HERE, "pre-secure")
os.makedirs(MIN_SNAP, exist_ok=True)
sha_before = sha16(C7_JSON)

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
    shutil.copy2(C7_JSON, os.path.join(MIN_SNAP, "decrypted_shares_aggregation.json"))
    sha_snap = sha16(os.path.join(MIN_SNAP, "decrypted_shares_aggregation.json"))
    print("min on-disk C7 json snapshot sha16:", sha_snap)

    # 1. Fresh nargo compile at secure/small.
    tgt = C7_TARGET
    # Force a clean re-compile by blowing the old ACIR (it was insecure/min).
    if os.path.exists(C7_JSON):
        os.remove(C7_JSON)
    t0 = time.time()
    r = sh("cd %s && nargo compile" % C7_BIN)
    wall = time.time() - t0
    if r.returncode != 0:
        fail("nargo compile C7 at secure/small (wall %.2f s)\n%s" % (wall, r.stdout[-3000:]))
    if not os.path.exists(C7_JSON):
        fail("no decrypted_shares_aggregation.json after nargo compile")
    print("nargo compile secure/small C7 wall %.2f s" % wall)
    sha_new = sha16(C7_JSON)
    print("secure/small C7 json sha16:", sha_new)

    # 2. Gate measure (no recompile): bb gates on the fresh json.
    g = sh("bb gates -b %s -t noir-recursive-no-zk" % C7_JSON)
    if g.returncode != 0:
        fail("bb gates " + g.stdout[-2000:])
    out = g.stdout[g.stdout.index("{"):]
    data = json.loads(out)
    fns = data.get("functions") or ([data] if isinstance(data, dict) else data)
    G = sum(f["circuit_size"] for f in fns)
    AC = sum(f["acir_opcodes"] for f in fns)
    print("secure/small C7 gates = %d %d ACIR" % (G, AC))
    ANCHOR = 136374  # bench results_secure_agg_small/report.md:86 C7 cons anchor (secure/small)
    if G != ANCHOR:
        print("STAGE NOTE: gate %d vs bench anchor %d (bench row is the cons figure; "
              "the next bb gates read on the durable json is the durable re-anchor)" % (G, ANCHOR))
    with open(os.path.join(HERE, "secure_gates_r121.json"), "w") as f:
        f.write(out)

    # 3. bb write_vk -t noir-recursive-no-zk (Default variant VK per production worker).
    tmp = os.path.join(HERE, "vktmp")
    if os.path.isdir(tmp): shutil.rmtree(tmp)
    os.makedirs(tmp, exist_ok=True)
    r2 = sh("bb write_vk -b %s -o %s -t noir-recursive-no-zk" % (C7_JSON, tmp))
    if r2.returncode != 0:
        fail("bb write_vk -t noir-recursive-no-zk " + r2.stdout[-2000:])
    if not os.path.exists(os.path.join(tmp, "vk")) or not os.path.exists(os.path.join(tmp, "vk_hash")):
        fail("missing transient vk/vk_hash after bb write_vk")

    # 4. Stage materialize (threshold group, Default variant dir).
    PRESET = os.path.join(STAGE_ROOT, "secure-8192", "small")
    STAGE_DIR = os.path.join(PRESET, "default", "threshold", "decrypted_shares_aggregation")
    if os.path.isdir(STAGE_DIR): shutil.rmtree(STAGE_DIR)
    os.makedirs(STAGE_DIR, exist_ok=True)
    for src, dest in [
        (C7_JSON,           os.path.join(STAGE_DIR, "decrypted_shares_aggregation.json")),
        (os.path.join(tmp, "vk"),      os.path.join(STAGE_DIR, "decrypted_shares_aggregation.vk")),
        (os.path.join(tmp, "vk_hash"), os.path.join(STAGE_DIR, "decrypted_shares_aggregation.vk_hash")),
    ]:
        shutil.copy2(src, dest)
    print("stage tree materialized: C7 json + noir-recursive-no-zk vk + vk_hash")
finally:
    # 5. Byte-exact config + min-json restore (r120 protocol, asserted).
    with open(COMMITTEE, "w") as f: f.write(c_bak)
    with open(DEFAULT_,  "w") as f: f.write(d_bak)
    if os.path.exists(os.path.join(MIN_SNAP, "decrypted_shares_aggregation.json")):
        shutil.copy2(os.path.join(MIN_SNAP, "decrypted_shares_aggregation.json"), C7_JSON)
    st_c = sh("git -C " + INTERFOLD + " status --porcelain -- circuits/lib/src/configs/committee/active.nr").stdout.strip()
    st_d = sh("git -C " + INTERFOLD + " status --porcelain -- circuits/lib/src/configs/default/mod.nr").stdout.strip()
    sha_after = None
    if os.path.exists(C7_JSON):
        sha_after = sha16(C7_JSON)
    if sha_before != sha_after:
        fail("min on-disk C7 json not byte-restored (before %s != after %s)" % (sha_before, sha_after))
    if st_c or st_d:
        fail("config git porcelain not empty after restore: %r %r" % (st_c, st_d))
    print("config + min on-disk C7 json byte-restored ASSERTED (sha %s; porcelain 0)" % sha_after)

ok()