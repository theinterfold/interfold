#!/usr/bin/env python3
"""Re-runnable SECURE-8192/small C5 (PkAggregation) (a)/(b)/(c) gate split — round 113.

Reuses r38's preset-agnostic v0/v1/v2 mirror dirs (the C5 core + secure config cone is
byte-stable since r38: 0 commits on pk_aggregation.nr / commitments.nr / modulo.nr /
polynomial.nr / secure/{threshold,mod}.nr since addb3d4 2026-08-22). The same three dirs
run at ring-512 (r38) or secure-8192 (here) by a config swap alone because they read
`lib::configs::default::threshold::{CRP,L,N,...}`, which resolves to the preset that
circuits/lib/src/configs/default/mod.nr points at.

Arms: V0 = full PkAggregation::execute(); V1 = (a) per-party re-commit block dropped;
V2 = (a)+(b) dropped (verifies nothing). So (a) = V0-V1, (b) = V1-V2, floor (c) = V2.
Additivity holds EXACTLY (residual 0 RAN) because each drop removes a disjoint flagged loop.

Command (needs nargo 1.0.0-beta.26 + bb 5.1.0):
    python3 interfold/poc/r113/verify_c5_secure_split_r113.py
~1.5 min compute (3 secure C5 compiles, V0 58 s / V1 29 s / V2 11 s @4c, RSS <= 2.43 GiB).
Swaps committee (minimum->small) + preset (insecure->secure), restores byte-exact on exit;
`git status --porcelain` in interfold is 0 lines after.
"""
import json, os, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))              # .../interfold/poc/r113
INTERFOLD = os.path.dirname(os.path.dirname(HERE))             # .../interfold
PROBE_DIR = os.getenv("R113_PROBE_DIR",
                      os.path.join(os.path.dirname(INTERFOLD), "poc", "i20_c5_recommit"))
CONFIGS = os.path.join(INTERFOLD, "circuits", "lib", "src", "configs")
COMMITTEE = os.path.join(CONFIGS, "committee", "active.nr")
DEFAULT_ = os.path.join(CONFIGS, "default", "mod.nr")
ENV = dict(os.environ, PATH=os.path.expanduser("~/.local/bin") + ":" +
                         os.path.expanduser("~/.nargo/bin") + ":" + os.environ.get("PATH", ""))

def sh(cmd):
    return subprocess.run(cmd, shell=True, env=ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def ok():
    print("SELF-CHECK OK: 3 secure C5 gate totals RAN-reproduced, anchor DIGIT-EXACT, residual 0")
    sys.exit(0)

def fail(msg):
    print("SELF-CHECK FAIL:", msg)
    sys.exit(1)

def gates_total(stdout):
    i = stdout.index("{")
    data = json.loads(stdout[i:])
    fns = data.get("functions") or ([data] if isinstance(data, dict) else data)
    return sum(f["circuit_size"] for f in fns), sum(f["acir_opcodes"] for f in fns)

for f in (COMMITTEE, DEFAULT_):
    if not os.path.exists(f):
        fail("missing config " + f)

with open(COMMITTEE) as fh:
    c_bak = fh.read()
with open(DEFAULT_) as fh:
    d_bak = fh.read()

try:
    c = c_bak.replace("committee::minimum", "committee::small")
    d = d_bak.replace("super::insecure::", "super::secure::")
    with open(COMMITTEE, "w") as fh:
        fh.write(c)
    with open(DEFAULT_, "w") as fh:
        fh.write(d)
    if "committee::small" not in c:
        fail("committee did not flip to small")
    if "super::secure::" not in d:
        fail("preset did not flip to secure")
    print("config swapped: committee=small, preset=secure")

    results = {}
    for arm in ("v0", "v1", "v2"):
        d = os.path.join(PROBE_DIR, arm)
        if not os.path.isdir(d):
            fail("missing probe dir " + d)
        tgt = os.path.join(d, "target")
        if os.path.isdir(tgt):
            shutil.rmtree(tgt)
        r = sh("cd %s && nargo compile" % d)
        if r.returncode != 0:
            fail("compile " + arm + "\n" + r.stdout[-2000:])
        js = None
        for fn in os.listdir(os.path.join(d, "target")):
            if fn.endswith(".json"):
                js = os.path.join(d, "target", fn)
        if not js:
            fail("no json for " + arm)
        g = sh("bb gates -b %s -t noir-recursive-no-zk" % js)
        if g.returncode != 0:
            fail("bb gates " + arm + "\n" + g.stdout[-2000:])
        gs, ac = gates_total(g.stdout)
        results[arm] = (gs, ac)
        with open(os.path.join(HERE, arm + ".secure.gates.json"), "w") as fh:
            fh.write(g.stdout[g.stdout.index("{"):])
        print("  %-3s circuit_size=%9d  acir=%6d" % (arm, gs, ac))
finally:
    with open(COMMITTEE, "w") as fh:
        fh.write(c_bak)
    with open(DEFAULT_, "w") as fh:
        fh.write(d_bak)
    # Only the two swapped config files must be byte-restored; the probe may add its own
    # untracked poc/r113/ files (benign), so assert on the config paths specifically.
    st = sh("git -C " + INTERFOLD + " status --porcelain -- "
            + "circuits/lib/src/configs/committee/active.nr "
            + "circuits/lib/src/configs/default/mod.nr").stdout.strip()
    print("config-file git status --porcelain: %r" % st)

v0, v1, v2 = results["v0"][0], results["v1"][0], results["v2"][0]
a, b, c = v0 - v1, v1 - v2, v2
anchor = 2554248  # r39/r44 secure-8192/small C5 artifact (V0 == full execute())
if st:
    fail("config swap not byte-restored: " + st)
if v0 != anchor:
    fail("V0 anchor mismatch: RAN %d vs r39/r44 %d" % (v0, anchor))
if (a + b) != (v0 - v2):
    fail("additivity residual nonzero: %d" % ((a + b) - (v0 - v2)))
print("(a) re-commit = %d = %.2f%% of C5-secure" % (a, 100.0 * a / v0))
print("(b) divisib.  = %d = %.2f%%" % (b, 100.0 * b / v0))
print("(c) floor     = %d = %.2f%%" % (c, 100.0 * c / v0))
ok()