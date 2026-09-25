#!/usr/bin/env python3
"""Re-runnable SECURE-8192/small compile+gate for the LAST DKG aggregator circuits
on box-1 — round 114 (aggregator-side pool minimality + secure anchors).

Scope (DKG pool only; the C6/C7 decryption pool is post-DKG by protocol):
  A) nodes_fold       (H-row per-node fold, non-ZK)  — secure/small
  B) dkg_aggregator   (top aggregator, EVM proof)    — secure/small
Baseline (RAN, this round, no compile): all 8 aggregator-pool artifacts read
ON-DISK at insecure-512/minimum via `bb gates -t noir-recursive-no-zk`
(nodes_fold 1,429,885 DIGIT-EXACT r54; 6-point cross-anchor table).

Mechanism = the r113 config swap (committee minimum->small, preset
insecure->secure), byte-restored on exit. ~2 min compute @4c, RSS small-class.

Command:
    python3 interfold/poc/r114/verify_agg_pool_secure_r114.py
Retention pins (checked after the compiles):
  nodes_fold   secure/small pub row width NODE_FOLD_PUBLIC_LEN(19,10,3) = 224,
               nodes array length = H = 10.
  dkg_aggregator pub inputs: nodes_fold_public len = 4 + 10*224 = 2244,
               committee_members len = 19, c5_public len = H+1 = 11,
               party_ids len = 10.
"""
import json, os, re, shutil, subprocess, sys, time, datetime

HERE = os.path.dirname(os.path.abspath(__file__))              # .../interfold/poc/r114
INTERFOLD = os.path.dirname(os.path.dirname(HERE))             # .../interfold
BIN = os.path.join(INTERFOLD, "circuits", "bin")
CONFIGS = os.path.join(INTERFOLD, "circuits", "lib", "src", "configs")
COMMITTEE = os.path.join(CONFIGS, "committee", "active.nr")
DEFAULT_ = os.path.join(CONFIGS, "default", "mod.nr")
ENV = dict(os.environ, PATH=os.path.expanduser("~/.local/bin") + ":" +
                         os.path.expanduser("~/.nargo/bin") + ":" +
                         os.environ.get("PATH", ""))
OUT = os.path.join(HERE, "secure_gates_r114.json")

def sh(cmd):
    return subprocess.run(cmd, shell=True, env=ENV, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)

def gates_total(stdout):
    i = stdout.index("{")
    data = json.loads(stdout[i:])
    fns = data.get("functions") or ([data] if isinstance(data, dict) else data)
    return sum(f["circuit_size"] for f in fns), sum(f["acir_opcodes"] for f in fns)

def pub_lens(path):
    j = json.load(open(path))
    out = []
    for prm in j["abi"]["parameters"]:
        t = json.dumps(prm.get("type", {}))
        m = re.search(r'"length":\s*(\d+)', t)
        out.append(m.group(1) if m else "")
    return j, out

for f in (COMMITTEE, DEFAULT_):
    if not os.path.exists(f):
        print("SELF-CHECK FAIL: missing config " + f); sys.exit(1)

with open(COMMITTEE) as fh:
    c_bak = fh.read()
with open(DEFAULT_) as fh:
    d_bak = fh.read()

results = {}
try:
    c = c_bak.replace("committee::minimum", "committee::small")
    d = d_bak.replace("super::insecure::", "super::secure::")
    with open(COMMITTEE, "w") as fh:
        fh.write(c)
    with open(DEFAULT_, "w") as fh:
        fh.write(d)
    assert "committee::small" in c, "committee did not flip to small"
    assert "super::secure::" in d, "preset did not flip to secure"
    print("config swapped: committee=small, preset=secure")

    for name in ("nodes_fold", "dkg_aggregator"):
        pkg = os.path.join(BIN, "recursive_aggregation", name)
        tgt = os.path.join(pkg, "target", name + ".json")
        t0 = time.time()
        r = sh("cd %s && nargo compile 2>&1" % pkg)
        wall = time.time() - t0
        mpeak = None
        mm = sh("grep VmHWM /proc/%s/status 2>/dev/null" % os.getpid())
        line = {"wall_s": round(wall, 2), "rc": r.returncode,
                "tail": r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""}
        g = sh("bb gates -b %s -t noir-recursive-no-zk 2>&1" % tgt)
        if g.returncode == 0:
            gg, aa = gates_total(g.stdout)
            line.update(gates=gg, acir=aa)
        j, lens = pub_lens(tgt)
        line["sha16"] = j["hash"][:16]
        line["param_lens"] = dict(zip([p.get("name","") for p in j["abi"]["parameters"]], lens))
        rt = j["abi"]["return_type"].get("abi_type", {})
        line["ret"] = json.dumps(rt)[:120]
        results[name] = line
        print(name, line)
finally:
    with open(COMMITTEE, "w") as fh:
        fh.write(c_bak)
    with open(DEFAULT_, "w") as fh:
        fh.write(d_bak)

with open(OUT, "w") as fh:
    json.dump(results, fh, indent=1)
print("records ->", OUT)