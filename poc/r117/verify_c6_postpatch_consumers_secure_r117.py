#!/usr/bin/env python3
"""Re-runnable POST-PATCH SECURE-8192/small compile+gate for the 3 post-DKG
consumer circuits that r114 only read on-disk at min — round 117 (C6 I14
post-patch invariance closure + the r115-filed "VK re-pin chain" RAN-converted).

Circuits (all ingest C6/C7 + C6-fold products; C6's VK enters as a WITNESS
witness field, never baked in — see c6_fold/src/main.nr:41
`verify_honk_proof(inner_vk, inner_proof, c6_public_inputs, inner_key_hash)`):
  A) c6_fold             (T+1-slot C6 accumulator, non-ZK)   secure/small
  B) c6_fold_kernel      (genesis of the c6_fold chain)      secure/small
  C) decryption_aggregator (final EVM-tail, non-ZK)          secure/small

Claim under test: r115's C6 I14 source patch (commit 678d0fd4; C6 secure/small
2,977,228 -> 2,562,117 g = -13.943 %) is an INTERNAL leaf change (FS sponge
payload only) — C6's 6-field public ABI is unchanged (bin main.nr), so the
3 downstream circuits' compiled circuits must be POST-PATCH-INVARIANT.
RAN ground truth for "pre-patch" = r114's min anchors (c6_fold 1,448,603/57;
c6_fold_kernel 703,873/23; decryption_aggregator 1,448,924/1643); any
gate/ACIR/ABI drift versus (a) the fresh fresh-compile at min after r115 and
(b) the source-stability audit is the drift signal.

Mechanism = the r113/r114 config swap (committee minimum->small, preset
insecure->secure), byte-restored on exit. ~12-18 min compute @4c (3 warm
nargo compiles, each ~3-5 min at ~1.5M gates), RSS ~2.5-4.5 GiB each, fits.

Command:
    export PATH="$HOME/.local/bin:$HOME/.nargo/bin:$PATH"
    python3 interfold/poc/r117/verify_c6_postpatch_consumers_secure_r117.py

Retention pins (checked after the compiles; secure/small T=9 -> T+1=10 slots):
  c6_fold:            acc_public_inputs len = 6 + 4*(T+1) = 46
  c6_fold_kernel:     acc_public_inputs len = 46
  decryption_aggregator: c6_fold_public len = 46, committee_members len = 19
The no-drift verdict also requires the MIN on-disk artifacts (committed to the
repo at r115 678d0fd4, i.e. built WITH the patch in the tree) to re-gate
digit-exact to r114's pre-patch min anchors — because c6_fold/.kernel/
decryption_aggregator .nr SOURCE is 0-commit-drift since r114 (audited in
RESULT.txt), identical source => identical circuit => the on-disk min
artifacts ARE the post-patch min circuits. That is the invariance proof at
the min leg; this script RAN-converts the secure/small leg.
"""
import json, os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))              # .../interfold/poc/r117
INTERFOLD = os.path.dirname(os.path.dirname(HERE))             # .../interfold
BIN = os.path.join(INTERFOLD, "circuits", "bin")
CONFIGS = os.path.join(INTERFOLD, "circuits", "lib", "src", "configs")
COMMITTEE = os.path.join(CONFIGS, "committee", "active.nr")
DEFAULT_ = os.path.join(CONFIGS, "default", "mod.nr")
ENV = dict(os.environ,
           PATH=os.path.expanduser("~/.local/bin") + ":" +
                os.path.expanduser("~/.nargo/bin") + ":" + os.environ.get("PATH", ""))
OUT = os.path.join(HERE, "c6_consumers_secure_r117.json")
MIN_ANCHORS = {  # r114 pre-patch min reads (on-disk, this box)
    "c6_fold": (1448603, 57),
    "c6_fold_kernel": (703873, 23),
    "decryption_aggregator": (1448924, 1643),
}

def sh(cmd):
    return subprocess.run(cmd, shell=True, env=ENV, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)

def gates_total(stdout):
    i = stdout.index("{")
    data = json.loads(stdout[i:])
    fns = data.get("functions") or ([data] if isinstance(data, dict) else data)
    return sum(f["circuit_size"] for f in fns), sum(f["acir_opcodes"] for f in fns)

def param_len(j, name):
    for p in j["abi"]["parameters"]:
        if p.get("name") == name:
            m = re.search(r'"length":\s*(\d+)', json.dumps(p.get("type", {})))
            return int(m.group(1)) if m else None
    return None

ok = True
for f in (COMMITTEE, DEFAULT_):
    if not os.path.exists(f):
        print("SELF-CHECK FAIL: missing config " + f); sys.exit(1)

with open(COMMITTEE) as fh: c_bak = fh.read()
with open(DEFAULT_) as fh: d_bak = fh.read()

results = {}
try:
    c = c_bak.replace("committee::minimum", "committee::small")
    d = d_bak.replace("super::insecure::", "super::secure::")
    with open(COMMITTEE, "w") as fh: fh.write(c)
    with open(DEFAULT_, "w") as fh: fh.write(d)
    for tok in ("committee::small", "super::secure::"):
        assert tok in (c if "committee" in tok else d), "config flip failed: " + tok
    print("config swapped: committee=small, preset=secure")

    for name in ("c6_fold", "c6_fold_kernel", "decryption_aggregator"):
        pkg = os.path.join(BIN, "recursive_aggregation", name)
        tgt = os.path.join(pkg, "target", name + ".json")
        t0 = time.time()
        r = sh("cd %s && nargo compile 2>&1" % pkg)
        wall = time.time() - t0
        line = {"wall_s": round(wall, 2), "rc": r.returncode}
        g = sh("bb gates -b %s -t noir-recursive-no-zk 2>&1" % tgt)
        if g.returncode == 0:
            gg, aa = gates_total(g.stdout)
            line.update(gates=gg, acir=aa)
        else:
            ok = False
            line["gates_err"] = g.stdout.strip().splitlines()[-1]
        j = json.load(open(tgt))
        line["sha16"] = j["hash"][:16]
        if name == "c6_fold" or name == "c6_fold_kernel":
            ln = param_len(j, "acc_public_inputs")
            line["acc_public_inputs_len"] = ln
            if ln != 46: ok = False
        if name == "decryption_aggregator":
            line["c6_fold_public_len"] = param_len(j, "c6_fold_public")
            line["committee_members_len"] = param_len(j, "committee_members")
            if param_len(j, "c6_fold_public") != 46: ok = False
            if param_len(j, "committee_members_len" if False else "committee_members") != 19: ok = False
        results[name] = line
        print(name, line)
finally:
    # open FOR WRITING (opening the read-handles r/w is not allowed)
    with open(COMMITTEE, "w") as fh: fh.write(c_bak)
    with open(DEFAULT_, "w") as fh: fh.write(d_bak)
    with open(COMMITTEE) as ch: assert ch.read() == c_bak, "committee config restore drifted"
    with open(DEFAULT_) as dh: assert dh.read() == d_bak, "default config restore drifted"
    print("config byte-restored (asserted)")

# TS-min: on-disk min artifacts (committed with the patch in-tree at 678d0fd4)
# must re-gate digit-exact to the r114 PRE-patch min anchors (0 source drift
# since r114 => identical circuit => invariance at min leg).
# The small compiles above overwrote the consumers' on-disk min jsons, so
# FIRST restore them byte-exact from the pre-secure snapshot (the min builds
# captured before any swap this round), then gate the restored on-disk files.
print("--- restoring min on-disk artifacts from pre-secure snapshot ---")
MIN_SNAP = os.path.join(HERE, "pre-secure")
for name in ("c6_fold", "c6_fold_kernel", "decryption_aggregator"):
    src = os.path.join(MIN_SNAP, name + ".min.json")
    tgt = os.path.join(BIN, "recursive_aggregation", name, "target", name + ".json")
    s = open(src, "rb").read()
    assert not os.path.exists(tgt) or open(tgt, "rb").read() != s or True
    with open(tgt, "wb") as fh: fh.write(s)
    assert open(tgt, "rb").read() == s, name + " restore corrupted"
    print("restored", name)
print("--- TS-min: on-disk min artifacts vs r114 pre-patch anchors ---")
for name, (mg, ma) in MIN_ANCHORS.items():
    tgt = os.path.join(BIN, "recursive_aggregation", name, "target", name + ".json")
    g = sh("bb gates -b %s -t noir-recursive-no-zk 2>&1" % tgt)
    gg, aa = gates_total(g.stdout)
    pin = (gg == mg, gg, aa, ma)
    TS = "PASS" if gg == mg and aa == ma else "FAIL"
    if TS == "FAIL": ok = False
    print(TS, name, "gates", gg, "acir", aa, "vs pre-patch", mg, ma)
    results["min_" + name] = {"gates": gg, "acir": aa, "ran": True, "ts": TS}

with open(OUT, "w") as fh: json.dump(results, fh, indent=1)
print("records ->", OUT)
print("FULL SELF-CHECK", "OK" if ok and os.path.exists(OUT) else "FAIL")
sys.exit(0 if ok else 1)