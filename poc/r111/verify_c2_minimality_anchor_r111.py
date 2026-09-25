#!/usr/bin/env python3
"""r111 re-runnable re-anchor: C2a/C2b on-disk artifacts -> RAN gate counts + cone drift.

Mirrors r110's C3 re-anchor. Closes the load-bearing C2 security numbers (the N=19 wall
table's RAN min floor 44.5 s / per-recipient C2a+C2b) and the C2 gate baseline to a single
re-runnable command + cross-checks:
  - the 4 on-disk C2 artifacts (insecure-512/minimum x2, secure-8192/minimum x2) sha-match
  - each circuit_size matches the standing RAN baseline (digit-exact):
      insecure-512/minimum  C2a 41,207  / C2b 79,554   (I16 r34 first-baseline)
      secure-8192/minimum   C2a 1,446,311 / C2b 2,888,964 (r45 / r99 / r100 re-anchored)
  - NO C2-cone source drift since the on-disk build (git).
Self-contained; run from anywhere (paths are absolute). `python3 verify_c2_minimality_anchor_r111.py`
"""
import json, os, re, subprocess, sys, hashlib

REPO = "/home/dev/interfold-research/interfold"
RT = os.path.join(REPO, "circuits/bin/dkg/target")

# (label, artifact path, sha16, expected circuit_size)
# insecure-512/minimum C2b + secure-8192/minimum C2b live in the flat dkg/target / poc dirs;
# the insecure-512/minimum C2a artifact filename is the lossy-transport-redacted `sk_sha…tion`
# (r92 class) -> resolved via glob, NEVER typed as a literal (byte-exact, r92 precedent).
# secure-8192/minimum C2a = the r99 fresh pin; C2b = the r45/r100-twin r75 pin.
C2B_INSECURE = os.path.join(RT, "e_sm_share_computation.json")
C2A_SECURE   = "/home/dev/interfold-research/poc/r99/c2a_min_secure_fresh.json"
C2B_SECURE   = "/home/dev/interfold-research/poc/r75/min/e_sm_share_computation.json"

def find_insecure_c2a():
    for f in sorted(os.listdir(RT)):
        if f.startswith("sk_sha") and f.endswith(".json"):
            return os.path.join(RT, f)
    return None

EXPECT = {
    "C2a insecure-512/minimum": (find_insecure_c2a(), "766839c5", 41207),
    "C2b insecure-512/minimum": (C2B_INSECURE, "90f939b1", 79554),
    "C2a secure-8192/minimum":  (C2A_SECURE,   "940f9cbe", 1446311),
    "C2b secure-8192/minimum":  (C2B_SECURE,   "b172dca5", 2888964),
}

def sha16(p):
    h = hashlib.sha256()
    h.update(open(p, "rb").read())
    return h.hexdigest()[:16]

def bb_gates(p):
    env = dict(os.environ, PATH=os.path.expanduser("~/.local/bin") + ":" + os.environ["PATH"])
    r = subprocess.run(["bb", "gates", "-b", p, "-t", "noir-recursive-no-zk"],
                       env=env, capture_output=True, text=True)
    m = re.findall(r'"circuit_size"\s*:\s*(\d+)', r.stdout)
    # functions[] array: take the first/final circuit_size (single-circuit artifact)
    return (int(m[-1]) if m else None), r.returncode

def main():
    ok = True
    for label, (path, exp_sha8, exp_gates) in EXPECT.items():
        if path is None or not os.path.exists(path):
            print(f"MISS artifact {label} ({path})"); ok = False; continue
        s = sha16(path)
        gates, rc = bb_gates(path)
        sha_ok = s.startswith(exp_sha8)
        gate_ok = (gates == exp_gates)
        print(f"{label:6} sha16={s}  gates={gates}  "
              f"(expect {exp_sha8}.. / {exp_gates})  {'OK' if (sha_ok and gate_ok) else 'FAIL'}")
        ok &= (sha_ok and gate_ok and rc == 0)

    # C2-cone drift: no commit may have touched the C2 cone AFTER the r45-era toolchain
    # (3c84684c, 2026-08-16) -- the insecure-512 artifacts were built at that toolchain and
    # re-prove to the I16 digits, and the secure pins are r45/r99/r100 (all >= that commit).
    # A drift beyond that => the on-disk anchor is stale, recompile needed.
    c = subprocess.run(
        ["git", "-C", REPO, "log", "--oneline", "3c84684c..HEAD", "--",
         "circuits/lib/src/core/dkg/share_computation.nr",
         "circuits/lib/src/math/commitments.nr",
         "circuits/lib/src/math/polynomial.nr",
         "circuits/lib/src/math/helpers.nr"],
        capture_output=True, text=True)
    drift = [l for l in c.stdout.splitlines() if l.strip()]
    print(f"C2-cone commits since 3c84684c (must be 0) = {len(drift)}")
    for l in drift:
        print("   DRIFT", l)
    ok &= (len(drift) == 0)

    print("SELF-CHECK", "OK" if ok else "FAILED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())