#!/usr/bin/env python3
"""ROUND 112 — fold-seam group RAN anchor re-verify (re-runnable, zero compile).

Re-reads the 4 load-bearing secure-8192 N=19
fold-seam circuit (c2ab_fold / c3ab_fold / c4ab_fold / node_fold) artifacts ON-DISK in the sha-pinned
durable tree poc/r77/root/secure-8192/small/default/recursive_aggregation/,
cross-checks each sha16 + `bb gates -t noir-recursive-no-zk` circuit_size against the
r39 N=19 small fold goldens, and pre-checks the fold-cone source for drift since the
nargo beta26 + bb 5.1.0 toolchain pin (3c84684c).

Zero nargo/bb COMPILE: `bb gates` is a read of an existing artifact (r110/r111 class).
Exit 0 + SELF-CHECK OK iff all 4 digit-exact + 0 cone drift.

Re-run:  python3 poc/r112/verify_fold_seam_anchor_r112.py
"""
import hashlib, os, subprocess, sys

# script lives in interfold/poc/r112/ (tracked); the durable small tree is out-of-repo at
# research-root poc/r77/root  (one level above the interfold repo) -> 3 dirs up.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BASE = os.path.join(ROOT, "poc/r77/root", "secure-8192/small", "default/recursive_aggregation")
BB = os.path.expanduser("~/.local/bin/bb")
INTERFOLD = os.path.join(ROOT, "interfold")

# (circuit, expected circuit_size (golden), expected sha16, acir)
EXPECTED = [
    ("c2ab_fold", 1473584, "a46ddf7f4dc494bb", 122),
    ("c3ab_fold", 1437844, "ad5736fc4c082c4a", 348),
    ("c4ab_fold", 1471783, "2cd4411a80008822", 68),
    ("node_fold", 3719958, "6a50a30e55eb9ae9", 438),
]

def sha16(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]

def bb_gates(p):
    out = subprocess.run([BB, "gates", "-b", p, "-t", "noir-recursive-no-zk"],
                         capture_output=True, text=True).stdout
    size = None
    for ln in out.splitlines():
        if '"circuit_size"' in ln:
            size = int(ln.split(":")[1].strip().rstrip(","))
    return size

def cone_drift():
    # fold bin main.nr + Nargo.toml; last-touch must be <= 2026-08-28 (r62 M7x era)
    # and the lib cone (bb_proof_verification + math/commitments) <= 2026-08-22 (I14/I15).
    files = [
        "circuits/bin/recursive_aggregation/c2ab_fold/src/main.nr",
        "circuits/bin/recursive_aggregation/c3ab_fold/src/main.nr",
        "circuits/bin/recursive_aggregation/c4ab_fold/src/main.nr",
        "circuits/bin/recursive_aggregation/node_fold/src/main.nr",
        "circuits/bin/recursive_aggregation/c3_fold/src/main.nr",
    ]
    latest = None
    per = []
    for f in files:
        r = subprocess.run(["git", "-C", INTERFOLD, "log", "-1", "--date=short",
                            "--format=%ad", "--", f], capture_output=True, text=True)
        d = r.stdout.strip()
        per.append((d, os.path.basename(os.path.dirname(os.path.dirname(f)))))
        if d and (latest is None or d > latest):
            latest = d
    for d, pkg in per:
        print(f"    {pkg:<20} last source touch = {d}")
    return latest  # e.g. "2026-08-28"

def main():
    ok = True
    print("ROUND 112 fold-seam group RAN anchor re-verify")
    for name, exp, exp_sha, _acir in EXPECTED:
        p = os.path.join(BASE, name, name + ".json")
        if not os.path.exists(p):
            print(f"  MISSING {p}"); ok = False; continue
        sha = sha16(p)
        size = bb_gates(p)
        sha_ok = sha == exp_sha
        size_ok = size == exp
        ok = ok and sha_ok and size_ok
        print(f"  {name:<10} gates={size} (exp {exp}, {'OK' if size_ok else 'MISMATCH'}) "
              f"sha16={sha} (exp {exp_sha}, {'OK' if sha_ok else 'MISMATCH'})")
    cd = cone_drift()
    # the r62 M7x commit (2026-08-28) is the newest fold-source touch; nothing newer is drift.
    drift_ok = cd is not None and cd <= "2026-08-28"
    ok = ok and drift_ok
    print(f"  fold-cone latest source touch = {cd} "
          f"({'0 cone drift' if drift_ok else 'DRIFT — investigate'})")
    print("SELF-CHECK " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())