#!/usr/bin/env python3
"""r110 re-runnable re-anchor: secure-8192/small C3 on-disk artifact -> RAN gate count.

Closes the load-bearing C3 security number to a single re-runnable command + cross-checks:
  - artifact sha is the committee-invariant class (r84)
  - circuit_size == the standing post-I15 secure C3 baseline (2,966,353; r41/r59)
  - no C3-cone source drift since the on-disk build (git)
Self-contained; `python3 verify_c3_secure_gate_anchor_r110.py` from the interfold repo root.
"""
import json, os, subprocess, sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# NOTE: this script lives at interfold/poc/r110/; interfold root is two up.
REPO = "/home/dev/interfold-research/interfold"

# the r81/r84-era on-disk secure-8192/small C3 artifact (committee-invariant class)
ARTIFACT = os.path.join(REPO, "target/tmp/.tmpKhXG7C/noir/circuits/secure-8192/small/recursive/dkg/share_encryption/share_encryption.json")
EXPECT_SHA16 = "73105502fd85a709"
EXPECT_GATES = 2966353  # standing post-I15 secure C3 baseline (r41/r59; r39 report ACIR 3,563,512)

def sha16(p):
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]

def main():
    ok = True
    if not os.path.exists(ARTIFACT):
        print("MISS artifact", ARTIFACT); return 2
    s = sha16(ARTIFACT)
    print(f"artifact sha16  = {s}  (expect {EXPECT_SHA16})")
    ok &= (s == EXPECT_SHA16)

    env = dict(os.environ, PATH=os.path.expanduser("~/.local/bin") + ":" + os.path.expanduser("~/.nargo/bin") + ":" + os.environ["PATH"])
    r = subprocess.run(["bb", "gates", "-b", ARTIFACT, "-t", "noir-recursive-no-zk"],
                       env=env, capture_output=True, text=True)
    import re
    m = re.search(r'"circuit_size"\s*:\s*(\d+)', r.stdout)
    gates = int(m.group(1)) if m else None
    print(f"bb gates rc     = {r.returncode}")
    print(f"circuit_size    = {gates}  (expect {EXPECT_GATES})")
    ok &= (gates == EXPECT_GATES)

    # C3-cone drift since the on-disk build (r81/r84 era). Only I3/I14/I15 may appear and all must
    # predate the artifact; a drift beyond those three => recompile needed, anchor invalid.
    c = subprocess.run(["git", "-C", REPO, "log", "--oneline", "--",
                        "circuits/lib/src/core/dkg/", "circuits/bin/dkg/share_encryption/",
                        "circuits/lib/src/configs/secure/"], capture_output=True, text=True)
    commits = [l for l in c.stdout.splitlines() if l.strip()]
    print("C3-cone commits (newest first):")
    for l in commits[:6]:
        print("   ", l)
    # the anchor is valid at HEAD iff no C3-cone commit is NEWER than the I15 commit (b7cfd49e)
    r2 = subprocess.run(["git", "-C", REPO, "log", "--oneline", "b7cfd49e..HEAD", "--",
                         "circuits/lib/src/core/dkg/", "circuits/bin/dkg/share_encryption/",
                         "circuits/lib/src/configs/secure/"], capture_output=True, text=True)
    drift = [l for l in r2.stdout.splitlines() if l.strip()]
    print(f"cones drifted since I15 (must be 0) = {len(drift)}")
    ok &= (len(drift) == 0)
    for l in drift:
        print("   DRIFT", l)

    print("SELF-CHECK", "OK" if ok else "FAILED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())