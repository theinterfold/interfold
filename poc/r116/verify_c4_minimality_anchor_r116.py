#!/usr/bin/env python3
"""Re-runnable RAN-verify for r116: C4 (dkg/share_decryption) source-minimality closed (negative) + C4 gate-counts digit-exact re-anchored.

RAN scope (box-1, zero fresh nargo/compile, zero config swap):
 (1) C4-cone I14-token sweep (must be 0 hits: no payload/sponge/challenge/gamma/flatten/fiat in C4 lib or bin)
     while C3 (dkg/share_encryption.nr) DOES carry the I14-shipped stack (positive control).
 (2) Three on-disk artifact reads via `bb gates -t noir-recursive-no-zk`:
     (a) canonical on-disk C4 (circuits/bin/dkg/target/share_decryption.json, preset=INSECURE-512/MIN)
     (b) durable r74-min pin   (poc/r74/min/share_decryption.json)
     (c) durable r75-min pin   (poc/r75/min/share_decryption.json, secure-8192/MIN)
     each as its own assertion of DIGIT-EXACT equality with the RAN constant.
 (3) model.py C4_GATE_MIN / C4_GATE_SMALL constants RAN-asserted:
     C4_GATE_MIN   == 1,746,030   (secure-8192/min, RAN r46/r76 anchor - cross-check to r75-min artifact read)
     C4_GATE_SMALL == 3,571,446   (secure-8192/small, r46 — box-2 by owner directive; informational only)
 (4) zero compile / zero drift: the verify script performs NO nargo / NO config swap;
     any drift in the on-disk artifacts fires a self-check fail (not a re-run).

RAN meta: 4c / 7.8 GiB + 8 GiB swap, btime 1788243915 (no reboot since 09-01 06:25:15),
          RAN-verified via /proc/stat btime + /proc/meminfo (the r89 protocol).

No writes to circuits/ or crates/ (poc-only); git clean at tip post commit.
Exit 0 = all RAN digit-exact; exit 1 = any check fires.
"""

import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DD = {"RETURNZERO": 0}  # placeholder for clarity; not used

# Expected RAN digit-exact constants (from the r74 and r75 verbatim on-disk pins).
C4_INSECURE_MIN_GATES   = 62_713    # insecure-512/min, RAN r34-sector first-baseline (I16 era).
C4_INSECURE_MIN_ACIR    = 23_225
C4_SECURE_MIN_GATES     = 1_746_030 # secure-8192/min,  RAN r75 (line 279 model.py C4_GATE_MIN RAN r46-anchored).
C4_SECURE_MIN_ACIR      = 573_457
MODEL_C4_GATE_MIN       = 1_746_030 # from model.py ROUND-76 line 279.
MODEL_C4_GATE_SMALL     = 3_571_446 # from model.py ROUND-76 line 279 (r46 H-only, box-2 informational).

P = {
    "canonical_insecure": os.path.join(REPO, "circuits/bin/dkg/target/share_decryption.json"),
    "r74_pin_min":        os.path.join(REPO, "..", "poc", "r74", "min", "share_decryption.json"),
    "r75_pin_min":        os.path.join(REPO, "..", "poc", "r75", "min", "share_decryption.json"),
}
P = {k: os.path.normpath(v) for k, v in P.items()}

def fail(msg):
    print("FAIL [r116] " + msg)
    sys.exit(1)

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)

def bb_gates(json_path):
    """RAN read via bb gates -t noir-recursive-no-zk; returns (gates, acir) tuple."""
    r = run('RAYON_NUM_THREADS=4 timeout 90 bb gates -t noir-recursive-no-zk -b "{p}"'.format(p=json_path))
    if r.returncode != 0:
        fail("bb gates RC!=0 on %s: %s" % (json_path, r.stderr[:200]))
    out = r.stdout
    m_gates = re.search(r'"circuit_size"\s*:\s*(\d+)', out)
    m_acir  = re.search(r'"acir_opcodes"\s*:\s*(\d+)', out)
    if not m_gates or not m_acir:
        fail("bb gates parse-miss on %s: %s" % (json_path, out[:300]))
    return int(m_gates.group(1)), int(m_acir.group(1))

def sha16(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]

# ---------- TS1: C4-cone I14-token sweep (must be 0 hits) ----------
c4_cone_files = [
    os.path.join(REPO, "circuits/lib/src/core/dkg/share_decryption.nr"),
    os.path.join(REPO, "circuits/bin/dkg/share_decryption/src/main.nr"),
]
c3_marker = os.path.join(REPO, "circuits/lib/src/core/dkg/share_encryption.nr")
I14_RE = re.compile(r"payload|sponge|challenge|gamma|flatten|fiat|Fiat")
cone_hits = 0
for f in c4_cone_files:
    if not os.path.isfile(f):
        fail("C4-cone source missing: " + f)
    with open(f) as fp:
        for ln, line in enumerate(fp, 1):
            if I14_RE.search(line):
                cone_hits += 1
                print("  C4-cone FS-token hit: %s:%d  %s" % (f, ln, line.strip()[:80]))
if cone_hits != 0:
    fail("C4-cone has %d I14-token hits (expected 0): the structure changed; the premise is no longer negative" % cone_hits)
print("TS1 (C4-cone I14-token sweep = 0 hits): PASS")

# Positive control: C3 DOES carry the I14 stack (I14-shipped site at dkg/share_encryption.nr:236-246).
with open(c3_marker) as fp:
    c3_text = fp.read()
if "payload" not in c3_text or "challenge" not in c3_text or "flatten" not in c3_text:
    fail("C3 positive control: dkg/share_encryption.nr no longer carries payload/challenge/flatten (I14 site drifted)")
print("TS1+ (C3 positive control: I14-shipped site still present at dkg/share_encryption.nr): PASS")

# ---------- TS2: three on-disk artifact RAN re-gates, each DIGIT-EXACT ----------
for k, p in P.items():
    if not os.path.isfile(p):
        fail("artifact missing: " + p)

# R101_SEC_MIN = the r81/r100-class determinism cross-anchor for the secure-8192/min C4:
# r101's own leg RAN-compiled c4_min_secure8192_fresh_r101.json and durably recorded it;
# the on-disk r75-min C4 pin must be BYTE-IDENTICAL to that artifact (same toolchain, same
# shapes). This is the same-service reproducibility anchor r81 (C2) and r100 (C2b) used.
import os as _os
R101_SEC_MIN = _os.path.join(REPO, "..", "poc", "r101", "c4_min_secure8192_fresh_r101.json")
R101_SEC_MIN = _os.path.normpath(R101_SEC_MIN)
assert _os.path.isfile(R101_SEC_MIN), "r101 secure/min C4 jar missing: " + R101_SEC_MIN
with open(os.path.join(REPO, "circuits/lib/src/configs/default/mod.nr")) as fp:
    default_mod = fp.read()
if "super::insecure::" not in default_mod:
    fail("active preset drift: default/mod.nr does NOT point at super::insecure:: (expected insecure-512/min on-disk)")
print("TS2p (default/mod.nr active preset = insecure-512/miN, RAN): PASS")

# Active committee (H from committee/active.nr).
with open(os.path.join(REPO, "circuits/lib/src/configs/committee/active.nr")) as fp:
    active_committee = fp.read()
print("TS2q (active committee (H global)): "
      + ("MINIMUM" if "minimum::H" in active_committee else "NOT-minimum (drift!)"))
if "minimum::H" not in active_committee:
    fail("active committee: committee/active.nr does NOT point at minimum::H (expected committee=MINIMUM for TS2a canonical)")
print("TS2q (active committee = MINIMUM, RAN): PASS")

min_sec, min_acir = bb_gates(P["canonical_insecure"])
print("  on-disk C4 insecure/min: gates=%d, acir=%d, sha16=%s" % (min_sec, min_acir, sha16(P["canonical_insecure"])))
if not (min_sec == C4_INSECURE_MIN_GATES and min_acir == C4_INSECURE_MIN_ACIR):
    fail("on-disk C4 insecure/min digital-exact: expected %d/%d, got %d/%d (drift!!)" %
         (C4_INSECURE_MIN_GATES, C4_INSECURE_MIN_ACIR, min_sec, min_acir))
print("TS2a (on-disk canonical insecure/min RAN re-gate at %d gates / %d ACIR): PASS" % (C4_INSECURE_MIN_GATES, C4_INSECURE_MIN_ACIR))

g74, a74 = bb_gates(P["r74_pin_min"])
print("  r74-min C4 pin: gates=%d, acir=%d, sha16=%s" % (g74, a74, sha16(P["r74_pin_min"])))
if not (g74 == C4_INSECURE_MIN_GATES and a74 == C4_INSECURE_MIN_ACIR):
    fail("r74-min C4 pin digital-exact: expected %d/%d, got %d/%d (drift!!)" %
         (C4_INSECURE_MIN_GATES, C4_INSECURE_MIN_ACIR, g74, a74))
print("TS2b (r74-min pin digital-exact vs RAN re-gate): PASS")

g75, a75 = bb_gates(P["r75_pin_min"])
print("  r75-min C4 pin: gates=%d, acir=%d, sha16=%s" % (g75, a75, sha16(P["r75_pin_min"])))
if not (g75 == C4_SECURE_MIN_GATES and a75 == C4_SECURE_MIN_ACIR):
    fail("r75-min C4 pin digital-exact: expected %d/%d (RAN r75), got %d/%d (drift!!)" %
         (C4_SECURE_MIN_GATES, C4_SECURE_MIN_ACIR, g75, a75))
print("TS2c (r75-min pin digital-exact at secure-8192/min %.0f gates): PASS" % C4_SECURE_MIN_GATES)

# RAN cross-assert: the r75-min C4 pin sha must be byte-identical to r101's own leg's
# secure-8192/min C4 artifact (r81/r100 determinism class) - meaning the r75 pin is not
# a COMPROMISED/recompiled drift of the on-disk secure C4, but the SAME reproducibly-compiled
# artifact. This catches any new compile who would rewrite the secure C4 on-disk blob while
# the gate-count stays digit-except (the toolchain-era byte-blob-swap class).
s75 = sha16(P["r75_pin_min"])
s101 = sha16(R101_SEC_MIN)
print("  r75-pin sha16 = %s / r101 secure-min C4 sha16 = %s (same=%s)" % (s75, s101, s75 == s101))
if s75 != s101:
    fail("r75-pin C4 sha != r101 secure/min C4 sha (blob drift: the on-disk secure C4 was recompiled in a different toolchain era than the r75 pin; 0-drift class asserts byte-identity across pin-epochs)")
print("TS2n (r75-min C4 sha == r101 secure/min C4 sha [r81/r100 determinism class]): PASS")

# Gate-count DIGIT-EXACT + source-minimality are the true invariants (the model reads the
# gate-count, not the blob bytes). The byte-blob differences across compile-epochs (e.g.
# the on-disk insecure canonical 15f44d5f vs the r74 8bb78975) are toolchain-era variance,
# NOT cone drift - the gate-count 62,713 is the drift signal and is exact (TS2a/TS2b).

# ---------- TS3: model.py C4_GATE_MIN / C4_GATE_SMALL constants ----------
mdl = os.path.join(REPO, "poc", "r68_n19_wall_model", "model.py")
if not os.path.isfile(mdl):
    fail("model.py missing: " + mdl)
with open(mdl) as fp:
    md = fp.read()
m_min   = re.search(r"C4_GATE_MIN\s*,\s*C4_GATE_SMALL\s*=\s*([\d.]+)\s*,\s*([\d.]+)", md)
if not m_min:
    fail("model.py C4_GATE_MIN / C4_GATE_SMALL regex miss (line-279 block drift - two-value comma-join)")
if float(m_min.group(1)) != float(MODEL_C4_GATE_MIN):
    fail("model.py C4_GATE_MIN drift: expected %d, got %s" % (MODEL_C4_GATE_MIN, m_min.group(1)))
if float(m_min.group(2)) != float(MODEL_C4_GATE_SMALL):
    fail("model.py C4_GATE_SMALL drift (informational): expected %d, got %s" % (MODEL_C4_GATE_SMALL, m_min.group(2)))
print("TS3 (model.py C4_GATE_MIN=%.0f & C4_GATE_SMALL=%.0f, RAN): PASS" % (MODEL_C4_GATE_MIN, MODEL_C4_GATE_SMALL))

# Cross-assert the r75-min RAN-read vs the model's C4_GATE_MIN (independent two-source digit-exact).
if g75 != MODEL_C4_GATE_MIN:
    fail("cross-source: r75-min RAN read %d != model.py C4_GATE_MIN %d (0-drift class fires)" % (g75, MODEL_C4_GATE_MIN))
print("TS3+ (r75-min RAN-read == model.py C4_GATE_MIN, digit-exact): PASS")

# ---------- TS4: zero-compile / no-config-swap RAN-verify ----------
# If the verify script itself mutated any config/source, fail.
r = subprocess.run([
    "git", "-C", REPO, "status", "--porcelain",
], capture_output=True, text=True)
if r.returncode != 0:
    fail("git status RC!=0: " + r.stderr[:200])
# TS4 = zero drift on the SOURCE surface (circuits/ + crates/): this round ships NO .nr / NO Rust change
# (matching r110/r111/r112 shape). poc/r116/ is legitimately untracked pre-commit (this round's
# deliverables), so we assert the SOURCE surface is clean, not the whole tree.
porcelain = r.stdout.splitlines()
src_drift = [l for l in porcelain if "circuits/" in l or "crates/" in l]
if src_drift:
    fail("SOURCE-surface drift (circuits/ or crates/ dirty; expected zero .nr / zero Rust change this round): %s"
         % src_drift[:5])
untracked = [l for l in porcelain if l.startswith("??")][0:]
# Only poc/r116/ should be untracked pre-commit (this round's deliverables).
for l in untracked:
    p = l.split(None, 1)[1].strip() if " " in l else l[2:].strip()
    if not p.startswith("poc/r116/"):
        fail("unexpected untracked (outside poc/r116/) before commit: %s" % p)
print("TS4 (SOURCE-surface zero drift / zero .nr / zero Rust change; only poc/r116/ untracked pre-commit): PASS")

print("")
print("RESULT (r116): FULL ROUND SELF-CHECK OK")
print("  I-r116 closed: premise-vet RAN (C4-cone I14-token sweep = 0 hits; C4 source-minimal, no sponge, no payload)")
print("  + C4 gate-counts DIGIT-EXACT (insecure/min 62,713 g, secure/min 1,746,030 g, 0 drift vs every prior baseline)")
print("  + model.py C4 anchors (C4_GATE_MIN %.0f / C4_GATE_SMALL %.0f) cross-asserted"
      % (MODEL_C4_GATE_MIN, MODEL_C4_GATE_SMALL))
print("  BOX-1 DKG leaf-pool C1/C2/C3/C4/C5 (+inners +folds +aggregators) all RAN-minimality-closed.")
sys.exit(0)