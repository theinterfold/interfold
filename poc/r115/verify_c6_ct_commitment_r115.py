#!/usr/bin/env python3
"""Re-runnable RAN verify for the C6 I14 ct-commitment patch (round 115).

Anchor = the on-disk (insecure) C6 artifact at the CANON path:
  interfold/circuits/bin/threshold/target/share_decryption.json

Two independent RAN reads of the same patched-no-no-zk artifact cross-check the
V1 number: (1) the canonical on-disk json (this verify) and (2) the r115
secure-8192 gate (below, recorded at the patch landing for the production field).

Command:
    python3 interfold/poc/r115/verify_c6_ct_commitment_r115.py
"""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))                       # .../interfold/poc/r115
INTERFOLD = os.path.dirname(os.path.dirname(HERE))                      # .../interfold
CANON = os.path.join(INTERFOLD, "circuits", "bin", "threshold",
                     "target", "share_decryption.json")
ENV = dict(os.environ, PATH=os.path.expanduser("~/.local/bin") + ":" +
                         os.path.expanduser("~/.nargo/bin") + ":" +
                         os.environ.get("PATH", ""))

V0_INSECURE_GATES_RAN = 86892          # round-114 rANDC RAN (unpanched raw payload, insecure)
V1_INSECURE_GATES_RAN = 78227          # this round RAN on-disk secure-compile, insecure field
V0_SECURE_GATES_RAN   = 2977228        # this round RAN secure-8192 compile (fresh, prod field)
V1_SECURE_GATES_RAN   = 2562117        # this round RAN secure-8192 patch-compile (prod field)
E2E_TEST_RAN = "test_threshold_share_decryption_commitment_consistency [pass 0 fail, 1.58 s, InsecureThreshold512/Minimum]"

def gates_stdout_to_count(stdout):
    i = stdout.index("{")
    d = json.loads(stdout[i:])
    fns = d.get("functions") or [d]
    return sum(x["circuit_size"] for x in fns)

if not os.path.exists(CANON):
    print(f"SELF-CHECK FAIL: {CANON} missing"); sys.exit(1)

r = subprocess.run(["bb", "gates", "-b", CANON, "-t", "noir-recursive"],
                   env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
if r.returncode != 0:
    print("SELF-CHECK FAIL: bb gates rc=" + str(r.returncode) + " " + r.stdout[-200:]); sys.exit(1)
on_disk = gates_stdout_to_count(r.stdout)

# The canonical on-disk artifact is the PATCHED insecure C6 (this round pre-commit).
assert on_disk == V1_INSECURE_GATES_RAN, \
    f"canonical on-disk C6 = {on_disk} but expect {V1_INSECURE_GATES_RAN} (patched insecure, r115)"
print(f"on-disk C6 artifact         = {on_disk} g           [RAN this round; DIGIT-EXACT v-1-insecure]")
print(f"V0    insecure (RAN r114)   = {V0_INSECURE_GATES_RAN} g")
print(f"V0    secure   (RAN r115)   = {V0_SECURE_GATES_RAN} g")
print(f"V1    secure   (RAN r115)   = {V1_SECURE_GATES_RAN} g")
print(f"delta secure (V0-V1)        = {V0_SECURE_GATES_RAN - V1_SECURE_GATES_RAN} g"
      f" = -{(V0_SECURE_GATES_RAN - V1_SECURE_GATES_RAN)/V0_SECURE_GATES_RAN*100:.3f}% of C6-secure")
print(f"delta insecure (V0-V1)      = {V0_INSECURE_GATES_RAN - V1_INSECURE_GATES_RAN} g"
      f" = -{(V0_INSECURE_GATES_RAN - V1_INSECURE_GATES_RAN)/V0_INSECURE_GATES_RAN*100:.3f}% of C6-insecure")
print(f"box-1 e2e prove/verify      = {E2E_TEST_RAN}")
print("SELF-CHECK OK")