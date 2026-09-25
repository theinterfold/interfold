#!/usr/bin/env python3
"""r122 - compile + stage the DecryptionAggregator (DA) at the PRODUCTION field
(secure-8192/small, N=19/T=9/H=10, L=3) into a self-contained stage tree which the
r122 cooperative (C6 + C7 + DA) end-to-end test reads from.

WHY (the gap this fills): r117 RAN-compiled the DA at secure/small freshly
(1,493,885 g / 9,526 ACIR) as its "re-pin chain" closure, but has NOT once
PROVED it. r119 RAN the c6_fold chain (10 C6 inners + 9 c6_fold steps) at
secure/small. r121 RAN the C7 leaf at secure/small (5 proves, avg 5.80 s).
The DecryptionAggregator — the top-level final on-chain proof that the
contract verifies, which transitively verifies an UltraHonkProof c6_fold +
an UltraHonkProof C7 + the cross-asserts (ct-uniformity, per-slot
d_commitment match, party_id validity/order, common domain) — has ONLY EVER
BEEN COMPILED, never proved, at any committee. This is the last post-DKG tail
trailing round: a box-1 RAN anchor at the production field, coordinate-backed
by the r119 c6_fold legs + the r121 C7 leg (both available as durable staged
trees; this stage only COMPILES + MATERIALIZES the DA + EVM VK and REUSES the
r119/r121 staged trees via dir-copy, NOT recompile).

Mechanism = the r115/r113/r117 self-restoring config swap. Tracing the DA
compile:
  - DA 1,493,885 gates is between C6 (2.56M) and C7 (136k), well within the
    box-1 7.8 GiB budget; the r117 RAN 1.1 s secure compile at the fresh
    workspace is reproducible here.
  - The EVM VK (`bb write_vk -t evm`) is the on-chain verification variant
    (docs: "keccak/evm — on-chain EVM-verifiable proofs"), matching
    prove_decryption_aggregation_jobs's CircuitVariant::Evm path
    (node_dkg_fold.rs:764-769).
  - The r119-staged trees (C6 leaf recursive/, c6_fold/c6_fold_kernel
    default/) + the r121-staged C7 leaf (default/threshold/
    decrypted_shares_aggregation/) are byte-conserved + reused via dir-copy
    (fast, no recompile); the r119/r120/r121 ROUND results record their
    RAN-verified sha proofs.

Stage tree root: interfold/poc/r122/root/secure-8192/small/
    recursive/threshold/share_decryption/{share_decryption.json, .vk, .vk_hash}
    default/recursive_aggregation/c6_fold/{c6_fold.json, .vk, .vk_hash}
    default/recursive_aggregation/c6_fold_kernel/{c6_fold_kernel.json, .vk, .vk_hash}
    default/threshold/decrypted_shares_aggregation/{decrypted_shares_aggregation.json, .vk, .vk_hash}
    default/recursive_aggregation/decryption_aggregator/decryption_aggregator.json
        (DA compiled ACIR under default/ variant, for witness generation via
         load_compiled_circuit(Default))
    evm/recursive_aggregation/decryption_aggregator/{decryption_aggregator.json, .vk, .vk_hash}
        (DA compiled ACIR + EVM variant VK under evm/, for the on-chain
         bb prove -t evm)

Command:
    python3 interfold/poc/r122/stage_da_secure_small_r122.py
"""
import json, os, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))      # .../interfold/poc/r122
INTERFOLD = os.path.dirname(os.path.dirname(HERE))     # .../interfold
BIN = os.path.join(INTERFOLD, "circuits", "bin")
CONFIGS = os.path.join(INTERFOLD, "circuits", "lib", "src", "configs")
COMMITTEE = os.path.join(CONFIGS, "committee", "active.nr")
DEFAULT_ = os.path.join(CONFIGS, "default", "mod.nr")
OUT = os.path.join(HERE, "stage_da_secure_small_r122.json")
ROOT = os.path.join(HERE, "root")
VKTMP = os.path.join(HERE, "vktmp")
PRER = os.path.join(HERE, "pre-secure")
E3_R122_STAGE_ROOT = os.path.abspath(ROOT)
ENV = dict(os.environ,
           PATH=os.path.expanduser("~/.local/bin") + ":" +
                os.path.expanduser("~/.nargo/bin") + ":" + os.environ.get("PATH", ""))

# The r119 + r121 secure/small stage trees (already RAN-verified + sha-gated
# in prior rounds); we copy them whole so the r122 leg can use their (C6
# leaf, c6_fold, c6_fold_kernel) + (C7 leaf) artifacts without recompile.
R119_ROOT = os.path.join(INTERFOLD, "poc", "r119", "root", "secure-8192", "small")
R121_ROOT = os.path.join(INTERFOLD, "poc", "r121", "root", "secure-8192", "small")
for n, p in [("r119", R119_ROOT), ("r121", R121_ROOT)]:
    if not os.path.isdir(p):
        print(f"SELF-CHECK FAIL: missing prior stage tree {p} (r{n})")
        sys.exit(1)

# DA stage dirs
D_DA_EVM  = os.path.join(ROOT, "secure-8192", "small", "evm",
                         "recursive_aggregation", "decryption_aggregator")
D_DA_DEF  = os.path.join(ROOT, "secure-8192", "small", "default",
                         "recursive_aggregation", "decryption_aggregator")
DA_CMPDIR = os.path.join(BIN, "recursive_aggregation", "decryption_aggregator")
DA_JSON   = os.path.join(DA_CMPDIR, "target", "decryption_aggregator.json")

def sh(cmd):
    return subprocess.run(cmd, shell=True, env=ENV, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)

def gates_total(stdout):
    i = stdout.index("{")
    data = json.loads(stdout[i:])
    fns = data.get("functions") or ([data] if isinstance(data, dict) else data)
    return sum(f["circuit_size"] for f in fns), sum(f["acir_opcodes"] for f in fns)

def sha16(path):
    return json.load(open(path))["hash"][:16]

for required in (COMMITTEE, DEFAULT_):
    if not os.path.exists(required):
        print("SELF-CHECK FAIL: missing config " + required); sys.exit(1)
if not os.path.exists(DA_JSON):
    print(f"SELF-CHECK FAIL: missing on-disk DA json {DA_JSON}"); sys.exit(1)

with open(COMMITTEE) as fh: c_bak = fh.read()
with open(DEFAULT_) as fh: d_bak = fh.read()
with open(DA_JSON, "rb") as fh: da_min_bak = fh.read()

if os.path.exists(ROOT): shutil.rmtree(ROOT)
if os.path.exists(VKTMP): shutil.rmtree(VKTMP)
os.makedirs(VKTMP, exist_ok=True)
os.makedirs(PRER, exist_ok=True)
os.makedirs(ROOT, exist_ok=True)

# Step A: seed the stage tree from the r119 + r121 prior secure/small stages
# (byte-copy; both RAN-verified + sha-gated in their rounds).
copy_map = [
    # (src, dst) — each dst relative to ROOT/secure-8192/small
    (os.path.join(R119_ROOT, "recursive", "threshold", "share_decryption"),
     "recursive/threshold/share_decryption"),
    (os.path.join(R119_ROOT, "default/recursive_aggregation/c6_fold"),
     "default/recursive_aggregation/c6_fold"),
    (os.path.join(R119_ROOT, "default/recursive_aggregation/c6_fold_kernel"),
     "default/recursive_aggregation/c6_fold_kernel"),
    (os.path.join(R121_ROOT, "default/threshold/decrypted_shares_aggregation"),
     "default/threshold/decrypted_shares_aggregation"),
]
for src, dst in copy_map:
    src = os.path.normpath(src)
    if not os.path.isdir(src):
        print(f"SELF-CHECK FAIL: missing source {src}"); sys.exit(1)
    shutil.copytree(src, os.path.join(ROOT, "secure-8192", "small", dst))
    print("copied", dst)

results = {}
try:
    c = c_bak.replace("committee::minimum", "committee::small")
    d = d_bak.replace("super::insecure::", "super::secure::")
    with open(COMMITTEE, "w") as fh: fh.write(c)
    with open(DEFAULT_, "w") as fh: fh.write(d)
    if "committee::small" not in c or "super::secure::" not in d:
        raise SystemExit("config flip failed (assert tokens)")
    print("config swapped: committee=small, preset=secure")

    # Step B: fresh nargo compile of the DA at secure/small (fresh — r115-era
    # toolchain-pin reproducibility, no warm-state dependency).
    line = {"compile_rc": -1, "writevk_rc": -1, "gates": None, "acir": None,
            "sha16": None, "compile_wall_s": None, "writevk_wall_s": None,
            "staged_evm": False, "staged_default_json": False}
    t0 = time.time()
    r = sh(f"cd {DA_CMPDIR} && nargo compile 2>&1")
    line["compile_wall_s"] = round(time.time() - t0, 2)
    line["compile_rc"] = r.returncode
    if r.returncode != 0:
        print("DA COMPILE FAILED:", r.stdout.strip().splitlines()[-1:2:])
        sys.exit(1)
    # Fresh artifact sha + gates
    g = sh(f"bb gates -b {DA_JSON} -t noir-recursive-no-zk 2>&1")
    if g.returncode == 0:
        line["gates"], line["acir"] = gates_total(g.stdout)
    line["sha16"] = sha16(DA_JSON)

    # Step C: materialize the DA json under both default/ (for witness gen) and
    # evm/ (for the bb prove -t evm), and generate the EVM VK.
    os.makedirs(D_DA_EVM, exist_ok=True)
    os.makedirs(D_DA_DEF, exist_ok=True)
    # json (identical ACIR, both dirs)
    shutil.copy2(DA_JSON, os.path.join(D_DA_EVM, "decryption_aggregator.json"))
    shutil.copy2(DA_JSON, os.path.join(D_DA_DEF, "decryption_aggregator.json"))

    # EVM VK
    t1 = time.time()
    vr = sh(f"bb write_vk -b {DA_JSON} -t evm -o {VKTMP} 2>&1")
    line["writevk_wall_s"] = round(time.time() - t1, 2)
    line["writevk_rc"] = vr.returncode
    if vr.returncode != 0:
        print("DA EVM WRITEVK FAILED:", vr.stdout.strip().splitlines()[-1:2:])
        sys.exit(1)
    vs  = os.path.join(VKTMP, "vk")
    vhs = os.path.join(VKTMP, "vk_hash")
    if not (os.path.exists(vs) and os.path.exists(vhs)):
        print("SELF-CHECK FAIL: missing EVM vk/vk_hash in", VKTMP)
        sys.exit(1)
    shutil.copy2(vs,  os.path.join(D_DA_EVM, "decryption_aggregator.vk"))
    shutil.copy2(vhs, os.path.join(D_DA_EVM, "decryption_aggregator.vk_hash"))
    print("EVM VK staged:", vr.returncode, line["writevk_wall_s"], "s")

    line["staged_evm"] = (os.path.exists(os.path.join(D_DA_EVM, "decryption_aggregator.json"))
                          and os.path.exists(os.path.join(D_DA_EVM, "decryption_aggregator.vk"))
                          and os.path.exists(os.path.join(D_DA_EVM, "decryption_aggregator.vk_hash")))
    line["staged_default_json"] = os.path.exists(os.path.join(D_DA_DEF, "decryption_aggregator.json"))

    results["da"] = line
    print("DA line", line)
finally:
    # Config byte-restore (asserted)
    with open(COMMITTEE, "w") as fh: fh.write(c_bak)
    with open(DEFAULT_, "w") as fh: fh.write(d_bak)
    if open(COMMITTEE).read() != c_bak: raise SystemExit("committee config restore drifted")
    if open(DEFAULT_).read() != d_bak:  raise SystemExit("default config restore drifted")
    print("config byte-restored (asserted)")
    # DA min snapshot restore (asserted)
    with open(DA_JSON, "wb") as fh: fh.write(da_min_bak)
    if open(DA_JSON, "rb").read() != da_min_bak:
        raise SystemExit("DA min on-disk restore corrupted")
    print("DA min on-disk json byte-restored (asserted)")

with open(OUT, "w") as fh: json.dump(results, fh, indent=1)
print("records ->", OUT)
ok = (results["da"]["compile_rc"] == 0 and results["da"]["writevk_rc"] == 0
      and results["da"]["gates"] is not None and results["da"]["staged_evm"]
      and results["da"]["staged_default_json"])
print("FULL SELF-CHECK", "OK" if ok else "FAIL")
print("E3_R122_STAGE_ROOT =", E3_R122_STAGE_ROOT)
sys.exit(0 if ok else 1)