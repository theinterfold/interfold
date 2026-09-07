#!/usr/bin/env python3
"""r118: in-place-derivation-leaf staleness audit — the r117 C6 defect class
(vk not derived from the co-located json), swept over the ENTIRE interfold
noir artifact surface a run could consume:
  (A) the box-2 durable tree  poc/r77/root/secure-8192/small  (the 55-file r78
      leg load surface: 3 leaves x 3 variant dirs + 9 recursive_aggregation
      folds, all secure-8192/small);
  (B) the in-repo min targets  circuits/bin/{dkg,threshold}/target +
      circuits/bin/recursive_aggregation/*/target  (the insecure-512/min
      on-disk artifacts the box-1 e2e tests load).

Method (RAN, bb 5.1.0): for every (json, vk) pair, re-derive the
noir-recursive VK from the ON-DISK ACIR json (`bb write_vk -t
noir-recursive`) and byte-compare to the CO-LOCATED on-disk vk. MATCH =
coherent pair (a proof built against this vk verifies against this json);
MISMATCH = the r117 defect (stale derived vk), the exact class r117 caught
+ repaired on the C6 axis.

SELF-CHECK: TS1 all expected (scope, circuit) rows present; TS2 zero
MISMATCH/DERIVE-FAIL/ABSENT; TS3 the 3 r99/r100/r101 self-healed secure-leg
insecure-min jsons carry their exact on-disk shas (766839c5 / 90f939b1 /
15f44d5f, digit-anchored r116/r100/r101); TS4 the C3 secure-8192
committee-independence class SURVIVES the sweep (tree C3 json sha 73105502
= r41/r75/r84/r110 bit-pin) and the mtime-cohort dating table is printed.

Usage: python3 verify_artifact_coherence_r118.py [interfold_repo_root]
Exit 0 = FULL SELF-CHECK OK; 1 = defect found or self-check failed.
"""
import hashlib
import json
import os
import subprocess
import sys
import time

BB = os.path.expanduser("~/.local/bin/bb")
REPO = (sys.argv[1] if len(sys.argv) > 1
        else os.environ.get("REPO_ROOT", "/home/dev/interfold-research/interfold"))
RESROOT = os.path.dirname(REPO) + "/"  # interfold-research/
TMP = "/tmp/r118_vkderives_verify"

TREE_MAP = {
    "C0_pk": "dkg/pk", "C3_share_encryption": "dkg/share_encryption",
    "C1_pk_generation": "threshold/pk_generation",
    "c2ab_fold": "recursive_aggregation/c2ab_fold",
    "c3_fold": "recursive_aggregation/c3_fold",
    "c3_fold_batch_b3": "recursive_aggregation/c3_fold_batch_b3",
    "c3_fold_batch_b10": "recursive_aggregation/c3_fold_batch_b10",
    "c3_fold_batch_merge_m7x": "recursive_aggregation/c3_fold_batch_merge_m7x",
    "c3_fold_kernel": "recursive_aggregation/c3_fold_kernel",
    "c3ab_fold": "recursive_aggregation/c3ab_fold",
    "c4ab_fold": "recursive_aggregation/c4ab_fold",
    "node_fold": "recursive_aggregation/node_fold",
}
INREPO_FOLDS = [
    "c2ab_fold", "c3_fold", "c3_fold_batch_b3", "c3_fold_batch_b10",
    "c3_fold_batch_merge_m7x", "c3_fold_kernel", "c3ab_fold", "c4ab_fold",
    "node_fold", "c6_fold", "c6_fold_kernel", "decryption_aggregator",
    "dkg_aggregator", "nodes_fold", "nodes_fold_kernel",
]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def audit(name, j, v):
    out = {"circuit": name,
           "json_sha16": sha(j)[:16] if os.path.exists(j) else None,
           "on_disk_vk_sha16": sha(v)[:16] if os.path.exists(v) else "ABSENT"}
    if not os.path.exists(j):
        out["verdict"] = "JSON-ABSENT"
        return out
    if not os.path.exists(v):
        out["verdict"] = "VK-ABSENT (no co-located vk on disk)"
        return out
    o = os.path.join(TMP, name)
    os.makedirs(o, exist_ok=True)
    for f in os.listdir(o):
        os.remove(os.path.join(o, f))
    t0 = time.time()
    try:
        p = subprocess.run([BB, "write_vk", "-t", "noir-recursive", "-b", j, "-o", o],
                           capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        out["verdict"] = "DERIVE-TIMEOUT"
        return out
    out["derive_wall_s"] = round(time.time() - t0, 2)
    if p.returncode != 0:
        out["verdict"] = "DERIVE-FAIL rc=%s" % p.returncode
        out["tail"] = (p.stderr or p.stdout)[-200:]
        return out
    dv = sha(os.path.join(o, "vk"))[:16]
    out["derived_vk_sha16"] = dv
    out["verdict"] = ("MATCH" if dv == out["on_disk_vk_sha16"]
                      else "MISMATCH on_disk=%s derived=%s" % (out["on_disk_vk_sha16"], dv))
    return out


def main():
    os.makedirs(TMP, exist_ok=True)
    rows = []
    small = RESROOT + "poc/r77/root/secure-8192/small"
    print("### A: BOX-2 DURABLE TREE (55-file r78 load surface, secure-8192/small) ###")
    for name, rel in TREE_MAP.items():
        base = os.path.join(small, "default", rel)
        cn = os.path.basename(rel)
        r = audit("T:" + name, os.path.join(base, cn + ".json"), os.path.join(base, cn + ".vk"))
        r["scope"] = "box2-tree"
        rows.append(r)
        print("  %-32s %s" % (r["circuit"], r["verdict"]))
    for name, rel in TREE_MAP.items():
        if "recursive_aggregation" in rel:
            continue
        cn = os.path.basename(rel)
        ss = [sha(os.path.join(small, v, rel, cn + ".json"))[:16]
              for v in ("default", "evm", "recursive")]
        r = {"circuit": "T:" + name, "scope": "box2-tree",
             "verdict": "3-VARIANT-IDENTICAL" if ss[0] == ss[1] == ss[2]
                        else "3-VARIANT-DIFF %s" % ss,
             "json_sha16": ss[0]}
        rows.append(r)
        print("  %-32s %s" % (r["circuit"], r["verdict"]))
    print()
    print("### B: IN-REPO MIN TARGETS (insecure-512/min on-disk, box-1 e2e consumables) ###")
    binr = REPO + "/circuits/bin"
    for name in INREPO_FOLDS:
        base = os.path.join(binr, "recursive_aggregation", name, "target")
        r = audit("R:" + name, os.path.join(base, name + ".json"),
                  os.path.join(base, name + ".vk_recursive"))
        r["scope"] = "inrepo-min"
        rows.append(r)
        print("  %-32s %s" % (r["circuit"], r["verdict"]))
    dkg = binr + "/dkg/target"
    leaf_files = sorted(f for f in os.listdir(dkg) if f.endswith(".json"))
    for f in leaf_files:
        name = f[:-5]
        r = audit("R:" + name, os.path.join(dkg, f), os.path.join(dkg, name + ".vk_recursive"))
        r["scope"] = "inrepo-min"
        rows.append(r)
        print("  %-32s %s" % (r["circuit"], r["verdict"]))
    c6 = binr + "/threshold/target"
    r = audit("R:C6_share_decryption", c6 + "/share_decryption.json",
              c6 + "/share_decryption.vk_recursive")
    r["scope"] = "inrepo-min"
    rows.append(r)
    print("  %-32s %s" % (r["circuit"], r["verdict"]))

    # ---------------- self-checks ----------------
    problems = []
    badv = [r for r in rows if r["verdict"] != "MATCH"
            and not r["verdict"].startswith("3-VARIANT-IDENTICAL")]
    for r in badv:
        problems.append("BAD [%s] %s" % (r["circuit"], r["verdict"]))
    ts1 = any(r["circuit"] == "T:node_fold" and r["scope"] == "box2-tree" for r in rows) and \
          any(r["circuit"] == "R:C6_share_decryption" for r in rows)
    if not ts1:
        problems.append("TS1: expected surface rows missing")
    ts2 = not badv
    shas = {r["circuit"]: r.get("json_sha16") for r in rows}
    c2a = [f[:-5] for f in leaf_files if f.startswith("sk_sh")][0]  # resolved from disk, not typed
    ts3_exp = {"R:share_decryption": "15f44d5f",
               "R:e_sm_share_computation": "90f939b1",
               "R:" + c2a: "766839c5"}
    for k, exp in ts3_exp.items():
        if not (shas.get(k) or "").startswith(exp):
            problems.append("TS3: %s json sha %s !~ %s" % (k, shas.get(k), exp))
    ts3 = not any(p.startswith("TS3") for p in problems)
    ts4 = (shas.get("T:C3_share_encryption") or "").startswith("73105502")
    if not ts4:
        problems.append("TS4: tree C3 json sha %s != 73105502 (r41/r75/r84/r110 bit-pin)"
                        % shas.get("T:C3_share_encryption"))

    print()
    print("### MTIME cohort dating (in-repo min leaf jsons) ###")
    for f in leaf_files:
        p = os.path.join(dkg, f)
        print("  %-28s %s  %s" % (f[:-5], sha(p)[:16],
              time.strftime("%Y-%m-%d %H:%M", time.localtime(os.stat(p).st_mtime))))
    p = c6 + "/share_decryption.json"
    print("  %-28s %s  %s" % ("C6_share_decryption", sha(p)[:16],
          time.strftime("%Y-%m-%d %H:%M", time.localtime(os.stat(p).st_mtime))))
    print()
    nmatch = sum(1 for r in rows if r["verdict"] == "MATCH"
                 or r["verdict"].startswith("3-VARIANT-IDENTICAL"))
    print("=== r118 artifact-coherence: %d/%d pair-sets coherent | non-MATCH %d ==="
          % (nmatch, len(rows), len(badv)))
    for p in problems:
        print("  PROBLEM: " + p)
    with open("/tmp/r118_verify_results.json", "w") as fh:
        json.dump(rows, fh, indent=1)
    if ts1 and ts2 and ts3 and ts4:
        print("FULL SELF-CHECK OK (TS1 surface / TS2 zero-defect / TS3 self-heal cohort / TS4 C3 pin)")
        sys.exit(0)
    print("SELF-CHECK FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()