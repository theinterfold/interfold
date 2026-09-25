import os, hashlib, subprocess, json
T = "/home/dev/interfold-research/interfold/circuits/bin/dkg/target"
BB = os.path.expanduser("~/.local/bin/bb")
names = {n: os.path.join(T, n) for n in os.listdir(T) if n.endswith(".json")}
gates_target = {
    "e_sm_share_computation": (10865172, 2771750),
    "share_decryption": (3571446, 734617),
}
ok = True
for n in sorted(names):
    b = names[n]
    h16 = hashlib.sha256(open(b, "rb").read()).hexdigest()[:16]
    st = os.stat(b)
    p = subprocess.run([BB, "gates", "-t", "noir-recursive-no-zk", "-b", b],
                       capture_output=True, text=True, timeout=300)
    d = json.loads(p.stdout)
    fs = d.get("functions", [])
    g = sum(f.get("circuit_size", 0) for f in fs)
    a = sum(f.get("acir_opcodes", 0) for f in fs)
    line = "%-28s %12d B  sha16=%s  gates=%d  acir=%d" % (n, st.st_size, h16, g, a)
    print(line)
    if "sk_" in n:
        if (g, a) == (9422519, 2370696):
            print("  C2a gates DIGIT-EXACT r126 (9422519/2370696) OK + sha 0c727f73cba3a28a expect", h16 == "0c727f73cba3a28a")
        else:
            ok = False; print("  C2a GATES MISMATCH vs r126 anchor")
    elif n in gates_target:
        exp = gates_target[n]
        if (g, a) == exp:
            print("  gates DIGIT-EXACT %d/%d OK" % exp)
        else:
            ok = False; print("  GATES MISMATCH vs expected %s" % (exp,))
print("TS1 full re-gate:", "OK" if ok else "FAIL")
raise SystemExit(0 if ok else 1)