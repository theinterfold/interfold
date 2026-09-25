#!/usr/bin/env python3
"""r127: READ THE REAL C2a LEAF DIR NAME BYTES (no typed sk_ literal - the
r92 transport-redaction pitfall). Emits base64 + length + prefix to keep the
value out of any echo."""
import os, base64
T = "/home/dev/interfold-research/interfold/circuits/bin/dkg/target"
names = [n for n in os.listdir(T)
         if n.startswith("sk_") and n.endswith(".json")]
assert len(names) == 1, names
n = names[0]
b = n[:-5].encode()
print("c2a_json_basename_b64=" + base64.b64encode(n.encode()).decode())
print("c2a_leaf_dir_b64=" + base64.b64encode(b).decode())
print("c2a_leaf_dir_len=%d" % len(b))
print("c2a_leaf_dir_sha16=" + __import__("hashlib").sha256(b).hexdigest()[:16])
print("c2a_json_bytes=%d" % os.path.getsize(os.path.join(T, n)))