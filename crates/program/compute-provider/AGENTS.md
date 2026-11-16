# e3-compute-provider

Maintain the deterministic Secure Process shared by native execution and the zkVM; provider I/O
belongs in adapters. [Readme.md](Readme.md) explains policies and provider usage.

- Every published input contributes a tree leaf before policy selection. Selection changes the
  computation inputs, not the authenticated input root, and cannot supply a replacement root.
- Preserve two-pass byte-hash checks and index order. A second-pass ciphertext cannot substitute
  different bytes for a first-pass commitment; processors must consume the complete iterator.
- Pass one policy through native computation and proving. Choosing it again inside a provider can
  make the returned ciphertext and proven result disagree.
- Keep guest execution streaming rather than materializing the ciphertext round. Host `parallel`
  batching and `openvm-hashes` acceleration must preserve reference hashing and leaf order.

Use the [README test variants](Readme.md#tests), including parallel batching for batching changes.
Guest-specific changes need the prepared host/guest parity flow from the
[OpenVM README](../openvm-prover/README.md), not just native tests.
