# e3-fhe

This is the runtime fhe.rs adapter and per-E3 FHE dependency extension, not the DKG workflow owner.

- Restore parameters and CRP from the FHE snapshot and inject the RNG separately; snapshotting a new
  RNG state or reconstructing a different CRP changes the cryptographic session.
- Keep snapshot repository scope and the typed `FHE_KEY` consistent with request hydration. An
  extension's absence from a snapshot is not permission to invent another request context.
- Secret-key serialization contains raw coefficients. Keep it behind the existing encrypted
  storage/caller boundaries and never add Debug/tracing of unsafe secret bytes.
- Aggregation decodes against this request's parameters and ciphertext; preserve ordered share
  inputs and the client crate's plaintext word encoding rather than duplicating conversion rules.

Run `cargo test --locked -p e3-fhe` for the focused adapter target; test new hydration behavior at
the request/builder boundary too. Adapter compilation does not replace the
[DKG](../../docs/architecture/dkg.md) or threshold-decryption acceptance flows.
