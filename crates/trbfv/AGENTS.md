# e3-trbfv

Maintain threshold-BFV calculations and typed encrypted share payloads here; actors/admission live
with the keyshare/aggregation capabilities.

- Runtime party IDs are zero-based; Shamir reconstruction coordinates become one-based exactly at
  the mathematical boundary. Sorting shares must retain their corresponding party IDs.
- Preserve party/modulus/coefficient axes when extracting or transposing shares. A selected roster
  position is not a full-committee recipient slot, and T is not the reconstruction share count.
- Threshold and transport-encryption parameters differ; select paired metadata through
  `e3-fhe-params`, not copied sizes/noise bounds. Reuse successful randomized outputs on recovery.
- `Encrypted<T>` contains bincode inside local encryption, so layout locks see opaque bytes, not T's
  fields. Treat inner-layout changes as saved-state compatibility changes and keep decrypted
  shares/raw secrets out of logs and ordinary snapshots.

Run `cargo test --locked -p e3-trbfv`; helper dependencies bring Solidity/prover prerequisites from
[test-helpers](../test-helpers/AGENTS.md). Math changes need independent reconstruction cases and
the affected [DKG](../../docs/architecture/dkg.md)/decryption flow, not only encryption round trips.
