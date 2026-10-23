# e3-zk-witness

This crate owns production inputs, deterministic witness preparation, commitments, and Noir JSON.
[README.md](README.md) owns the API and representation contracts.

- Take the concrete configuration from `e3-zk-config`; do not reconstruct it from a preset in a
  witness caller. Keep sample generation in the unpublished sample crate.
- Generic arithmetic belongs in `e3-polynomial`, FHE views in `e3-polynomial-fhe`, and scalar BFV
  derivation in `e3-fhe-params`. Preserve explicit order, centering, CRT limbs, padding, and signed
  field encoding at the witness boundary.
- Prepare user encryption from the exact ciphertext and its intermediates. `encrypt_and_prepare`
  encrypts once; preserve separate ct0/ct1 quotients and canonical `to_json` fields.
- C7 requires exactly canonical T+1 ordered one-based recipients and level-zero contexts. C6/C7
  share the configured native ascending message prefix. A changed host width needs matching ABIs.
- Keep witness/randomness output out of runtime diagnostics. Artifact file writes belong to build.

Run `cargo test --locked -p e3-zk-witness`. Preserve independent arithmetic and malformed-input
tests. Statement changes also need matching Noir/real-proof acceptance under
[proof statements](../../../docs/architecture/proof-statements.md), not only sample success.
