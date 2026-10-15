# e3-zk-helpers

Keep circuit-specific computation, witness shape, packing, and code generation here. The
[README](README.md) distinguishes exact arithmetic, FHE conversion, and parameter ownership.

- Generic polynomial arithmetic belongs in `e3-polynomial`, native ascending FHE conversion in
  `e3-polynomial-fhe`, and scalar parameter derivation in `e3-fhe-params`. Do not duplicate them
  inside a circuit computation to make its tests self-contained.
- Explicit reversal, centering, signed-field encoding, CRT order, and witness padding are ABI
  decisions. Preserve canonical zero/padded shapes at this boundary, not by normalizing generic
  polynomial constructors. Keep independent negacyclic reference tests.
- Circuit metadata selects threshold versus paired DKG parameters and witness families. Committee
  selection must match compiled Noir artifacts; a sampled witness is not proof of compatibility.
- Change generators/encoding owners, not generated `configs.nr` or Prover files. Keep private
  witness/randomness output out of normal runtime diagnostics.

Run `cargo test --locked -p e3-zk-helpers`; changed witness statements also need matching prepared
Noir/real-proof tests. Use [artifact CLI](../zk/cli/README.md) for commands and
[proof statements](../../docs/architecture/proof-statements.md) for cross-layer review.
