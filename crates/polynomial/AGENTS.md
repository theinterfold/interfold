# e3-polynomial

Keep exact integer arithmetic independent of FHE, witness encodings, and actors.
[README.md](README.md) explains the separate `e3-polynomial-fhe` child package and coefficient
conventions.

- Arithmetic uses descending coefficients, while constructors preserve order and padding. FHE views
  may still be ascending until explicitly reversed; do not normalize order implicitly.
- Preserve integer quotients and exact-division errors. Replacing these operations with modular FHE
  ring arithmetic loses witness information even when residues look identical.
- Most operations retain shape, but multiplication of a zero operand returns canonical scalar zero.
  Witness padding belongs to the circuit owner; do not globally normalize constructors to fix it.
- CRT limbs are ordered residue polynomials, not words of one integer. The optional serde layout,
  including the `limbs` name and padding, is a consumer compatibility boundary.

Run `cargo test --locked -p e3-polynomial --all-features`, preserving independent arithmetic
references and overflow/fallback cases. Circuit folding and witness-shape changes belong in
[zk-helpers](../zk-helpers/README.md), not generic polynomial APIs.
