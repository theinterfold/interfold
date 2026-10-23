# e3-polynomial-fhe

This separate root workspace package reads FHE polynomials into the parent's exact-integer types.
See the [parent README](../README.md) for conversion semantics.

- Convert NTT/NTT-Shoup inputs to power basis before reading coefficients; representation words are
  not coefficient values.
- Preserve native ascending order. This adapter does not reverse, center, pack, or encode witnesses;
  callers explicitly cross those boundaries in `e3-zk-witness`.
- CRT conversion preserves modulus-row order and coefficient shape. Reconstructed conversion
  combines residues modulo Q; do not confuse the two output meanings.
- Keep this one-way conversion boundary small. Do not add test-only reverse APIs or pull circuit
  metadata into the adapter merely to simplify one witness caller.

The [README](README.md#tests) locates current consumer coverage. For representation changes, cover
power-basis and transformed inputs plus affected witness tests; compiling this conversion-only
package is not a parity check.
