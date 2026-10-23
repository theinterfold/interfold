# e3-polynomial

Keep exact integer arithmetic independent of FHE, witness encodings, and actors.
[README.md](README.md) owns coefficient order, CRT limbs, the FHE adapter, and focused tests.

- A representation change can preserve a polynomial but change a witness, commitment, or serialized
  value. Treat serialization changes as compatibility decisions, not incidental cleanup.
- Keep integer quotients and exact-division errors. Modular ring arithmetic cannot replace them
  merely because residues match.
- Keep circuit-specific shape, reversal, encoding, and padding at the
  [witness boundary](../zk/witness/README.md). Do not change generic arithmetic to make a witness
  failure disappear.
- Preserve canonical scalar zero from multiplication and constructor order/padding. Keep independent
  arithmetic references and overflow/fallback cases in tests.
