# Polynomial arithmetic

This arithmetic serves consumers beyond Noir circuits. A representation change can preserve the
mathematical polynomial while changing a witness, commitment, or serialized value.

- Keep circuit-specific shape and encoding decisions at the witness boundary, not in generic
  arithmetic.
- Treat serialization changes as compatibility decisions, not incidental cleanup. Ask before
  changing an established format unless the request includes that migration.
- A parameter or witness failure is not permission to change arithmetic conventions until a test
  passes. Establish which boundary owns the mismatch first.

Use `README.md` for coefficient-order conventions, CRT limb meaning, the FHE adapter, and focused
verification commands. Those details have one owner rather than a second copy here.
