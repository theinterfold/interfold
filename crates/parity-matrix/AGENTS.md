# e3-parity-matrix

Maintain finite-field parity-matrix derivation here, not generated Noir configuration files.
[README.md](README.md) defines matrix orientation and the supported parameter contract.

- Preserve validated rectangular dimensions and checked operation compatibility; malformed matrices
  should fail at the boundary rather than panic halfway through elimination.
- Generator columns include the prescribed evaluation domain, including its zero point. Shifting to
  runtime party IDs changes the code being checked, not just its labels.
- Modular inverses and elimination must surface unsupported/noninvertible cases; ordinary integer
  division is not finite-field division.
- A different valid null-space basis can change committed generated output. Review deterministic
  row/pivot order and regenerate through `pnpm build:circuits --committee <name>`, not hand edits to
  circuit files. `pnpm build:circuits check --committee all` compares an isolated rendered copy.

Use the [README tests](README.md#testing), retaining independent parity/property checks.
Generator/output changes also need the
[circuit artifact flow](../../docs/architecture/circuit-artifacts.md) and affected circuit tests;
algebraic validity alone does not establish artifact parity.
