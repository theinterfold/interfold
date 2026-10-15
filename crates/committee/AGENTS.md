# e3-committee

This is the canonical owner of committee names and parameter values, not a runtime selector.

- Enum variant order is a bincode wire contract; names also appear in JSON, CLI values, and active
  circuit stamps. Do not reorder or rename variants as cosmetic cleanup.
- Keep threshold lookup distinct from honest-roster lookup. N, H, and T have different consumers;
  derive values here instead of reproducing committee tables in callers.
- Unknown parameter pairs must remain errors, not guesses at the nearest supported committee.
- A new committee requires coordinated generated circuit/config outputs and verifier compatibility;
  adding an enum variant alone does not make its proofs usable.

Run `cargo test --locked -p e3-committee` for serialized variants and lookup behavior. Follow
[circuit artifacts](../../docs/architecture/circuit-artifacts.md) for coordinated generation and
[selection](../../docs/architecture/committee-selection.md) for runtime meaning.
