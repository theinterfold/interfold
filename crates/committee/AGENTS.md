# e3-committee

This owns canonical committee parameters and ordered membership/lookup, not runtime selection.

- Enum variant order is a bincode wire contract; names also appear in JSON, CLI values, and active
  circuit stamps. Do not reorder or rename variants as cosmetic cleanup.
- Keep threshold lookup distinct from honest-roster lookup. N, H, and T have different consumers;
  derive values here instead of reproducing committee tables in callers.
- Unknown parameter pairs must remain errors, not guesses at the nearest supported committee.
- Membership preserves supplied order, spelling, duplicate behavior, and lowercase lookup. Its
  derived index is not serialized. Formation, address normalization, and failover stay in sortition.
- A new committee requires coordinated generated circuit/config outputs and verifier compatibility;
  adding an enum variant alone does not make its proofs usable.

Use the [README tests](README.md#tests) for serialized variants and lookup behavior. Follow
[circuit artifacts](../../docs/architecture/circuit-artifacts.md) for coordinated generation and
[selection](../../docs/architecture/committee-selection.md) for runtime meaning.
