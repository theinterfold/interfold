# e3-safe

This crate owns SAFE sponge behavior and native/guest Poseidon2 equivalence.

- Domain tags, IO-pattern encoding, absorb/squeeze sequencing, and finish validation are part of the
  commitment statement. Do not relax a pattern failure into a partially computed hash.
- Preserve canonical field/byte conversions and reference permutation behavior. A faster guest path
  must return the same digest as native execution for the same transcript.
- `openvm` enables guest integration; `phase-trace` is diagnostic instrumentation, not a different
  commitment format. Keep target-specific code behind its existing cfg/feature boundaries.
- Updating permutation constants or sponge parameters requires coordinating every Noir/Rust/
  contract commitment consumer, not simply refreshing expected native vectors.

Run `cargo test --locked -p e3-safe` for native vectors and accelerated-reference tests. Guest-only
changes additionally need the pinned [OpenVM parity workflow](../openvm-prover/README.md); enabling
all features on a host is not a substitute for a guest build. See
[proof statements](../../docs/architecture/proof-statements.md).
