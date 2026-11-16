# e3-tests

This is the cross-capability/multi-node harness owner; `src/main.rs` intentionally does no work.

- Prefer observable history, disk restart, and final output assertions over mailbox timing or
  reimplemented reducer logic. Reuse the existing ciphernode-system harness and replay loaders.
- A full-proof scenario asserts outcomes (key, plaintext, accepted roster, no faults), never how
  actors order their events, and never waits for a progress deadline. Add a fault as a named
  `trbfv_scenario_*` test, not as an environment switch on an existing one. A scenario CI runs gets
  its own leg; one CI does not run is `#[ignore]`d with the reason.
- Keep `tests/trbfv/` split four ways, as private modules: `scenario.rs` holds the fault and the
  expected outcome as data; `runner.rs` executes and returns `Observations`, asserting nothing
  beyond what it needs to keep driving the protocol; `assertions.rs` checks the expectation over the
  observations, with no live node; `benchmark.rs` formats and exports timings and proofs. No traits,
  no scenario crate.
- Keep node buses, stores, RNGs, and terminal cleanup isolated. Multi-node proof benchmarks need
  per-node RNG mutexes rather than one shared lock that hides resource contention.
- The manifest enables builder test helpers and test-only proof aggregation skipping. Cargo feature
  unification can enable these across a workspace test graph; ordinary test success does not prove
  production feature containment or recursive proof verification.
- Layout-lock fixtures cover listed serde roots, not repository paths, hand-written framing, or
  opaque encrypted payloads. Review compatibility/version decisions before intentional regeneration.

Choose the affected target using the
[README test map/prerequisites](README.md#tests-choose-a-target). Encoding changes need the consumer
layout lock; behavioral changes need a named history/restart scenario. Ignored/skipped scenarios and
layout checks are not full restart or cryptographic assurance; see
[persistence](../../../docs/architecture/persistence-and-replay.md).
