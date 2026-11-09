# e3-tests

## Purpose

Cross-capability and multi-node ciphernode test harness. `src/main.rs` intentionally does no work;
use Cargo's named integration targets, not `cargo run`, to exercise the system.

Mock transport/restart behavior lives privately in `tests/ciphernode_system/libp2p_mock.rs`;
synthetic registration lives in `tests/common`. Neither establishes peer authorization or proof
validity. The fixture ownership decisions are recorded in the
[testing domain](../../../docs/architecture/repository-testing.md#fixture-ownership-2325).

The external integration scripts build `fake_encrypt` and `pack_e3_params` from this package's
`src/bin`. Their CLI names/arguments are unchanged; they reuse production parameter codecs and
commitments. Build them without the dev-only node graph:

```sh
cargo build --locked -p e3-tests --bin fake_encrypt --bin pack_e3_params
```

## Map

| Location                                                                 | Responsibility                                                       |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| [`tests/ciphernode_system/`](tests/ciphernode_system)                    | Multi-node builder/handle harness, histories, and network helpers.   |
| [`tests/integration.rs`](tests/integration.rs)                           | Named full-proof scenarios, the benchmark entry, and P2P forwarding. |
| [`tests/trbfv/`](tests/trbfv)                                            | Scenario, runner, assertions, node factory, benchmark exports.       |
| [`tests/large_work_plan_recovery.rs`](tests/large_work_plan_recovery.rs) | Reopen large proof plans and dispatch missing work.                  |
| [`tests/layout_lock.rs`](tests/layout_lock.rs)                           | Runtime encoding roots and repository/event samples.                 |
| [`src/main.rs`](src/main.rs)                                             | Empty executable, not a test runner.                                 |

Scenarios compose real actors with isolated buses/stores and selectable transport/worker
substitutes. They publish histories, observe outcomes, and for recovery reopen saved state. Which
parts are mocked or ignored is specific to the scenario, not guaranteed by the package name.

## Tests: choose a target

- [integration.rs](tests/integration.rs): one `trbfv_scenario_*` test per full-proof scenario, each
  a whole E3 on real ciphernodes through [ciphernode_system](tests/ciphernode_system/mod.rs), plus
  P2P forwarding tests. A scenario asserts outcomes only: the key, the plaintext, the accepted DKG
  roster, and the absence of faults. It does not assert how actors order their events, and it does
  not wait for a progress deadline.
- [trbfv/](tests/trbfv): the private modules behind those tests. `scenario.rs` holds a `Scenario`:
  the injected `Fault` and the `Expect`ed outcome, as data. `runner.rs` builds the nodes, executes
  the phases, injects the fault, and returns the `Observations`; it asserts nothing about the
  outcome. `assertions.rs` evaluates the expectation over the observations, with no live node.
  `benchmark.rs` formats and exports the same observations. An outcome over observations the runner
  already returns is an `Expect` field in `scenario.rs` and its check in `assertions.rs`; one that
  needs a new reading or wait adds that observation to `runner.rs`.
- [large_work_plan_recovery.rs](tests/large_work_plan_recovery.rs): persisted large-work-plan
  recovery scenarios.
- [layout_lock.rs](tests/layout_lock.rs): listed persisted/wire serde roots, repository value types,
  and event-ID samples. It does not cover store paths, manual framing, or opaque encrypted payloads;
  see [layout-lock](../layout-lock/README.md).

After preparing tools, run a focused target from the repository root:

```sh
cargo test --locked -p e3-tests --test layout_lock
cargo test --locked -p e3-tests --test integration -- --list
```

Select a named scenario from the list rather than launching every expensive integration or ignored
proof benchmark. [Root package scripts](../../../package.json) provide the broader integration and
real-proof suites.

## Full-proof scenarios

`trbfv_scenario_standby_node`, `trbfv_scenario_party_offline_after_c0`,
`trbfv_scenario_restart_during_c4` and `trbfv_scenario_restart_during_c6` each run a whole E3 with
real proofs, about nine minutes each, so CI gives each its own leg. The two restart scenarios give
the nodes persistent stores, stop a roster member while its C4 or C6 proof is pending, and rebuild
it from those stores and its identity; the run must still finish with that member publishing its
share. All four use the committee the local circuits were built for
(`circuits/bin/.active-preset.json`, `minimum` when it is absent) and read only proof-system and
timeout settings from the environment: `E3_CUSTOM_BB`, `CIPHERNODE_SKIP_PROOF_AGGREGATION`, and the
`E3_*_COLLECTION_TIMEOUT_SECS` collector timeouts.

```sh
E3_CUSTOM_BB=$(which bb) cargo test -p e3-tests --test integration trbfv_scenario_standby_node -- --exact --nocapture
```

`benchmark_trbfv_actor` is `#[ignore]`d. The [circuit benchmark](../../zk/benchmarks/README.md) runs
it in release mode with `BENCHMARK_MODE`, `BENCHMARK_MULTITHREAD_JOBS`, `BENCHMARK_SUMMARY_OUTPUT`,
and `BENCHMARK_FOLDED_OUTPUT`, and parses the JSON it writes; keep those shapes stable. Correctness
scenarios never read `BENCHMARK_*`.

## Prerequisites and assurance

Prepare root `pnpm evm:build` and `pnpm fixtures:build`, with bash, solc, jq, and Anvil for chain
scenarios. [Prover setup](../../zk/prover/README.md) explains matching nargo/bb/artifacts and
build-time fixture side effects. Even the layout target compiles the runtime dependency graph. Tests
may skip when tools are absent, and ignored scenarios need explicit selection.

This harness enables builder `test-helpers` and `test-only-skip-proof-aggregation`. Cargo feature
selection is dev-only; fixture-bin builds do not enable those features. Test feature unification can
enable them throughout a workspace test graph; successful tests do not establish production feature
containment or recursive proof verification. Deterministic RNGs and mocked transport are isolated
per node but do not model all distributed failures. See
[persistence and replay](../../../docs/architecture/persistence-and-replay.md) for current
restart/overflow assurance limits. See [AGENTS.md](AGENTS.md) for isolation and regression-design
guidance.
