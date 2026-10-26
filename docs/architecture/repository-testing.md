# Ciphernode test harness and evidence

Owners: [mechanical test support](../../crates/test-support/),
[BFV ballot fixtures](../../crates/bfv-test-support/),
[integration scenarios](../../crates/tests/tests/), and
[real recursive-proof tests](../../crates/zk/prover/tests/). Root
[package scripts](../../package.json) own setup and commands. This page describes what the test
boundaries establish, not a replacement inventory of tests.

## In-process nodes and simulated transport

### Fixture ownership (#2325)

The consumer audit on `d1a6d2384` separates the former `e3-test-helpers` families as follows.
Directory placement does not change protocol ownership or introduce a `testing/` capability family.

| Fixture family                                       | Independent consumers                                                                  | Decision and dependency boundary                                                                                                          |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Seeded RNGs, scoped tracing, bb discovery            | Aggregation, events/event-system, EVM, TrBFV, builder/entrypoint, prover, system tests | Share mechanical support in unpublished `e3-test-support`, with no internal dependencies.                                                 |
| Isolated event bus and history/error collectors      | Aggregation, EVM, prover                                                               | Share behind event-system's opt-in `test-support` feature; no BFV setup or node composition.                                              |
| BFV/RNG/event setup tuple                            | Aggregation (other callers discard all BFV values)                                     | Local private aggregation fixture, composed from the event fixture and canonical parameter builders.                                      |
| Threshold-share/public-key/decryption-key generation | TrBFV integration suite only                                                           | Local `trbfv/tests/common`; retain production share operations and parameter/codec owners.                                                |
| Encrypted random ballots and tally                   | TrBFV integration and system tests                                                     | Share only this family in unpublished `e3-bfv-test-support`; depend on FHE primitives, not event/runtime/prover crates.                   |
| Mock gossip/DHT/restart transport                    | System harness only                                                                    | Local `tests/tests/ciphernode_system`; retain its existing transport regression tests.                                                    |
| Synthetic committee registration                     | System integration suite only                                                          | Local private system-test fixture; not a committee policy API.                                                                            |
| Anvil discovery                                      | Prover integration suites only                                                         | Local `zk/prover/tests/common`.                                                                                                           |
| Encryption/parameter CLI fixtures                    | External system integration scripts                                                    | System-test owner bins; keep CLI names/arguments and canonical commitments/codecs. Separate bin dependencies from dev-only node assembly. |
| Unused helper edges                                  | No direct source, macro, or bin consumer                                               | Remove with the helper package; check focused graphs/features, not just a unified workspace build.                                        |

The old package's normal edges to aggregator, data, FHE, keyshare, multithread, request, SDK,
sortition, and bincode have no direct fixture consumer. Transitive feature enablement is not a
contract: fixture bins explicitly request parameter `abi-encoding`, and each event-fixture consumer
opts into its feature. Sync has no helper source use and needs no replacement dependency. The
repository containment check keeps both support packages unpublished and dev-only, rejects internal
normal/build dependencies from them, and prevents production dependencies on system tests.

This is test placement/dependency isolation only: no persisted/wire layout, cryptographic statement,
parameter, event identity, or deployed verifier changes. Neither `protocol_version` nor
`node_generation` changes; no runtime rollout/reset or data migration is required. Rollback is a
source-level revert, without regenerating artifacts. Proof/chain prerequisites remain separate from
native fixture evidence.

The old Cargo package/import paths are removed rather than compatibility-re-exported; known
repository consumers move with them. External test consumers must migrate their imports. The two new
support packages and the system-test package are unpublished; production publishing order is
unchanged. CI still obtains the same fixture-bin names through the integration prebuild script.

Mechanical support does not assemble runtimes. Event-system owns isolated bus/history fixtures;
aggregation keeps its BFV setup private. The integration crate keeps `Libp2pMock` local. Its
[`CiphernodeSystemBuilder`](../../crates/tests/tests/ciphernode_system/mod.rs) assembles several
ciphernode handles in one process. `simulate_libp2p()` connects their broadcast events and DHT
records through the mock. `restart_node` shuts down a node, rebuilds it through the supplied
closure, and replaces its mock-network attachment.

This exercises node actors without real QUIC, discovery, peer-held DHT persistence, or separate
operating-system processes. Shared-process scheduling and orderly restart are not arbitrary crash
recovery. [Network delivery](network-delivery.md) and [persistence](persistence-and-replay.md)
retain the production gaps those scenarios do not close.

## Proofs and compatibility

ZK configuration, production preparation, artificial samples, build operations, and benchmark
orchestration have [separate owners](../../crates/zk/README.md). Samples use dev-dependencies except
for the unpublished benchmark tool; no package may depend on that benchmark owner. The repository
containment check handles aliases and target-specific dependency tables.

`pnpm test:circuit-build` and `pnpm test:circuit-bench` cover tooling contracts without launching a
full proof campaign. Benchmark schema 2 keeps production Rust phases separate from historical
`isolated_nargo`, integration wall time, and overlapping job time. Missing measurements stay null;
failed stages fail the run. Replay re-verifies saved proofs without recreating them; report runs no
compiler, prover, integration, or EVM command and does not overwrite saved data.

Integration setup can locate `bb` or install the required backend/artifacts. The test crate also
enables test-only proof-aggregation support: inspect the selected scenario's settings before calling
a passing run real-proof coverage. Production rejection of proof skipping is a separate boundary.
[Circuit artifacts](circuit-artifacts.md) owns matching tools, presets, committees, and keys.

`layout-lock` fixtures check explicitly registered persisted/wire roots. They do not cover every
type, store key, encrypted payload, or log frame. [Schema validation](persistence-and-replay.md)
owns their compatibility meaning; refreshing a fixture is not a migration.

Start with the affected owner's focused Cargo tests. Use `pnpm rust:test` for the configured Rust
suite, `pnpm rust:test:proofs` for real recursive-proof scenarios, and `pnpm test:integration` for
the external integration harness. These are different boundaries, not interchangeable success
signals. A proof statement change needs the relevant real-crypto and Noir coverage; a compile or
mock-network pass is insufficient. Secure-only paths need secure witnesses.

For recovery tests, assert accepted state and pending effects after the chosen failure point. Do not
substitute handler counts, elapsed sleeps, or a higher cursor for observable delivery and
durability. [Design principles](design-principles.md#evidence-for-a-refactor) describes the target
comparison with uninterrupted execution.
