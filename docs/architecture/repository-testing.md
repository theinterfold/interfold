# Ciphernode test harness and evidence

Owners: [shared helpers](../../crates/test-helpers/),
[integration scenarios](../../crates/tests/tests/), and
[real recursive-proof tests](../../crates/zk/prover/tests/). Root
[package scripts](../../package.json) own setup and commands. This page describes what the test
boundaries establish, not a replacement inventory of tests.

## In-process nodes and simulated transport

`e3-test-helpers` supplies deterministic setup, application helpers, history collectors, and
`Libp2pMock`. The integration crate's
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
