# e3-ciphernode-builder

## Purpose

Library composition root for a ciphernode: it connects storage, chain adapters, networking, request
routing, and protocol capabilities. It is not an executable; normal operators use the
[CLI](../cli/README.md), whose [entrypoint](../entrypoint/README.md) also owns process fencing.

Production startup and the in-process test harness use the same builder. It returns a
`CiphernodeHandle` once the node has completed startup recovery and reached live-source readiness.

## Map

| Module                                                           | Responsibility                                                                 |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| [`builder/mod.rs`](src/builder/mod.rs)                           | Public builder, options, defaults, and full/bootstrap profiles.                |
| [`builder/startup.rs`](src/builder/startup.rs)                   | Startup phases and their `Storage`, `Restart`, `Live`, and `Protocol` outputs. |
| [`builder/evm.rs`](src/builder/evm.rs)                           | Contract readers and writers for enabled chains.                               |
| [`builder/chain_parameters.rs`](src/builder/chain_parameters.rs) | Chain-derived DKG fold contexts and accusation vote validity.                  |
| [`builder/extensions.rs`](src/builder/extensions.rs)             | Request routing, proof recovery, and full-node protocol extensions.            |
| [`builder/sortition.rs`](src/builder/sortition.rs)               | Sortition and ciphernode-selector assembly from restored state.                |
| [`builder/net.rs`](src/builder/net.rs)                           | Network policy, libp2p/channel transport, and startup buffering.               |
| [`builder/restart.rs`](src/builder/restart.rs)                   | Restart decisions derived from local lifecycle stages.                         |
| [`recovery.rs`](src/recovery.rs)                                 | Restart-state backfill and committee snapshot reconciliation.                  |
| [`finalized_lifecycle.rs`](src/finalized_lifecycle.rs)           | Reconciliation with finalized chain lifecycle.                                 |
| [`ciphernode.rs`](src/ciphernode.rs)                             | Running node handle, health signals, and shutdown.                             |

## Startup lifecycle

`build_inner` assembles the node in phases: storage admission and restart recovery, the live event
pipeline, protocol infrastructure, EVM adapters, extensions, networking, and synchronization. The
phase outputs carry the resources needed by subsequent steps. The module documentation in
[`startup.rs`](src/builder/startup.rs) explains the sequence; the
[persistence contract](../../docs/architecture/persistence-and-replay.md) describes replay and
failure boundaries across crates.

## Choose a node profile

The public constructors are:

```rust
// Signatures; types come from e3-utils, e3-crypto, and e3-zk-prover.
pub fn full(rng: SharedRng, cipher: Arc<Cipher>, zk_backend: ZkBackend) -> Self;
pub fn bootstrap(rng: SharedRng, cipher: Arc<Cipher>) -> Self;
```

- **Full** installs threshold keyshare, public-key/plaintext aggregation, proof workers, accusation
  voting, commitment checks, and protocol contract readers/writers.
- **Bootstrap** serves discovery/history with networking and the Interfold reader. It does not join
  committees, prove, sign protocol messages, or send protocol transactions. It still needs an
  operator identity and uses routing, lifecycle, sortition, and DA infrastructure. It may start
  without peer history when none is available.

Persisted directories are role-stamped: full and bootstrap nodes cannot reuse each other's store.

## Configure and start

The production recipe is [entrypoint startup](../entrypoint/src/start/start.rs): seed a `SharedRng`,
load the password-backed `Cipher`, choose a profile, then configure:

- `with_chains(&[ChainConfig])` and `with_network(profile, peers, quic_port)`;
- `with_persistence(&log_path, &kv_path)` (otherwise storage is in memory);
- `with_multithread_config(reserve_threads, concurrent_jobs)` for full-node CPU/memory admission;
- startup buffer limits, name/logging, and optional shared stores for local commands.

`build().await -> anyhow::Result<CiphernodeHandle>` completes initial replay and live-source
readiness before returning. Run it inside an Actix runtime; its actor setup uses local tasks, so do
not move the startup future to an arbitrary `tokio::spawn` worker. Enabled chains need reachable RPC
endpoints and deployed contracts. Full nodes also need matching
[Noir/Barretenberg artifacts](../zk/prover/README.md); preparation may install artifacts. The
entrypoint applies a configured startup deadline around `build()`.

## Handle and shutdown

`CiphernodeHandle` exposes `bus()`, `eventstore()`, `aggregate_ids()`, `network_status()`, and the
operator address/peer ID. `with_history_collector()` enables the optional `history()`. Watch
`persistence_health()` and `gateway_failure()` for fatal storage or chain-ingestion failure; these
are explicit signals, not supervision of every actor panic.

The CLI supplies separate actor-thread panic monitoring. Library embedders must choose their own
process supervision. Full-node startup requires a live SlashingManager on every enabled chain;
bootstrap does not resolve managers or sign accusation votes.

Consume the handle with `shutdown(deadline).await`: it acknowledges shutdown handlers, flushes the
event pipeline, then drains snapshots and closes storage within the supplied deadline. See
[persistence and replay](../../docs/architecture/persistence-and-replay.md) for guarantees and
recovery limits, and [e3-tests](../tests/README.md) for in-process multi-node usage.

## Tests

From the repository root:

```sh
cargo test --locked -p e3-ciphernode-builder
```

This runs the crate's startup, profile, recovery, and handle tests. The finalized-lifecycle tests
start Anvil, so Foundry is required. Prepare the
[shared test prerequisites](../test-helpers/README.md#prerequisites-before-invoking-cargo) first;
the dependency graph includes Solidity fixtures and build-time Noir preparation.

Multi-node scenarios live in [e3-tests](../tests/README.md), which also uses this builder. List its
scenarios with `cargo test --locked -p e3-tests --test integration -- --list`, then select the
scenario to run. In-memory startup tests and persisted restart scenarios exercise different paths.

## Related documentation

- [Entrypoint](../entrypoint/README.md): production startup and process management.
- [Event system](../event-system/README.md): lower-level event runtime assembly.
- [Slashing](../../docs/architecture/slashing.md): chain-specific manager resolution.
- [AGENTS.md](AGENTS.md): conventions and constraints for changing this crate.
