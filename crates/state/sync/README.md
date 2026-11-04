# e3-sync

## Purpose

Startup replay and historical reconciliation shared by ciphernode composition. The crate provides
async services and pure schema/role decisions, not an Actix actor or an alternate owner of protocol
decisions.

## Map

| Location                                                                                                             | Responsibility                                                                  |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| [`service.rs`](src/service.rs)                                                                                       | Async startup, checkpoint projections, history collection, and effect barriers. |
| [`workflow.rs`](src/workflow.rs), [`state.rs`](src/state.rs)                                                         | Planning and snapshot-derived replay/chain cursors.                             |
| [`preflight.rs`](src/preflight.rs), [`schema_version.rs`](src/schema_version.rs), [`node_role.rs`](src/node_role.rs) | Raw store admission and schema/role decisions.                                  |
| [`replay_spool.rs`](src/replay_spool.rs)                                                                             | Paged disk-backed replay and aggregate-head merge.                              |
| [`history.rs`](src/history.rs), [`collect_history.rs`](src/collect_history.rs)                                       | Network/EVM history coordination and completion.                                |
| [`repo.rs`](src/repo.rs)                                                                                             | Cursor and schema/role repositories.                                            |

The service inspects compatible state, replays logged inputs after snapshot cursors, reconciles
external history, and acknowledges effect/live barriers. Planning/admission decisions are separate
from store/mailbox adapters, so they can be understood without starting a node.

## Startup integration

Storage admission precedes actor writes: inspect raw persisted schema and role, establish a
compatible checkpoint, and reconcile the router before resuming work. Public helpers include
`inspect_persisted_schema_version`, `preflight_schema_version`, `preflight_node_role`,
`reconcile_request_router_checkpoint`, and `project_restored_request_contexts`. The
[builder startup caller](../../ciphernode/builder/src/startup.rs) supplies repositories, aggregate
IDs, and the sequence-history reader in the production order.

`sync(bus, evm_config, repositories, aggregate_config, eventstore).await` performs the
replay/history workflow. Production uses `sync_with_net_ready` with a readiness future armed before
network startup, so an immediate no-peer signal cannot be missed. Do not run a second sync workflow
independently on an already-running node.

Replay preserves durable sequence order within each aggregate and uses hybrid logical clocks only to
merge aggregate heads. Current-boot `EffectsEnabled`, `SyncEffect`, and `SyncEnded` barriers
coordinate effects, reconciliation, and live buffering; old journal entries cannot satisfy those
startup acknowledgments. Failed required network history fails startup rather than silently treating
a partial history as complete.

`NodeRole`, `SnapshotMeta`, and schema/role decision types support inspection and recovery
consumers. Lower-level replay-spool/planner internals are not a separate public runtime API. See
[persistence and replay](../../../docs/architecture/persistence-and-replay.md) and
[historical network sync](../../../docs/architecture/network-delivery.md#historical-sync-and-coverage)
for bounds and known recovery gaps.

## Tests

Run `cargo test --locked -p e3-sync`; replay-focused targets do not need EVM/prover fixture builds.

[`tests/`](src/tests) separates schema/role admission, history failures, gates, and
checkpoint/replay scenarios. Replay-spool tests use actual paged load/replay and temporary storage,
including byte-limited pages and sequence-preserving merge. Whole-node hydration is in
[e3-tests](../../tests/README.md). See [AGENTS.md](AGENTS.md) for recovery changes.
