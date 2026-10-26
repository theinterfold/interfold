# e3-event-system

## Purpose

Runtime assembly of the event bus, per-aggregate event stores, sequencer, snapshot buffer, and data
store. [e3-events](../events/README.md) owns their messages/types and pipeline behavior;
[e3-data](../data/README.md) provides storage implementations. This crate wires them without
requiring a full ciphernode.

## Map

| Location                                                       | Responsibility                                                                      |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| [`event_system.rs`](src/event_system.rs)                       | Lazy backend/actor assembly, snapshot admission, clock seeding, stores, and health. |
| [`eventbus_factory.rs`](src/eventbus_factory.rs)               | Default process-local bus and disabled-handle factories.                            |
| [`global_eventstore_cache.rs`](src/global_eventstore_cache.rs) | Sequence/timestamp reader abstraction and optional reader cache.                    |
| [`global_store_cache.rs`](src/global_store_cache.rs)           | Opt-in process-local data-store access for commands.                                |

An enabled handle publishes through the sequencer to the aggregate store, then the bus admits the
event to snapshot tracking and fans out to subscribers. Snapshot writes go through the buffer to the
chosen data backend. Assembly shares one failure channel across persistence/admission paths; it does
not introduce protocol actors.

## Create a runtime

Choose `EventSystem::in_mem()` (`new()`/Default are equivalent) or
`EventSystem::persisted(log_path, sled_path)`. Both expose the same handles and query recipients.
Persisted setup checks schema compatibility before opening aggregate logs/indexes.

Configure `with_aggregate_config(...)` and either `with_fresh_bus()` or `with_event_bus(...)` before
calling getters. Initialization is lazy and keeps the first value; the uncustomized bus is
process-wide. Independent tests/nodes should use a fresh or explicit bus.

Inside an Actix runtime, a minimal isolated setup is:

```rust
use e3_event_system::EventSystem;
use e3_events::hlc::Hlc;

async fn setup() -> anyhow::Result<()> {
    let system = EventSystem::in_mem().with_fresh_bus();
    let store = system.store()?;
    let bus = system.enable_handle_with_hlc(Hlc::from_str("example")).await?;
    bus.flush_event_pipeline().await?;
    store.shutdown().await?;
    Ok(())
}
```

## Handles and health

`handle()` returns a disabled bus and registers snapshot pre-fanout admission.
`enable_handle_with_hlc` additionally waits for registration and seeds the clock above every store's
durable maximum before publication. Use that path for restored production stores, rather than
directly enabling a handle with an unseeded clock.

`store()` connects the snapshot buffer to the data store; `eventstore_reader()` provides
sequence/timestamp query recipients. Lower-level `buffer()`, `sequencer()`, and `eventstore_addrs()`
support specialized assembly. Watch `failure_receiver()` for explicit persistence/admission failure
signals. Global shared-store/reader caches are opt-in and process-local, not inter-process database
sharing.

Both in-memory and persisted assembly connect the aggregate router to that same failure watch. An
event with no configured store therefore reports fatal storage failure without a panic or dispatch
to another aggregate. The CLI or library caller must monitor the watch to stop its process.

For production lifecycle/replay use [CiphernodeBuilder](../ciphernode-builder/README.md) and the
[persistence contract](../../docs/architecture/persistence-and-replay.md).

## Tests

`cargo test --locked -p e3-event-system`, with [helper prerequisites](../test-helpers/README.md).

Inline `event_system.rs` scenarios cover both backends, multiple aggregates, pre-fanout admission,
durable-clock seeding, and shutdown final-state writes using temporary storage.
[`tests/sequencer.rs`](tests/sequencer.rs) covers sequence numbering, event bursts, and equal EVM
facts on the domain and snapshot paths; [`tests/bus_handle.rs`](tests/bus_handle.rs) covers HLC
restart seeding and causal order across buses. They exercise assembly, not a complete ciphernode
restart. [AGENTS.md](AGENTS.md) owns ordering/cache change rules.
