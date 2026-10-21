# e3-events

## Purpose

Ciphernode event vocabulary and transport pipeline: protocol payloads, event contexts, bus
publication/subscription, durable sequencing, aggregate queries, and snapshot admission. Payloads
include cryptographic types; this is not a dependency-free collection of DTOs.

## Map

| Location                                                                                                                     | Responsibility                                                         |
| ---------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [`interfold_event/`](src/interfold_event)                                                                                    | Protocol payloads, event enum, proof/work envelopes, and typed events. |
| [`event_context.rs`](src/event_context.rs), [`hlc.rs`](src/hlc.rs)                                                           | Causal/durable context and hybrid logical clock.                       |
| [`bus_handle.rs`](src/bus_handle.rs), [`eventbus.rs`](src/eventbus.rs)                                                       | Publication, subscriptions, fanout, history, and barriers.             |
| [`sequencer.rs`](src/sequencer.rs), [`eventstore.rs`](src/eventstore.rs), [`eventstore_router.rs`](src/eventstore_router.rs) | Persist-before-dispatch sequencing and aggregate queries.              |
| [`snapshot_buffer/`](src/snapshot_buffer)                                                                                    | Event admission, state batches, aggregate delay, and drain.            |
| [`traits.rs`](src/traits.rs), [`data_events.rs`](src/data_events.rs), [`store_keys.rs`](src/store_keys.rs)                   | Event/storage interfaces, data commands, and durable key names.        |

Publication creates an unsequenced event; the sequencer appends it through the aggregate store
before fanout. Snapshot admission sees each occurrence before domain deduplication. Capability
handlers then update projections or request effects with the delivered causal context.

## Event model

`InterfoldEventData` holds domain payloads and `EventType` selects subscriptions.
`InterfoldEvent<S>` pairs a payload with `EventContext<S>`: logical ID, causation/origin, timestamp,
aggregate, source, and sequence state. `E3id` includes the chain ID, so equal numeric request IDs on
different chains are distinct. Import `e3_events::prelude::*` for the event
publisher/subscriber/context traits used by capability crates.

`Unsequenced` and `Sequenced` distinguish events awaiting persistence from durable occurrences.
Logical identity is not delivery identity: repeated equal facts can be distinct chain log
occurrences or verification batches.

## Runtime use

Most consumers obtain an enabled `BusHandle` from [EventSystem](../event-system/README.md) or
[CiphernodeBuilder](../ciphernode-builder/README.md), not by manually wiring the actors:

- `subscribe(EventType, recipient)` delivers matching sequenced events to Actix recipients.
- `publish(data, context)` preserves causation; `publish_without_context(data)` creates an origin.
- `with_ec(context)` provides a causally scoped handle for subsequent work.
- `EventStoreQueryBy<SeqAgg>` / `<TsAgg>` query per-aggregate sequence/timestamp history through a
  response recipient; apply count/byte limits and inspect response errors/progress.

`Sequencer` connects append/flush acknowledgment to bus fanout. `SnapshotBuffer` receives pre-fanout
admission, before domain deduplication, and batches state writes by event progress. The mechanisms
and their ordering are described in
[persistence and replay](../../docs/architecture/persistence-and-replay.md), not duplicated here.

Use `publish_shutdown_and_wait` and `flush_event_pipeline` for acknowledged shutdown/drain, followed
by the data store's shutdown. A successful enqueue alone does not prove durable acceptance. Explicit
store/admission health signals do not supervise every actor panic.

An event naming an unconfigured aggregate signals fatal storage failure instead of panicking or
writing to another aggregate. EventSystem connects that signal to node health; a standalone router
without the signal does not obtain process-level monitoring.

## Tests

Run `cargo test --locked -p e3-events` with the
[test-helper prerequisites](../test-helpers/README.md). Serialization compatibility spans saved
events and network envelopes; see [upgrades](../../docs/architecture/upgrades.md).

Tests are colocated with pipeline modules: stores cover append/query/failure behavior; bus tests
cover delivery/barriers; snapshot-buffer tests cover batching/timing; HLC tests cover
ordering/drift. Scenarios that need an assembled `EventSystem` live in
[e3-event-system](../event-system/README.md#tests). Production health monitoring and whole-node
restart are separate consumer tests. See [AGENTS.md](AGENTS.md) for identity, encoding, and pipeline
changes.
