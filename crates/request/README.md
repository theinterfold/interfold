# e3-request

## Purpose

Per-E3 context routing and lifecycle projection. The router admits requests from chain facts or
restored contexts, constructs their capability recipients through extensions, and forwards events.
It does not own the cryptographic statements implemented by those recipients.

## Map

| Location                                                                                                   | Responsibility                                                 |
| ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| [`routing/actor.rs`](src/routing/actor.rs), [`routing/handlers.rs`](src/routing/handlers.rs)               | Router/extension interface and mailbox delivery.               |
| [`routing/workflow.rs`](src/routing/workflow.rs), [`routing/event_buffer.rs`](src/routing/event_buffer.rs) | Admission/routing decisions and deferred recipient queues.     |
| [`routing/unadmitted_inputs.rs`](src/routing/unadmitted_inputs.rs)                                         | Bounded peer-event hold before chain admission.                |
| [`routing/effects/`](src/routing/effects)                                                                  | Context construction, hydration, checkpoints, and snapshots.   |
| [`context.rs`](src/context.rs), [`meta.rs`](src/meta.rs), [`hetrogenous_map.rs`](src/hetrogenous_map.rs)   | Per-E3 recipients, metadata, and typed dependencies.           |
| [`lifecycle/`](src/lifecycle), [`canonical_key.rs`](src/canonical_key.rs)                                  | Node-wide stage projection and shared confirmed-key authority. |
| [`repo.rs`](src/repo.rs)                                                                                   | Router/context/lifecycle persistence accessors.                |

Chain admission creates a context; extensions add dependencies and recipients as prerequisites
arrive. Deferred history reaches a new recipient before the creating event. Hydration restores
recipients from a checkpoint before replay, while lifecycle tracks progress outside any one
recipient's cryptographic state machine.

## Build a router

`E3Router::builder(bus, store)` supplies the metadata extension by default. Add capabilities with
`E3RouterBuilder::with(extension)` or `with_recipient("recipient_name", extension)`, then await
`build()` to hydrate and attach. Named recipients let the router defer relevant history until the
extension creates its actor. Use the
[ciphernode extension wiring](../ciphernode-builder/src/builder/extensions.rs) for a complete
composition, including restored selections and terminal-state gates.

`E3Extension` implements synchronous `on_event(context, event)` and async
`hydrate(context, snapshot)`. An extension can inject typed dependencies with
`E3Context::set_dependency` or register an Actix recipient with `set_event_recipient`. `TypedKey<T>`
retrieves dependencies without capability-specific casts. `E3MetaExtension` populates `META_KEY`;
`DKG_FOLD_ATTESTATION_CONTEXT_KEY` carries the corresponding proof context.

`E3Context::effects_enabled` distinguishes replay from live work. It stays false until the router
receives `EffectsEnabled`; extensions must pass that state to actors created during replay.

## Lifecycle and key authority

`E3LifecycleCoordinator` is a separate node-wide observer with persisted stage projection; it is
attached by [builder startup](../ciphernode-builder/src/builder/startup.rs). Terminal local state
does not itself prove confirmed chain completion, and failed contexts can remain alive for
accusation work. Peer traffic cannot create an admitted E3.

Peer events arriving before chain admission wait in a bounded memory-only queue. They follow the
admitting chain event in arrival order; a restart before admission loses that held history. This
queue is separate from deferred delivery to missing recipients.

`canonical_key::CanonicalPublicKeys` is the shared cache for confirmed key identity and
decryption-domain repair. Its EVM projection establishes authority; a local `PublicKeyAggregated`
intent cannot. Repository factory traits expose typed context, metadata, lifecycle, and
router-checkpoint storage to startup/recovery consumers.

See [persistence and replay](../../docs/architecture/persistence-and-replay.md) for checkpoint,
deferred-queue, overflow, and teardown limits.

## Tests

Run `cargo test --locked -p e3-request`. Routing/lifecycle `workflow_tests.rs` cover pure decisions;
[`routing/tests.rs`](src/routing/tests.rs) exercises checkpoint hydration and failed-context
teardown. Buffer/capacity tests cover per-E3/global limits and retained allocation; pre-admission
cases cover ordered delivery, overflow, teardown, and completed-E3 rejection. Context/typed-map
tests cover recipient order and lookup. Whole-node restart is in [e3-tests](../tests/README.md). See
[AGENTS.md](AGENTS.md) for routing/checkpoint changes.
