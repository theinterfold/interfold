# Interfold Ciphernode Target Architecture

This document defines the target architecture for the Rust ciphernode. It is a design constraint for
new code and the destination for incremental refactors; it is not a claim that every existing module
already complies.

For the current implementation and protocol sequence, read
[`CRATES_ARCHITECTURE.md`](CRATES_ARCHITECTURE.md) and [`flow-trace/`](flow-trace/). When documents
disagree with deployed contracts or executable protocol tests, the contracts and tests win and the
documents must be corrected.

The repository-wide thin-actor findings and deliberate residuals are recorded in
[`ACTOR_AUDIT.md`](ACTOR_AUDIT.md).

## Why Interfold Uses Actors

Interfold is an asynchronous, multi-party cryptographic workflow. A node concurrently receives chain
logs, peer messages, timers, proof results, storage acknowledgements, and operator signals. Work is
partitioned by E3 and must remain responsive while cryptographic jobs run for seconds or minutes.
Actors are a good fit for those concurrency boundaries.

Actors are not the domain model. Putting every rule, state transition, and external effect in an
Actix handler creates large stateful objects that are hard to test and impossible to replay with
confidence.

The governing principle is:

> Actors are concurrency boundaries. Deterministic reducers own protocol and workflow decisions.
> Effect runners perform crypto, storage, network, and chain I/O. Every correctness-relevant
> transition and intent is recoverable.

This means Interfold keeps global choreography between nodes while using explicit, persisted local
orchestration for each E3.

## Sources of Authority

In descending order:

1. Deployed contract behavior and protocol/circuit invariants.
2. Compatibility and end-to-end tests.
3. Durable event and snapshot schemas already used by production nodes.
4. [`flow-trace/`](flow-trace/) and [`CRATES_ARCHITECTURE.md`](CRATES_ARCHITECTURE.md).
5. This target document.

A cleanup must never silently change committee ordering, threshold meaning, proof multiplicity,
hashing, signatures, circuit witness shape, event identity, or replay semantics. Such a change is a
protocol migration and requires explicit versioning and compatibility tests.

## Canonical Module Structure (Normative)

The filesystem is organized by capability first and role second:

> Folders answer “what protocol capability am I changing?” Files answer “what role does this code
> play in that capability?”

This keeps all code needed to understand one protocol slice together. It also avoids top-level layer
directories whose contents grow into unrelated lists of actor names, workflow names, and domain
names.

```text
crates/<crate>/src/
  lib.rs
  <small_capability>.rs
  <capability>/
    actor.rs
    handlers.rs
    state.rs
    workflow.rs
    transitions.rs
    intents.rs
    effects.rs
    validation.rs
    tests.rs
  messages.rs
  repo.rs
```

Only create the files a capability needs. A pure capability that fits in one file stays at the crate
root, for example `network_status.rs`. Once it needs multiple roles, create one capability directory
and move the implementation into it. Do not create an empty directory hierarchy in advance.

The standard role names are:

| File             | Owns                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------- |
| `actor.rs`       | actor identity, construction, owned runtime state, lifecycle, and public surface      |
| `handlers.rs`    | mailbox entry points and outer-envelope validation                                    |
| `state.rs`       | durable or derivable capability state and accepted input values                       |
| `workflow.rs`    | deterministic decisions, transitions, and intent production                           |
| `transitions.rs` | reducer implementation when separating it makes `workflow.rs` a clearer surface       |
| `intents.rs`     | typed effect intents when they would obscure the workflow                             |
| `effects.rs`     | persistence, crypto workers, bus publication, timers, network, chain, and process I/O |
| `validation.rs`  | reusable pure protocol validation                                                     |
| `tests.rs`       | focused capability tests when only one suite is needed                                |

Use `handlers/`, `effects/`, `transitions/`, or `tests/` only after the corresponding single file
has several independent concerns. Files below those directories use semantic operation names such as
`publish_result.rs`, `verify_key_proofs.rs`, or `fetch_history.rs`. Stage labels such as `c1.rs`,
`c5.rs`, and generic names such as `runtime.rs`, `helpers.rs`, `logic.rs`, or `utils.rs` are not
acceptable substitutes for a responsibility.

When a capability needs separate suites for separate roles, name them after the role:
`actor_tests.rs`, `workflow_tests.rs`, `state_tests.rs`, or the corresponding directory form. This
is preferable to several unrelated test modules hidden behind one generic `tests.rs`.

A specialized pure algorithm may use a semantic filename beside the standard roles when forcing it
into `workflow.rs` or `validation.rs` would hide what it does. Examples include
`derive_decryption_key.rs` and `ticket_selection.rs`. Its name must describe the protocol operation,
not its implementation mechanism or historical location.

### Where a new file goes

Use this decision order:

1. Identify the protocol capability that owns the behavior. Extend that directory; do not choose a
   top-level layer first.
2. If the behavior decides what should happen from explicit inputs, put it in `workflow.rs`,
   `validation.rs`, or a named pure algorithm file.
3. If it performs I/O or dispatches work, put it in `effects.rs` (or a semantic file below
   `effects/`).
4. If it receives an Actix message, put the entry point in `handlers.rs`; actor construction and
   lifecycle stay in `actor.rs`.
5. If no existing capability owns it, start with `<capability>.rs`. Promote it to a directory only
   when a second role appears.

`lib.rs` declares modules, composes the public surface, and re-exports stable APIs. Crate-wide
`messages.rs` and `repo.rs` are allowed when several capabilities genuinely share that vocabulary.
Concrete cross-capability adapters or startup composition may also remain at the crate root, but a
one-capability adapter belongs with its capability.

Root files named `actors.rs`, `domain.rs`, `workflow.rs`, `adapters.rs`, or `runtime.rs` may exist
as temporary compatibility views. They use `#[path = "..."]` declarations to preserve established
Rust module paths while implementation files live in capability directories. They must not acquire
new business logic and must not grow back into layer directories.

### Responsibility and dependency rules

Business logic lives with its capability. Pure protocol rules and calculations do not know which
actor invoked them; workflows deterministically turn state plus input into a new state and typed
intents. Actors apply those decisions and effects execute the resulting I/O.

```text
<capability>/actor.rs + handlers.rs ──► workflow.rs ──► state.rs / validation.rs
                 │                           │
                 └──────────────────────────► effects.rs ──► external systems
```

- `state`, `validation`, workflows, and pure algorithm files must not depend on Actix, repositories,
  network clients, wall-clock calls, or process execution.
- A workflow must not call concrete I/O. It returns explicit intents or typed decisions.
- Actors and handlers own serialization, scheduling, supervision, and dispatch; they do not own
  threshold rules, canonical ordering, proof validity, or state-machine legality.
- Effects translate typed intents into bounded concrete work. They do not decide protocol
  progression.
- Compatibility views may expose old module paths but may not invert these dependencies.

Cross-crate dependencies must follow the workspace layering documented in
[`CRATES_ARCHITECTURE.md`](CRATES_ARCHITECTURE.md). A lower-level crate must not import an
actor-bearing orchestration crate merely to reuse a value type.

## Domain Layer

The domain layer owns rules whose result depends only on its inputs, including:

- threshold and committee calculations;
- canonical party, score, proof, and ciphertext ordering;
- membership and multiplicity validation;
- commitment/link consistency rules;
- state-machine legality;
- stable IDs, hashes, and signature preimages;
- typed decisions such as `Accept`, `IgnoreDuplicate`, `Reject`, `FailE3`, or `Accuse`.

Domain functions return typed errors and decisions. They do not publish events, log as their only
error handling, read the clock, or mutate actor state.

Protocol-specific invariants must be named and tested. Important examples include:

- runtime `party_id` is derived from the finalized committee normalized by ascending address;
- the active aggregator is the lowest eligible `party_id` after on-chain exclusions and the current
  phase's durable unresponsive-party set;
- the DKG aggregation circuit receives exactly `H` canonical honest NodeFold proofs and exactly `N`
  ordered committee addresses;
- C2a/C2b are singleton proofs, while C3a/C3b follow the configured recipient/row multiplicities;
- TrBFV and Noir witness dimensions come from the active preset, never from incidental vector size.

## Workflow Layer

Long-running protocol behavior is modeled as a deterministic transition:

```rust,ignore
pub struct Transition<S, I> {
    pub state: S,
    pub intents: Vec<I>,
}

pub trait Workflow {
    type State;
    type Input;
    type Intent;
    type Error;

    fn reduce(
        state: &Self::State,
        input: Self::Input,
    ) -> Result<Transition<Self::State, Self::Intent>, Self::Error>;
}
```

An input is a fact already accepted at a trust boundary: a chain observation, verified peer message,
timer firing, effect result, or operator command. An intent describes work to perform, for example:

```rust,ignore
enum DkgIntent {
    PersistDeadline { deadline: Timestamp },
    GenerateEncryptionKey { operation_id: OperationId },
    VerifyShareBundle { operation_id: OperationId, party_id: PartyId },
    BroadcastThresholdShare { operation_id: OperationId },
    PublishFailure { operation_id: OperationId, reason: FailureReason },
}
```

Reducers may update persisted workflow state and emit zero or more intents. They do not await,
spawn, address actors, or execute an intent themselves.

Each intent that can change protocol outcome has:

- a stable operation/idempotency key derived from E3, stage, party, artifact type, and index;
- enough versioned data to retry after restart;
- an explicit result type;
- a retry classification (`never`, `bounded`, `until deadline`, or `operator intervention`);
- a terminal failure mapping where retry cannot restore progress.

## Actor Layer

An actor owns serialized access to one runtime partition. It may:

- receive and authenticate messages;
- preserve per-E3 ordering;
- load and persist workflow state;
- call a reducer;
- durably record transitions and intents;
- dispatch committed intents to effect runners;
- apply correlated results;
- schedule persisted deadlines;
- cancel work and stop child actors;
- expose health, queue, and progress signals;
- supervise or recreate owned children.

An actor handler must not:

- perform BFV/TrBFV/Noir calculations;
- execute `bb`, EVM RPC, libp2p, filesystem, or repository operations inline;
- encode protocol validity as an unstructured sequence of mutations and `do_send` calls;
- ignore a full or closed correctness-critical mailbox;
- keep restart-critical progress solely in memory;
- use detached tasks with no owner, cancellation, or shutdown barrier.

“Thin” is about responsibility, not line count. A handler that validates an envelope, invokes one
transition, commits it, and dispatches its intents is thin even if the surrounding actor contains
careful runtime plumbing. A 20-line handler that performs an irreversible unacknowledged send is not
architecturally sound.

## Adapter and Effect Layer

Effect runners own concrete side effects:

- BFV/TrBFV computation;
- ZK proving and verification processes;
- EventStore and snapshot storage;
- EVM reads and transaction submission;
- libp2p publication and synchronization;
- clocks and timers;
- local secret encryption and filesystem access.

Heavy computation runs in bounded worker pools, never in an actor mailbox thread. Pools are bounded
by both job count and estimated bytes. Jobs report correlation ID, operation ID, success/failure,
timing, and cancellation outcome.

Adapters translate external representations into domain values and enforce the boundary's trust
policy. Peer identity, committee membership, claimed party slot, signature, chain ID, E3 ID, proof
type, payload size, and schema version are checked before a message can drive a workflow.

## Durable Processing Model

The target event path is:

```text
EVM / libp2p / operator
          │
          ▼
 authenticated ingress adapters
          │
          ▼
 durable journal + stable event identity
          │
          ▼ partition by (chain_id, e3_id)
 per-E3 workflow actor → pure reducer
          │
          ▼
 committed effect intents
          │
          ▼
 bounded effect runners
          │
          ▼
 durable, correlated results ─────► workflow actor
```

Delivery is at-least-once. Exactly-once execution is not assumed. Correctness comes from stable
identity, idempotent transitions, effect deduplication, and on-chain/read-before-write guards.

For every correctness-relevant step:

1. Validate and deduplicate the input.
2. Reduce it to a new state plus intents.
3. Atomically commit the state transition and/or an outbox record before dispatch.
4. Acknowledge the input only after that commit succeeds.
5. Execute intents outside the actor's critical section.
6. Persist the correlated result before it can unlock the next transition.
7. Retry according to policy until success, terminal failure, cancellation, or persisted deadline.

If the current storage abstraction cannot atomically commit a snapshot and outbox entry, record the
intent itself as the durable source of truth and make replay re-derive the state. Never mutate
memory and then rely on a fire-and-forget persistence message as proof of durability.

## State Classification

Every state field is classified during review:

| Class     | Meaning                                          | Requirement                                            |
| --------- | ------------------------------------------------ | ------------------------------------------------------ |
| Durable   | Losing it can change outcome or stall progress   | Persist with a versioned schema before acknowledgement |
| Derivable | Reconstructible from authoritative durable facts | Document the source and test reconstruction            |
| Ephemeral | Cache/telemetry only; safe to lose               | Bound it and make loss behavior explicit               |

Pending proof bundles, decrypted-share progress, accusation votes/timeouts, retry state, active
aggregator designation, deadlines, and undispatched external effects are durable unless a stronger
authoritative source can deterministically recreate them.

Snapshots are optimization checkpoints, not a second authority. Event replay from an earlier
checkpoint and snapshot hydration at the same logical point must produce equivalent workflow state
and pending intents.

## Event and Message Taxonomy

Names must reflect semantics. Persisting all messages under one `Event` label hides important
reliability differences.

| Kind                  | Meaning                         | Examples                                                     | Default durability                          |
| --------------------- | ------------------------------- | ------------------------------------------------------------ | ------------------------------------------- |
| Fact                  | Something already happened      | `CommitteeFinalized`, `ProofVerified`, `CiphertextPublished` | Durable                                     |
| Intent                | Work that must be attempted     | `GenerateC5`, `PublishCommittee`, `ScheduleDeadline`         | Durable outbox                              |
| Result                | Outcome of an intent            | `C5Generated`, `PublishConfirmed`, `ComputeFailed`           | Durable                                     |
| Query                 | Request for current information | health/status/repository lookup                              | Ephemeral                                   |
| Infrastructure signal | Runtime lifecycle               | `EffectsEnabled`, readiness, shutdown                        | Durable only when needed for recovery/audit |

Legacy names may be retained for wire/schema compatibility, but their semantic kind must be
documented. For example, `ComputeRequest` is an intent even if its historical Rust type is stored in
the event journal.

All durable envelopes carry schema version, event ID, causation ID, origin ID, chain ID where
applicable, aggregate/E3 key, source, and timestamp/watermark metadata. Received network events keep
the sender's stable identity; local transport metadata must not accidentally create a new logical
event on every replay.

## Routing, Backpressure, and Ordering

- Protocol work is partitioned by `(chain_id, e3_id)` so one expensive or blocked E3 cannot pause
  unrelated E3s.
- Ordering is guaranteed within a partition. Global total ordering is used only where a documented
  invariant requires it.
- Correctness-critical sends are acknowledged and bounded by timeout. A failed send is retried or
  escalated; it is never only logged.
- Buffers are bounded by both item count and bytes. Overflow has an explicit policy and metric.
- Replay uses bounded paging/merge and the same acknowledgement semantics as live delivery.
- Queries and telemetry may use lossy delivery only when callers can distinguish
  loss/unavailability.

`do_send` is allowed for best-effort telemetry. It is not allowed for state persistence, workflow
progression, timers, proof/results, cleanup, network publication, or external transaction intents.

## Timers and Deadlines

Persist the absolute protocol deadline and timer purpose, not only an in-memory Actix handle. On
restart, compare the persisted deadline with an injected clock and deterministically emit either a
new timer intent or the overdue input. Timer cancellation is itself part of the workflow transition.

Staggered submitters use a stable rank and persisted attempt state. Restarting must not reset a
fallback delay in a way that suppresses the only remaining submitter.

## Choreography and Local Orchestration

Interfold remains choreographed across nodes and contracts: no node is the global coordinator.
Inside one node, a per-E3 workflow is explicitly orchestrated so its durable state answers:

- what facts have been accepted;
- which stage and canonical participants apply;
- which operations are pending, running, succeeded, or terminally failed;
- which deadlines remain;
- which actor/worker owns each in-flight operation.

The `E3LifecycleCoordinator` is a projection, not the source of truth. Authoritative stage comes
from canonical chain facts plus durable local workflow facts. A projection may be deleted and
rebuilt without changing execution.

## Schema Evolution

Rust type compatibility is not a storage migration strategy. Every durable event, snapshot, and
outbox payload has an explicit schema version and decoder policy.

- Adding/removing/reordering a field requires a compatibility test against checked-in fixtures.
- Bincode payloads are never assumed self-describing or forward compatible.
- A version mismatch either runs a tested migration or fails startup with an actionable error.
- Migrations are restartable and do not destroy the previous data until the replacement is verified.
- Wire compatibility and storage compatibility are reviewed separately.

## Testing Requirements

Domain and workflow tests are actor-free and deterministic. They cover:

- every legal and illegal transition;
- duplicates, reordering, missing parties, expulsion, and threshold boundaries;
- canonical ordering and proof multiplicities for every supported preset;
- intent idempotency keys and terminal failure mapping.

Runtime tests cover:

- mailbox saturation, unavailable recipients, and bounded timeouts;
- worker failure/cancellation and actor restart;
- duplicate fact/result delivery;
- shutdown barriers and effect gating.

Recovery tests use a crash matrix around each effect:

1. before transition commit;
2. after commit but before dispatch;
3. while the effect is running;
4. after external success but before result commit;
5. after result commit but before the next input.

Each case must converge to the same state and external outcome as uninterrupted execution. Snapshot
hydration and full replay must produce equivalent state plus pending intents.

Integration tests assert end-to-end protocol behavior. Long cryptographic tests run after fast
domain, workflow, crate, and workspace checks have passed.

The `test_trbfv_actor` tally check compares the complete result vector and requires one decryption
proof per tally. Empty, missing, and surplus tallies must fail even when the event sequence
succeeds.

The recursive `node_fold_correlated_sparse_self_slot_proves_and_verifies` test and the full
`test_trbfv_actor` flow belong to the slow lane. Debug builds may spend minutes in real proof/FHE
work and may emit a "running for over 60 seconds" progress warning. That warning is not a failure;
the test harness exit status is authoritative. Keep these tests enabled, run them last, and give CI
an explicit timeout based on measured debug-runtime headroom rather than weakening their coverage.

## Code Shape and Review Heuristics

Files and structs are organized around one reason to change. Roughly 300 lines is a review trigger,
not a mechanical limit: generated bindings, tables, and cohesive algorithms may be longer. A large
file must not combine unrelated message definitions, domain rules, persistence, actor handlers,
effect execution, and tests.

A struct is likely a god object when it owns several independent lifecycles, mixes durable and
ephemeral state without classification, or requires most dependencies for only a few handlers.
Extract behavior by responsibility:

1. pure domain rule or value;
2. workflow state and reducer;
3. effect port/runner;
4. repository/codec;
5. actor façade and message routing;
6. test support.

Do not hide coupling by splitting one `impl` into arbitrary files while keeping the same god struct.
The goal is smaller ownership and explicit contracts, not a lower line count alone.

## Migration Rules

Refactor one recoverable protocol slice at a time:

1. Lock current behavior with protocol and compatibility tests.
2. Classify its messages and state.
3. Extract pure domain decisions.
4. Introduce workflow state, inputs, intents, and stable operation IDs.
5. Add durable dispatch/result handling.
6. Move concrete I/O into bounded adapters.
7. Add crash/replay equivalence tests.
8. Remove the legacy path only after both paths agree.
9. Update `CRATES_ARCHITECTURE.md` and the relevant flow trace in the same change.

Temporary bridges are permitted when named, tested, and tracked for removal. New code must not add
another unacknowledged correctness edge merely because a neighboring legacy path still has one.

## Definition of Done for an Actor Refactor

An actor is considered architecturally thin when:

- its protocol decisions can be tested without Actix;
- its durable state and derivable/ephemeral fields are explicit;
- its handlers translate inputs, invoke reducers, commit, and dispatch intents;
- heavy work and external I/O run behind bounded effect interfaces;
- every critical send and persistence step has success/failure semantics;
- restart restores pending deadlines and effects;
- duplicate and out-of-order delivery is deterministic;
- supervision, cancellation, cleanup, readiness, and metrics are defined;
- documentation and flow traces describe the implemented behavior.

The actor model is therefore retained, but actors cease to be containers for the whole protocol.
They become reliable runtime shells around deterministic, recoverable workflows.
