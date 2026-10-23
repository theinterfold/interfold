# Ciphernode design principles

This is the direction for new code and incremental refactors, not a claim that every existing path
already satisfies it. [Domain references](AGENTS.md) describe implemented contracts and open limits.
Deployed behavior, protocol statements, compatibility tests, and existing durable schemas constrain
changes; an architectural cleanup cannot silently change them.

## Capability before layer

Keep one protocol capability together. A small capability can stay in one file; separate actor,
workflow/state, validation, and effects only when they have distinct responsibilities. Do not create
empty layer trees or interfaces merely to make the directory symmetric. Name extracted files after
their operation, not generic `logic`, `runtime`, or a circuit number that hides their
responsibility.

KISS means the smallest cohesive solution. SOLID means clear reasons to change and interfaces that
actual callers need, not a trait around every function. Extend the existing owner before adding a
second copy of a formula, schema fact, or decision. When extracting shared logic, move its original
caller first and preserve behavior before adding another caller.

Thinness is about responsibility, not a line limit. Generated bindings and cohesive mathematical
algorithms can be long. Splitting one large `impl` across files does not remove mixed ownership.
Follow repository formatting and nearby naming; there is no architectural reward for arbitrary cuts.

## Decision, coordination, and I/O

- **Domain rules** decide threshold, ordering, membership, commitment consistency, identity, and
  state-machine legality from explicit inputs. Return typed decisions/errors, not logging alone.
- **Workflows** turn accepted facts and state into transitions and typed intents. Pure state,
  validation, and algorithm modules should not import Actix, concrete repositories, network clients,
  wall clocks, or process execution. Inject time and external outcomes as inputs.
- **Actors** serialize a runtime partition, validate outer messages, invoke decisions, correlate
  outcomes, schedule/cancel work, and supervise owned children. They are concurrency boundaries, not
  containers for cryptographic rules or inline blocking computation.
- **Effects/adapters** execute bounded crypto, storage, RPC, network, timer, and process operations.
  Translate external representations and enforce the relevant trust boundary before progression.
- **Composition roots** wire concrete implementations. Lower-level crates must not import the full
  ciphernode builder merely to reuse a value or test helper.

Existing separation is often module-level: event vocabulary includes rich cryptographic types and
many actors still know concrete repositories. Do not claim a clean crate dependency graph already
exists, or hide those dependencies behind empty ports. Compatibility re-exports may preserve
callers, but should not acquire a second implementation or invert ownership.

## Recoverable orchestration

Nodes and contracts remain choreographed across the network; no node becomes a global coordinator.
Within a node, an E3 workflow should make accepted facts, canonical participants, pending
operations, deadlines, and cancellation ownership explicit. A local computed result is an intent,
not proof that the chain accepted it. Projections must not silently become a second authority.

The **target** for a correctness-relevant operation is:

1. Authenticate and deduplicate the input.
2. Reduce to state and intents without I/O.
3. Commit transition/intent before acknowledging or dispatching it.
4. Execute outside the decision's critical section.
5. Persist a correlated result before it unlocks the next step.

Use stable semantic operation keys, versioned retry inputs, explicit result types, retry/deadline
classification, and terminal failure mapping. If snapshot/outbox atomicity is unavailable, a durable
intent may be the replay authority; merely queueing a persistence message is not proof of
durability. This is a design obligation, **not** a general transactional outbox provided by today's
runtime.

The remaining durable intent/result boundary is tracked in
[#2265](https://github.com/theinterfold/interfold/issues/2265); it requires schema and crash
evidence, not just moving effect functions between files.

Assume duplicate delivery, not exactly-once execution. Idempotent transitions, effect deduplication,
and external preflight/replay protection must make repeats safe. At-least-once delivery itself still
has [live fanout and recovery gaps](persistence-and-replay.md#remaining-durability-gaps).

Classify every state field by loss semantics:

| Class     | Obligation                                                                        |
| --------- | --------------------------------------------------------------------------------- |
| Durable   | Loss can change outcome or stall progress: persist/version before acknowledgment. |
| Derivable | Name authoritative durable inputs and test reconstruction.                        |
| Ephemeral | Safe to lose; bound memory and make loss behavior explicit.                       |

A timer handle or worker correlation is not automatically safe to lose. Preserve enough semantic
state to recreate deadlines, proof bundles, random contributions, roles, and undispatched effects.
Persist absolute deadline and purpose; restart must not buy another full timeout or fallback delay.
Current volatile accusation state and other exceptions stay explicit in their domain documents.

Distinguish facts, intents, results, queries, and process signals even when legacy types call all of
them events. Facts/results and outcome-changing intents need recovery semantics; queries may be
ephemeral. Current-boot readiness/effect signals must not be replayed as previous-boot instructions.
Preserve stable logical identity separately from transport delivery and receiver-local context.

## Bounded runtime boundaries

Partition protocol work by chain/E3 where ordering requires it, without introducing a global
ordering dependency accidentally. Correctness-critical delivery needs acknowledgment, timeout, and
retry or escalation; fire-and-forget is not a substitute. Bound queues by count **and retained
bytes**, with an explicit overflow policy. Runtime telemetry may be lossy only when loss is
distinguishable.

Heavy work belongs in resource-bounded pools, not mailbox threads. Every spawned operation needs an
owner, completion/error route, cancellation behavior, and shutdown boundary. Already-running native
work may not be preemptible; document that limit instead of calling all work canceled. A local
prover, worker, or RPC failure must not become evidence of peer misconduct.

These are design goals with current exceptions. [Persistence](persistence-and-replay.md),
[network delivery](network-delivery.md), [DKG](dkg.md), and [decryption](threshold-decryption.md)
own their actual ordering, buffering, failover, and durability contracts.

## Evidence for a refactor

Test decisions without actors where possible; test runtime acceptance, saturation, shutdown, and
effect fencing at the adapter boundary. Cover duplicates, reordered/late outcomes, invalid inputs,
threshold boundaries, and preset-dependent proof multiplicity. Do not duplicate stronger owner tests
or reimplement the algorithm inside an assertion.

Recovery changes need crash points before commit, after commit/before dispatch, during execution,
after external success/before result commit, and before the next transition. Compare uninterrupted
execution with recovery, including external effects. Full replay and snapshot hydration equivalence
is a target requiring evidence, not an existing general guarantee.

Use production replay (`ReplaySpool::load`/`replay`) for replay regressions, with a separate source
bus so fixture creation cannot seed destination clocks/dedup. Slow real-proof/FHE tests belong after
fast tests with measured timeouts; a long-running warning is not a failure or permission to disable
them. Compilation does not establish proof verification.

Refactor one recoverable slice at a time. Preserve observable behavior, keep required compatibility
tests, and remove a legacy path only after comparison supports it. Storage/wire changes need the
[compatibility decision](../../CONTRIBUTING.md#protocol-compatibility) and [rollout](upgrades.md),
not a documentation-only waiver.
