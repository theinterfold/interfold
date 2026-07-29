# Ciphernode Actor Audit

This audit records the repository-wide thin-actor and source-layout review. Read it with
[`ARCHITECTURE.md`](ARCHITECTURE.md), which defines the target, and
[`CRATES_ARCHITECTURE.md`](CRATES_ARCHITECTURE.md), which describes the implementation.

## Method

An actor is thin when it has one runtime reason to change: mailbox serialization, routing,
scheduling, lifecycle, or supervision. Line count is evidence, not the definition. Roughly 300
production lines triggers a responsibility review; tests, generated bindings, and cohesive
cryptographic algorithms are judged separately.

The audit checked all nine crates that originally contained `src/actors/`. Before this refactor, 17
production actor modules were over the review threshold; the largest were `ThresholdKeyshare` (2,198
lines), `PublicKeyAggregator` (1,591), `ProofRequestActor` (1,344), and
`ThresholdPlaintextAggregator` (1,029).

The first extraction made the actors thin but retained layer-first `actors/`, `workflow/`, and
`domain/` trees. That made placement hard to infer because one protocol capability was scattered
across several top-level folders. The follow-up layout groups implementation by capability and uses
the same role vocabulary inside each capability. Root compatibility files preserve established Rust
paths; they do not own implementation. Inline test suites were also moved beside the roles they
exercise so production responsibility size remains visible.

## Findings by crate

| Crate           | Actors reviewed                                                                                  | Result                                                                                                                                                                                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `e3-aggregator` | committee finalizer, keyshare/decryption buffers, public-key aggregator, plaintext aggregator    | `committee_finalization`, `public_key_aggregation`, and `plaintext_aggregation` each contain their actor, handlers, workflow/state, semantic effects, and tests.                                                                                       |
| `e3-evm`        | parser/router/hub, chain gateway, readers, registry/interfold/slashing writers, log fetcher      | Each chain capability owns its actor plus events/workflow/effects. `log_fetching` is explicitly an adapter capability; provider and transaction work is no longer hidden below actor `runtime/`.                                                       |
| `e3-keyshare`   | encryption/share/decryption collectors, `ThresholdKeyshare`                                      | The `threshold_keyshare` capability contains the request-local coordinator, collectors, persisted state, pure DKG calculations, handlers, and semantically named effect operations. Transient async-gap data remains grouped in `PendingKeyshareWork`. |
| `e3-net`        | event buffer/translator, sync manager, document publisher/converter                              | Admission, readiness, rebroadcast, historical sync, conversion, and DHT/gossip effects are isolated. The actors now own transport ordering and lifecycle rather than document-validation policy.                                                       |
| `e3-request`    | lifecycle coordinator, E3 router                                                                 | `routing` and `lifecycle` contain predictable actor/workflow roles; context construction, snapshots, and the request event buffer are named beside routing instead of hidden in a generic runtime package.                                             |
| `e3-slashing`   | accusation manager, commitment consistency checker                                               | `accusation_voting` and `commitment_consistency` each co-locate the actor shell with deterministic workflow decisions and adjacent tests.                                                                                                              |
| `e3-sortition`  | sortition, ciphernode selector                                                                   | `sortition` contains actor, registry, selection backend, ticket rules, and retention; `ciphernode_selection` contains its actor and handlers.                                                                                                          |
| `e3-sync`       | bootstrap/replay functions and messages                                                          | This crate has no Actix actor. The `sync` capability honestly names its service, state, workflow, preflight, history collection, and tests.                                                                                                            |
| `e3-zk-prover`  | proof requester, share verifier, C0 verifier, node proof aggregator, ZK worker, commitment links | Proof capabilities co-locate actor, handlers, state/workflow, effects, and tests. Effect files use semantic proof-operation names instead of unexplained `c0`–`c7` filenames; pure commitment links have their own capability.                         |

## State classification applied

- Persisted workflow state: aggregation and keyshare state enums stored through repositories.
- Derivable state: canonical committee/preset caches rebuilt from repositories and replay.
- Ephemeral effect state: correlation IDs, collector addresses, timer handles, early-arrival
  buffers, and in-flight submission guards. These are grouped and named rather than mixed into
  protocol state.
- External authority: EVM contract state. Writer preflights provide cross-restart idempotency, and
  startup pairs durable effect intents with their completion events before re-driving open loops.

`Persistable::try_mutate` now accepts the snapshot write into the bounded store mailbox before it
exposes the new value in memory. This does not turn snapshots into an external-effect outbox; the
append-only event log and chain remain the stated authorities. Synchronous `BusHandle` publication
still uses the existing burst-tolerant `do_send` path and is recorded as backpressure debt.

## Deliberate residuals

This refactor does not split files only to satisfy a number. Generated ABI bindings, circuit witness
construction, and cohesive FHE/math algorithms may exceed 300 lines. Large non-actor composition or
infrastructure coordinators—notably `CiphernodeBuilder`, `NetInterface`, and the multithread task
pool—need their own behavior-preserving projects if their responsibilities are changed.

The append-only event log now supplies durable effect intent: startup scans it in bounded pages,
pairs supported intents with completion/terminal events, and emits internal `EffectRetry`
envelopes only after `EffectsEnabled`. This closes the snapshot-advanced/open-loop loss mode.
There is still no atomic transaction/receipt outbox or full EVM reorg rollback; contract simulation
and canonical backfill remain the authority when a crash lands between submission and observation.
