# DKG Restart Safety — Design Note

Status: design + Phase 1 implemented. Scope: making a committee node survive a crash/restart
**mid-DKG** so the E3 still completes (key aggregated + published on chain), without equivocation,
false accusations, or stalls.

## Background: the failure class

The DKG runs as a pipeline of **ephemeral actors** (`ThresholdKeyshare`, `ProofRequestActor`,
`ShareVerificationActor`, `CommitmentConsistencyChecker`, `PublicKeyAggregator`,
`ThresholdPlaintextAggregator`). Each one, for a given stage:

1. receives an input event (e.g. `ThresholdSharePending`, `ShareVerificationDispatched`),
2. dispatches async work as a `ComputeRequest` carrying a `CorrelationId`,
3. holds in-memory `pending` state keyed by that `CorrelationId`,
4. on the matching `ComputeResponse`, finalizes the stage and publishes the next event.

This pipeline implicitly **assumes the process never restarts mid-flight**. When it does, three
distinct things broke, one per actor, which we hit one at a time:

- `ProofRequestActor` — `pending_threshold` map lost; replayed `ThresholdSharePending` re-issued
  proofs but the original in-flight responses were dropped.
- `CommitmentConsistencyChecker` — created late (on `CommitteeFinalized` replay), so it missed the
  earlier `ProofVerificationPassed` (C0) events and false-accused honest peers on C0→C3. (Fixed by
  EventStore rehydration + buffering checks until rehydrated.)
- `ShareVerificationActor` — `pending` verifications lost; the `VerifyShareProofs` response came back
  with a correlation that didn't match the restarted actor's freshly-dispatched one, so it was
  dropped and the stage hung.

## Root cause (the unifying observation)

Two facts make the whole class:

1. **Correlation IDs are not stable across restart.** `CorrelationId::new()` is a per-process
   monotonic counter (`NEXT_CORRELATION_ID.fetch_add`), assigned in dispatch order. After a restart
   the same logical compute gets a different number.
2. **`ComputeEffectGate` dedups by request *content*** — `RequestKey = (E3id, ComputeRequestKind)`,
   ignoring the correlation — and forwards one copy of a duplicated request. So the correlation on
   the forwarded request (and hence the response) need not equal the one the restarted actor is
   waiting on.

Actors match responses by correlation, but the correlation doesn't survive restart → responses are
dropped → stages hang. Every per-actor bug above is a symptom of this.

A precondition for any fix: **compute inputs must be deterministic**, otherwise a regenerated
request differs and (a) can't match a persisted response and (b) trips equivocation. This is already
true: TrBFV share material is re-derived from persisted state (not re-sampled), and BFV share
**encryption** randomness is now derived deterministically from a per-node secret
(`derive_share_encryption_seed`, see `crates/keyshare/src/domain/share_generation.rs`).

## Design: content-derived correlation IDs (the keystone)

Make the correlation ID of a compute request a deterministic function of its content:

```
correlation_id = stable_hash(e3_id, ComputeRequestKind)
```

This is the right key because `ComputeRequestKind` is *already* the gate's dedup key and already
derives `Hash`/`Eq`. With deterministic inputs, the hash is stable across restart and identical for a
replayed vs. regenerated request.

Consequences, uniformly across every compute actor:

- The `ComputeResponse` correlation equals the correlation **any** actor instance (pre- or
  post-restart) would use → request/response matching survives restart. No per-actor bespoke
  recovery needed.
- It aligns with the gate's content-dedup: the correlation is now a function of the same content the
  gate keys on, so there is no "old vs new correlation" race — duplicate requests collapse and the
  single forwarded copy carries the correct, matchable correlation.
- It is idempotent: re-dispatching the same logical compute is a no-op at the gate, and a persisted
  `ComputeResponse` (same correlation) can finalize the stage.

Mechanics: `ComputeRequest::{new,zk,trbfv}` derive the correlation from content (the explicit
`correlation_id` parameter is removed, so the compiler forces every dispatch site to stop minting a
random one). Actors that track pending read `request.correlation_id` back. Non-compute correlation
uses (net/DHT request-response) keep `CorrelationId::new()`.

## Supporting pieces (already in place)

- **Deterministic inputs** — done (deterministic share encryption; TrBFV gen re-derived from
  persisted state).
- **Input re-drive on restart** — `ThresholdKeyshare::resume_in_flight_work` re-publishes
  `EncryptionKeyPending` / `ThresholdSharePending` from persisted state (byte-identical), and
  publishes a `DkgDocumentResyncRequest` so peers re-announce documents this node missed.
- **Consistency-checker rehydration** — `CommitmentConsistencyChecker` rebuilds its verified-proof
  cache from the EventStore on startup and buffers checks until rehydrated.

## Phasing

- **Phase 1 (keystone):** content-derived correlation IDs for compute requests. Fixes the
  `ShareVerificationActor` stall and structurally prevents the whole correlation-mismatch class.
- **Phase 2:** response replay — on restart, deliver persisted `ComputeResponse`s so already-finished
  stages finalize without re-running expensive ZK proofs. Sound because both the correlation and the
  proof outputs are deterministic.
- **Phase 3:** audit each compute actor for input-re-drive completeness via a shared helper, so every
  stage re-populates its `pending` from re-delivered inputs uniformly.
- **Phase 4 (separate, cross-cutting):** event retention for in-flight E3s. The *inbound* peer-document
  resync and any event-replay rehydration are bounded by snapshot compaction (observed: the resync
  responder re-announced only 1 of a node's documents because `since=0` returned post-snapshot events
  only). The compute-pipeline re-drive is state-based and snapshot-safe, so it is unaffected; this
  phase fixes the inbound document side, e.g. by not compacting an E3's events until it is terminal.

## Risks to validate

- **bb proving determinism** — Phases 1–2 and the no-equivocation guarantee assume identical witness
  ⇒ identical proof bytes. Add an explicit test.
- **No two *distinct* logical computes share identical content** — they shouldn't (content carries
  every distinguishing input), and the gate already assumes this; confirm for `VerifyShareProofs`
  with overlapping party sets.
- **Hash stability** — use a stable, explicit hash (not `std` `DefaultHasher`, whose output is not
  guaranteed stable across toolchain versions) so an E3 in flight across a binary upgrade still
  matches. 64-bit width makes collisions negligible.
