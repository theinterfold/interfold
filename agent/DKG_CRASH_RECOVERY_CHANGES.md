# DKG Crash-Recovery — Detailed Change Log & Reasoning

Branch: `fix/crash-retry-e3` (rebased onto `origin/main` incl. `1fdbae7dd` "stop minting at tge",
which carries an idempotent `CiphertextOutputPublished` keyshare fix).

This document explains **every code change** made to let a committee ciphernode survive a `kill -9`
mid-DKG and still have the E3 complete (committee public key aggregated + published on chain) —
without equivocation, false accusations, or stalls. It is the implementation companion to:
- `agent/DKG_RESTART_SAFETY.md` — original design note / failure-class framing.
- `agent/DKG_CRASH_RECOVERY_FINDINGS.md` — the live-reproduction findings that drove the work.

The changes group into **seven workstreams** (A–G) plus mechanical call-site updates and tooling.
None of it is committed yet. Two items need review before landing — see [§11](#11-open-review-items).

---

## 0. The failure class

The DKG runs as a pipeline of **ephemeral actors** (`ThresholdKeyshare`, `ProofRequestActor`,
`ShareVerificationActor`, `CommitmentConsistencyChecker`, `PublicKeyAggregator`,
`ThresholdPlaintextAggregator`). Each stage: receives an input event → dispatches async work as a
`ComputeRequest` carrying a `CorrelationId` → holds in-memory `pending` state keyed by that id → on
the matching `ComputeResponse`, finalizes and emits the next event.

This pipeline implicitly **assumes the process never restarts mid-flight**. On restart, several
independent things broke; each workstream below fixes one. The unifying mechanism is the event-store
replay on boot: load snapshot → replay local events → EVM sync → P2P sync → `EffectsEnabled` →
dispatch historical events. In-memory `pending`/correlation state is lost, and ephemeral actors are
re-created *late*, so they miss earlier events unless explicitly rehydrated.

---

## A. Restart-safe request/response correlation (content-derived `CorrelationId`)

**Problem.** `CorrelationId::new()` is a per-process `AtomicUsize` counter. On restart it resets, so a
regenerated `ComputeRequest` gets a *different* id than the original; when its `ComputeResponse`
returns, the dispatching actor — whose `pending` map was rebuilt with new ids — can't match it and
**drops the response**, hanging the stage (observed: `ShareVerificationActor` verify hang;
`node_proof_aggregator` "orphan correlation" errors).

**Fix.** Make the correlation id a deterministic hash of the request content, so a replayed request
and its regenerated twin share one id that is stable across restarts.

- **`crates/events/src/correlation_id.rs`** — add `CorrelationId::from_seed(bytes) -> Self`:
  SHA-256 of the bytes, first 8 bytes → `u64` → `usize`. SHA-256 (not `std`'s `DefaultHasher`,
  which is not stable across toolchains); 64 bits makes collisions negligible.
- **`crates/events/src/interfold_event/compute_request/mod.rs`** — `ComputeRequest::{new,zk,trbfv}`
  **drop the `correlation_id` parameter** and derive it via
  `derive_correlation(e3_id, request) = from_seed(bincode(e3_id) ++ bincode(request))`. Callers that
  need the id read it back from the returned `ComputeRequest.correlation_id`.
- **`crates/multithread/src/effect_gate.rs`** — the `ComputeEffectGate` already dedups buffered
  compute effects by `(E3id, ComputeRequestKind)` (ignoring correlation). Tests updated to the
  no-correlation-arg constructor; a new `compute_corr()` helper asserts that a stale replayed copy
  and its regenerated twin **collapse to one** content-derived id (the gate's intended behaviour).

**Why this is safe.** The dedup key is the full request payload; only the correlation id differs
between a stale and a re-driven request, so collapsing them cannot drop a semantically distinct
compute. Determinism of the request content is guaranteed by workstream C (deterministic secrets).

Mechanical fallout: ~25 `ComputeRequest::{zk,trbfv}` call sites lost their `correlation_id` argument
(see [§9](#9-mechanical-call-site-updates)).

---

## B. No false accusations on restart (consistency-checker rehydration)

**Problem.** The `CommitmentConsistencyChecker` is a per-E3 ephemeral actor created **late** — on the
`CommitteeFinalized` replay during boot. By then the C0/C1 `ProofVerificationPassed` events verified
earlier in the replay have already passed and never reach it. Its cross-circuit links (e.g. C0→C3,
a `SourceMustExistInTargets` link) then evaluate against an **incomplete cache** and **false-accuse
honest peers**, triggering slashing.

**Fix (`crates/slashing/`).**
- **`domain/commitment_consistency.rs`** — add `cache_verified_proof(data)`: inserts a verified
  proof into the cache **without** evaluating links or emitting violations. Preload-only, so it can
  never re-emit a violation already handled before the crash. Two new tests pin the behaviour:
  `rehydrated_target_prevents_false_consistency_violation` (matching target rehydrated ⇒ no false
  violation) and `missing_matching_target_causes_violation` (proves the first test is meaningful and
  documents the pre-fix failure mode).
- **`actors/commitment_consistency_checker.rs`** — on startup, query the `EventStore` (threaded in as
  a `Recipient<EventStoreQueryBy<TsAgg>>`) for prior `ProofVerificationPassed` events and preload
  them via `cache_verified_proof`. **Buffer** incoming `CommitmentConsistencyCheckRequested` in
  `pending_checks` until rehydration completes (`rehydrated: bool`), so no link is evaluated against
  a half-built cache.
- **`commitment_consistency_checker_ext.rs`** + **`ciphernode-builder/src/ciphernode_builder.rs`** —
  thread `eventstore.ts()` through extension setup so the checker can query the store.
- **`domain/accusation_voting.rs`** — mechanical `ComputeRequest` call-site updates (workstream A).

---

## C. No equivocation on restart (deterministic share regeneration)

A node killed mid-share-generation **regenerates** its threshold-share material on resume. If that
regeneration is not byte-identical to what it (partially) committed before the crash, peers see a
different C0→C3 chain, raise a `CommitmentConsistencyViolation`, and (falsely) move to slash it —
which reverts on chain and stalls the E3. Three randomness sources had to be made deterministic.

### C.1 — C3 share-encryption randomness
- **`crates/keyshare/src/domain/share_generation.rs`** — add `derive_share_encryption_seed(party_id,
  sk_raw)` (SHA-256 over a domain tag + party_id + the node's secret-key bytes) and replace the
  `OsRng` at the BFV share-encryption site with `ChaCha20Rng::from_seed(...)`. RFC-6979-style: the
  RNG *source* becomes deterministic; the sampled distributions are unchanged, so the C3 circuit
  accepts the witness identically.

### C.2 — Threshold **secret** generation (`GenPkShareAndSkSss`)
The C.1 fix only covered C3 *encryption*; the **secret itself** (`SecretKey::random`), smudging
noise, and Shamir shares were still freshly sampled on re-issue (the resume path re-issues
`GenPkShareAndSkSss` from scratch when the in-flight `source` is incomplete). Fresh secret ⇒
different C0–C3 ⇒ the `C3aSkShareEncryption` consistency violation we reproduced live.

- **`crates/trbfv/src/gen_pk_share_and_sk_sss.rs`** — add `secret_seed: [u8;32]`
  (`#[serde(default)]`) to the request; build a single `ChaCha20Rng` driving **all** secret sampling
  from it. **All-zero seed ⇒ fall back** to the supplied entropic RNG (`from_rng`), so behaviour is
  unchanged for non-resumable callers and old serialized requests.
- **`crates/trbfv/src/gen_esi_sss.rs`** — same treatment for the **ESM (smudging-noise) Shamir
  sharing** (encrypted in C3b); otherwise C3b would equivocate next.
- **`crates/keyshare/src/domain/share_generation.rs`** — add `derive_secret_gen_seed(e3_id_bytes,
  sk_bfv_raw)`: SHA-256 over a domain tag + length-prefixed e3_id + the node's persisted **`sk_bfv`**
  (the BFV secret key, generated once in the encryption-key phase, carried forward, stable across
  restart, private).
- **`crates/keyshare/src/actors/threshold_keyshare.rs`** — in
  `handle_gen_pk_share_and_sk_sss_requested` derive the seed from `sk_bfv` + e3_id and pass it in;
  in `handle_gen_esi_sss_requested` derive a **domain-separated** seed (`"esi-sss:{e3_id}"`) so the
  two RNG streams never overlap.
- **`crates/keyshare/Cargo.toml`** — add `sha2`.
- **`crates/test-helpers/src/usecase_helpers.rs`** — pass `secret_seed: [0u8;32]` (entropic
  fallback) at the two test construction sites.

**Security (requires crypto-owner review).** The threshold secret is now a one-way (SHA-256) function
of `sk_bfv`. No entropy reduction: `sk_bfv` is full-entropy and already persisted encrypted at rest;
knowing the derived secret does not reveal `sk_bfv`. Cross-node threshold security is unaffected
(both secrets already live on the same node). Same trust model as the accepted C.1 seed.

---

## D. Inbound artifact re-delivery on restart (DKG document resync)

**Problem.** DKG share documents (BFV encryption keys, threshold shares, decryption-key shares)
travel over the **Kademlia DHT**, announced **once** via an ephemeral `DocumentPublishedNotification`
gossip. A node that was **down** when a peer first announced its document never learned the
(content-addressed) DHT key and **cannot recompute it**, so it can never fetch that inbound share.
Re-broadcasting only a node's *own* outputs doesn't help — it's the *peers'* shares that are missing.

**Fix — a resync request that asks alive peers to re-announce their documents.**
- **`crates/events/src/interfold_event/dkg_document_resync_request.rs`** (NEW) — the
  `DkgDocumentResyncRequest { e3_id, requester }` event. Re-announcing is idempotent (content-
  addressed DHT; receivers dedup by sender `party_id`).
- **`crates/events/src/interfold_event/mod.rs`** — register the event (module, re-export, enum
  variant, `get_e3_id()` arm, `impl_event_types!`).
- **`crates/net/src/domain/event_translation.rs`** — add it to `is_forwardable_event` so it crosses
  the gossip channel.
- **`crates/net/src/actors/net_sync_manager.rs`** —
  - `own_document_request(event)` maps a node's own `ThresholdShareCreated` /
    `EncryptionKeyCreated` / `DecryptionKeyShared` back to a `PublishDocumentRequested` (re-PUT +
    re-announce).
  - `handle_resync_request(e3_id)` — on receiving a peer's request, query the EventStore for that E3
    and re-announce our matching documents.
  - `handle_resync_response(e3_id, events)` — re-PUT/re-announce documents **and** re-gossip
    forwardable artifacts for the E3.
  - `maybe_rebroadcast_own_artifacts` / `handle_rebroadcast_response` — on `NetReady` (restart),
    re-broadcast our own forwardable + document artifacts.
  - Subscribe to `DkgDocumentResyncRequest`; Local source → gossip out **and** handle; Net source →
    handle.
- **`crates/keyshare/src/actors/threshold_keyshare.rs`** — `resume_in_flight_work` publishes a
  `DkgDocumentResyncRequest` when resuming a DKG phase; a periodic `ResyncTick` re-emits it
  (`notify_later`, 6 ticks × 8s) so peer artifacts produced *after* the first request still arrive.

---

## E. Re-drive in-flight DKG work on resume (`ThresholdKeyshare`)

**File: `crates/keyshare/src/actors/threshold_keyshare.rs`** (largest single change).

`resume_in_flight_work` (invoked on `EffectsEnabled`) now re-drives the node's **own** phase output
so a crash mid-phase doesn't lose a never-broadcast artifact, per state:
- `CollectingEncryptionKeys` → re-publish `EncryptionKeyPending` (C0 re-run over the fixed BFV key is
  deterministic).
- `GeneratingThresholdShare` → if the retained `source` is **complete**, re-publish
  `ThresholdSharePending` **byte-identically** via the new
  `build_and_publish_threshold_share_pending(state, source, ec)` helper (deterministic encryption,
  workstream C); otherwise re-issue `GenPkShareAndSkSss` from scratch — now safe because C.2 makes
  that byte-identical too.
- `AggregatingDecryptionKey` → re-publish from the retained `threshold_share_source`.
- `ReadyForDecryption` (only when `keyshare_published`) / `Decrypting` → re-publish `KeyshareCreated`
  / re-issue the decryption-share request.

Supporting state change — **`crates/keyshare/src/domain/keyshare_state.rs`** — adds
`threshold_share_source: Option<Box<GeneratingThresholdShareData>>` (`#[serde(default)]`) to
`AggregatingDecryptionKey`, so the byte-identical re-publish source survives the C3→C4 transition.

---

## F. Gossip mesh re-forms after restart (Fix 1)

**File: `crates/net/src/net_interface.rs`.**

**Problem.** gossipsub exchanges topic subscriptions **only on the first connection to a peer**
(`other_established == 0`). When a node restarts with the **same PeerId** while survivors still hold
the **stale connection** to its dead process, the rejoin is treated as non-first, peers never
re-advertise their subscriptions, and the rejoining node can't publish (`InsufficientPeers`) — even
though the connection is up.

**Approaches that did not work (so we don't retry them):** raising `idle_connection_timeout` (fixed
churn, not subscriptions, and *prolongs* the blocking stale connection); `add_explicit_peer`
(publish is still gated on known subscription state); an `unsubscribe()+subscribe()` re-advertise
toggle (gossipsub delivers the pair **out of order** — the `UNSUBSCRIBE` lands last and wipes the
subscription).

**Fix.** On `ConnectionEstablished`, track connection ids per peer
(`peer_connections: HashMap<PeerId, Vec<ConnectionId>>`). When a **second** connection to an
already-connected peer appears (signature of a same-PeerId rejoin over a stale connection),
`disconnect_peer_id()` the peer entirely + trigger a Kademlia bootstrap so it redials. The redial is
then a genuine **clean first connection** → gossipsub does its normal, correct, single subscription
exchange. Guarded by a **15s per-peer cooldown** (`last_force_disconnect`) so two healthy nodes that
dial each other simultaneously can't ping-pong disconnects.

Supporting tuning in the same file:
- QUIC `max_idle_timeout = 15s` + `keep_alive_interval = 5s` (`with_quic_config`) so a dead peer's
  connection is evicted promptly rather than lingering.
- A modest swarm `idle_connection_timeout = 20s` so a fresh connection isn't torn down before
  gossipsub grafts it.
- gossipsub `heartbeat_interval` **10s → 1s** (libp2p default) so the mesh forms/heals in ~1–2s.
- `add_explicit_peer` on first connection / `remove_explicit_peer` on full disconnect (kept as a
  belt-and-suspenders; harmless).
- `ConnectionClosed` now destructures `connection_id` to prune `peer_connections`.

**Verified live:** aggregator restart → on-chain `KeyPublished`, 0 accusations.

---

## G. Public-key aggregation completes after a restart

Two changes in the aggregator.

### G.1 — Accept no-aggregation fold markers (pre-existing, refined)
**`crates/aggregator/src/actors/publickey_aggregator.rs`** — with proof aggregation **off**, nodes
emit `DKGRecursiveAggregationComplete` with `(proof=None, attestation=None)`; the handler accepts the
`(None, None)` case so `try_publish_complete` can detect `all_proofs_are_none` and publish. The C5
path logs `"C5 proof signed — waiting for cross-node DKG fold to complete..."`.

### G.2 — Keyshare-collection timeout (Fix 3)
**Problem.** `PublicKeyAggregation::add_keyshare` transitions `Collecting → VerifyingC1` only when
`unique_parties >= n` (all N). With H < N, a member capped out of the honest roster (or briefly
absent) never publishes the keyshare the aggregator is waiting for, and it **waits forever**
(`project_aggregator_no_timeout` class).

**Fix.**
- **`crates/aggregator/src/domain/publickey_aggregation.rs`** — `force_verifying_c1(state)`:
  transition `Collecting → VerifyingC1` with whatever was collected, but **only** when
  `submission_order.len() > threshold_m` (a viable honest set exists); else `None`. C1 + canonical
  lowest-`H` capping then pick the deterministic honest roster.
- **`crates/aggregator/src/actors/publickey_aggregator.rs`** — mirror the
  `ThresholdPlaintextAggregator` timeout pattern:
  - `keyshare_collection_timeout()` — env `E3_KEYSHARE_COLLECTION_TIMEOUT_SECS`, default **300s**.
  - `started()` schedules `KeyshareCollectionTimeout` via `notify_later` (handle stored).
  - The `KeyshareCreated` handler captures `last_ec` (a real event context) before adding the share.
  - `Handler<KeyshareCollectionTimeout>`: if still `Collecting` and `force_verifying_c1` returns
    `Some`, force the transition (reusing `last_ec`) and dispatch C1; if already past `Collecting`,
    no-op; if too few keyshares, warn and leave (the normal path / DKG-window backstop still apply).
  - No explicit cancel needed: a timer firing after normal completion no-ops via the state check.

**Status / risk.** Implemented + builds; the mechanism fires and correctly *bails* when too few
keyshares are present. It is a defensive **backstop** — with workstream C the keyshare now delivers
(common case completes normally) and a permanently-offline member gets *expelled* (lowering live N).
**Tuning matters for correctness, not just liveness:** too short and a slow-but-honest node whose
proof is still running is wrongly excluded. Keyshares were observed arriving ~38s after collection
starts (proof-bound); the 300s default leaves margin, but prod must size it above worst-case proof
latency.

---

## 9. Mechanical call-site updates

Dropping the `correlation_id` argument from `ComputeRequest::{zk,trbfv}` (workstream A) touched
every dispatch site; where the dispatcher tracks the request it now reads
`request.correlation_id` back:
- `crates/zk-prover/src/actors/proof_request.rs`, `node_proof_aggregator.rs`, `share_verification.rs`
- `crates/aggregator/src/actors/threshold_plaintext_aggregator.rs`,
  `crates/aggregator/src/actors/publickey_aggregator.rs`
- `crates/keyshare/src/actors/threshold_keyshare.rs`
- `crates/slashing/src/domain/accusation_voting.rs`
- `crates/multithread/src/effect_gate.rs` (tests)

`crates/keyshare/src/actors/threshold_keyshare.rs` also dropped an unused `CorrelationId` import and
added a `time::Duration` import (for `ResyncTick`/timeouts).

---

## 10. Tooling / config (non-functional)

- **`deploy/local/run_service.sh`** — tee each ciphernode's stdout to
  `examples/CRISP/.interfold/logs/<cn>.log` for the live reproduction harness.
- **`examples/CRISP/interfold.config.yaml`**, **`packages/crisp-contracts/deployed_contracts.json`**,
  **`Cargo.lock`** — local deploy/test artifacts.
- **`agent/flow-trace/00_INDEX.md`**, **`06_DEACTIVATION_AND_COMPLETION.md`** — doc updates (bug #10
  + restart sections).
- **NOTE:** `crates/cli/src/helpers/telemetry.rs` carried a temporary `libp2p_gossipsub=DEBUG` filter
  used only for diagnosis; it was **reverted** and is not part of the change set.

---

## 11. Open review items

1. **Crypto-owner review** of workstream C (deterministic secret derived from `sk_bfv`). Flagged in
   the doc-comments of `derive_secret_gen_seed` / `derive_share_encryption_seed`.
2. **Prod sizing** of `E3_KEYSHARE_COLLECTION_TIMEOUT_SECS` (default 300s) above worst-case proof
   latency, to avoid excluding slow-but-honest nodes (workstream G.2).

---

## 12. Verification

Live, on-chain reproduction on the local CRISP stack (`anvil` + 5 ciphernodes; `cli init` /
`cli check-e3-ready --e3id N`; kill target at `STARTING MULTITHREAD zk_share_encryption`; cn1 is the
bootstrap, never killed):
- **Aggregator (party 0) killed mid-C3 → restarted:** on-chain `KeyPublished == true`, all nodes
  complete, **0 accusations**. (Workstreams A, B, C, D, E, F.)
- **Non-aggregator (party 1/2) killed mid-C3 → restarted:** on-chain `KeyPublished == true`,
  **0 accusations / 0 `proposeSlash`** (was 2 violations + slash attempts before workstream C).
- **Full workspace builds clean** (`cargo build`; only a pre-existing unrelated
  `workspace.msrv` manifest warning).

Not yet exercised end-to-end: the G.2 timeout's *drive-completion* path (delivery now succeeds /
offline members get expelled), and a wider matrix of kill phases / multi-node kills.
