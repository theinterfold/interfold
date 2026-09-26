# Invariants — Node / actor runtime

Scope: `crates/` actor, event, persistence, and networking code. Release compatibility, layering,
durability and replay, ordering and backpressure, schema evolution.

Read `00_INDEX.md` first: it carries the meta-invariants and the open-issues list that apply to
every section.

Terms: in this file, "persist" and "commit" mean durable on disk. The EventStore flushes an appended
event before dispatch. `Persistable::try_mutate` only enqueues a snapshot write; the snapshot
reaches disk when its batch flushes. Where a rule says persist or commit and the code only enqueues,
the rule still applies and the code has a durability gap. A **Gap:** note marks a requirement that
the code does not meet yet.

## Node / actor runtime

### Release compatibility

- Before EVM readers and protocol actors start, each enabled ciphernode chain reads the
  governance-selected `NodeReleaseRegistry`, verifies that the compiled compatibility values meet
  the required policy, and acknowledges its exact release ID and values on-chain. A missing
  controller or stale protocol/generation is a startup error. — `e3_evm::node_release`;
  `flow-trace/07`
- `protocol_version` covers incompatible contracts, events, cryptography, protocol behavior, and
  scopes every P2P protocol name. Nodes on different protocol versions do not discover, gossip, or
  synchronize with each other. `node_generation` covers a mandatory node-only release. P2P
  serialization compatibility within one protocol version remains separately gated by
  `GOSSIP_WIRE_MAJOR` and `SYNC_WIRE_MAJOR`. — `crates/config/protocol-release.toml`;
  `flow-trace/07`. The `interfold-bfv-v2` circuit identity uses `protocol_version = 4`. The later
  mandatory runtime recovery release increases `node_generation` to 2.
- Protocol 4 is also the coordinated fhe.rs l-BFV contribution-wire cutoff. Public-key and
  relinearization-key contribution bytes use their typed envelope formats; old bare contribution
  bytes are rejected by the typed decoders and must not be replayed or republished. Development
  records from before this cutoff are disposable and require fresh key generation.

### Layering

- Actors are **concurrency boundaries only**: deterministic reducers own protocol decisions; effect
  runners do crypto/storage/network/chain I/O. `state`/`validation`/ workflow/pure-algorithm code
  must not depend on Actix, repositories, network, wall-clock, or process execution; workflows
  return typed intents, never perform I/O. **Gap:** `crates/sync/src/sync/state.rs` reads
  repositories, and `crates/net/src/document_publishing/workflow.rs` and
  `crates/keyshare/src/threshold_keyshare/timeout_policy.rs` read the wall clock. Do not add more. —
  `ARCHITECTURE.md`
- Trust-boundary checks before any message drives a workflow: peer identity, committee membership,
  claimed party slot, signature, chainId, e3Id, proof type, payload size, schema version. **Gap:**
  the code runs these checks in two stages. Net ingress checks the wire envelope (magic, wire
  version, size, network ID) before a workflow sees the message. Share verification checks the
  signer, party slot, e3Id, and circuit later, before a party counts as honest. Most message types
  lack an explicit schema version. — `ARCHITECTURE.md`; `crates/net/src/network_sync/wire.rs`;
  `crates/zk-prover/src/share_verification/`

### Durability, persistence, replay

- Delivery is **at-least-once**; correctness comes from stable identity, idempotent transitions,
  effect dedup, and read-before-write guards — never from assumed exactly-once execution. **Gap:**
  live EventBus fan-out logs a subscriber that misses `FANOUT_ACCEPT_TIMEOUT` and does not retry,
  and restart replays only the suffix after each snapshot cursor, so a missed live delivery is not
  always redelivered. — `ARCHITECTURE.md`; `crates/events/src/eventbus.rs`
- **Commit-before-dispatch:** validate + dedup → reduce → atomically commit transition/outbox → ack
  → execute intents outside the critical section → persist correlated results before they unlock the
  next transition. Never mutate memory and rely on fire-and-forget persistence. **Gap:**
  `Persistable::try_mutate` enqueues its snapshot write and does not wait for it. Slash submissions
  have a durable intent record; no general transactional outbox exists. — `ARCHITECTURE.md`;
  `crates/data/src/persistable.rs`
- The append-only event log is the durable source of truth; snapshots and the timestamp index are
  derived optimizations. Replay-from-checkpoint and snapshot-hydration at the same logical point
  must produce equivalent state and pending intents. **Gap:** startup replays only the suffix after
  each snapshot cursor, so current recovery needs the matching snapshots, and no test compares full
  replay with hydration. — `ARCHITECTURE.md`; `CRATES_ARCHITECTURE.md`;
  `crates/sync/src/sync/service.rs`
- Before startup enables the event bus, its HLC must be greater than the greatest timestamp in all
  durable event logs. A snapshot timestamp alone is not a sufficient clock floor because the log can
  contain a newer post-snapshot suffix. — INDEX concern #56
- Event-log flush synchronizes the active segment, index, and log directory before live dispatch.
  Startup verifies every committed blob reference before it removes unreferenced blob files. Replay
  and index reconciliation are bounded by both event count and decoded bytes; one valid event may
  exceed the page budget so the cursor can still advance. — `CRATES_ARCHITECTURE.md`
- `E3LifecycleCoordinator` never emits protocol events. It must stay rebuildable from the event log.
  Startup reads its persisted stage map to prune terminal E3 state and to seed writer and compute
  recovery, so treat its schema and update order as durable. — `crates/request/src/lifecycle/`;
  `crates/ciphernode-builder/src/recovery.rs`; `flow-trace/06`
- EventStore duplicate rule: same HLC timestamp + stable event ID + **equal payload** is an
  idempotent duplicate (even across Local/Net transport); different payloads at the same timestamp
  fail closed. — INDEX concern #15
- Crash-torn log tails: truncate only an unindexed CRC/length-invalid physical suffix; indexed
  corruption is fatal. — INDEX concern #16
- Process-infrastructure events belong to one boot and are never EventStore replay inputs. The
  current boot must publish fresh sync, readiness, effect, and shutdown phase events; otherwise a
  payload-derived event ID can suppress the event that startup is waiting for. The `NetReady`
  listener is armed before the network transport starts. — INDEX concern #44
- The request-router recovery checkpoint has one canonical root key. Every live or recovery update
  retains the highest sequence observed for each aggregate. Startup advances a trailing checkpoint
  from its missing EventStore suffix, and the final snapshot drain preserves event order. An older
  contextual write must never replace newer admission state or move a covered-prefix cursor
  backward. — INDEX concern #43
- Before actor hydration, startup checks each persisted request context against finalized Ethereum
  lifecycle state. A complete E3 or a non-slashing failed E3 must not resume local protocol work. A
  failed E3 that requires accusation or slashing work must retain its context. An unavailable or
  unknown canonical result must fail startup. If the E3 exists at chain head but not yet at the
  finalized block, recovery keeps the context and waits; finality lag is not an unknown E3. **Gap:**
  not implemented. Startup prunes terminal E3 state from the local event-log projection and the
  lifecycle map; no code reads a finalized block. Concern #48 remains open. — INDEX concern #48
- EventStore replay preserves durable sequence inside each aggregate. It uses HLC order only to
  choose between the next events of different aggregates. A late event can have an older remote HLC
  and must not move ahead of an earlier local sequence from the same aggregate. — INDEX concern #43
- Snapshot-derived participation state is injected directly. Restart must not append synthetic
  `CiphernodeSelected` or `AggregatorChanged` events. A derived local selection resumes only at the
  fenced `SyncEffect` boundary. — INDEX concern #45
- Every state field is classified **Durable / Derivable / Ephemeral**. Pending proof bundles,
  decrypted-share progress, accusation votes/timeouts, retry state, active-aggregator designation,
  deadlines, and undispatched external effects are durable unless a stronger authority can
  deterministically recreate them. Process lifetime does not make an actor-local cache durable.
  **Gap:** accusation votes and timers, and `ComputeEffectGate` buffers, are in memory only. —
  `ARCHITECTURE.md`; `CRATES_ARCHITECTURE.md`
- `NodeProofAggregator` persists ordered DKG inner proofs and fold metadata before it accepts them.
  It persists a completed fold before publication. Restart must restore inputs or the completed
  output and resume only after `EffectsEnabled`. `KeyPublished` and terminal E3 events release the
  saved node-fold data. — `flow-trace/04`; `flow-trace/06`
- Replayed randomized DKG outputs must be reused exactly. If a TrBFV response arrives before a
  rebuilt collector restores its prerequisite state, hold the response until that state is ready; do
  not dispatch a replacement computation that would produce different shares and proofs. —
  `flow-trace/04`; INDEX concern #57
- A live randomized TrBFV request can retry only before it publishes a successful response. A failed
  attempt is not a durable protocol contribution. After success becomes durable, replay must reuse
  that exact response and must not regenerate the contribution. — `flow-trace/04`; INDEX concern #57
- A replayed C1 verification result can arrive before replayed keyshares restore `VerifyingC1`. Hold
  at most one result, bind it to the saved selected roster, and apply it when those inputs are
  ready. Never apply it to a replacement roster. A result received after C1 is complete is an
  idempotent duplicate. — `flow-trace/04`; INDEX concern #58
- On restart in `ReadyForDecryption`, rebuild the C4 collector from the saved roster and replay
  saved peer C4 shares. A restored C4 proof job cannot advance DKG if its peer-share collector is
  absent. After collection is complete, a duplicate C4 share must not start another collector. Saved
  C0 and C4 inputs must keep the first message from each party, as the live collectors do. —
  `flow-trace/04`
- `CommitmentConsistencyChecker` persists its complete verified-proof cache and accepted DKG roster
  in the same snapshot batch as each event that changes them. Hydration restores this state before
  recovered proof work resumes. A restarted checker must not evaluate C2, C3, C4, or aggregate
  proofs against an empty or partial pre-crash history. Successful E3 teardown clears the durable
  checker state in the completion event's snapshot batch. **Gap:** a failed snapshot write is only
  logged and retried on the next change; processing and publication continue. —
  `crates/slashing/src/commitment_consistency/actor.rs`; `flow-trace/04`; `flow-trace/06`
- A graceful-shutdown deadline must be longer than the EventBus fanout timeout, and every external
  supervisor must wait longer than the node deadline before it sends `SIGKILL`. A process that must
  outlive its CLI launcher must use the detached spawn path; dropping an owning child handle stops
  that child. — `flow-trace/06`
- A fatal threshold-keyshare collector timeout commits `KeyshareState::Failed` before it publishes
  `E3Failed`. The persisted failure stage and reason are immutable. After hydration,
  `EffectsEnabled` redrives the saved failure and does not resume the earlier DKG phase. **Gap:**
  the failed snapshot write is enqueued without a durability acknowledgement before `E3Failed`
  (`crates/keyshare/src/threshold_keyshare/handlers.rs`). —
  `flow-trace/04`; INDEX concern #36
- Secure-16384 local l-BFV generation uses the separate
  `//threshold_keyshare_lbfv_generation/v1/{e3_id}` snapshot. It persists the encrypted generation
  seed and source before dispatch, derives missing row requests by stable operation ID, and commits
  both documents plus the signed manifest before publication. `KeyshareCreated` cannot publish until
  that bundle is durable. Completion or terminal failure removes the stored generation secret, seed,
  response, and encrypted RLK witness. The main `KeyshareState::Failed` snapshot is authoritative if
  a process exit interrupts a cross-repository failure update. Recovery removes pending l-BFV
  secrets before it redrives the saved failure. Existing threshold-keyshare snapshots remain
  unchanged. — `flow-trace/04`
- Secure-16384 public-key publication uses the separate `//publickey_lbfv_publication/v1/{e3_id}`
  snapshot. Schema 2 rejects pending version-2 key envelopes. It validates the E3 identity and
  `DkgAggregatorV2` circuit, commits the `LbfvPublicKeyAggregated` intent before emission, and
  redrives the intent after restart. The registry writer adapts the local event to the existing
  public-key submission gate and passes the V2 proof and attestation bundle to `publishCommittee`.
  The legacy public-key recovery schema remains unchanged. — `flow-trace/04`
- Secure-16384 l-BFV row aggregation uses `//publickey_lbfv_aggregation/v1/{e3_id}`. The sidecar
  binds the proof domain, the immutable ascending accepted-party set, both accepted document
  families, five PK proofs, five RLK proofs, the fold cursor, both operational keys, and the final
  V2 proof. The active aggregator derives the operational public key and RLK only from those
  accepted documents after the five-row fold completes. If C5 completes first, publication waits for
  both persisted keys. Restart must derive a missing operational key from the same durable documents
  before it dispatches the final V2 proof. Schema 4 rejects schema-1 through schema-3 sidecars
  because their operational-key bytes use the pre-cutover fhe.rs codec. A persisted aggregation
  failure is terminal and immutable. Restart must clear process-local correlations, publish
  `E3Failed(DKGInvalidShares)`, and suppress all proof and publication work. —
  `LbfvAggregationStateV1`; `aggregate_lbfv.rs`; `flow-trace/04`

### Ordering, backpressure, effects

- Protocol work must be partitioned by `(chain_id, e3_id)`, with ordering guaranteed within each
  partition. Legal E3 progress is monotonic. On-chain committee ordering is authoritative. **Gap:**
  per-E3 actors are keyed by `E3id`, which includes `chain_id`, but durable order is per chain
  aggregate, and EventBus fan-out delivers one event at a time, so a slow subscriber can block
  unrelated E3s. — `ARCHITECTURE.md`; `crates/events/src/e3id.rs`; `crates/events/src/eventbus.rs`
- Correctness-critical sends are acknowledged and timeout-bounded; `do_send` is allowed only for
  best-effort telemetry. Buffers are bounded by both item count and bytes with an explicit overflow
  policy. **Gap:** 84 `.do_send(` call sites remain (the count covers all sites, not only
  correctness paths), including `BusHandle` publication, `Sequencer`, `DataStore::write`, snapshot
  batches, EVM routing, and keyshare collectors. `pnpm check:invariants` blocks growth of the total
  only. — `ARCHITECTURE.md`; `scripts/invariant-baselines.env`
- Timers: persist the absolute deadline + purpose, not an in-memory handle; on restart, compare to
  the injected clock and deterministically re-arm or fire overdue. **Gap:** accusation timers are
  memory-only `run_later` handles; keyshare collectors read `SystemTime::now()` instead of an
  injected clock; the slash fallback delay restarts in full (see `01_PROTOCOL_ONCHAIN.md`). —
  `ARCHITECTURE.md`
- Effects stay disabled until durable replay completes and both historical sources merge in HLC
  order. Startup fences `EffectsEnabled` → `SyncEffect` → canonical history → `SyncEnded` in that
  order. `ComputeEffectGate` buffers and deduplicates until `EffectsEnabled`. It sends a live
  response or error to every waiting correlation ID. It reuses a response seen during replay, but
  not a replayed error, so the regenerated request runs again. —
  `crates/multithread/src/effect_gate.rs`; `CRATES_ARCHITECTURE.md`
- A terminal E3 cancels its local node-scoped compute-task group. Work already executing may finish,
  but queued proof jobs from that E3 must not consume task-pool capacity ahead of a later active E3.
  One node's local failure must not cancel another node's work when tests or embeddings share a task
  pool. — `flow-trace/04`
- A local prover, verifier, task-pool, or resource failure is not evidence of peer misbehavior.
  Retry the exact ZK request, preserve its durable input, and let canonical E3 lifecycle facts end
  recovery. Only a completed cryptographic check can classify a peer proof as invalid. —
  `flow-trace/04`
- Sortition delays, committee-finalization timers, and slash submissions persist their semantic
  inputs before effects run. Restart re-arms them only after `EffectsEnabled`; an additive migration
  may backfill a missing versioned record but must not replace an existing one. — INDEX concern #46
- Durable EVM settlement receipts (`RewardCredited`, `RewardClaimed`) are global facts — never
  routed into a completed per-E3 context. — INDEX concern #8
- Replayed committee events must not replace a restored per-E3 actor with a fresh instance; the
  router's `on_event` path must not do synchronous store reads. — `flow-trace/06`
- A well-formed `E3Requested` with an unsupported committee-size/preset enum is a benign skip (emit
  `Processed` so ordering advances); ABI-decode failures still fail closed. — INDEX concern #13
- A randomness fulfillment reader must retry a failed registry read once with a new provider for the
  same chain. It must retain the new provider after a successful reconnect and reject the log if the
  retry still cannot verify the accepted request. — `flow-trace/03`
- A chain gateway that fails closed after startup must make the node exit unsuccessfully after a
  durability shutdown. A running node must not report healthy after chain ingestion stops. **Gap:**
  `dappnode/healthcheck.sh` checks the process, local files, and the QUIC port, not chain ingestion.
  — `crates/cli/src/start.rs`; `flow-trace/03`; `flow-trace/06`
- A network event cannot create a request context for an unknown E3. Only chain events or restored
  snapshots admit an E3; peer events can only contribute to an admitted one. —
  `crates/request/src/routing/workflow.rs`

### Schema evolution

- Rust type compatibility is **not** a storage-migration strategy: every durable payload carries an
  explicit schema version; add/remove/reorder of fields requires a compatibility test against
  checked-in fixtures; version mismatch runs a tested migration or fails startup with an actionable
  error. **Gap:** persisted state is positional bincode, and only a few types have a version field
  or a layout fixture. Until that changes, increase `SCHEMA_VERSION`
  (`crates/sync/src/sync/schema_version.rs`) for every incompatible change to a persisted type or
  `InterfoldEventData` variant, including an added field. Startup halts on any mismatch. —
  `ARCHITECTURE.md`; `00_INDEX.md` known open issues
