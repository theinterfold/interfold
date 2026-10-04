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
- `protocol_version` covers incompatible contracts, events, cryptography, and protocol behavior. It
  is part of the gossip topic, the Identify string, and the Kademlia and sync protocol names, and a
  peer with a different Identify string is disconnected, so nodes on different protocol versions do
  not discover, gossip, or synchronize with each other. `node_generation` covers a mandatory
  node-only release. Within one protocol version, increase `GOSSIP_WIRE_MAJOR` or `SYNC_WIRE_MAJOR`
  when a gossip or sync payload layout changes incompatibly. —
  `crates/config/protocol-release.toml`; `crates/net/src/network.rs`; `flow-trace/07`

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
  version, size, network ID) before a workflow sees the message. DKG share and C4 intake verify the
  finalized dealer's signature over the complete message before saving or collecting it. Rejected
  messages leave the dealer slot free. C0 intake checks the signed proof and its key commitment
  before pending verification. Share verification checks proof signatures, party slots, E3 IDs, and
  circuits before a party counts as honest. Most message types lack an explicit schema version. —
  `ARCHITECTURE.md`; `crates/net/src/network_sync/wire.rs`;
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
- A data directory belongs to one node role. All readers of a chain share one block cursor, so a
  node with fewer readers advances it past events that a node with more readers still needs.
  `preflight_node_role` stamps the role on first boot and refuses a directory of the other role; an
  unmarked directory that existed before this startup is a full node's. The storage schema guard
  rejects schema 7 directories from releases without this marker. Releases before the marker use
  schema 7 or earlier, so they halt on a schema-8 directory instead of opening it without the role
  check. **Gap:** v0.18.0 opens a schema-7 directory that a development build wrote with the marker,
  without the role check. — `crates/sync/src/sync/node_role.rs`; `crates/sync/src/sync/preflight.rs`
- Before startup enables the event bus, its HLC must be greater than the greatest timestamp in all
  durable event logs. A snapshot timestamp alone is not a sufficient clock floor because the log can
  contain a newer post-snapshot suffix. — INDEX concern #56
- Event-log flush synchronizes the active segment, index, and log directory before live dispatch.
  Startup verifies every committed blob reference before it removes unreferenced blob files. Replay
  and index reconciliation are bounded by both event count and decoded bytes; one valid event may
  exceed the page budget so the cursor can still advance. — `CRATES_ARCHITECTURE.md`
- `E3LifecycleCoordinator` never emits protocol events. It must stay rebuildable from the event log.
  Startup reads its persisted stage map to prune terminal E3 state and to seed writer and compute
  recovery, so treat its schema and update order as durable. **Gap:** startup also writes a terminal
  stage that it reads at the finalized block (INDEX concern #48). The event log does not contain
  that stage, so only the persisted snapshot holds a canonical Failed stage of this kind. A rebuild
  from the log records that E3 as Complete and loses its failure settlement recovery; an ordinary
  restart keeps the snapshot. A replayable canonical observation is still required. —
  `crates/request/src/lifecycle/`; `crates/ciphernode-builder/src/recovery.rs`;
  `crates/ciphernode-builder/src/finalized_lifecycle.rs`; `flow-trace/06`
- EventStore duplicate rule: same HLC timestamp + stable event ID + **equal payload** is an
  idempotent duplicate (even across Local/Net transport); different payloads at the same timestamp
  fail closed. — INDEX concern #15
- Crash-torn log tails: truncate only an unindexed CRC/length-invalid physical suffix; indexed
  corruption is fatal. — INDEX concern #16
- Canonical decryption authority is a derivable projection of confirmed chain observations. Startup
  rebuilds it from the full retained log before proof replay and actor hydration. Key recovery must
  include publication and chunk history before snapshot cursors. C6 intent admission precedes
  deduplication, and compute admission precedes dispatch and response reuse. Final plaintext intents
  also pass canonical domain admission before publication deduplication and release. The writer
  seeds terminal E3 IDs from confirmed chain history and retires pending publication work on
  confirmed terminal stages. It discards later intents for those E3s. Missing authority retains one
  sequence range per active E3; payloads stay in the event log. Admission reads bounded pages only
  for the E3 whose authority becomes available, without rescanning other deferred work. The shared
  request router performs no key-authority RPC or retry wait. — `crates/evm/src/canonical_key.rs`;
  `crates/request/src/canonical_key.rs`; `flow-trace/06`
- Plaintext hydration recovers deferred ciphertext from the full retained event log, including the
  prefix covered by snapshots. A missing actor rebuilds authenticated shares from that prefix before
  effects resume. Existing snapshots remain dormant until confirmed key authority arrives; missing
  authority must not abort startup or replace retained state. Deferred recipients keep a history
  range and one effects-enabled signal, not payload queues. Recovery reads bounded event-log pages.
  Retained or replayed C6 shares cannot reserve a slot with a noncanonical domain. Hydration removes
  invalid work, clears its verification outcomes and derived proofs, and rebuilds collection from
  signed history with effects disabled. Retained C7 proofs also bind to the selected C6 batch and
  plaintext. Mismatched C7 work is regenerated without discarding valid C6 work. —
  `crates/aggregator/src/ext.rs`; `crates/aggregator/src/plaintext_aggregation/effects/recovery.rs`
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
  unknown canonical result must fail startup, except on a chain that the configuration disables: the
  node does not read that chain, so its contexts resume unchecked. If the E3 exists at chain head
  but not yet at the finalized block, recovery keeps the context and waits; finality lag is not an
  unknown E3. Before the restart backfill, startup reads `getE3Stage` and `getFailureReason` at the
  finalized block for each context that the router holds when startup replay ends, whose local
  lifecycle stage is not terminal: the checkpoint's contexts, with the admissions and completions of
  the logged events after the checkpoint applied. It reads 16 contexts per batch. The connection to
  the chain and each batch have a 60 s bound, and a batch is read again twice after an RPC error. It
  writes the canonical stage of a finished E3 to the lifecycle store, so every restart decision that
  reads the lifecycle treats that E3 as terminal. The router does not forward `EffectsEnabled` to a
  restored context whose lifecycle stage is terminal and publishes `E3RequestComplete` for it;
  startup pruned its finalized committee. The data-availability coordinator of each chain drops the
  restored key assembly and ciphertext retrieval of such an E3 before `EffectsEnabled`, and ignores
  later facts for it. Any other E3 that failed at the finalized block keeps its context for
  accusation or slashing work, but its other work ends: the router forwards a Failed
  `E3StageChanged` to the context when the router is built, before replay, or at `EffectsEnabled`
  for a context that replay admits, so its keyshare and its public-key and plaintext aggregators
  stop, also a plaintext aggregation that still waits for the key's chain authority, and a recipient
  that the context creates later gets it first; a selection of the E3, recovered, replayed or live,
  starts no protocol actor; the compute gate and ZK recovery start with the Failed stage for it, so
  the C0 verifier admits none of its inputs, recovered, replayed or live, and the gate still admits
  accusation re-verification; and the data-availability coordinator drops its restored work. The
  Failed event has the E3's aggregate and the router's cursor of it, so the actors' cleanup writes
  are not stale. A disabled chain covers the contexts of its configured `chain_id`; a context of a
  chain that the configuration does not have fails startup. **Gap:** a context whose local lifecycle
  stage is Failed completes at `EffectsEnabled` even when its failure reason needs accusation work,
  because the lifecycle does not keep the reason. This is follow-up work. Document publication
  recovery does not read the lifecycle. — `crates/ciphernode-builder/src/finalized_lifecycle.rs`;
  `crates/evm/src/finalized_lifecycle.rs`; INDEX concern #48
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
  saved node-fold data. `ProofRequestActor` publishes the own C0 (seq 0) before
  `EncryptionKeyCreated`, so this store holds C0 before keyshare can leave key collection, the only
  state that requests C0 again. With proof aggregation on, a C4 request waits for the seq layout
  from `ThresholdSharePending`. — `flow-trace/04`; `flow-trace/06`
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
  C0 and C4 inputs must keep the first authenticated message from each party, as the live collectors
  do. A C2/C3 batch with no proof that passes local prechecks still dispatches and saves its
  outcome. A later authenticated share can grow that batch, including after hydration. Each new
  threshold-share collector receives saved expulsions, then all retained authenticated shares. Key
  calculation completion and actor shutdown stop that collector and its timers. — `flow-trace/04`
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
- A threshold-keyshare collector failure must match the E3 and its current collection phase before
  it clears collector references, writes state, or publishes events. Canonical key publication
  supersedes all DKG collector failures. A `PublicKeyAggregated` intent and its saved public-key
  context do not establish canonical publication or suppress a current collector failure.
  `CommitteePublished` and `E3StageChanged` at `KeyPublished` or a later successful stage preserve
  this fact even without `PublicKeyAggregated`. Hydration restores it from the E3 lifecycle
  projection before the actor starts. An earlier stage cannot reset it, and another E3 cannot
  establish it. Threshold-share failures cannot replace `ReadyForDecryption` or a later phase. C4
  failures apply in `ReadyForDecryption` only before C4 verification completes or keyshare
  publication is authorized. — `crates/keyshare/src/threshold_keyshare/handlers.rs`; `flow-trace/04`
- A fatal threshold-keyshare collector timeout commits `KeyshareState::Failed` before it publishes
  `E3Failed`. The persisted failure stage and reason are immutable. After hydration,
  `EffectsEnabled` redrives the saved failure and does not resume the earlier DKG phase. **Gap:**
  the `Failed` snapshot write is enqueued without a durability acknowledgement before `E3Failed` is
  published (`crates/keyshare/src/threshold_keyshare/handlers.rs`). — `flow-trace/04`; INDEX concern
  #36

### Ordering, backpressure, effects

- Protocol work must be partitioned by `(chain_id, e3_id)`, with ordering guaranteed within each
  partition. Legal E3 progress is monotonic. On-chain committee ordering is authoritative. **Gap:**
  per-E3 actors are keyed by `E3id`, which includes `chain_id`, but durable order is per chain
  aggregate, and EventBus fan-out delivers one event at a time, so a slow subscriber can block
  unrelated E3s. — `ARCHITECTURE.md`; `crates/events/src/e3id.rs`; `crates/events/src/eventbus.rs`
- Canonical key publication ends DKG-specific expulsion and exclusion handling in every public-key
  aggregator, including standbys whose local DKG phase is incomplete. Hydration derives publication
  from the existing lifecycle projection. This does not suppress chain failures or plaintext
  failures when fewer than T+1 valid roster shares remain. —
  `crates/aggregator/src/public_key_aggregation/effects/mod.rs`; `crates/aggregator/src/ext.rs`;
  `flow-trace/04`; `flow-trace/06`
- Correctness-critical sends are acknowledged and timeout-bounded; `do_send` is allowed only for
  best-effort telemetry. Buffers are bounded by both item count and bytes with an explicit overflow
  policy. **Gap:** 82 `.do_send(` call sites remain (the count covers all sites, not only
  correctness paths), including `BusHandle` publication, `Sequencer`, `DataStore::write`, snapshot
  batches, EVM routing, and keyshare collectors. `pnpm check:invariants` blocks growth of the total
  only. The request router's `EventBuffer` bounds missing-recipient queues by items and accounted
  bytes, per E3 and globally: 4,096 entries / 1 GiB per E3 and 16,384 entries / 3 GiB per router.
  Each copy reserves its encoded bytes, nested inline storage, and 64 bytes per allocation
  candidate. Queue reservations cover spare inline capacity. Shared bytes retain no spare capacity,
  and deferred key and threshold-share copies compact their shared collections. The capacity
  envelope follows recipient creation points and reserves memory outside the byte ceiling for
  fragmentation and live work. Installed extensions declare the expected recipients. A bootstrap
  context expects none. Within the limits, deferred events precede the event that creates the
  recipient, including early decryption shares. Overflow clears only the affected recipient's
  deferred queue and records its delivery failure until teardown or restart. It logs at ERROR and
  disables further deferral for that queue. Live delivery and other E3s continue. The E3 can fail at
  its existing deadline. **Gap:** deferred events and their failure records remain in memory only.
  Restart does not recover a backlog before the existing checkpoint. Capacity derivation:
  `flow-trace/03` §Request-router deferred delivery. — `ARCHITECTURE.md`;
  `scripts/invariant-baselines.env`; `crates/request/src/context.rs`;
  `crates/request/src/routing/event_buffer.rs`
- Timers: persist the absolute deadline + purpose, not an in-memory handle; on restart, compare to
  the injected clock and deterministically re-arm or fire overdue. **Gap:** accusation timers and
  the request router's slashable-failure teardown grace are memory-only `run_later` handles;
  keyshare collectors read `SystemTime::now()` instead of an injected clock; the slash fallback
  delay restarts in full (see `01_PROTOCOL_ONCHAIN.md`). — `ARCHITECTURE.md`
- Effects stay disabled until durable replay completes and both historical sources merge in HLC
  order. Startup fences `EffectsEnabled` → `SyncEffect` → canonical history → `SyncEnded` in that
  order. `ComputeEffectGate` buffers and deduplicates until `EffectsEnabled`. It sends a live
  response or error to every waiting correlation ID. It reuses a response seen during replay, but
  not a replayed error, so the regenerated request runs again. A request under a new ID whose
  result has not reached the gate 10 minutes after it went to the worker goes to the worker again,
  because fan-out can drop that result. —
  `crates/multithread/src/effect_gate.rs`; `CRATES_ARCHITECTURE.md`
- Keyshare coalesces decryption work per phase in each process. Admission of an already-retained
  canonical key is a no-op. Repeated chain observations and resume signals cannot add share
  correlations or repeat C6 proof intents. Hydration clears the dispatch markers, and the worker
  retains the same request for local retries. A phase whose result has not arrived for 5 minutes
  sends its request again, at most 6 times, because EventBus fan-out can lose a request or a result.
  Each C6 redelivery has a fresh random value that a restart cannot repeat, and its completion
  carries that value so EventBus deduplication passes it. A terminal event stops redelivery at once.
  — `crates/keyshare/src/threshold_keyshare/effects/create_decryption_share.rs`; `flow-trace/04`
- A terminal E3 cancels its local node-scoped compute-task group. Work already executing may finish,
  but queued proof jobs from that E3 must not consume task-pool capacity ahead of a later active E3.
  Accusation re-verification runs in its own group: a failure does not cancel it, so a node can
  still vote on an accusation of a failed E3; the end of the request cancels it. One node's local
  failure must not cancel another node's work when tests or embeddings share a task pool. —
  `flow-trace/04`
- A local prover, verifier, task-pool, or resource failure is not evidence of peer misbehavior.
  Retry the exact ZK request, preserve its durable input, and let canonical E3 lifecycle facts end
  recovery. Only a completed cryptographic check can classify a peer proof as invalid. —
  `flow-trace/04`
- C0 recovery scans durable inputs and local outcomes before actor startup, including events before
  the snapshot cursor. It skips legacy records that the EventStore router quarantines, but rejects
  other sequence gaps. An empty filtered page is not end-of-log until the physical cursor passes the
  log head. Recovery advances one physical record at a time across empty pages, including pages
  limited by decoded bytes. Later C0 inputs remain recoverable. It applies the live admission checks
  and excludes E3s past DKG, and the verifier refuses a replayed or later input of an E3 whose DKG
  ended before startup. Recovered and replayed C0 inputs dispatch only after `EffectsEnabled`;
  document deduplication cannot erase unresolved verification work. Local failures retry with a
  delay that doubles from 5 to 60 seconds. `E3RequestComplete` cancels the retries. —
  `crates/zk-prover/src/proof_verification/recovery.rs`; `flow-trace/06`
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
  durability shutdown. A running node must not report healthy after chain ingestion stops. The chain
  reader reports each successful head read to an `IngestionProgressSink`; `interfold start` writes
  one heartbeat file per chain under `<node data dir>/ingestion/`, and `dappnode/healthcheck.sh`
  fails when a heartbeat is older than 120 s or neither its head nor its cursor moved for 600 s.
  `start` first records how many chain readers it starts, and when (`<node data dir>/ingestion/expected`);
  after a 900 s startup grace the check requires a heartbeat from each, so a reader that never
  reaches its first read fails it too. **Gap:** a heartbeat write that fails after the startup
  probe is only logged. —
  `crates/evm/src/chain_reader/progress.rs`; `dappnode/healthcheck.sh`; `flow-trace/03`;
  `flow-trace/06`
- A network event cannot create a request context for an unknown E3. Only chain events or restored
  snapshots admit an E3; peer events can only contribute to an admitted one. —
  `crates/request/src/routing/workflow.rs`
- Identify must not cache peer addresses independently of the filtered Kademlia address path. Each
  compatible Identify exchange for an admitted peer must refresh that peer's filtered Kademlia
  addresses. Keep unique filtered addresses within both limits: 8 addresses and 2 KiB of encoded
  multiaddresses, including peer IDs. Select live endpoints that the peer still advertises first,
  then fill the remaining slots in advertised order. Remove superseded Identify addresses, but
  retain up to 2 live connection endpoints until they close. A withdrawn endpoint is removed after
  its last connection closes. Only newly admitted connections receive admission notifications. —
  `crates/net/src/net_interface.rs`
- An inbound DHT put must not replace a locally published record or shorten a stored replica's
  expiry. No expiry means an unlimited lifetime. Inbound replicas are bounded per sender (160), in
  total (3,040) and in value bytes (a 2 GiB ceiling), from four concurrent N=19 E3s with a 2x
  margin. At a limit a new replica evicts others instead of being refused: expired records go first,
  then the sender at its own limit gives up its oldest replica, and under node-wide pressure the
  sender over its share in the short dimension gives up its oldest, as many as the new replica
  needs; it is refused only when nothing it may evict makes room. This node's records and the
  documents it restored are never evicted for a replica, and a local write that finds the store full
  evicts a replica. The replica ledger follows every store change: removal, expiry pruning,
  Kademlia's own removal of expired records, and a replica that becomes this node's record. —
  `crates/net/src/replica_ledger.rs`; `crates/net/src/net_interface.rs`
- A periodic network re-send backs off to a cap, stops when its phase ends, and has a lifetime
  bound. It does not start for one of the last 1,024 E3s whose terminal stage came from the chain,
  also from replayed history. After a restart, local replay schedules the re-sends again in log
  order and they wait until it finishes; the restart re-broadcast schedules none. Re-announcing a
  DHT document sends only its notification; the full document is uploaded to peers again only by a
  bounded refresh (once per 30 minutes, one upload started at a time). Removing a publication stops
  its announcement and upload and cancels their scheduled retries. Its cleanup commands wait in one
  queue of at most 4,096 keys that drops its oldest entries when full. At startup, publications
  start only at `SyncEnded`. Library-driven record replication stays disabled. A document is
  announced only after the publisher's own DHT store holds it, and a failing upload never delays its
  announcement. **Gap:** stopping a publication ends the Kademlia query of a DHT put only in its
  upload phase. Requests that the query already gave to the connection handlers, queued or in
  progress, still go out, and a put that still looks up its closest peers runs on and then uploads.
  — INDEX concerns #60, #62, #63, #74; `crates/net/src/document_publishing/workflow.rs`;
  `crates/net/src/network_sync/effects/rebroadcast.rs`
- A node does not accept or forward a gossip message ID while it remains in its seen cache. It does
  not store a peer event again while its payload-derived ID remains in the stored window. A rejected
  event-store handoff releases that ID; a failed append stops the node. Both caches admit every new
  ID without a rate throttle, including during startup draining. Capacity comes from four concurrent
  N=19, H=14 committees with a 2x margin, retry bursts, and a six-hour TTL. Peers borrow idle
  capacity. At capacity, a peer at its fair share evicts its own oldest entry; a peer below its
  share reclaims space from the largest owner. Early eviction increments
  `seen_ids_early_evictions_total` in structured WARN logs with bounded log frequency. Retention can
  shorten under pressure; it must not reject required protocol inputs. Notification shape and expiry
  checks precede acceptance, without suppressing valid relays for another party. Malformed messages
  get `Reject`. Expiry alone gets `Ignore` after all other validation, so timing cannot penalize a
  relay. No message-count or byte-rate throttle discards valid relay traffic. Per-message wire size
  limits still apply. — INDEX concerns #61, #62; `crates/net/src/gossip_ingress.rs`;
  `crates/net/src/seen_messages.rs`; `crates/net/src/ingress_limits.rs`;
  `crates/net/src/network_sync/wire.rs`; `crates/net/src/event_translation/`
- A notification adds a fetch candidate only for its own party filter. A waiting document keeps one
  notification per filter with the latest expiry. Early buffering also distinguishes peers. A forged
  or expired notification cannot displace a correct one. A DHT GET accepts only the record for the
  requested key. — INDEX concern #69; `crates/net/src/document_publishing/workflow.rs`;
  `crates/net/src/document_publishing/effects.rs`
- Network ingress loops do not wait for long I/O such as a DHT fetch. They hand the work to the
  actor, which bounds its concurrency. A transient wrapper retains the propagation peer across
  buffering. Document fetches serve due peers with the fewest active reads and rotate ties, with at
  most 8 active reads and 512 queued documents. A lone peer can use all idle slots. Each GET
  releases its slot after one attempt; retries return to the fair queue. No per-peer cap drops work
  while global capacity is idle. The queue covers four concurrent N=19 E3s with a 2x margin. A
  document retains up to 128 announcers across queueing, active reads, and retries. At capacity, new
  announcers replace the oldest ones after the first. Any retained announcer can supply its next
  fair slot, charged only to that peer, with one fetch per document. Duplicate announcements do not
  advance retry deadlines. Queue ownership uses the retained announcer with the least queued work,
  including on retry. Before eviction, shared work moves to a less loaded announcer. A busy peer
  cannot evict a shared document while another retained announcer has no queued work. Document IDs
  and serialized metadata do not include transport attribution. —
  `crates/net/src/document_publishing/handlers.rs`; `crates/net/src/document_publishing/workflow.rs`
- Log volume must not scale with payload size or redelivery count. Byte payloads format through
  `hexf` (length and edge digits), network commands log `NetCommand::summary`, and the default log
  filter drops libp2p gossipsub warnings. — INDEX concern #65; `crates/utils/src/formatters.rs`;
  `crates/cli/src/helpers/telemetry.rs`

### Schema evolution

- Rust type compatibility is **not** a storage-migration strategy: every durable payload carries an
  explicit schema version; add/remove/reorder of fields requires a compatibility test against
  checked-in fixtures; version mismatch runs a tested migration or fails startup with an actionable
  error. **Gap:** persisted state is positional bincode, and only a few types have a version field.
  The layout locks (`crates/layout-lock`, listed in `00_INDEX.md`) fail when the encoding of a
  listed root changes, and when fields with the same encoding are swapped or renamed. A change can
  still ship with a rewritten fixture: only review of the fixture diff ties it to a version change.
  Roots that no lock lists, store keys, hand-written formats, and values stored inside opaque bytes
  are not covered. Until that changes, increase `SCHEMA_VERSION`
  (`crates/sync/src/sync/schema_version.rs`) for every incompatible change to a persisted type or
  `InterfoldEventData` variant, including an added field. Startup and event readers check the marker
  through the raw key/value store before opening, repairing, or decoding logs and derived state.
  `node validate` uses the same check before all event and snapshot checks, including with
  `--repair`. A mismatch names the supported recovery action and leaves log bytes unchanged. —
  `crates/sync/src/sync/preflight.rs`; `crates/entrypoint/tests/validate_older_schema.rs`;
  `ARCHITECTURE.md`; `00_INDEX.md` known open issues
