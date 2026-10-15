# Persistence, replay, and shutdown

Owners: [event system](../../crates/event-system/), [events](../../crates/events/),
[data](../../crates/data/), [request router](../../crates/request/), [sync](../../crates/sync/), and
[ciphernode builder](../../crates/ciphernode-builder/). [Design principles](design-principles.md)
describe the direction; owner-local documentation describes implementation boundaries. Neither makes
an unimplemented durability guarantee true.

Here **durable** means flushed to disk. EventStore flushes appended events before dispatch.
`Persistable::try_mutate` only enqueues a snapshot write; durability arrives when its batch flushes.
An enqueued mutation is not a commit acknowledgment.

## Contracts and actual boundaries

The intended model is at-least-once delivery with stable identity, idempotent reducers, deduplicated
effects, and read-before-write guards, never assumed exactly-once execution. The desired sequence is
validate/dedup → reduce → atomic transition/outbox commit → acknowledgment → external intents →
persist correlated results before progress. **Current gaps below limit both claims.** Actors are
concurrency boundaries; deterministic workflows return typed intents, adapters perform I/O.

Durable work must preserve chain/E3 identity and monotonic legal progress. E3 actors include chain
in `E3id`, but durable ordering is by chain aggregate, not independent E3 partitions. Fan-out sends
one event at a time, so a slow subscriber can block unrelated requests. Canonical on-chain committee
ordering remains authoritative.

| Boundary              | Current contract                                                                                                                                                                                                                                                        |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Event identity        | Same HLC + stable event ID + equal payload is an idempotent duplicate, even Local vs Net; retain first context. Different payload at the same timestamp fails closed.                                                                                                   |
| Log append            | Sync blob first, then log record and index before broadcast; sync directory initially and after rollover. Append/flush failure stops storage and signals supervisor; startup/CLI exits nonzero.                                                                         |
| Log recovery          | Verify every referenced blob's hash/length before decoding or deleting unreferenced files. Recover complete CRC-valid unindexed records; truncate only an unindexed invalid physical suffix or exact index-free two-byte rollover remnant. Indexed corruption is fatal. |
| Replay order          | Preserve durable sequence inside each aggregate. HLC chooses between aggregate heads only; an older remote HLC cannot jump an earlier local sequence.                                                                                                                   |
| Bounded reads         | Count and decoded-byte page budgets both apply, with one larger valid event allowed for progress. A short or filtered-empty page is not necessarily end-of-log; follow physical cursor/head.                                                                            |
| Snapshot batches      | Open each durable live/replay sequence's batch before domain dedup. Newer sequences schedule older open batches; storage atomically rejects contextual writes older than its aggregate cursor. Drain cross-aggregate batches in original event order.                   |
| Infrastructure events | Sync/readiness/effect/shutdown events belong to this boot, never EventStore replay. Arm `NetReady` listener before transport so old payload IDs cannot suppress current startup readiness.                                                                              |

Large local events use versioned content-addressed blobs beside the log; 32 MiB inline/network
limits remain. Runtime query errors return to correlated callers, not panics. Startup replay uses
bounded disk-backed external merge runs with bounded file-descriptor fan-in. It waits for each
EventBus handler acceptance; unavailable/timed-out replay listeners fail recovery. This does not
make every downstream asynchronous snapshot edge durable at each step.

Snapshot admission precedes domain dedup even for source/forked buses. Delivery occurrence identity
keeps equal EVM facts from different logs and equal local verdicts/errors from different causal
dispatches deliverable, while redelivery of one occurrence remains idempotent. Do not collapse that
identity into only payload equality when changing the event pipeline.

EventStore append/index/flush error paths call `report_fatal_failure` and stop the actor;
EventSystem connects the health watch, builder fails startup, and the CLI monitors it after startup
and exits unsuccessfully. A standalone helper without the signal does not acquire that process
guarantee. Tests in [eventstore.rs](../../crates/events/src/eventstore.rs) cover append/flush
failure and stopping before dispatch; [CLI start](../../crates/cli/src/start.rs) owns the health
wait. **Other actor panics and dead fire-and-forget mailboxes are not universally supervised**: for
example an unconfigured aggregate panics EventStoreRouter without using that explicit health path.
Logging/trapping a handler error is also not itself a restart. Broader acknowledged pipeline work is
tracked in [#2266](https://github.com/theinterfold/interfold/issues/2266).

Before enabling EventBus, seed its HLC above the greatest timestamp in **all durable logs**,
including post-snapshot suffixes. A snapshot alone is not a clock floor. Correlation IDs similarly
reserve a high-water range in `correlation-ids` beside the log before replay; restart rises above
the previous reservation even after wall-clock rollback. Old state without the file starts from the
clock; the v0.19 reset prevents carrying pre-reservation history into that release.

## Startup and canonical reconciliation

Full and bootstrap composition share storage/router/lifecycle/sortition/DA infrastructure, but
bootstrap reads only Interfold and has no protocol recipients, compute scheduler/memory admission,
keyshare/prover/aggregators, registry/bonding readers, or transaction writers. It still needs
encrypted identity for node/HLC/peer identity and serves gossip, discovery, documents, and history.
Its optional peer-history policy allows a seed to start without available peers; a full node fails
required-history fetch. Profile isolation is not permission to reuse one populated role's cursors
for the other.

Startup verifies schema and node role before logs/index repair or decoding. One data directory
belongs to one role: all chain readers share a block cursor, so a smaller reader set can skip events
required by another role. `preflight_node_role` stamps first boot and rejects another role; a
pre-existing unmarked directory is a full node's. Schema 8 prevents old schema-7 binaries ignoring
the role check. Historical limitation: v0.18.0 can open a schema-7 directory written with the
development role marker without checking that marker.

Recover selector and finalized-committee snapshots, prune terminal E3s, and fail on contradictory
committees/missing required metadata. Seed roles, party IDs, verifier caches, and DHT interests
directly. Do not append synthetic selections/role changes on each boot. Apply derived local
participation only at fenced `SyncEffect`, after effects attach and before canonical backfill.

The router checkpoint is exactly `//router/recovery_checkpoint`, holding active/completed contexts
and aggregate cursors. Keep the highest sequence on live and recovery paths. If it trails snapshot
cursors, project **only its missing EventStore suffix** without replacing admission state or
replaying that suffix into hydrated protocol actors. Never let an older contextual write move a
cursor backward. The live `on_event` path must not synchronously read stores or replace restored
actors with fresh ones.

Before hydration, finalized Ethereum reconciliation reads `getE3Stage`/`getFailureReason` for every
restored or replay-admitted context with nonterminal local stage. It handles 16 contexts per batch,
60-second connection/batch limits, and two retries on RPC error. Complete and non-slashing failed
E3s become terminal; slashable failures retain their contexts for accusation work only. A chain-head
E3 not yet finalized waits rather than being called unknown. Unknown E3, failed bounded reads, or an
unconfigured chain fails startup. Explicitly disabled configured chains resume their contexts
unchecked.

For retained slashable failures, seed Failed into router recipients before replay or at effects for
a newly admitted context; later recipients get it first. Stop keyshare, PK/plaintext aggregation
(also while waiting for authority), C0 verification, ordinary compute, and DA recovery, while
retaining accusation re-verification. Give cleanup the E3's aggregate/cursor so writes are not
stale. Completed contexts receive `E3RequestComplete`, not another effects signal. Document
publication recovery does not itself read lifecycle; canonical backfill closes it later.

**Two open reconciliation gaps:** lifecycle stores stage but not failure reason, so a **locally
Failed** context completes on restart even when accusation work remains. Also, a canonical Failed
stage read at startup exists only in the lifecycle snapshot, not a replayable event. Ordinary
restart keeps it, but rebuilding from the log can record Complete and lose failure-settlement
recovery. A canonical observation still needs a replayable representation (historical concern #48).

Canonical key authority is rebuilt from full retained chain history before proof replay/hydration,
including publication/chunks before snapshot cursors.
[Threshold decryption](threshold-decryption.md) owns C6/C7 admission, dormant snapshots, bounded
deferred history, and result repair. Missing authority must not block unrelated E3s or turn gossip
into authority. The EVM writer seeds terminal IDs from confirmed history and discards later
publication work for those IDs.

The E3LifecycleCoordinator observes monotonically and emits no protocol events. Its stage map feeds
cleanup, writer, and compute recovery, so its schema/update order is durability-critical despite
being a projection. Dashboard projections are disposable: page logs to derive stages, committees,
tickets, failures, rewards, IDs, causation/origin, HLC, aggregate, watermark, and recorded source.
Local causality is exact; network context stays receiver-local. Known ABI logs without a protocol
decoder become lossless named `EvmLogObserved`; absent catalog signatures are `UnknownEvmLog` with
raw topics/data. Settlement receipts are global facts and cannot reopen completed per-E3 actors.

## Deferred recipients and capacity

Only chain facts or restored snapshots admit an E3; peers cannot create unknown contexts. Installed
extensions declare expected recipient keys; dependency-only extensions and bootstrap contexts expect
none. A missing recipient receives deferred events in arrival order **before** its creation event.
Each recipient copy reserves its own item and byte budget:

| Scope                         |  Items | Accounted bytes |
| ----------------------------- | -----: | --------------: |
| E3, across missing recipients |  4,096 |           1 GiB |
| Router                        | 16,384 |           3 GiB |

`event_size` accounts fixed-integer bincode, inline storage, and 64 bytes per allocation candidate
in one serde pass without allocating an encoded copy. It reserves twice event inline size for queue
capacity. Collections, fields, strings, and elements may conservatively reserve without separate
allocations. `ArcBytes` removes spare capacity; deferred shared key/share collections are compacted.
Encoded size alone is not retained-memory accounting, and the ceiling is not total RSS.

The capacity rationale is four concurrent N=19/H=14 secure-8192 histories (three threshold/two DKG
limbs, one smudging polynomial). Accusation/checker recipients start at committee finalization;
keyshare/PK at local selection; plaintext after ciphertext plus dependencies. Their histories do not
all overlap. The late plaintext allowance reserves 1,536 records, including 108 C3 proofs,
C0/C1/C2/C4, four records per proof, 256 controls, and `32*N` key/share/document records. It budgets
160 MiB pending C1–C3 witnesses, 128 MiB separately routed failed compute payloads, 144 MiB
peer/outbound documents, 64 MiB C4 requests/failures, and 64 MiB remaining work: 560 MiB rounded to
640 MiB.

Before selection allow 80 MiB/256 records per recipient; up to five formation prefixes (400 MiB)
drain before local witnesses, rather than five copies of the largest history. E3 limits leave 384
MiB and 2,560 items above the late allowance; four histories reserve 2.5 GiB/6,144 records, leaving
512 MiB under the router cap. An 8 GiB process budget additionally reserves 1.5 GiB
fragmentation/in-flight storage and 3.5 GiB baseline/live/system; prover memory is separate. These
are operating allowances, not validation rules for arbitrary payloads or allocations already owned
outside the router.

Overflow clears only that missing recipient's E3 queue, logs ERROR, records delivery failure, and
disables further deferral until teardown/restart. Live routing, checkpoints, other recipients, and
other E3s continue; the affected E3 can fail at its existing deadline. **Gap:** queues and failure
records are memory-only; restart cannot recover their pre-checkpoint backlog.

[Capacity tests](../../crates/request/src/routing/capacity_tests.rs) route four independently
allocated secure-sized histories through real recipient creation, including full failed C3/C4
requests and document envelopes. They test ordered delivery, default-limit overflow, spare-capacity
release, and allocation-heavy empty buffers. Linux RSS checks require distinct resident storage and
<=4.5 GiB growth at saturation. This does not establish a maximum node RSS or durable queue
recovery.

## Effect recovery and shutdown

Fence startup `EffectsEnabled` → `SyncEffect` → merged canonical history → `SyncEnded`. Compute
waits for effects; document publication waits for SyncEnded. `ComputeEffectGate` subscribes before
replay, uses durable lifecycle, coalesces requests/new hydrated correlations, reuses successful
responses but not replayed errors, and answers every waiting correlation. Outcomes must match the
E3. Discard DKG work after KeyPublished while keeping C6 verification (inspect proof type in the
shared verification request). Before release/reuse, canonical C6 admission still applies.

After ten minutes without an outcome for a fresh ID, resend only once no identical request remains
queued/running. A hung run waits for its prover cap. Terminal E3 cancels queued node-scoped compute
work; executing Rayon jobs may finish, but cannot revive the E3. The key includes local node
identity so one node cannot cancel another in a shared pool. Accusation re-verification has its own
group, survives local failure, and ends with request teardown.

Local resource/prover/verifier failure retries exact requests, never labels peer data invalid.
Production begins at two compute jobs/two reserved CPUs, reduces against CPU and host/cgroup memory
(4 GiB node reserve plus 13 GiB per prover), and refuses participation if one prover cannot fit.
Retries back off to five minutes, use bb low-memory mode after the first attempt, and limit WARN
retry messages to one per node per minute. Task panics/channel closure become structured local
errors. The pinned bb timeout is configurable (`bb_timeout_secs`, default 12 hours); kill timed-out
processes and bound included output. Per-attempt temporary directories clean normal/stale restart
work. Do not reuse historical #72's older 7,200-second timeout as the current default.

Durable phase recovery is domain-owned: [DKG](dkg.md), [decryption](threshold-decryption.md),
[sortition](committee-selection.md), and [slashing](slashing.md). Absolute deadlines/purpose,
semantic inputs, randomized contributions, proof bundles, publication intents, and failover state
must survive or be deterministically derivable. Classify fields Durable/Derivable/Ephemeral; process
lifetime alone does not justify ephemeral state. Additive backfill creates missing versioned
records, never overwrites existing ones. Missing required/unsupported active recovery records fail
startup.

Shutdown's barrier covers delivery of persisted Shutdown to current subscribers, event flush, open
snapshot drain, and backing-store flush. It does not own every detached task; process exit can
cancel unowned work. Node deadline is 60 seconds (30-second fanout plus flush margin); swarm/Docker
wait 65 before SIGKILL. Detached daemon launch confirms its control socket; dropping a launcher must
not kill the daemon. Supervisors must exceed the node deadline, not merely equal it.

Chain gateway fatal errors after startup trigger unsuccessful exit **after durability shutdown**.
Head-read heartbeats under `<data>/ingestion/` fail health at >120 seconds age or no head/cursor
movement for 600 seconds. Record expected reader count/start first; after 900-second startup grace
every expected reader needs a heartbeat. **Gap:** post-probe heartbeat write failures are only
logged.

## Storage representations and decoding

The data crate's [in-memory store](../../crates/data/src/in_mem_kv_store.rs) uses
[`e3-hamt`](../../crates/hamt/) to share unchanged nodes between immutable map versions. Here
"persistent" describes the data structure, not a disk flush. Its exported dump remains a
bincode-encoded ordered map; changing the live structure does not authorize changing those bytes.

[`e3-utils`](../../crates/utils/src/bounded_bincode.rs) provides fixed-integer bincode decoding with
a byte budget and complete-consumption check. Its retry and channel adapters are mechanisms, not
durable delivery guarantees. [`BytesSerde`](../../crates/utils-derive/src/lib.rs), re-exported by
utils, gives one-field byte newtypes hex in human-readable formats and bytes in binary formats
through `AsBytesSerde`. A readable JSON value does not establish binary-layout compatibility.

## Schemas and validation

Persisted snapshots/events are positional bincode; gossip embeds bincode in a versioned envelope.
Only some types have per-type versions (for example BondOwnerState). Until a tested per-type
migration exists, every incompatible persisted layout/event variant change, even an added field,
requires a manual `SCHEMA_VERSION` increase. Raw preflight runs before logs/index
opening/repair/decoding; `node validate`, including `--repair`, uses it and leaves incompatible log
bytes unchanged. Global storage schema is **not linked** to `protocol-release.toml`; wire major
changes are separate.

[Layout locks](../../crates/layout-lock/) detect encoding drift and same-encoding field
swaps/renames for roots explicitly listed by hand.
[Shared fixtures](../../crates/tests/tests/layout_lock.rs) cover events, keyshares, gossip, public
repositories; e3-slashing/e3-zk-prover cover private roots and e3-net covers DHT documents and
sample wire frames. **Not covered:** unlisted roots, repository store keys, hand-written log
framing, or opaque encoded/encrypted contents (SharedSecret shares, fhe.rs keys in SensitiveBytes).
Rewriting a fixture does not raise a version; review must connect the diff to schema or wire
rollout. Rust type compatibility is not a migration strategy.

`node validate` opens no absent store, reports unreadable cursors/projections as failed checks, and
detects recoverable tails read-only. With node stopped, `--repair` applies narrowly bounded
tail/index recovery and reconciles derived sortition membership/history against intact logs without
deleting identity or already matching history. It is not generic repair for committed corruption.
[Upgrades](upgrades.md) owns controlled reset, role changes, and identity preservation.

## Remaining durability gaps

- Live fanout logs an accept timeout and does not retry. Snapshot-suffix replay does not necessarily
  redeliver it. Thus at-least-once is a requirement, not a complete live guarantee.
- Snapshot `try_mutate` queues without acknowledgment; no general transactional outbox exists. Slash
  intent and BFV key DurableIntent are narrower protections, not replacements.
- Current recovery needs matching snapshots, not log alone. No test compares full replay and
  hydration for equivalent state/pending intents. Canonical startup failure observations add the gap
  above.
- Accusation votes/timers, slashable-failure teardown, compute-gate buffers, and deferred recipient
  queues are memory-only. Slash fallback due time resets. Collector clocks are not injected.
- Checker snapshot failure and terminal DKG snapshot publication remain unacknowledged; C4
  roster-fixed writes can be stale after restart. [DKG](dkg.md) retains exact failure windows.
- `sync/state.rs` reads repositories; document workflow and keyshare timeout policy read wall clock,
  exceptions to the target pure-workflow boundary. Do not widen them.
- Chain nonce serialization is in memory; only slash submissions have a durable intent record beyond
  replay-derived publication work. Other transactions rely on preflight. Chain confirmation depth
  supplies no general reorg rollback. Cancellation ownership remains uneven across crates.
- The program-server test endpoint is unauthenticated and is never a production trust boundary.
- Snapshot routing still retains a child Batch actor for each open aggregate/sequence until flush;
  bounded replay pages do not bound the whole simultaneously open snapshot set. Its asynchronous
  edges need their own delivery/pressure evidence, not an event-log page-limit argument.

## Existing guards

Use `pnpm check:repository` for Cargo feature containment, Docker workspace coverage, and configured
shutdown grace. These configuration checks do not prove runtime delivery or a successful shutdown.
The remaining `do_send` sites include correctness paths; a call-count ceiling cannot establish safe
delivery. Proof-skipping rejection is tested in
[`start/start.rs`](../../crates/entrypoint/src/start/start.rs), but those unit tests exercise the
validation function rather than the full startup path.
[Schema tests](../../crates/entrypoint/tests/validate_older_schema.rs) check failure before
recovery;
[finalized reconciliation tests](../../crates/ciphernode-builder/src/finalized_lifecycle.rs) include
bounded failed-batch retry. [Effect-gate tests](../../crates/multithread/src/effect_gate.rs) include
`replayed_failure_does_not_suppress_a_recovery_attempt`. Run affected focused Cargo tests and
`pnpm test:integration` for cross-layer restart/shutdown scenarios. None closes the gaps merely by
existing.
