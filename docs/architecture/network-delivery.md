# Peer admission and document delivery

Owner: [e3-net](../../crates/net/). This is protocol transport, not Avail application
[data availability](data-availability.md). [Persistence](persistence-and-replay.md) owns durable
event admission and startup fences; [upgrades](upgrades.md) owns wire/release compatibility.

## Network and trust boundaries

A stable 32-byte network ID scopes Identify, gossip, Kademlia, and historical sync, alongside
protocol version. Stage peers until exact Identify/capability admission; disconnect incompatible
peers. Production policies require at least one deployment: an empty map cannot imply unrestricted
access. Gossip's versioned envelope binds magic, version, network/deployment, aggregate, event ID,
payload hash, and size. Only permitted chain-bound aggregates enter historical sync;
chain-independent aggregate zero cannot arrive through peer history. Validate before EventBus
admission. Most protocol payloads still lack explicit per-type schema versions; later domain
admission checks signatures/committee statements.

Never offer the old unscoped protocol as fallback. Mainnet/Sepolia DNS bootstrap aliases are
distinct; retired bootstrap addresses are not compiled defaults. Legacy records in the wrong
aggregate can be quarantined without deleting operator data. Permanent compatibility failures differ
from transient Identify timeout cooldowns; keep all simultaneous connection outcomes. Sync
validation failure sends a terminal protocol error rather than leaving the caller to time out.

Identify must refresh filtered Kademlia addresses, not maintain a bypass cache. Retain unique
filtered addresses within **8 entries and 2 KiB encoded**, including peer IDs. Prefer advertised
live endpoints, then advertised order. Remove superseded addresses; retain at most two live
endpoints until their last connection closes, then remove withdrawn ones. Only new admitted
connections notify admission. Reject self-dials below DNS in QUIC, filter public-profile loopbacks
before listeners are known, and remove self-reaching addresses without quarantining the real peer.
After outages, configured peers can redial the last concrete outbound address of their trusted
identity as well as DNS.

Transport connections do not prove protocol readiness. Give new peers time to subscribe, then close
all connections of peers still lacking the gossip topic. Redial backoff doubles for repeated missing
subscriptions, resets on subscription, and expires 30 minutes after its redial time. Remove that
peer from Kademlia and suppress **all** outbound dials including queries during backoff. Release
readiness requires expected directed topic subscriptions on every node, not only admitted QUIC
connections.

## Gossip identity and overload

Periodic retransmission uses a fresh transport delivery ID but the same embedded protocol event ID.
Libp2p may transmit again; EventBus and stored-event identity still deduplicate the fact. Do not
accept or forward IDs retained in the six-hour seen window. Stored-event retention is also bounded;
rejected handoff releases its reservation and append failure stops the node.

Capacity follows four concurrent N=19/H=14 E3s with 2x margin plus retry bursts. Peers borrow idle
capacity. At pressure a peer at fair share evicts its own oldest ID; a peer below share reclaims
from the largest owner. Early eviction increments `seen_ids_early_evictions_total` in bounded WARN
logs. Retention may shorten, but new valid protocol inputs must not be rate-throttled away. The
libp2p duplicate cache keeps its 60-second default so messages first received before admission can
return; the application window prevents old copies circulating for hours. Heartbeat is one second.

Notification shape/expiry validation precedes admission. Malformed messages get Reject; expiry alone
gets Ignore after other checks, not a relay score penalty. Valid relays for another party remain
valid. No message-count or byte-rate throttle discards them; per-message size caps still apply.

Long-lived raw NetEvent consumers warn on `Lagged(n)` and continue from retained events; closure
alone ends receive tasks. NetEventBuffer does this only after SyncEnded: startup lag fails readiness
closed. The raw channel carries everything; the separate application channel carries gossip and
publish/DHT results so connection/sync bursts cannot consume its startup buffer. Command callers
register by correlation at the producer, which delivers results **before** broadcast. These results
bypass NetEventBuffer and are not held until SyncEnded. The document publisher sends no
result-waiting command before that fence; translator gossip can run earlier. After held application
events, `StartupBufferReleased` triggers storage flush before history replies vouch for a range.

## Historical sync and coverage

Startup peer history is bounded across **all aggregates, retries, and peer-list waits**: 512 pages,
50,000 events, 128 MiB, and five minutes per attempt, without an operator override. Missing required
sources or exhausted budget fails full-node startup; bootstrap explicitly permits absent peer
history. After required sources exist, exhaustion while seeking optional coverage hints stops that
extra search rather than discarding the collected sources. Reset can recover only still-available
chain/peer facts, not a deleted secret share or every historical gossip event.

Fetch an aggregate from two admitted sources when available, or its sole connected peer. Page each
source from the requested timestamp and union by event ID with earliest time. Require
payload-derived IDs, equal payloads for repeated IDs, advancing cursors, and no events before the
requested boundary. Compare timestamp claims against retained local records and historical EVM
inputs (including quarantined legacy records that still occupy timestamps). Different IDs/payload
digests at one claimed timestamp fail rather than collide later in EventStore. The local claim scan
is also bounded. Replace bad sources; give replaceable slow peers bounded opportunities so they
cannot consume the entire attempt.

History serving uses timestamp-index order, not physical log order: older remote timestamps can
follow newer log records. Storage pages are count/decoded-byte bounded, admit one larger record for
progress, and move the reply cursor past every consumed record, including filtered ones. Direct-wire
response limits still apply; an oversized single response event fails rather than silently
disappearing. Checksums of neighboring records read in one storage window can also make a query fail
on corruption.

`observed_from` is a **hint**, not a completeness proof. It starts only after the responder's
startup gossip buffer is durably drained. Later ingress lag revokes it for that process; a changing
hint cannot vouch for the current reply or turn a previously unvouched fetch into covered history.
If no source hints at full-range live observation, fetch up to four peers total with remaining
budget and warn that coverage may be incomplete. A dishonest hint can stop that optional search
after two sources, and gossip still queued ahead of storage is absent even with an honest hint.
Enforce clock-drift allowance when complete source history is ready and again before publication;
unpublished future history fails startup. These are bounded reconciliation heuristics, not archival
availability or consensus.

[Network-sync tests](../../crates/net/src/network_sync/tests.rs) exercise source conflicts, coverage
hints, and shared budgets. They do not prove that two peers retained every fact ever published.

## DKG documents

The publisher reconstructs outbox and received IDs from durable logs. Store each document in its own
DHT first, then announce a small notification independent of peer-upload success. A failed upload
must not delay announcement. Reannounce notifications from 30 seconds, doubling to five minutes,
with 10% jitter where configured; refresh full uploads only every 30 minutes, one upload started at
a time with two put attempts. Retry failed announce/upload from 15 seconds to five minutes; an
announce retry does not upload again. Library-driven hourly replication stays disabled; prune expiry
every minute. Kademlia stream timeout is 60 seconds.

Recovery derives a missing publication request from a durable local key/share artifact. A crash
after artifact commit but before the derived request therefore need not lose publication. This is a
narrow reconstruction path, not a transactional outbox for arbitrary network effects; see
[document recovery](../../crates/net/src/document_publishing/recovery.rs).

Each publication starts only at SyncEnded. Ready/Roster retransmission similarly waits for local
replay, backs off 30 seconds to five minutes, and retains the latest own message per E3/party/kind
for eight hours. Decryption-share event gossip backs off 60 seconds to ten minutes. Chain-terminal
memory keeps the last 1,024 E3s and prevents later retransmission scheduling; replay schedules local
messages in log order, while restart rebroadcast sends recent messages once without re-caching.

A Kademlia inbound-put acknowledgment is not proof of storage: the receiver decides later. Count a
put as replicated only when a post-upload lookup returns its record **from another peer**. This
proves that peer served bytes at that moment, not persistence through its restart. The network
interface owns at most 16 result-pending puts. A reported result retains its Kademlia place until
query termination; remaining uploads can overlap the next replication. Each command has a caller
deadline (240 seconds from send, versus caller's 270-second wait), including commands taken late.

The DHT replication factor stays 20, so a refresh can still upload to 20 peers. A lookup reliably
reaches the original publisher only in a network of roughly that size; larger networks depend on
replication success. libp2p-gossipsub 0.49.4 also does not decrement its publish counter for an
expired queued publish. Bounded publish-result timeouts and retransmission mitigate liveness, not
guaranteed delivery; no-peer errors use a longer join retry window and invalid payloads do not
retry.

## Fetch and storage fairness

Ingress never awaits a long DHT fetch. Keep propagation-peer attribution transiently through
buffering, not in document identity/serialized metadata. An early notification is keyed by
peer/document/party filter, keeps latest expiry, and is rechecked after selection. Allowed filters
are empty or one party. The early queue allows 3,040 notifications (four N=19 rounds, 2x margin);
prune expiry on new ingress.

Document fetches use at most **8 active reads, 512 queued documents, 128 announcers per document**.
A due peer with fewest active reads gets the next slot, rotating ties; a lone peer may use all
capacity. One GET attempt releases its slot within 90 seconds; retries return to the fair queue with
backoff until success, E3 closure, or notification expiry, not an arbitrary six-failure limit.
Duplicate announcements do not advance retry deadlines. A document has at most one fetch and can use
any retained announcer; at capacity replace oldest announcers after the first. Assign queue
ownership to the least-loaded retained announcer, including retry; move shared work before eviction.
A busy peer cannot evict shared work while another announcer has no queue. No per-peer cap wastes
idle global capacity; pressure can reclaim from largest owners, otherwise replace only the peer's
more-failed work. Overflow waits for a later announcement rather than falsely claiming delivery.

GET accepts only the requested key. Retain one waiting notification per filter with latest expiry;
accept under the first whose metadata matches fetched bytes, and validate late notifications against
those bytes. A forged/expired notification cannot displace correct metadata or a self-consistent
record for the wrong key. Suppress duplicate documents.

Inbound puts cannot replace a locally published record or shorten a replica's expiry; no expiry
means unlimited lifetime. Replica ledger bounds inbound storage at 160 per sender, 3,040 total, and
2 GiB value bytes. Under pressure evict expired first, then sender's oldest at sender limit;
globally, donor over fair share in the short dimension loses oldest records until enough room.
Refuse only if eligible evictions cannot make room. Local/restored publications are never evicted
for replicas; a local write can evict a replica. Update ledger on removal, expiry, library pruning,
and conversion to local ownership.

## Cleanup and remaining loss windows

Canonical KeyPublished stops DKG notifications/uploads/retries and prunes locally published records.
C4 `DecryptionKeyShared` is a DKG document; later `DecryptionshareCreated` is event gossip. Local
request completion alone is not canonical termination. Recovery retains canonical DKG closure and
drops expired outbox entries before admitting replayed publications.

Cleanup has one queue of 4,096 keys and one waiting send; full queues drop oldest with WARN so
record expiry/put timeout remain the fallback. Cancellation reports immediately and starts no new
check, but ends a Kademlia put only in upload/check phases. Requests already handed to connection
handlers still run, and a query looking up closest peers continues then uploads. **Full cancellation
is unresolved.**

At SyncEnded, restore received **broadcast** documents into the in-memory DHT one at a time, best
effort: at most 512 documents/128 MiB, last received in log order, selected while paging local
history (1,024 events/16 MiB). Expired/full-store records are skipped. Receipts replayed after the
committee snapshot may join the queue. Party-filtered documents are not restored because their sole
recipient is this node. Replica puts themselves are not persisted.

**Open risks (#75/#76):** ended E3s can take restore slots before backfill prunes them, evicting
open rounds. Live chain facts held by the gateway until SyncEnded can close an E3 only after
publications start, allowing one stale announce/upload. An offline dealer's recipient-specific
shares are lost when the nodes holding their in-memory replicas restart. "Replicated" does not imply
durable availability.

Log volume must not scale with bytes/redeliveries: use `hexf` length/edges, `NetCommand::summary`,
and default suppression of noisy gossipsub warnings. `RUST_LOG` extends defaults only for named
targets.

## Existing guards

[Network source tests](../../crates/net/src/) cover admission, seen windows, replica accounting,
document workflow, and result routing. [Wire tests](../../crates/net/src/network_sync/wire.rs) lock
sample messages/frames; [layout locks](persistence-and-replay.md#schemas-and-validation) do not
cover every future payload automatically. Run `cargo test -p e3-net` and the affected network
restart scenario through `pnpm test:integration`. A stable-identity restart with topic readiness is
stronger than counting connections; unit fairness tests do not establish persistence of peer-held
replicas.
