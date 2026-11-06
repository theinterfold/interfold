# Ciphernode v2: decision log

The v2 node is written as new crates beside the current node, and replaces it in one release. The
contracts do not change: every byte a contract verifies stays identical. This log records the rules
for v2 code, the decisions, and the problems in the current node that each decision removes.

## Rules for v2 code

Each rule is checkable in review.

1. **Colocate by capability.** A machine, the wire messages it owns, their slot rules, and its tests
   live in one module.
2. **Dependencies point to what changes less.** `e3-protocol` ← `e3-engine` ← adapters ← `e3-node`.
   The core (`e3-protocol`, `e3-engine`) links no I/O crate, no actix, and none of the current
   runtime (`e3-events`, `e3-request`, `e3-data`, `e3-slashing`).
3. **Explicit over implicit.** Phases are enums with exhaustive matches. No string keys, no
   registration order, no call order that callers must know.
4. **Self-contained.** No globals. No environment reads below the composition root. Time and
   randomness reach a machine only as inputs.
5. **Deep modules.** Small interfaces over large implementations. No pass-through wrappers, no
   extension points without a second user, no dead code.
6. **No special cases by default.** Each one that stays is listed under "Special cases kept", with
   the requirement behind it. No retry or sleep as a patch, no swallowed error, no disabled test.
7. **Comments state facts outside the code** (chain, libp2p, circuits, contracts). They never
   restate the code.
8. **Tests check behavior at the owner's boundary.** Each test must fail when the rule it protects
   is reverted. No test restates the implementation.

## Decisions

- **D1. A rewrite beside the current node.** No step has to keep the current node working, so no
  compatibility scaffolding is built. New crates sit in the existing families; the current crates are
  deleted after the switch.
- **D2. One embedded transactional store (redb).** One transaction per machine step holds the
  journaled input, the new state, and the outbox entries. Pure Rust, ACID, no C++ build.
- **D3. tokio tasks and bounded channels; no actix.** No task awaits another in a cycle. The outbox
  dispatcher runs on its own task and reads the store. The libp2p loop never waits for a consumer.
- **D4. Time is an input.** Every input carries the time at which it was applied (`Timed<T>`).
  Machines never read a clock, so replay is exact.
- **D5. Randomness is an input.** Machines never draw randomness. A random value arrives as a job
  result and is journaled before any effect that uses it leaves the node.
- **D6. Identity by source, not by clock.** Chain facts by (chain, block, log index). Peer messages
  by slot (E3, sender, kind, subject). Job results by semantic job id. Effects by a deterministic id.
- **D7. Contract-verified bytes are locked by golden tests first.** Vectors are taken from the
  current code before any port; the v2 code must reproduce them.

- **D8. One pure `Node` machine, one journal.** The node's whole protocol state is one
  deterministic machine; each E3 is a plain struct inside it, and admission and routing are pure
  code. The engine journals every input with its time, commits the effects and a periodic snapshot
  in the same transaction, and replays the journal after the latest snapshot on restart. Large
  payloads are stored once by hash, so snapshots stay small. A failed commit consumes the engine,
  because its state may be ahead of the store.
- **D9. Machines are deterministic.** State uses ordered maps, never iteration order of hash maps;
  a machine reads no clock, draws no randomness, and holds no secret key. Signatures are effects
  whose results come back as inputs.

- **D10. Peer messages wait in the bounded hold until the chain fact that lets the node judge
  them:** the committee's finalization for DKG messages, the key's publication for decryption
  shares. Before that, nothing can say whether a sender may speak, and a libp2p peer ID is not bound
  to an operator, so an attacker can sign as many operator addresses as it likes. This replaces the
  early-key record in `Init` ([dkg](dkg.md), key collection row).
- **D11. Every input first applies the deadlines that have passed.** A tick only wakes the machine,
  so a late wake-up changes nothing: a key check that returns after the key cutoff does not count,
  whether or not the cutoff's tick came first ([dkg](dkg.md), "Timing and collection").

- **D12. Ready reports only grow.** A member's later Ready must contain its earlier one; each
  receiver drops expelled dealers itself when it chooses a roster. Today a reporter drops expelled
  dealers, so a receiver that has not seen the expulsion yet must hold the update
  ([dkg](dkg.md), "One H-roster").
- **D13. One verification job per dealer.** A verdict covers one dealer's exact message, so a verdict
  can never apply to a batch it was not made for, and growth needs no new batch.
- **D14. Signatures are requested in batches.** One request carries every hash of a step (a dealer's
  C1, C2, and per-recipient C3 proofs), and its answer returns every signature in order.

- **D15. Only roster members make a decryption key (C4) and send a keyshare.** Decryption admits
  only roster members' C6 shares ([threshold decryption](threshold-decryption.md)), and the key
  aggregates only roster keyshares, so a C4 or keyshare from outside the roster changes nothing.
  Every member still checks the roster members' C4 proofs, so accusations against them can reach
  quorum.
- **D16. Accepting a roster fixes it.** C4 starts in the step that accepts the roster, as it does
  live today; the current node's replacement by a lower proposer only happens while effects are
  disabled during replay, which v2 does not have.

- **D17. Proof bytes are blobs.** A proof in machine state is its bytes' blob reference plus its
  public inputs. The contracts sign and compare only the Keccak-256 of proof bytes, which is the
  blob reference's hash, so signing and signature checks need no bytes; jobs and the chain writer
  read the bytes from the blob store. A Small committee's DKG holds hundreds of proofs, and inline
  bytes would put megabytes into every snapshot.

- **D18. Decryption takes its authority from the chain.** The key event gives the committee in the
  registry's order, the roster (the selected party IDs in the proof's public inputs), and the key
  commitment; the decryption domain is computed from them and the ciphertext's hash
  ([threshold decryption](threshold-decryption.md), "Authority before work"). The DKG only supplies
  this node's sealed decryption key, and only when it summed that key over the chain's roster.

- **D19. One re-send rule for every message a node sends.** While the work a message feeds still
  runs at the node, its latest message of each kind goes again after one minute, then at doubling
  intervals up to ten minutes, for at most eight hours ([threshold decryption](threshold-decryption.md),
  "Restart and redelivery limits"). Receivers keep the first copy. This replaces per-phase timers,
  document re-announcement as the only DKG recovery, and the promoted aggregator's roster
  re-proposal.

- **D20. Selection reads the node's own registry history.** Activity, ticket balances, bond owners,
  and the identity policy are chain facts with their block times; selection reads them at T−1 for
  a request at T ([committee selection](committee-selection.md)). The node's load limit counts the
  live E3s it holds a ticket for, so no separate counter can drift. Under a required identity
  policy v2 ranks every eligible operator, which is today's fallback when the eligibility read
  fails; porting that read, which keeps the owner shortlist, is still open.

- **D21. No history sync.** A node that restarts or joins late gets each peer message whose work
  still runs from the peer's re-sends (D19), and every chain fact from the reader, which resumes
  at its last applied log. No protocol replays gossip history, so no history can outgrow a
  transfer limit or be gossiped again by its readers.

- **D22. Blobs travel from their publisher, not through DHT records.** Gossip carries the operator
  signed message with blob references, and the network adapter delivers it at once. The machine
  fetches a message's blobs only once the message's E3 admits it (a member's first message of its
  kind, correctly signed), with an effect the adapter carries out: it asks the peers that sent the
  message, publisher first, and keeps only bytes that hash to the reference and have its length.
  The machine takes the message once the blobs are in the store. So a sender outside the
  committee costs a node no download, and a member at most one message of each kind; the adapter
  bounds the bytes on their way at once. A sender's message of a kind is the only one of that kind
  fetched from it until the node takes it, even when a blob of it never comes. Each E3 keeps its
  own blobs, a blob request names the E3, and the node closes an E3's blobs once its work ends:
  the store waits for writes under way, deletes them, and refuses later ones for as long as it
  runs. At a start the node drops the outbox work of E3s it no longer holds before running any. The protocol says which blobs a node needs: a share
  message's only for its recipient. A publisher uploads a broadcast blob once per receiver and a
  share once, where a DHT put of the current node goes to twenty peers. A share comes only from
  its dealer, so members need direct connections: peers that identify on the network enter
  Kademlia's routing table, whose lookups connect to the peers they find. Open: gossip still
  forwards a non-member's envelopes, since the adapter does not know the committees.

- **D23. A ciphertext is fetched, not read from the log.** The deployed Interfold logs a content
  hash and its availability coordinates (`CiphertextOutputReferencePublished`). Decryption emits a
  fetch effect for them and starts its jobs when the bytes return, so a slow availability layer
  delays only that E3, and the outbox repeats the fetch after a restart.
- **D24. Nodes fail stalled E3s and settle failed ones, in turns.** Each chain fact that starts a
  stage gives the deadline after which the contract fails it. From one second after it, nodes call
  `markE3Failed` in turns 30 seconds apart: committee members by party ID, and, before a committee
  exists, the request's eligible operators in address order. While the request waits for
  randomness the deadline is the randomness deadline; once the seed arrives, ticket holders
  finalize after the committee deadline, and the others wait the DKG window more, after which the
  contract fails a committee that met its threshold too. After a failure the same turns call
  `processE3Failure`. A node that has a turn keeps the E3 until the chain logs the settlement,
  however long the contract keeps it closed. A node that holds a committee's work keeps it, and
  its blobs, until the slashing manager logs `E3DependenciesReleased`: accusations that expel no
  member can come, and be appealed, even after settlement, until governance closes the E3 there.
  A failed E3 that governance never closes keeps its committee's work. The finalizer takes the same turns. The node judges deadlines by
  its own clock, so a node that replays old history submits these calls for E3s that ended long
  ago; each ends at its preflight.
- **D25. The node refreshes its operator in each owner capacity window, whatever the identity
  policy.** Under a required policy an owner's capacity reads zero from the start of each 30-day
  window until its operators refresh, so requests can fail with `InsufficientBondOwners`. The chain
  offers no view of the policy, and a node that starts after the policy's event would not know it,
  so the node refreshes unconditionally: ten minutes after a start, then a minute and an hour after
  each window starts, since a refresh counts for the window of its block.
- **D26. A data directory carries its layout.** The node writes the layout beside its files: the
  protocol's `ENCODING_VERSION` for the journal and snapshots, and the store's version for the blob
  folders and the wallet file. It refuses a directory in another layout, so an update never
  misreads an old journal or deletes old blobs as foreign. A test fingerprints a sample journal and
  snapshot, so an encoding change fails until its version changes. v2 has no migrations before its
  first release: a layout change means starting from an empty directory.

## Problems in the current node, with the fix above them

- **Separate inputs, effects, signals, and notifications; wire types apart from internal types.**
  - `crates/events/src/interfold_event/event_data.rs:58`: one enum (99 variants) is the log record,
    the bus message, the gossip payload, the job call, and the process signal.
  - `crates/state/sync/src/workflow.rs:45`: process signals are skipped on replay by a hand list.
  - `crates/net/src/events.rs:107`: the gossip payload is the bincode of the internal event.
- **One durability rule: journal + state + outbox per machine, in one transaction; replay runs the
  pure step and ignores effects.**
  - `crates/events/src/store_keys.rs`: 11 recovery and checkpoint records next to actor snapshots and
    the event log.
  - `crates/state/request/src/context.rs`: each extension must pass `effects_enabled` to the actors it
    creates; nothing enforces it (the bugs fixed by #2439 and #2443).
  - `crates/ciphernode/multithread/src/effect_gate.rs`: a 1,288-line gate dedupes job requests that
    replay sends again.
- **Jobs are a typed service with semantic ids, not events.**
  - `crates/orchestration/keyshare/src/effects/generate_threshold_share.rs:23-32`: a job request is
    published as a durable event.
- **Bounded channels, no cyclic waits, effects in the outbox until done.**
  - `crates/events/src/eventbus.rs:43`, `:282`, `:310`: live fan-out waits 30 s, holds the bus, and
    drops on timeout.
  - `crates/orchestration/keyshare/src/actor.rs:195-197`: re-send timer for lost decryption work.
- **One struct per E3 owns all its sub-state; phases are typed.**
  - `crates/state/request/src/context.rs:35-37`: actors kept in a string-keyed map, values in a
    heterogeneous map.
  - `crates/state/request/src/routing/actor.rs:93`: extension order matters and is unenforced.
  - `crates/orchestration/keyshare/src/actor.rs:204`: one actor keeps 4 saved stores, about 8
    in-memory flags, and timers.
- **Operator-signed wire payloads checked once at the edge, with per-kind slot rules.**
  - `crates/net/src/network.rs:185`: `validate_event` checks only the E3 and the chain; the operator
    is a payload field that each consumer checks.
- **A pure protocol crate at the bottom of the graph.**
  - `e3-events` links `e3-trbfv`, `e3-zk-config`, `e3-evm-contracts`, `e3-crypto`; `e3-zk-prover` links
    `e3-slashing` and `e3-request`; `e3-evm` links `e3-sortition` and `e3-request`.

## Special cases kept

None yet.
