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
