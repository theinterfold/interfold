# Interfold Ciphernode — Architecture & Contribution Guide

> Read this **before** writing or modifying any Rust code in `crates/`. It defines the canonical
> structure, the actor/service pattern, and the rules that keep the architecture from drifting. Also
> read `agent/RULES.md` and the relevant `agent/flow-trace/*.md` for protocol behavior.

---

## 1. The Core Principle: Actors are Transport, Services are Logic

The ciphernode is an [actix](https://docs.rs/actix) actor system wired around a central pub/sub
`EventBus<InterfoldEvent>`. The single most important architectural rule:

> **Actors do message passing ONLY. ALL business logic lives in plain, sync, actor-free service
> structs.**

An actor's `Handler` is a thin shell that:

1. Destructures the incoming event/message.
2. Calls a pure service method.
3. Applies the returned decision (persist state, publish events, schedule timers).

It contains **no** validation, no crypto, no aggregation, no state-transition rules, no math. Those
belong in the service.

### Why

- **Testability** — services are unit-tested synchronously with no actix runtime, no bus, no store.
  Fast, deterministic, exhaustive.
- **Reasoning** — protocol logic reads top-to-bottom in one place instead of being scattered across
  `Handler` impls and implicit event dispatch.
- **Resilience** — pure services with explicit decision enums make replay, restart, and
  snapshot/hydrate behavior predictable.

### The shape of a thin actor handler

```rust
impl Handler<InterfoldEvent> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) {
        let (data, ec) = msg.into_components();
        match data {
            InterfoldEventData::E3Requested(d) => {
                // 1. call pure service -> decision
                let outcome = self.state_service.on_e3_requested(d);
                // 2. apply decision (I/O only)
                self.apply(outcome, &ec, ctx);
            }
            _ => (),
        }
    }
}
```

### The shape of a pure service

```rust
// NO actix, NO Persistable, NO BusHandle, NO Addr in this file.
// `tracing` logging is allowed.
pub struct EncryptionKeyCollection { /* plain fields */ }

pub enum CollectOutcome { Ignored, Pending, Completed(Bundle) }

impl EncryptionKeyCollection {
    pub fn collect(&mut self, share: EncryptionKeyShare) -> CollectOutcome { ... }
}

#[cfg(test)]
mod tests { /* sync unit tests against the service */ }
```

---

## 2. Canonical Crate Layout

Every **actor-bearing** crate uses this layout. No exceptions without a written justification in the
crate's module docs.

```
crates/<name>/src/
  lib.rs            # module decls + `pub use` re-exports ONLY. Public API surface.
  actors/
    mod.rs          # `mod x; pub use x::*;`
    <actor>.rs      # thin actix Actor + Handler shells (NO business logic)
  domain/
    mod.rs          # `mod x; pub use x::*;`
    <service>.rs    # pure sync service + its state types + its #[cfg(test)] tests
  messages.rs       # actor Message types / rtypes (or messages/ dir if many)
  repo.rs           # Repository factory traits for this crate's persisted state
  ext.rs            # E3Extension impl + hydrate path, if the crate plugs into E3Router
  <support>.rs      # config.rs, backends.rs, etc. as needed
```

**Leaf / library crates (no actors)** do not need the `actors/`+`domain/` split, but still follow:
**one major struct → one file**; `lib.rs` only wires and re-exports; no dead/old files.

### lib.rs is wiring only

```rust
mod actors;
mod domain;
mod repo;
pub mod ext;

pub use actors::*;
pub use domain::*;
pub use repo::*;
```

`lib.rs` must never contain logic or type definitions. If you find yourself adding a `struct` or
`fn` to `lib.rs`, it belongs in a module.

### Preserving public API across refactors

When moving a type into `domain/`, re-export it from the actor file if external crates referenced
the old path, e.g.:

```rust
// in actors/publickey_aggregator.rs
pub use crate::domain::publickey_aggregation::PublicKeyAggregatorState;
```

The public API (`e3_<crate>::SomeType`) must stay byte-for-byte identical so downstream crates don't
break.

---

## 3. Where to Make Specific Modifications

| You want to…                                              | Edit here                                                                                                |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Add/change a protocol state transition or validation rule | `domain/<service>.rs` (a pure method + a decision enum variant)                                          |
| React to a new event type                                 | The actor's `Handler<InterfoldEvent>` match arm → delegate to a service method                           |
| Add a new persisted state                                 | New `Repository` factory in `repo.rs` + a `StoreKeys::<name>()` in `crates/events/src/store_keys.rs`     |
| Add a new cross-actor event                               | New variant in `InterfoldEventData` + struct in `crates/events/src/interfold_event/` + `EventType` entry |
| Add a new actor                                           | New file in `actors/`, register in `actors/mod.rs`, give it an `attach()` ctor, subscribe it on the bus  |
| Add a timeout/timer                                       | Schedule in the actor via `ctx.run_later`; compute the _policy_ (when/why) in a pure service             |
| Change DKG/proof/aggregation math                         | The relevant `domain/` service; update `agent/flow-trace/04_*.md` same change                            |
| Change committee/sortition selection                      | `crates/sortition/src/domain/`; update flow-trace `03_*.md`                                              |
| Track E3 lifecycle stage                                  | `crates/request/src/domain/lifecycle.rs` (pure) + `actors/lifecycle_coordinator.rs` (thin)               |

---

## 4. Data Management Through the System

### 4.1 The persistence stack

```
Service state (plain struct, Serialize + Deserialize + Clone)
   �packaged in⌄
Persistable<T>        // crates/data — in-memory value + durable mirror
   ⥥ created by⌄
Repository<T>         // a typed, scoped handle to the KV store
   ⥥ produced by⌄
Repositories factory  // store.repositories() → all repo factory traits
   ⥥ keyed by⌄
StoreKeys::xxx()      // canonical key strings, ALL defined in one file
   ⥥ backed by⌄
DataStore → InMemStore | SledStore (KV); EventStore (append-only log)
```

### 4.2 Rules for persisted state

- **Every persisted type is `Serialize + DeserializeOwned + Clone + Send + Sync`.** This is the
  `PersistableData` bound.
- **All store keys live in `crates/events/src/store_keys.rs`.** Never inline a raw key string
  anywhere else. Add a `StoreKeys::<name>()` method.
- **Define a repository factory trait per crate** in `repo.rs`:
  ```rust
  pub trait E3LifecycleRepositoryFactory {
      fn e3_lifecycle(&self) -> Repository<HashMap<E3id, E3Stage>>;
  }
  impl E3LifecycleRepositoryFactory for Repositories {
      fn e3_lifecycle(&self) -> Repository<HashMap<E3id, E3Stage>> {
          Repository::new(self.store.scope(StoreKeys::e3_lifecycle()))
      }
  }
  ```
- **Load with a default** at actor `attach()` time:
  ```rust
  let store = repo.load_or_default(HashMap::new()).await?;
  ```
- **Mutate through `Persistable`**, never bypass it:
  - `try_mutate(&ctx, |state| Ok(new_state))` — mutate _with_ an event context so the write is
    causally ordered (preferred inside event handlers).
  - `try_mutate_without_context(|state| ...)` — only for setup/bootstrapping.
  - `set(value)` — overwrite (used by snapshot mirrors like the lifecycle map).
  - `clear()` — delete the key.
  - `get()` → `Option<T>`; `try_get()` → `Result<T>`.

### 4.3 EventContext: causal ordering

Events carry an `EventContext<Sequenced>` (`ec`). When persisting in response to an event, thread
that `ec` through `try_mutate(&ec, ...)`. This preserves the hybrid-logical-clock ordering used by
sync/replay. **Do not invent a fresh context** for a write that is caused by an inbound event.

### 4.4 Snapshot vs. EventStore — two persistence mechanisms

1. **EventStore** (append-only): every `InterfoldEvent` is logged. On restart the log is
   **replayed** (with side-effects disabled) to rebuild state.
2. **Snapshot / Repository KV**: actors persist their current state so replay can start from the
   last snapshot instead of genesis.

Both must agree. A service rebuilt from replay must reach the _same_ state as one restored from a
snapshot. This is why services are pure and transitions monotonic — see §6.

### 4.5 Upgrade safety — never break on-disk formats

- Persisted formats are **bincode**. Changing field order/type of a persisted struct breaks
  deserialization of existing nodes' data on upgrade.
- When you must evolve a persisted type, keep it backward compatible (additive optional fields,
  versioned enums) and **preserve the byte layout of legacy data**. Example: `InMemKvStore::dump()`
  still serializes a `BTreeMap` for byte-identical compatibility with pre-HAMT dumps.
- Add a round-trip / legacy-format test when touching a persisted type.

---

## 5. Events & The Bus

- `EventBus<InterfoldEvent>` is the single pub/sub fabric. Actors subscribe via
  `bus.subscribe(EventType::X, addr.into())` or `bus.subscribe_all(&[...], addr)`.
- `InterfoldEvent` wraps `InterfoldEventData` (the variant enum) + an `EventContext`. Use
  `msg.into_components()` to get `(data, ec)`.
- **Events are facts, not commands.** They describe what happened. An actor decides for itself how
  to react. Do not use events as RPC.
- `EffectsEnabled` gates side-effecting work so that historical replay does not re-trigger on-chain
  submissions. Subscribe effectful behavior behind it (see sortition's `E3Requested` gating).
- Errors go on the bus too: `bus.err(EType::<Subsystem>, anyhow!(...))`. Use a non-blocking error
  for recoverable issues; never `panic!` in a handler.

### Adding an event

1. Add struct in `crates/events/src/interfold_event/<name>.rs` (derive
   `Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize`).
2. Add a variant to `InterfoldEventData` and an `EventType` entry in `interfold_event/mod.rs`.
3. Re-export from `mod.rs`.
4. If it carries an E3, ensure `get_e3_id()` returns it.
5. Update the relevant flow-trace doc.

---

## 6. The E3 Lifecycle Coordinator (single source of truth for stage)

The node is **choreographed** — no component "drives" the protocol. To still have one durable answer
to "what stage is each E3 at?", `e3-request` provides:

- `domain/lifecycle.rs` — pure `E3LifecycleService { stages: HashMap<E3id, E3Stage> }`.
  - `observe(&InterfoldEventData) -> LifecycleDecision`
  - Stage advance is **monotonic / forward-only** (ranked).
  - Terminal stages (`Complete`, `Failed`) are **frozen**.
  - Out-of-order earlier-stage events return `Regressed` and are ignored.
- `actors/lifecycle_coordinator.rs` — thin `E3LifecycleCoordinator` actor that loads the persisted
  map, subscribes to lifecycle events + `Shutdown`, persists on `Advanced`/`Terminal`, logs active
  E3s on shutdown.

**The coordinator is ADDITIVE.** It observes and records. It **must never** emit protocol events or
drive subsystems — doing so would break the choreography and create duplicate effects. Stage
mapping:

| Event                                                                    | Stage                       |
| ------------------------------------------------------------------------ | --------------------------- |
| `E3Requested`                                                            | `Requested`                 |
| `CommitteePublished` / `CommitteeFinalized`                              | `CommitteeFinalized`        |
| `PublicKeyAggregated`                                                    | `KeyPublished`              |
| `CiphertextOutputPublished`                                              | `CiphertextReady`           |
| `PlaintextAggregated` / `PlaintextOutputPublished` / `E3RequestComplete` | `Complete`                  |
| `E3Failed`                                                               | `Failed`                    |
| `E3StageChanged`                                                         | `new_stage` (authoritative) |

---

## 7. Decision Enums — the service↔actor contract

Services return their decisions as explicit enums; actors `match` and apply them. This keeps the I/O
boundary visible and testable.

Conventions:

- Name outcomes by what the actor must do, not by internal state:
  `{ Ignored, Pending, Completed(..) }`,
  `RoutingDecision { Broadcast, Ignore, Process { post_forward }, AlreadyCompleted }`,
  `Vec<VoteAction>`, etc.
- Prefer returning a `Vec<Action>` when one event causes several effects.
- Never return raw booleans for multi-way decisions — use an enum.
- The actor's job after `match` is strictly: persist, publish, schedule, forward.

---

## 8. Testing Conventions

- **Unit tests live next to the service** they cover, in `#[cfg(test)] mod tests` inside the
  `domain/` file. They are synchronous, no actix, no bus, no store.
- Use property/oracle tests for data structures (e.g. HAMT vs `BTreeMap` over thousands of random
  ops).
- Actor-level tests are only for genuinely actor-specific wiring; if the bus setup is heavy and the
  logic is already covered by the service tests, do not duplicate it at the actor level.
- When you move a test during a refactor, **move it next to the new home** of the logic — never
  leave orphaned tests behind.
- Verify against **real APIs**. Do not fabricate constructors/`Default` impls in tests; check the
  actual type first.

### Verification commands (run before claiming done)

```bash
cargo build --workspace
cargo clippy -p <crate> --all-targets        # clean on the crate's own src/
cargo test  -p <crate>
# Full gates:
pnpm rust:test
pnpm test:integration
pnpm check:committee                           # circuit config invariant
```

The workspace baseline is **not** clippy-clean; only enforce clippy-clean on the crate you touched
(its own `src/`).

---

## 9. Dos and Don'ts

### Do

- Put every state transition, validation, and computation in a pure `domain/` service with unit
  tests.
- Keep `lib.rs` to module decls + re-exports.
- Define one struct per file; name the file after the struct.
- Route all persistence through `Repository`/`Persistable` and `StoreKeys`.
- Thread the inbound `EventContext` into `try_mutate`.
- Make stage/state advances monotonic and replay-safe.
- Preserve on-disk (bincode) formats; add legacy round-trip tests.
- Update the matching `agent/flow-trace/*.md` in the same change when behavior, signatures, events,
  CLI, timeouts, or proof steps change.
- Gate side-effects behind `EffectsEnabled` so replay is safe.
- Delete old files when refactoring; no duplicates left behind.

### Don't

- Put business logic in a `Handler` (no validation/crypto/aggregation/math).
- Add types or functions to `lib.rs`.
- Inline raw store-key strings outside `store_keys.rs`.
- Invent a fresh `EventContext` for an event-caused write.
- Emit protocol events from the lifecycle coordinator (it is observe-only).
- Use events as commands/RPC.
- `panic!`/`unwrap()` in handlers — surface errors on the bus.
- Change a persisted struct's field order/type without an upgrade-safe path.
- Block the actor thread on long sync work (offload; keep handlers fast).
- Rename crates and move logic in the same change (renames are a separate mechanical PR).
- Hand-edit the three circuit config files — use `pnpm build:circuits`.

---

## 10. Crate Map (subsystems)

| Subsystem    | Crates                                                                                                     |
| ------------ | ---------------------------------------------------------------------------------------------------------- |
| Protocol     | `aggregator`, `keyshare`, `sortition`, `slashing`, `request`, `committee-hash`                             |
| FHE / crypto | `fhe`, `trbfv`, `bfv-client`, `multithread`, `crypto`, `fhe-params`, `polynomial`, `parity-matrix`, `safe` |
| ZK           | `zk-prover`, `zk-helpers`, `compute-provider`                                                              |
| EVM          | `evm`, `evm-helpers`, `indexer`                                                                            |
| Runtime      | `events`, `data`, `sync`, `net`, `config`, `logger`, `fs`, `hamt`                                          |
| Node         | `ciphernode-builder`, `entrypoint`, `cli`, `daemon-server`, `console`, `init`, `dashboard`                 |
| Clients      | `sdk`, `wasm`, `program-server`                                                                            |
| Tooling      | `interfoldup`, `utils`, `utils-derive`, `test-helpers`, `support`, `scripts`, `tests`                      |

All crates use the `e3-` package prefix except `interfoldup`.

---

## 11. Refactor Pattern Recap (the proven playbook)

When asked to extract logic from an actor:

1. Read the actor file(s) fully; identify embedded logic.
2. Create `domain/<service>.rs` with a plain struct + decision enum; move domain types + transition
   fns; add `#[cfg(test)]` tests.
3. Register in `domain/mod.rs`; re-export from `lib.rs`.
4. Thin each `Handler` to: destructure → call service → apply decision.
5. Re-export moved types from the actor file to preserve public paths.
6. `cargo test -p <crate>` + `cargo clippy -p <crate> --all-targets`; build downstream consumers;
   `cargo build --workspace`.
7. Update flow-trace only if observable behavior/signatures/events changed.
8. Delete the old flat file. No duplicates.
