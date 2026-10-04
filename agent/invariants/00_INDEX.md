# Interfold — Invariants

Things that must remain true. Breaking any of these is a protocol bug, a soundness bug, or a
data-loss bug — not a style issue. Each entry cites where it is enforced or documented. When editing
code near one of these, re-read the cited source first; when a change necessarily violates one,
treat it as a protocol migration (versioning + compatibility tests), never a silent edit.

Some entries are mechanically enforced and will fail pre-push: committee sync
(`pnpm check:committee`), harness-doc drift (`pnpm check:docs`), and `pnpm check:invariants` (the
`do_send` ratchet with its baseline in `scripts/invariant-baselines.env`, skip-proof feature
containment, the runtime proof-skip guard, ciphernode Docker workspace coverage, and Compose
`stop_grace_period` > 60 s). The rest are review-enforced: run the procedure in
`agent/prompts/invariant-reviewer.md` (Claude `/invariant-review`; the `invariant-review` skill in
other tools).

An entry is a requirement or review claim, not proof that the implementation satisfies it. Verify
the cited contract, test, schema, and runtime path. If a higher-authority source contradicts these
files, preserve the higher-authority behavior and correct the file in the same change. A target
design citation alone does not establish current runtime behavior.

A **Gap:** note on an entry means the current code does not meet that requirement yet. Do not rely
on the property it describes and do not widen the gap. Close a gap only in a scoped change. Never
weaken a requirement to match the code; record the gap instead.

## How to read this directory

Consult this directory for protocol-bearing changes (`agent/RULES.md` §Protocol-bearing changes).
Read this index: the routing table, the meta-invariants, and the open issues for your area. In each
section that a matching row names, search for the files, contracts, events, and symbols that your
diff changes, and read the entries that match. A changed path can match more than one row. The
sections are not independent: `02` also governs verifier contracts, the compute provider, and CRISP,
and `01` also governs Rust sortition and eligibility reads. If a section names a file or symbol that
your diff changes, search that section too (`rg -l '<file or symbol>' agent/invariants/`).

| Changed path                                                                                                                                                                   | Read                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `packages/interfold-contracts/contracts/`                                                                                                                                      | `01_PROTOCOL_ONCHAIN.md`                                                                               |
| `packages/interfold-contracts/contracts/verifiers/`                                                                                                                            | also `02_CRYPTO_CIRCUITS.md` and `04_BUILD_CONFIG.md`                                                  |
| `packages/interfold-contracts/{scripts,tasks,deploy,ignition}/`                                                                                                                | `01_PROTOCOL_ONCHAIN.md` + `04_BUILD_CONFIG.md`                                                        |
| `circuits/`                                                                                                                                                                    | `02_CRYPTO_CIRCUITS.md`                                                                                |
| `crates/` (any crate)                                                                                                                                                          | `03_ACTOR_RUNTIME.md`                                                                                  |
| `crates/{zk-prover,zk-helpers,trbfv,fhe-params,compute-provider,wasm,support,committee-hash}/`                                                                                 | also `02_CRYPTO_CIRCUITS.md`                                                                           |
| `crates/{sortition,evm}/`                                                                                                                                                      | also `01_PROTOCOL_ONCHAIN.md`                                                                          |
| `crates/data-availability/`                                                                                                                                                    | also `01_PROTOCOL_ONCHAIN.md`, `02_CRYPTO_CIRCUITS.md`, and `agent/flow-trace/08_DATA_AVAILABILITY.md` |
| `crates/cli/`                                                                                                                                                                  | also `04_BUILD_CONFIG.md` (CLI secrets)                                                                |
| `examples/CRISP/`, `templates/`                                                                                                                                                | `01_PROTOCOL_ONCHAIN.md` + `02_CRYPTO_CIRCUITS.md`                                                     |
| `packages/interfold-sdk/`                                                                                                                                                      | `02_CRYPTO_CIRCUITS.md`                                                                                |
| `scripts/`, `crates/*/build.rs`, `.github/workflows/`, `crates/Dockerfile`, root `{Cargo.toml,Cargo.lock,package.json,pnpm-lock.yaml,pnpm-workspace.yaml,rust-toolchain.toml}` | `04_BUILD_CONFIG.md`; also `02` for toolchain pins                                                     |
| `deploy/`, `dappnode/`                                                                                                                                                         | `03_ACTOR_RUNTIME.md` + `04_BUILD_CONFIG.md`                                                           |
| committee-sync sources (list below)                                                                                                                                            | `02_CRYPTO_CIRCUITS.md` §Committee config sync                                                         |

Committee-sync sources are the files `scripts/check-committee.sh` compares. Some sit under paths
that route elsewhere, so they need the crypto section in addition to their own row:
`packages/interfold-contracts/scripts/protocol/constants.ts`,
`packages/interfold-contracts/scripts/utils.ts`,
`packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol`,
`packages/interfold-contracts/tasks/interfold.ts`, `packages/interfold-sdk/src/utils.ts`, and
`crates/evm-helpers/src/contracts.rs`. `scripts/circuit-constants.ts` also holds committee values;
the gate does not compare it, so review it against `02` by hand.

Read whole section files only for a full invariant audit that the user asks for.

## Review budget

Invariant review is **one sequential reviewer pass**, as `agent/prompts/invariant-reviewer.md`
§Review budget defines. Spawn parallel reviewers only when the user explicitly asks for a
per-invariant or per-section audit.

## Meta-invariants

These apply to every section.

- **Sources of authority, descending:** (1) deployed contract behavior and protocol/circuit
  invariants, (2) compatibility/e2e tests, (3) durable event/snapshot schemas, (4) `flow-trace/` +
  `CRATES_ARCHITECTURE.md`, (5) `ARCHITECTURE.md` (target design). When docs disagree with
  contracts/tests, fix the docs. — `ARCHITECTURE.md` §Sources of Authority
- **A cleanup must never silently change:** committee ordering, threshold meaning, proof
  multiplicity, hashing, signatures, circuit witness shape, event identity, or replay semantics. —
  `ARCHITECTURE.md`

## Known open issues (check before assuming current behavior is correct)

The "Verified Bugs & Protocol Concerns" table in `flow-trace/00_INDEX.md` records history and can be
wrong. This list and the **Gap:** notes in the section files are the open-issue list. Verify each
item in code before you rely on it.

- Slashing: a restart resets the fallback submission delay. — `01_PROTOCOL_ONCHAIN.md` §Slashing and
  failure settlement
- Startup reconciles restored request contexts with finalized chain state, but concern #48 stays
  open for a local Failed stage whose reason needs accusation work (restart completes it), for a
  slashing failure that is absent from the local records, and for contexts that the replayed
  EventStore suffix admits (follow-up work). A canonical Failed stage from that read is only in the
  lifecycle snapshot, not in the event log. — `03_ACTOR_RUNTIME.md` §Durability, persistence, replay
- Circuit artifacts: release packaging does not yet provide the archive digest before binary builds.
  Downloads require a version-bound pin in `versions.json`. — `02_CRYPTO_CIRCUITS.md` §Noir /
  Barretenberg compatibility
- CLI: the CLI accepts secrets on argv. — `04_BUILD_CONFIG.md`
- EventBus fan-out waits for each subscriber to accept the event within a timeout, but a timeout is
  only logged and the event is not retried. 82 `.do_send(` sites remain in total, including the
  `Sequencer` and the E3 router context. — `03_ACTOR_RUNTIME.md` §Ordering, backpressure, effects
- The event log and snapshots are positional bincode, and gossip carries bincode payloads inside a
  versioned envelope. A per-type schema version exists only on some types, for example
  `BondOwnerState`. The main storage guard is the global `SCHEMA_VERSION` in
  `crates/sync/src/sync/schema_version.rs`, which a change must increase by hand. Layout locks
  (`crates/layout-lock`) fail when the encoding of a listed root changes, and when fields with the
  same encoding are swapped or renamed. `crates/tests/tests/layout_lock.rs` covers the event log,
  keyshare payloads, gossip payloads, and public repository values. In-crate locks cover the private
  roots in `e3-slashing` and `e3-zk-prover` and the DHT document payload in `e3-net`.
  `crates/net/src/network_sync/wire.rs` covers sample wire messages and their request-response
  frames. Not covered: roots that no lock lists, because the lists are kept by hand; the store keys
  under which repositories write their values; hand-written formats, such as commit-log framing; and
  values stored inside opaque bytes, such as the encrypted `SharedSecret` shares in the keyshare
  snapshot and the fhe.rs keys in `SensitiveBytes`. A rewritten fixture raises no version: only
  review of the fixture diff ties a layout change to a `SCHEMA_VERSION` or wire-version change.
  `crates/config/protocol-release.toml` is not linked to `SCHEMA_VERSION`. `03_ACTOR_RUNTIME.md`
  §Schema evolution states the target.
- `ComputeEffectGate` is in-memory only — no durable external-effect outbox yet.
- Network: command results go from the network interface to the registered caller, not through
  `NetEventBuffer`, so they are not held until `SyncEnded`. The document publisher sends no command
  that waits for a result before `SyncEnded`, and application events stay buffered. libp2p-gossipsub
  0.49.4 does not decrement its publish counter when it drops an expired queued publish. The DHT
  replication factor stays at 20, so a refresh still sends a document to up to 20 peers. A put
  returns after one peer stores the record. An aborted put ends its Kademlia query only in the
  upload phase, and requests that the query already gave to the connection handlers, queued or in
  progress, still go out. A put that still looks up its closest peers runs on and then uploads. So
  uploads can overlap the next replication; a full cancel is follow-up work. —
  `crates/net/src/events.rs`; `crates/net/src/document_publishing/`
- Residual runtime risks: `e3-evm` serializes nonces in memory; only slash submissions have a
  durable intent record, and other transactions rely on preflight reads. Chain ingestion relies on
  confirmation depth, not reorg rollback. Accusation votes and timers lack durable reconstruction.
  The `e3-program-server` test endpoint is unauthenticated (never a production boundary).
  Cancellation ownership is not uniform across crates. — `CRATES_ARCHITECTURE.md` §Subsystem
  contracts
