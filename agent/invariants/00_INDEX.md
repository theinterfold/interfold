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

Read this index, then the section files that the rows for your changed paths name. A changed path
can match more than one row; read every section that the matching rows name. The sections are not
independent: `02` also governs verifier contracts, the compute provider, and CRISP, and `01` also
governs Rust sortition and eligibility reads. If a section names a file or symbol that your diff
changes, read that section too (`rg -l '<file or symbol>' agent/invariants/`).

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

Read the whole directory only when the change spans layers (contracts ↔ Rust ↔ circuits) or when
you are asked for a full invariant audit.

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

- Sortition: Rust scores tickets against a byte-reversed VRF seed, so its shortlist can differ from
  the on-chain scores. — `01_PROTOCOL_ONCHAIN.md` §E3 request and committee selection
- Eligibility: asset-configuration and node-release changes bump the eligibility version, but Rust
  does not consume those events and keeps a stale activity view. — `01_PROTOCOL_ONCHAIN.md`
  §Activation
- Slashing: a restart resets the fallback submission delay. — `01_PROTOCOL_ONCHAIN.md` §Slashing and
  failure settlement
- Startup does not reconcile persisted request contexts with finalized chain state; concern #48
  remains open. — `03_ACTOR_RUNTIME.md` §Durability, persistence, replay
- Circuit artifacts: the source hash does not cover the shared Noir library, and a node installs a
  downloaded archive without `checksums.json`. — `02_CRYPTO_CIRCUITS.md` §Noir / Barretenberg
  compatibility
- Deployment and CLI: `deployInterfold.ts` sends one setter without waiting for its receipt, and the
  CLI accepts secrets on argv. — `04_BUILD_CONFIG.md`
- CLI `activate` calls `register` and reverts for registered operators. —
  `crates/cli/src/ciphernode/lifecycle.rs`
- EventBus fan-out waits for each subscriber to accept the event within a timeout, but a timeout is
  only logged and the event is not retried. 84 `.do_send(` sites remain in total, including the
  `Sequencer` and the E3 router context. — `03_ACTOR_RUNTIME.md` §Ordering, backpressure, effects
- The event log and snapshots are positional bincode, and gossip carries bincode payloads inside a
  versioned envelope. A per-type schema version exists only on some types, for example
  `BondOwnerState`. The main storage guard is the global `SCHEMA_VERSION` in
  `crates/sync/src/sync/schema_version.rs`, which a change must increase by hand. Layout fixture
  tests exist for only a few types, for example `CommitteeFinalized`
  (`dkg_fold_attestation_context_established.rs`) and `BondOwnerState`. Most `InterfoldEventData`
  variants have none. `crates/config/protocol-release.toml` is not linked to `SCHEMA_VERSION`.
  `03_ACTOR_RUNTIME.md` §Schema evolution states the target.
- `ComputeEffectGate` is in-memory only — no durable external-effect outbox yet.
- Residual runtime risks: `e3-evm` serializes nonces in memory; only slash submissions have a
  durable intent record, and other transactions rely on preflight reads. Chain ingestion relies on
  confirmation depth, not reorg rollback. Accusation votes and timers lack durable reconstruction.
  The `e3-program-server` test endpoint is unauthenticated (never a production boundary).
  Cancellation ownership is not uniform across crates. — `CRATES_ARCHITECTURE.md` §Subsystem
  contracts
