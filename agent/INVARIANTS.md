# Interfold — Invariants

Things that must remain true. Breaking any of these is a protocol bug, a soundness bug, or a
data-loss bug — not a style issue. Each entry cites where it is enforced or documented. When editing
code near one of these, re-read the cited source first; when a change necessarily violates one,
treat it as a protocol migration (versioning + compatibility tests), never a silent edit.

Some entries are mechanically enforced and will fail pre-push: committee sync
(`pnpm check:committee`), harness-doc drift (`pnpm check:docs`), and the `do_send` ratchet +
skip-proof feature containment (`pnpm check:invariants`, baselines in
`scripts/invariant-baselines.env`). The rest are review-enforced — the `invariant-reviewer` agent
(`/invariant-review`) checks a diff against this file.

## Meta-invariants

- **Sources of authority, descending:** (1) deployed contract behavior and protocol/circuit
  invariants, (2) compatibility/e2e tests, (3) durable event/snapshot schemas, (4) `flow-trace/` +
  `CRATES_ARCHITECTURE.md`, (5) `ARCHITECTURE.md` (target design). When docs disagree with
  contracts/tests, fix the docs. — `ARCHITECTURE.md` §Sources of Authority
- **A cleanup must never silently change:** committee ordering, threshold meaning, proof
  multiplicity, hashing, signatures, circuit witness shape, event identity, or replay semantics. —
  `ARCHITECTURE.md`

## Protocol / on-chain

### Tokens and bonding

- Ticket deposits/withdrawals use **raw stablecoin base units**, never `× ticketPrice`;
  `ticketPrice` is used only in the activation check and sortition eligibility. tFOLD is minted 1:1
  with underlying USDC. — `BondingRegistry.sol` (`addTicketBalance`, `removeTicketBalance`);
  `flow-trace/02`
- Tickets (tFOLD) are **non-transferable**: `permit`/`delegateBySig` always revert; transfers
  restricted to mint/burn/bonding/whitelist. Collateral cannot be moved to dodge slashing; snapshot
  eligibility at `requestBlock-1` stays attributable. — `flow-trace/02`
- `totalBonded(account)` = active FOLD license bond + pending-but-still-slashable exits; FOLD
  `_update` enforces locked-floor accounting. — `flow-trace/02`
- A bond-owner transfer must preserve the previous owner's locked-FOLD coverage. The wallet balance
  plus remaining bonds must equal or exceed `lockedBalanceOf(previousOwner)`. —
  `BondingRegistry.acceptBondOwner`; `flow-trace/01`, `02`
- Bonding-asset rotation only after old-asset balances fully drain. Replacement assets must be
  deployed contracts, and a replacement license token must return a valid value from
  `lockedBalanceOf`. — `flow-trace/02`; INDEX concern #23

### Activation (auto-evaluated in `_updateOperatorStatus`, never a standalone call)

- Operator active ⇔ `registered` AND `licenseBond >= licenseRequiredBond × licenseActiveBps/10000`
  (default 80%) AND `ticketBalance / ticketPrice >= minTicketBalance`. — `BondingRegistry.sol`;
  `flow-trace/01`, `02`
- `minTicketBalance` must remain nonzero. — `flow-trace/02`
- **Eligibility policy version is monotonic and fail-closed:** any effective change to `ticketPrice`
  / `licenseRequiredBond` / `licenseActiveBps` / `minTicketBalance` bumps
  `eligibilityConfigurationVersion`, resets `numActiveOperators`, and invalidates all cached
  statuses in O(1). Rust sortition consumes the same `ConfigurationUpdated` event and marks
  operators inactive until a matching `OperatorActivationChanged` arrives. — `BondingRegistry.sol`;
  INDEX concern #24

### E3 request and committee selection

- Request params: `M > 0`, `N >= M`, `inputWindow.start >= block.timestamp`, `end >= start`;
  `N <= numActiveOperators` at `requestCommittee`. — `flow-trace/03`
- Sortition score is deterministic and identical on- and off-chain:
  `score = keccak256(address ‖ ticket ‖ e3Id ‖ seed)`,
  `seed = uint256(keccak256(block.prevrandao, e3Id))`; top-N lowest win. — `flow-trace/03`
- Eligibility is **snapshot-based**: ticket balances at `requestBlock-1` via
  `getTicketBalanceAtBlock`; IMT root snapshotted at request time. —
  `CiphernodeRegistryOwnable.sol`; `flow-trace/03`
- `finalizeCommittee()` requires the submission window to have **closed** (`>=` deadline); the first
  successful call locks the canonical on-chain committee order. — `flow-trace/03`
- **Per-E3 dependency freeze:** each request snapshots the addresses of Interfold, registries,
  slashing manager, refund manager, treasury, and the policy version; in-flight E3s drain through
  their request-time deployments regardless of later governance rotation. — `flow-trace/03`, `05`

### Deadlines

- Every stage has a deadline; once missed, **anyone** may call `markE3Failed(e3Id)`.
  `computeDeadline = inputWindow.end + computeWindow`; `dkgDeadline = now + dkgWindow`. —
  `flow-trace/03`
- Known open issue: `gracePeriod` is stored/validated but never applied in any deadline check (dead
  code). — `Interfold.sol`; INDEX concern #3

### Slashing and failure settlement

- Fault attribution drives payout direction: requester/DP/CP failures pay completed work + protocol
  share from the request-time fee escrow; supplier/ciphernode failures return **100% of fee escrow
  to the requester with no protocol cut**, honest nodes compensated only from actual ticket slashes.
  — `flow-trace/05`
- Slash assets keep their own ERC-20 denomination — independent pull claims, no conversion;
  different decimals never mix. — `flow-trace/05`
- Slashed **ticket** funds are always escrowed first; destination depends on terminal outcome
  (failure → honest nodes; none → snapshotted treasury; success → split by `successSlashedNodeBps`).
  **License-bond** slashes go straight to treasury. — `flow-trace/05`
- Requester refunds are decoupled from slash execution; `protocolShareBps` and per-node payouts are
  snapshotted at `calculateRefund` and never altered by slashed assets; base refunds never consume
  the protected reserve. — `flow-trace/05`
- Dual-role accounts (requester + honest node) claim via independent ledgers, each once. —
  `flow-trace/05`
- Every ticket slash records a durable, proposal-scoped route and reserves the asset against
  treasury withdrawal **before** escrow; retries are idempotent. — INDEX concern #30
- Slash-policy validity: `!requiresProof ⇒ appealWindow > 0`; ≥1 nonzero penalty; nonzero
  `failureReason < _MAX_FAILURE_REASON` and implies `affectsCommittee = true`; a failure-triggering
  slash expels the faulty operator **before** honest recipients are resolved. — `flow-trace/05`
- Accusation quorum: `agree_count >= threshold_m`; voters must be active committee members; all
  votes agree. Lane A is **attestation-based** (ECDSA per voter), not on-chain ZK re-verification.
  Vote digest / EIP-712 type hashes must match the Solidity constants exactly (Rust ↔ Solidity). —
  `flow-trace/05`; `SlashingManager.sol`
- Staggered slash submission: agreeing voters ranked by ascending address, rank N waits `N × skew`
  (default 30 s); restarts must not reset the fallback delay. — `flow-trace/05`
- **Deferred-slash collateral gate:** one unresolved-proposal counter covers both slashing lanes;
  ticket withdrawal, license unbonding, deregistration, and exit claims stay blocked until
  resolution. Every current or retained historical slashing manager participates in the exit gate. —
  INDEX concerns #1, #26; `flow-trace/06`
- Exit queue caps explicit non-empty tranche count; drained single-asset tranches release capacity.
  — INDEX concern #18

## Cryptography / circuits

### Committee config sync (the `check:committee` gate)

- Committee `(N, T, H)` must be identical across **four** files:
  `circuits/lib/src/configs/committee/active.nr`, `circuits/bin/.active-preset.json`,
  `packages/interfold-contracts/scripts/utils.ts` (`BFV_DKG_H`/`BFV_THRESHOLD_T`), and
  `crates/zk-helpers/src/ciphernodes_committee.rs`. Drift means the next build silently produces
  verifiers/proofs for the wrong committee. Switch only with
  `pnpm build:circuits --committee <name>`; enforced by `scripts/check-committee.sh`.
- Canonical sizes: `minimum` (3,1,2) · `micro` (9,4,5) · `small` (19,9,10) — must mirror `mod.nr`
  and `CiphernodesCommitteeSize::values()`. — `scripts/circuit-constants.ts`
- Wrapper Solidity verifiers (`BfvPkVerifier`, `BfvDecryptionVerifier`) have an `(H, T)`-specific
  public-input layout and must be redeployed on committee change.
- Parity matrices (`parity_{insecure,secure}.nr`) are derived artifacts regenerated from preset
  `QIS` + committee `(N, T)`; hand-edits are caught by regenerate-and-diff.

### DKG / threshold structure

- SK splits into N shares; any **M+1** reconstruct/decrypt. — `flow-trace/04`
- `party_id` derives from the finalized committee normalized by ascending address; 1-indexed,
  strictly increasing. Active aggregator = lowest non-expelled `party_id`. — `ARCHITECTURE.md`;
  `flow-trace/04`
- DKG aggregation receives **exactly H** canonical honest NodeFold proofs (unique in-range party
  IDs) and **exactly N** ordered committee addresses; every preset has `H < N` — never assert
  `H == N`. A mixed Some/None NodeFold set is terminal DKG failure. — `ARCHITECTURE.md`;
  `flow-trace/04`
- Proof multiplicity: C2a/C2b singleton per recipient; C3a/C3b follow configured Shamir
  multiplicities. Witness dimensions come from the **active preset**, never incidental vector sizes.
  — `ARCHITECTURE.md`; `CRATES_ARCHITECTURE.md`
- All C0–C7 proofs must complete before `ThresholdShareCreated` is published. — `flow-trace/04`

### Proof binding / domain separation (audit-fix invariants — do not regress)

- **PK domain binding (C-08):** `BfvPkVerifier.verify` checks
  `committeeHash = keccak256(abi.encodePacked(topNodes))` (as 128-bit limbs) against the proof's
  public inputs, binding the proof to the specific committee. — `flow-trace/04`
- **Decryption-proof replay prevention (C-03):** every secret-bearing C6 proof commits to the domain
  `(chainId, Interfold address, e3Id, committeeHash, ciphertextOutputHash, committeePublicKey)`;
  folding requires one common domain; the wrapper rejects any domain differing from the contract's
  recomputed value and checks per-party SK/ESM commitments against registry-stored DKG anchors. —
  `flow-trace/04`; INDEX concern #34
- **Ctx-witness binding (C-04, commit `cd7cbceea`):** the off-chain SAFE ciphertext commitment is
  stored at ciphertext publication, propagated as a final-proof public input, and compared on-chain
  (no BFV decoding/Poseidon2 in Solidity); C3/C6 commitments are checked against their ciphertext
  witnesses. — INDEX IF-004
- **Client PK commitment binding (C-01):** serialized PK event bytes are an untrusted transport
  hint; indexers store the decoded key only when its recomputed commitment equals the on-chain
  (C5-proven) value. — INDEX concern #33
- **No proof-disabled bypass (C-02):** both final verifier calls are mandatory in production;
  `skip_proof_aggregation` works only under the `test-only-skip-proof-aggregation` Cargo feature;
  production verifiers reject placeholder C5/C7 proofs. — INDEX concern #32
- Circuit soundness fixes to preserve: `ModU64::div_mod` verifies
  `result*divisor == dividend (mod modulus)` (IF-001); C7 compares **every** decoded coefficient,
  including zeros, to the claimed message (IF-002).

## Node / actor runtime

### Layering

- Actors are **concurrency boundaries only**: deterministic reducers own protocol decisions; effect
  runners do crypto/storage/network/chain I/O. `state`/`validation`/ workflow/pure-algorithm code
  must not depend on Actix, repositories, network, wall-clock, or process execution; workflows
  return typed intents, never perform I/O. — `ARCHITECTURE.md`
- Trust-boundary checks before any message drives a workflow: peer identity, committee membership,
  claimed party slot, signature, chainId, e3Id, proof type, payload size, schema version. —
  `ARCHITECTURE.md`

### Durability, persistence, replay

- Delivery is **at-least-once**; correctness comes from stable identity, idempotent transitions,
  effect dedup, and read-before-write guards — never from assumed exactly-once execution. —
  `ARCHITECTURE.md`
- **Commit-before-dispatch:** validate + dedup → reduce → atomically commit transition/outbox → ack
  → execute intents outside the critical section → persist correlated results before they unlock the
  next transition. Never mutate memory and rely on fire-and-forget persistence. — `ARCHITECTURE.md`
- The append-only event log is the durable source of truth; snapshots and the timestamp index are
  derived optimizations. Replay-from-checkpoint and snapshot-hydration at the same logical point
  must produce equivalent state and pending intents. — `ARCHITECTURE.md`; `CRATES_ARCHITECTURE.md`
- `E3LifecycleCoordinator` is a projection — rebuildable, never a source of truth, never emits
  protocol events. — `ARCHITECTURE.md`; `flow-trace/06`
- EventStore duplicate rule: same HLC timestamp + stable event ID + **equal payload** is an
  idempotent duplicate (even across Local/Net transport); different payloads at the same timestamp
  fail closed. — INDEX concern #15
- Crash-torn log tails: truncate only an unindexed CRC/length-invalid physical suffix; indexed
  corruption is fatal. — INDEX concern #16
- Every state field is classified **Durable / Derivable / Ephemeral**. Pending proof bundles,
  decrypted-share progress, accusation votes/timeouts, retry state, active-aggregator designation,
  deadlines, and undispatched external effects are durable unless a stronger authority can
  deterministically recreate them. An actor-local cache is not durable just because the actor
  outlives the process. — `ARCHITECTURE.md`; `CRATES_ARCHITECTURE.md`

### Ordering, backpressure, effects

- Protocol work is partitioned by `(chain_id, e3_id)`; ordering guaranteed within a partition only.
  Legal E3 progress is monotonic. On-chain committee ordering is authoritative. — `ARCHITECTURE.md`;
  `CRATES_ARCHITECTURE.md`
- Correctness-critical sends are acknowledged and timeout-bounded; `do_send` is allowed only for
  best-effort telemetry. Buffers are bounded by both item count and bytes with an explicit overflow
  policy. — `ARCHITECTURE.md`
- Timers: persist the absolute deadline + purpose, not an in-memory handle; on restart, compare to
  the injected clock and deterministically re-arm or fire overdue. — `ARCHITECTURE.md`
- Effects stay disabled until durable replay completes and both historical sources merge in HLC
  order; `ComputeEffectGate` buffers/dedups until `EffectsEnabled`. — `CRATES_ARCHITECTURE.md`
- Durable EVM settlement receipts (`RewardCredited`, `RewardClaimed`) are global facts — never
  routed into a completed per-E3 context. — INDEX concern #8
- Replayed committee events must not replace a restored per-E3 actor with a fresh instance; the
  router's `on_event` path must not do synchronous store reads. — `flow-trace/06`
- A well-formed `E3Requested` with an unsupported committee-size/preset enum is a benign skip (emit
  `Processed` so ordering advances); ABI-decode failures still fail closed. — INDEX concern #13

### Schema evolution

- Rust type compatibility is **not** a storage-migration strategy: every durable payload carries an
  explicit schema version; add/remove/reorder of fields requires a compatibility test against
  checked-in fixtures; version mismatch runs a tested migration or fails startup with an actionable
  error. — `ARCHITECTURE.md`

## Build / config sync

- Committee four-file sync (above) — `scripts/check-committee.sh`, pre-push + CI.
- **Never hand-edit generated files:** parity matrices, `utils.ts` H/T values, verifier contracts
  (`generate-verifiers.ts` output), `.active-preset.json`.
- Upgradeable-contract storage baselines are committed and CI-gated (missing baselines, compiler
  drift, layout incompatibility, bad gap consumption all fail); baseline creation is an explicit
  maintainer command. — INDEX concern #27
- Contracts CI fails a release if `Interfold` / aggregator-verifier runtime bytecode is within 256
  bytes of the EIP-170 limit. — INDEX concern #22
- BFV verifier constructors require a deployed circuit-verifier contract and nonzero recursive VK
  hashes. — INDEX concern #21
- CLI secrets are passed over **stdin only** — never argv or environment; private keys are never
  stored in plaintext. — `flow-trace/00`, `01`
- **Deployment writes must be mined, not only sent.** Every configuration transaction in
  `scripts/deployInterfold.ts` goes through the `send()` helper in `scripts/utils.ts`, which awaits
  the receipt and fails on a missing receipt or a non-success status. A bare
  `await contract.setX(...)` resolves when the transaction is dispatched, so on a real network a
  dropped write leaves the reference at `address(0)` while the script still exits zero.
- **A deployment must end with a verified wiring graph.** After configuration, `deployInterfold.ts`
  reads back every cross-contract reference (Interfold, CiphernodeRegistry, BondingRegistry,
  InterfoldTicketToken, SlashingManager, E3RefundManager) and throws with the full list of
  mismatches if any address differs from the deployed one. Add a read-back entry for each new
  cross-contract setter.

## Known open issues (check before assuming current behavior is correct)

The authoritative list is the "Verified Bugs & Protocol Concerns" table in `flow-trace/00_INDEX.md`.
Still open as of 2026-07:

- `gracePeriod` is dead code in timeout checks (concern #3).
- CLI `activate` actually calls `register` and reverts for registered operators (#4).
- EventBus fan-out still uses unacknowledged `do_send`; replay materializes the full range in memory
  (#11).
- `ComputeEffectGate` is in-memory only — no durable external-effect outbox yet.
- Residual runtime risks: `e3-evm` in-process nonce serialization without a durable tx outbox or
  full reorg rollback; accusation votes/timers lack complete durable reconstruction;
  `e3-program-server` test endpoint is unauthenticated (never a production boundary); cancellation
  ownership is not uniform across crates. — `CRATES_ARCHITECTURE.md` §Subsystem contracts
