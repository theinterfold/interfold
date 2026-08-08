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
- Ticket and license tokens, expected decimals, `ticketPrice`, and `licenseRequiredBond` change as
  one configuration. Asset identity changes only after old balances, E3 assignments, slash locks,
  and pending slash routes fully drain. Replacement assets must be deployed contracts, and a
  replacement license token must return a valid value from `lockedBalanceOf`. Slash policies are
  bound to the exact BondingRegistry and asset-configuration version. — `flow-trace/02`, `05`; INDEX
  concern #23
- The fee token, expected decimals, and every raw-unit pricing term change as one configuration.
  Each E3 snapshots its fee token at request time. Decimal validation checks the unit scale only; it
  does not establish the token's economic value. — `Interfold.setFeeAssetConfig`; `flow-trace/03`

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

- A request can select only the parameter set and committee shape in `ActiveCryptoConfig.sol`.
  `pnpm build:circuits` generates that binding from the active preset. Governance cannot enable a
  different parameter hash, `[H, N]`, or verifier threshold without rebuilding the circuits and
  contracts. Pricing uses circuit threshold `T`, not on-chain viability value `H`.
  `N <= numActiveOperators` at `requestCommittee`. — `flow-trace/03`
- Sortition score is deterministic and identical on- and off-chain:
  `score = keccak256(address ‖ ticket ‖ e3Id ‖ seed)`,
  `seed = uint256(keccak256(block.prevrandao, e3Id))`; top-N lowest win. — `flow-trace/03`
- **Per-E3 sortition state is immutable:** for request timestamp `T`, the request-time eligible
  count, each operator's eligibility, and each ticket balance come from `T-1`. The request also
  freezes `ticketPrice`, and Rust consumes the same timepoint and price. Current registration and
  activity are additional liveness checks only. The IMT root is snapshotted at request time. —
  `CiphernodeRegistryOwnable.sol`; `flow-trace/03`
- `finalizeCommittee()` requires the submission window to have **closed** (`>=` deadline); the first
  successful call locks the canonical on-chain committee order. — `flow-trace/03`
- **Per-E3 dependency freeze:** each request snapshots the addresses of Interfold, registries,
  slashing manager, refund manager, treasury, and the policy version; in-flight E3s drain through
  their request-time deployments regardless of later governance rotation. — `flow-trace/03`, `05`
- **Selected-member collateral remains slashable:** committee requests assign their request-time
  registry in `BondingRegistry`, and successful finalization records one unresolved obligation per
  member. Deregistration may queue collateral, but `claimExitsFor` cannot pay it out until that
  registry observes a terminal E3 and releases the complete committee. — `flow-trace/03`, `06`;
  INDEX concern Z-04
- **E3 program allowlist:** production initialization registers one deployed E3 program before
  ownership transfers to the Safe. Later registrations are append-only and owner-only. Every
  registered address must contain runtime code. — `Interfold.sol`; `flow-trace/03`

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
- Committee finalization freezes each operator's reward recipient for that E3. Success rewards,
  failed-E3 work rewards, and slash-funded rewards use that address even if bond ownership changes
  later. — `flow-trace/03`, `flow-trace/05`, `flow-trace/06`
- Every ticket slash records a durable `(manager, proposalId)` route and reserves the asset against
  treasury withdrawal **before** escrow. The route preserves its E3, target, token, amount, and
  request-time refund destination; retries are idempotent. — `flow-trace/05`
- **E3 reward eligibility is order-independent:** an unresolved expelling proposal holds only the
  accused operator's prospective fee and slash-funded shares. A cleared proposal releases those
  shares, while execution reallocates them to the remaining operators. Peer claims do not wait. A
  non-expelling slash excludes its target only from that proposal's penalty proceeds. All paths use
  the recipient frozen at committee finalization. — `flow-trace/05`, `flow-trace/06`
- Slash-policy validity: `!requiresProof ⇒ appealWindow > 0`; ≥1 nonzero penalty. The retained
  `failureReason` field is 0 or `InsufficientCommitteeMembers`; execution does not select failure
  attribution from policy data. — `flow-trace/05`; INDEX concerns Z-07, Z-32
- **Committee viability loss is atomic:** if an expulsion leaves fewer than H active members, the
  same transaction must fail the affected nonterminal E3 with the supplier-paid
  `InsufficientCommitteeMembers` reason. Reusing this existing reason preserves the persisted enum
  layout. A failed callback rolls back the penalties, ban, and expulsion. Complete and failed E3s
  allow later slashes. Committee key, ciphertext, and plaintext publication all require a currently
  viable request-time committee. — `flow-trace/04`, `05`; INDEX concern Z-32
- Accusation quorum: `agree_count >= threshold_m`; voters must be active committee members; all
  votes agree. Lane A is **attestation-based** (ECDSA per voter), not on-chain ZK re-verification.
  Vote digest / EIP-712 type hashes must match the Solidity constants exactly (Rust ↔ Solidity). —
  `flow-trace/05`; `SlashingManager.sol`
- Staggered slash submission: agreeing voters ranked by ascending address, rank N waits `N × skew`
  (default 30 s); restarts must not reset the fallback delay. — `flow-trace/05`
- **Deferred-slash collateral gate:** every manager atomically records proposal locks in
  `BondingRegistry`. Ticket withdrawal, license unbonding, deregistration, and exit claims read the
  registry's aggregate lock count and stay blocked until resolution. User exits must not call a
  slashing manager. A retained manager cannot be revoked until its E3 assignments, locks, bans, and
  fund routes are clear. — INDEX concerns #1, #26, Z-44; `flow-trace/06`
- Exit queue caps explicit non-empty tranche count; drained single-asset tranches release capacity.
  — INDEX concern #18

## Cryptography / circuits

### Committee config sync (the `check:committee` gate)

- Committee `(N, T, H)` must be identical across **five** files:
  `circuits/lib/src/configs/committee/active.nr`, `circuits/bin/.active-preset.json`,
  `packages/interfold-contracts/scripts/utils.ts` (`BFV_DKG_H`/`BFV_THRESHOLD_T`), and
  `crates/zk-helpers/src/ciphernodes_committee.rs`, plus
  `packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol`. The Solidity file also binds
  the active BFV parameter-set hash. Drift means the next build silently produces verifiers or
  proofs for the wrong configuration. Switch only with `pnpm build:circuits --committee <name>`;
  enforced by `scripts/check-committee.sh`.
- Canonical sizes: `minimum` (3,1,2) · `micro` (9,4,5) · `small` (19,9,10) — must mirror `mod.nr`
  and `CiphernodesCommitteeSize::values()`. — `scripts/circuit-constants.ts`
- Wrapper Solidity verifiers (`BfvPkVerifier`, `BfvDecryptionVerifier`) have an `(H, T)`-specific
  public-input layout and must be redeployed on committee change.
- Parity matrices (`parity_{insecure,secure}.nr`) are derived artifacts regenerated from preset
  `QIS` + committee `(N, T)`; hand-edits are caught by regenerate-and-diff.

### Noir / Barretenberg compatibility

- Treat Nargo, the Rust Noir crates, witness serialization, Barretenberg, circuit release archives,
  verification keys, and generated Solidity verifiers as one compatibility unit. The current unit is
  Nargo and Rust Noir `1.0.0-beta.26` with Barretenberg `5.1.0`. — `.github/workflows/ci.yml`;
  `crates/zk-prover/versions.json`; `Cargo.toml`
- Rust-generated witnesses must use `WitnessStack::serialize()`. Do not serialize a witness stack
  with `bincode`; Barretenberg 5 accepts the beta.26 MessagePack format markers, not the legacy
  marker. — `crates/zk-prover/src/witness.rs`
- Rebuild and publish circuit archives with the pinned Nargo version before changing
  `required_circuits_version`. Regenerate all dependent verification keys and Solidity verifiers
  with the pinned Barretenberg version. A release archive from an older serialization format can
  pass checksum verification but fail during ACIR decoding or proof generation.

### DKG / threshold structure

- SK splits into N shares; any **M+1** reconstruct/decrypt. — `flow-trace/04`
- DKG runtime and NodeFold `party_id` derives from the finalized committee normalized by ascending
  address; it is zero-indexed and strictly increasing. Active aggregator = lowest non-expelled
  `party_id`. Decryption-aggregator Shamir coordinates are a separate 1-indexed circuit format and
  translate to zero-indexed registry slots at the wrapper boundary. — `ARCHITECTURE.md`;
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
- **Ciphertext-duty proof (Zenith #15):** each E3 snapshots the protocol verifier for its encryption
  scheme at request time. Before `CiphertextReady`, this verifier checks a RISC Zero receipt that
  binds the chain, Interfold address, E3 ID, scheme ID, BFV parameter hash, committee public key,
  output hash, and SAFE commitment. The E3 program verifies application rules separately and cannot
  create a decryption duty by itself. — `flow-trace/04`; INDEX Z-15
- **Client PK commitment binding (C-01):** serialized PK event bytes are an untrusted transport
  hint; indexers store the decoded key only when its recomputed commitment equals the on-chain
  (C5-proven) value. Proof-backed committee publication never accepts key bytes. Public-key
  candidates are bounded, permissionless, and repeatable, so an invalid candidate cannot block a
  later valid one. — INDEX concerns #33, Z-31
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
- A fatal threshold-keyshare collector timeout commits `KeyshareState::Failed` before it publishes
  `E3Failed`. The persisted failure stage and reason are immutable. After hydration,
  `EffectsEnabled` redrives the saved failure and does not resume the earlier DKG phase. —
  `flow-trace/04`; INDEX concern #36

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
