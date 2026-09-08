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

An entry is a requirement or review claim, not proof that the implementation satisfies it. Verify
the cited contract, test, schema, and runtime path. If a higher-authority source contradicts this
file, preserve the higher-authority behavior and correct this file in the same change. A target
design citation alone does not establish current runtime behavior.

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
  with its underlying asset. — `BondingRegistry.sol` (`addTicketBalance`, `removeTicketBalance`);
  `flow-trace/02`
- Tickets (tFOLD) are **non-transferable**: `permit`/`delegateBySig` always revert; transfers
  restricted to mint/burn/bonding/whitelist. Collateral cannot be moved to dodge slashing; snapshot
  eligibility at `requestBlock-1` stays attributable. — `flow-trace/02`
- `totalBonded(account)` = active FOLD ciphernode bond + pending-but-still-slashable exits; FOLD
  `_update` enforces locked-floor accounting. — `flow-trace/02`
- A bond-owner transfer must preserve the previous owner's locked-FOLD coverage. The wallet balance
  plus remaining bonds must equal or exceed `lockedBalanceOf(previousOwner)`. —
  `BondingRegistry.acceptBondOwner`; `flow-trace/01`, `02`
- **Bonded-voting history mirrors the mapping, never a delta.**
  `BondingRegistry._syncBondedCheckpoint` sends the owner's current `_bondedByOwner` total to
  `BondedCheckpoints`, and must be called from every site that mutates it: bond, slash, both sides
  of a bond-owner transfer, and exit claim (which mutates through a storage pointer inside
  `BondingAssetLib`, so the checkpoint is taken by the caller). Unbonding is deliberately not a
  write site — the FOLD stays with the registry until claimed. A missed site is caught by
  `bonded(owner) == totalBonded(owner)`, which compares the checkpoint's current value against the
  mapping at the same instant, and holds for every owner that has been synchronized at least once —
  configuring `BondedCheckpoints` does not backfill, so an owner that bonded beforehand reads as
  zero until its next mutation or a `resyncBondedCheckpoint` call. A delta-derived history would
  drift silently instead, and it would drift in voting weight. `sync` skips a write that records the
  value already latest — exact, because a lookup at the skipped timepoint resolves to the preceding
  entry — so the permissionless `resyncBondedCheckpoint` cannot be used to grow an owner's history
  by a checkpoint per block. — `BondingRegistry.sol`; `BondedCheckpoints.sol`; `flow-trace/02`
- **The numerator comes from the votes source; the denominator is always the token.**
  `BondedVotes.getPastVotes` sums whatever `votesSource` attributes to the account and that
  account's bonded FOLD, while `getPastTotalSupply` passes the **token's** supply through unchanged.
  `votesSource` is either the token itself (wallet-held FOLD votes, the original behaviour) or an
  escrow adapter (only locked FOLD votes, so holders must lock to participate while operators keep
  weight by bonding). Reading the denominator off the escrow instead would omit the bonded half and
  let participation exceed 100%. Summed voting power must never exceed total supply. —
  `BondedVotes.sol`; `flow-trace/02`
- **Escrowed and bonded FOLD cannot overlap; vesting-locked and bonded do, and must be netted.**
  Escrowing custodies the token in the escrow and bonding custodies it in the registry, so no token
  can be in both. Both were transferred rather than burned, so both are still inside the token's
  total supply — which is what makes the ratio sound in either configuration. Under an escrow votes
  source `BondedVotes` adds a third source, `InterfoldToken.lockedBalanceAt`, because vesting-locked
  FOLD sits in the holder's own wallet and the transfer hook will not let it reach the escrow. That
  source **does** overlap the bond: a bond satisfies a lock (`transferableBalanceOf` nets the two),
  so bonded FOLD is reported by `lockedBalanceAt` and by the bonded history while existing once.
  `_lockedVotes` therefore subtracts the bond from the locked balance, saturating at zero, making
  the pair worth `max(bonded, locked)` — then caps the result at the account's wallet balance,
  because slashing takes the bond without taking the lock and would otherwise leave the account
  voting with FOLD the slash recipient now holds. The lock schedule is read **only** when the votes
  source is an escrow: when the token votes for itself, locked FOLD is wallet FOLD the token has
  already counted. — `BondedVotes.sol`; `InterfoldToken.sol`; `flow-trace/02`
- **The lock schedule is present-state, not history.** `lockedBalanceAt` walks an account's
  **current** locks and evaluates them against the timestamp given, so a lock created after a
  governance snapshot appears in that snapshot's answer — unlike the bonded history, which is
  checkpointed. Sound for vesting locks, which are minted or claimed rather than acquired at will;
  it must not be treated as a general past balance. — `BondedVotes.sol`; `InterfoldToken.sol`
- **An escrow votes source requires a token with a lock schedule.** `_bindVotesSource` staticcalls
  `lockedBalanceAt` once at construction and reverts `LockedBalancesUnsupported` if it cannot
  answer. Tolerating the failure at read time would return zero and disenfranchise exactly the
  locked holders the third source exists to enfranchise. — `BondedVotes.sol`
- **Every summed source must share the token's clock.** `BondedCheckpoints` keys by
  `block.timestamp` to match `InterfoldToken`'s ERC-6372 `mode=timestamp`, and `BondedVotes`
  compares the history's clock **and** a non-token votes source's clock against the token's at
  construction. Summing a timestamp-keyed history with a block-numbered source answers for two
  unrelated points in time and is undetectable downstream. — `BondedVotes.sol`; `flow-trace/02`
- **`BondedVotes` binds token, votes source, registry and history as one unit.** The constructor
  reads `checkpoints.registry()` and requires that registry's `getCiphernodeBondToken()` to equal
  the token. A non-token votes source is bound the same way: `_bindVotesSource` resolves its
  `escrow()` and requires that escrow's `token()` to equal the voting token, reverting
  `VotesSourceMismatch` otherwise. The clock check alone proves a source speaks the token's units,
  not that it is _about_ that token: a history written by a registry custodying something else, or
  an escrow over a different asset, would mint weight the denominator does not back, and no reader
  downstream could tell. Because the registry check calls the registry, `BondedVotes` can only be
  constructed after the registry is configured — `protocol/deployContracts` therefore deploys
  `BondedCheckpoints` only, and `--action activate-voting` deploys `BondedVotes` once the governance
  batch has run. — `BondedVotes.sol`; `protocol/activateVoting.ts`; `flow-trace/02`
- **`BondedVotes.balanceOf` attributes custodied FOLD to whoever it belongs to.** Bonding moves FOLD
  into the registry and locking moves it into the escrow, while the adapter attributes each to the
  account it belongs to, so counting it at the custodian's address as well would place the same
  tokens twice and push summed balances above total supply — the denominator every holder-percentage
  view divides by. The registry's entry subtracts `totalCiphernodeBondLiability`, saturating at
  zero, and the escrow's own entry is netted to zero for the same reason — every unit it holds is
  attributed to a locker, and it publishes no liability total to subtract instead; locked FOLD is
  added per account via the escrow's `votingPowerForAccount`, which is delegation-blind, rather than
  the adapter's own `balanceOf`, which counts lock NFTs rather than tokens. `getVotes` needs no such
  adjustment: the registry never delegates, so bonded FOLD carries no wallet votes to double. —
  `BondedVotes.sol`; `flow-trace/02`
- **`setBondedCheckpoints` is one-shot per ciphernode bond token, and self-verifying.** It requires
  the checkpoint contract to name this registry **and** to accept a write from it, checked by
  syncing the zero address, whose bonded total is always zero. `registry()` alone is insufficient:
  `InterfoldTicketToken` answers it with the registry address, so a mix-up would spend the slot on a
  contract with no `sync` and revert every later bond, slash, claim and owner transfer. Repointing
  while one is attached is refused: it would abandon recorded history and silently change every past
  answer. While unset the sync is a no-op, not a revert, so an upgrade cannot freeze bonding before
  the contract is configured. — `BondingRegistry.sol`; `flow-trace/02`
- **Ciphernode-bond-token rotation detaches the bonded history.** The history counts
  ciphernode-bond-token units, but `BondedVotes` adds them to the voting power of one token fixed at
  construction, so a replacement token's bonds entering the same history would be counted as the old
  token and could push summed voting power above its total supply. Rotation already requires every
  old bond to be drained, so each owner's last recorded total is zero and detaching freezes a
  settled history. The detached contract stays correct for the timepoints it covers; a new era needs
  a fresh `BondedCheckpoints` and a fresh `BondedVotes` bound to the new token. —
  `BondingRegistry._setBondingAssetConfig`; `flow-trace/02`
- **`BondingRegistry` is at its EIP-170 ceiling.** It is gated at 256 bytes of headroom by
  `scripts/checkContractSize.ts`, and logic is kept in `BondingAssetLib`, `BondingEligibilityLib`,
  `BondingSlashingLib`, `BondingRegistrationLib` and `BondingOwnershipLib` for that reason. Every
  library must be linked in all deploy paths (ignition, `deployAndSave`, `protocol/deployContracts`,
  `upgrade/safeProxyUpgrade`, `deploymentRecords`, `protocol/types`) — a missing link fails at
  deployment, not at compile. The `Operator` struct stays declared in `BondingRegistry`: the upgrade
  baseline compares type labels, so relocating it reads as a type change on an unchanged layout. —
  `BondingRegistry.sol`; INDEX concern #22
- Ticket and ciphernode bond tokens, expected decimals, `ticketPrice`, and `requiredCiphernodeBond`
  change as one configuration. Asset identity changes only after old balances, E3 assignments, slash
  locks, and pending slash routes fully drain. Replacement assets must be deployed contracts, and a
  replacement ciphernode bond token must return a valid value from `lockedBalanceOf`. Slash policies
  are bound to the exact BondingRegistry and asset-configuration version. Asset activation requires
  the ticket token to authorize the BondingRegistry. A later mismatch makes operators inactive
  without blocking ciphernode bond slashes, bans, or exit bookkeeping. Ciphernode-bond-token
  rotation atomically sends any balance above `totalCiphernodeBondLiability` to the treasury before
  validating the replacement, so an unsolicited transfer cannot interleave with rotation. —
  `flow-trace/02`, `05`; INDEX concern #23
- The fee token, expected decimals, and every raw-unit service price change as one configuration.
  `setRandomnessFlatFee` is the only narrow pricing update: it changes only the nonzero flat fee and
  preserves the token, decimal scale, treasury, margin, protocol share, and service prices. The flat
  randomness fee uses the fee token's raw units. Each request states its expected token and maximum
  fee. Each E3 snapshots its fee token at request time. Decimal validation checks the unit scale
  only; it does not establish the token's economic value. — `Interfold.setFeeAssetConfig`;
  `Interfold.setRandomnessFlatFee`; `flow-trace/03`
- **Custody assets use exact, non-rebasing accounting:** the fee token, ticket underlying, and
  ciphernode bond token must transfer exact amounts and must not rebase account balances. Every
  custody deposit checks the custody increase. Every outbound transfer checks the recipient increase
  and custody decrease. A mismatch reverts the complete accounting transaction and preserves all
  other pooled liabilities. — `InterfoldPricing.sol`; `InterfoldTicketToken.sol`;
  `BondingAssetLib.sol`; `E3RefundManager.sol`; `flow-trace/02`, `03`, `05`

### Activation (auto-evaluated in `_updateOperatorStatus`, never a standalone call)

- Operator active ⇔ its acknowledged release has exactly the required `protocolVersion`, meets the
  minimum `nodeGeneration`, AND `registered` AND
  `ciphernodeBond >= requiredCiphernodeBond × ciphernodeBondActiveBps/10000` (default 80%) AND
  `ticketBalance / ticketPrice >= minTicketBalance`. — `BondingRegistry.sol`; `flow-trace/01`, `02`
- `minTicketBalance` must remain nonzero. — `flow-trace/02`
- **Eligibility policy version is monotonic and fail-closed:** any effective change to `ticketPrice`
  / `requiredCiphernodeBond` / `ciphernodeBondActiveBps` / `minTicketBalance` bumps
  `eligibilityConfigurationVersion`, resets `numActiveOperators`, and invalidates all cached
  statuses in O(1). Rust sortition consumes the same `ConfigurationUpdated` event and marks
  operators inactive until a matching `OperatorActivationChanged` arrives. — `BondingRegistry.sol`;
  INDEX concern #24
- **Mandatory release policy changes are paused, drained, and monotonic:** governance may raise the
  required protocol version or node generation only while requests are paused, `activeE3Count == 0`,
  and `unreleasedCommitteeCount == 0`. The change invalidates every cached operator status in O(1).
  A node becomes active again only after it acknowledges compatible values. Never lower either
  required counter; roll back code under a new release ID and a higher generation. —
  `NodeReleaseRegistry.sol`; `flow-trace/07`
- **Release acknowledgement is not remote attestation:** it prevents accidental stale software
  participation. Byzantine safety still depends on threshold cryptography, proof verification,
  slashing, and committee validation. — `flow-trace/07`

### E3 request and committee selection

- E3 IDs include the Interfold controller address in their high 160 bits. The low 96 bits form the
  controller-local sequence. On-chain snapshots, signed payloads, Rust persistence, and indexer keys
  must preserve the complete `uint256`. — `Interfold.initialize`; `flow-trace/03`
- A request can select only the parameter set and committee shape in `ActiveCryptoConfig.sol`.
  Mainnet supports `secure-8192` with `minimum`, `micro`, and `small` committees. Sepolia and local
  chains support `insecure-512` and `secure-8192` with `minimum`, `micro`, and `small` committees.
  Governance cannot enable a different parameter hash, `[H, N]`, or verifier threshold without
  rebuilding the circuits and contracts for that pair. The request supplies the expected
  configuration ID, which binds the scheme, parameter hash, and circuit version; committee size is
  snapshotted separately. Solidity snapshots the ID, and Rust rejects an event or stored E3 when
  `cryptoConfigId != expectedCryptoConfigId`. BFV verifier mappings may point at routers, which
  dispatch by public-input length and VK hash anchors to the concrete verifier for the generated
  pair. Pricing uses circuit threshold `T`, not on-chain viability value `H`.
  `N <= numActiveOperators` at `requestCommittee`. — `flow-trace/03`
- Mainnet CRISP activation is one paused and drained governance batch. It upgrades Interfold to the
  secure crypto configuration, installs every secure BFV verifier route, registers secure BFV
  parameters, wires the receipt verifier, registers CRISP, binds CRISP, and raises the required node
  protocol version. The partial CRISP-only builder must not run on mainnet. Old nodes become
  ineligible in the activation transaction. The CRISP program and ciphertext verifier image IDs must
  both equal the RISC Zero image generated by the same release source. Requests remain paused until
  the activation validator succeeds and enough matching release-ready nodes are online. —
  `scripts/upgrade/secureCrisp.ts`; `scripts/upgrade/validateSecureCrisp.ts`; `flow-trace/07`
- Sortition score is deterministic and identical on- and off-chain:
  `score = keccak256(address ‖ ticket ‖ e3Id ‖ seed)`, where
  `seed = keccak256(randomWord ‖ chainId ‖ registry ‖ e3Id ‖ requestId)`; top-N lowest win. Each E3
  freezes one `IRandomnessProvider` request, response deadline, and submission window after the paid
  request is stored. The production provider uses Chainlink VRF v2.5 subscription funding. It never
  re-requests an E3, checks the configured subscription balance floor before requesting, and the
  Registry rejects responses from the Ethereum request block, future-dated responses, and late
  responses. This release supports Ethereum mainnet, Sepolia, and local development chains only. The
  first request that expires without a usable response clears the active provider. This blocks new
  requests until governance pauses the protocol and restores a provider. A timely accepted response
  remains readable after terminal cleanup so fresh historical replay derives the same committee
  request; late responses remain unusable. Rust reads the accepted seed and request context at the
  fulfillment block. If historical block state is unavailable, it accepts retained current state
  only when the Registry still reports the seed as ready. Unverifiable state rejects the log and
  fails closed for replay. Governance can change the provider or response timeout only while
  requests are paused and all committee obligations are released. The E3 computation seed remains
  separate. — `flow-trace/03`
- **Per-E3 sortition state is immutable:** for request timestamp `T`, the request-time eligible
  count, each operator's eligibility, and each ticket balance come from `T-1`. The request also
  freezes `ticketPrice`, and Rust consumes the same timepoint and price. Current registration and
  activity are additional liveness checks only. The IMT root is snapshotted at request time. —
  `CiphernodeRegistryOwnable.sol`; `flow-trace/03`
- `finalizeCommittee()` requires the submission window to have closed. The first successful call
  locks the canonical on-chain committee order. A ready committee must finalize by its absolute
  request-time DKG cutoff. Delayed finalization cannot extend the paid lifecycle. — `flow-trace/03`
- **Exit timing strictly covers sortition:** `BondingRegistry.exitDelay` must remain greater than
  `CiphernodeRegistryOwnable.randomnessRequestTimeout + sortitionSubmissionWindow`. Value setters
  and registry-pointer setters enforce the relationship; equality is invalid because ticket
  submission includes the deadline. — `BondingRegistry.sol`; `CiphernodeRegistryOwnable.sol`;
  `flow-trace/02`, `03`
- **One coherent dependency generation:** each request validates and snapshots the complete
  Interfold, registry, bonding, slashing, refund, treasury, and policy graph. Governance must pause
  requests and drain all E3s, committees, operators, bans, and slash routes before it replaces any
  graph member. Old and new generations never serve requests at the same time. — `flow-trace/03`,
  `05`
- **Candidate and member collateral remains slashable:** committee requests assign their
  request-time registry in `BondingRegistry`. A top-N ticket submission locks its candidate, and a
  better ticket releases the displaced candidate. Finalization retains each winner's obligation.
  `claimExitsFor` cannot pay a locked candidate or member until displacement or terminal committee
  release. — `flow-trace/03`, `06`; INDEX concerns Z-04, Z-37
- **Exit timing covers frozen requests:** `exitDelay` must exceed the current submission window and
  the remaining time for the latest request-time committee deadline. Each request raises a monotonic
  deadline watermark. The time-based floor decreases after old windows expire, and the
  BondingRegistry cannot clear its registry pointer. — `flow-trace/02`, `03`, `06`; INDEX Z-37
- **E3 program allowlist:** production initialization registers one deployed E3 program and assigns
  Interfold ownership to the configured protocol owner. Later registration and retirement are
  owner-only. Retirement closes only new request admission; existing E3s keep their snapshotted
  program. Every registered address must contain runtime code. `MockE3Program` is the stateless
  bootstrap option. It has no administrative controls and applies no application rules. Its
  deterministic test receipt is not production data availability, so requests remain paused until a
  production program is registered and wired. The request-time BFV ciphertext verifier and
  decryption verifier remain mandatory. Its mutable failure controls live only in
  `MockE3ProgramHarness`. A protocol upgrade that makes the program interface incompatible must
  retire every incompatible bootstrap program before requests resume. — `Interfold.sol`;
  `MockE3Program.sol`; `flow-trace/03`

### Deadlines

- Every stage has a deadline. Once a deadline is missed, **anyone** may call `markE3Failed(e3Id)`.
  The request snapshots all timeout windows. The randomness response starts the full ticket
  submission window; the DKG deadline equals that resolved committee deadline plus the DKG window.
  The compute deadline starts at the later of key publication and the end of the input window.
  Request validation reserves the full worst-case randomness, sortition, DKG, compute, and
  decryption lifecycle. — `flow-trace/03`
- Known open issue: `gracePeriod` is stored/validated but never applied in any deadline check (dead
  code). — `Interfold.sol`; INDEX concern #3

### Slashing and failure settlement

- Fault attribution drives payout direction: requester/DP/CP failures pay completed work + protocol
  share from the request-time service fee escrow; supplier/ciphernode failures return **100% of
  service fee escrow to the requester with no protocol cut**, honest nodes compensated only from
  actual ticket slashes. The request-time randomness fee is not fee escrow. It remains a treasury
  claim after any accepted randomness request, including a request that later times out. —
  `flow-trace/05`
- Slash assets keep their own ERC-20 denomination — independent pull claims, no conversion;
  different decimals never mix. — `flow-trace/05`
- Slashed **ticket** funds are always escrowed first; destination depends on terminal outcome
  (failure → honest nodes; none → snapshotted treasury; success → split by `successSlashedNodeBps`).
  **Ciphernode-bond** slashes do not leave the registry at execution: the amount is recorded in
  `slashedCiphernodeBond` and the FOLD stays in registry custody. Only `withdrawSlashedFunds`
  (owner-called) moves it to `slashedFundsTreasury`, releasing the matching
  `totalCiphernodeBondLiability` as it goes — so custody and liability are retired together. —
  `BondingRegistry.slashCiphernodeBond`, `BondingRegistry.withdrawSlashedFunds`; `flow-trace/05`
- Requester refunds are decoupled from slash execution; `protocolShareBps` and per-node payouts are
  snapshotted at `calculateRefund` and never altered by slashed assets; base refunds never consume
  the protected reserve. — `flow-trace/05`
- Only the original requester can cancel an E3, and only after its request-bound randomness deadline
  passes without a usable seed. Cancellation records `CommitteeFormationTimeout`, releases the
  Registry obligation, and leaves refund processing permissionless. A timely or pending VRF result
  cannot be selectively canceled. — `flow-trace/05`
- Dual-role accounts (requester + honest node) claim via independent ledgers, each once. —
  `flow-trace/05`
- Committee finalization freezes each operator's reward recipient for that E3. Success rewards,
  failed-E3 work rewards, and slash-funded rewards use that address even if bond ownership changes
  later. — `flow-trace/03`, `flow-trace/05`, `flow-trace/06`
- Every ticket slash records a durable `(manager, proposalId)` route and reserves the asset against
  treasury withdrawal **before** escrow. The route preserves its E3, target, token, amount, and
  request-time refund destination; retries are idempotent. — `flow-trace/05`
- **E3 reward eligibility is order-independent:** an unresolved expelling proposal holds only the
  accused operator's unclaimed fee and slash-funded shares, including a base share calculated before
  the proposal opened. A cleared proposal releases those shares, while execution reallocates them to
  the remaining operators. Rewards claimed before a proposal opens remain final. Peer claims do not
  wait. A non-expelling slash excludes its target only from that proposal's penalty proceeds. All
  paths use the recipient frozen at committee finalization. — `flow-trace/05`, `flow-trace/06`
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
  `BondingRegistry`. Ticket withdrawal, ciphernode bond unbonding, deregistration, and exit claims
  read the registry's aggregate lock count and stay blocked until resolution. User exits must not
  call a slashing manager. A retained manager cannot be revoked until its E3 assignments, locks,
  bans, and fund routes are clear. — INDEX concerns #1, #26, Z-44; `flow-trace/06`
- Exit queue caps explicit non-empty tranche count; drained single-asset tranches release capacity.
  — INDEX concern #18

## Cryptography / circuits

### Committee config sync (the `check:committee` gate)

- Committee `(N, T, H)` and each complete BFV parameter tuple must stay synchronized. The tuple is
  defined for deployment in `packages/interfold-contracts/scripts/protocol/constants.ts`, for
  ciphernodes in `crates/fhe-params/src/constants.rs`, and for circuits in
  `circuits/lib/src/configs/{insecure,secure}/threshold.nr`. Committee values also appear in
  `circuits/lib/src/configs/committee/active.nr`, `packages/interfold-contracts/scripts/utils.ts`,
  `crates/zk-helpers/src/ciphernodes_committee.rs`, and
  `packages/interfold-contracts/contracts/lib/ActiveCryptoConfig.sol`. The generated Solidity and
  TypeScript values bind the BFV parameter-set hashes and configuration IDs. The gate verifies the
  tuple, the circuit error bound, and every runtime configuration-ID copy. The local
  `circuits/bin/.active-preset.json` cache may differ from the production chain pair. Drift means a
  deployment can register parameters that ciphernodes or circuits do not implement. Regenerate
  configuration constants with `pnpm build:circuits sync-config --preset <name> --committee <name>`;
  switch and build circuits only with `pnpm build:circuits --committee <name>`. Both paths are
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
- `required_circuits_version` must equal the Interfold release tag that publishes its archive. The
  release workflow rejects a different value because the ciphernode resolves both the GitHub release
  and `circuits-{version}.tar.gz` from this field.
- A circuit release archive that supports current deployments must include every
  `insecure-512/{minimum,micro,small}` and `secure-8192/{minimum,micro,small}` pair. Each pair has a
  build stamp with the exact preset, committee, and source hash. `checksums.json` and `SHA256SUMS`
  must cover the archive contents. Nodes select the artifact directory from the E3's on-chain
  parameter set and committee size.

### DKG / threshold structure

- SK splits into N shares; any **M+1** reconstruct/decrypt. — `flow-trace/04`
- Runtime `party_id` derives from the finalized committee normalized by ascending address and is
  zero-indexed. Circuit-side Shamir coordinates are `party_id + 1` and must be strictly increasing.
  The active aggregator is the lowest eligible runtime `party_id` after exclusions and the current
  phase's durable unresponsive-party set. — `ARCHITECTURE.md`; `flow-trace/04`
- Every committee member persists validated aggregation inputs. Failover starts only after
  `AggregationInputsReady` confirms that the phase can resume from durable state. Only the active
  party can launch aggregation effects or accept their results. — `flow-trace/04`; INDEX concern #42
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
- **The compute path carries no external audit.** The 2026-08-17 Zenith audit covered six Solidity
  files and no Rust. `crates/compute-provider`, the RISC Zero guest, `crates/zk-helpers`, and
  `Risc0BfvCiphertextVerifier.sol` were outside both the audit and its mitigation review, so a
  `Resolved` `Z-` row is this repository's remediation rather than a re-reviewed one. Treat changes
  in these areas as unaudited by default. — `flow-trace/00`;
  `packages/interfold-contracts/audits/README.md`
- **A Secure Process derives its input root; it never receives it.** `ComputeInput` holds only
  `fhe_inputs`, and `ComputeInput::process` derives the leaves from the ciphertexts it processed.
  The protocol verifier takes the input root from the proof envelope and does not constrain it, so
  the E3 program's comparison against its own on-chain root is the only check — and that comparison
  is worthless if the guest can be handed leaves that disagree with the ciphertexts it consumed.
  Publication is unpermissioned and one-shot, with no dispute path, so any party could otherwise
  publish a tally over ciphertexts that were never submitted. `MerkleTreeBuilder::with_leaf_hashes`
  is `#[cfg(test)]` to keep it out of that path. — `flow-trace/04`
- **Every E3 program must compare the proof's input root against its own root.**
  `Risc0BfvCiphertextVerifier` takes no `inputRoot` argument and constrains none. A program that
  skips the comparison accepts a result computed over any input set. — `flow-trace/04`
- **A Secure Process derives its leaves; it never receives them, and never drops one.**
  `MerkleTreeBuilder::compute_leaf_hashes` builds every leaf from the ciphertexts it was given and
  pushes one per on-chain input leaf, whatever the E3 program's policy decides about computing over
  it. Both rules are applied by `e3-compute-provider` rather than delegated: a received root can
  disagree with the data it claims to describe, and a missing leaf changes the root and makes the
  result unpublishable. — `flow-trace/04`
- **A CRISP input is committed before it is finalized, but computation requires both.**
  `publishInput` verifies the Noir proof and the configured service's EIP-712 storage attestation,
  then reserves the leaf and index so a later input can name it as its parent. `finalizeInput` must
  prove VectorX availability for the exact committed content hash. The input tuple cannot change
  between the calls, and `CRISPProgram.verify` must reject while any committed input remains
  pending. — `flow-trace/08`
- **CRISP input envelopes use one flat ABI parameter sequence.** The SDK uses `encodeAbiParameters`
  for the six fields. The server uses parameter decoding for that sequence and parameter encoding
  for the signed commitment payload that Solidity reads through `abi.decode`. Treating the envelope
  as one wrapped struct adds a leading tuple offset and breaks the boundary. — `flow-trace/08`
- **Avail-backed CRISP rounds leave a usable voting interval.** `CRISPProgram.validate` derives the
  worst-case key time from the E3 timeout snapshot and the request-time Registry windows. The
  commitment cutoff must be at least one hour after both that time and the configured input start.
  The server repeats the production minimum as an early configuration check, but it is not the
  security boundary. — `flow-trace/08`
- **Avail references name exact application bytes.** The application content hash is
  `keccak256(rawBytes)`, which is also the `leaf` returned by Avail's proof API. The official bridge
  hashes that value once more when it verifies the submitted-data Merkle root. Solidity binds the
  proof API leaf to `contentHash`, and every reader hashes retrieved raw bytes again before decoding
  or proving over them. An App ID or RPC response is not a correctness proof. — `flow-trace/08`
- **The leaf layout and input selection are the E3 program's, not the crate's.** They are supplied
  as an `InputPolicy`, because a leaf must match whatever that program builds on chain and no two
  programs need agree, and because "what does a second input for the same participant mean?" has no
  universal answer. `InputPolicy::default` is the historical behaviour — leaf is the ciphertext's
  own commitment, every input counts — which matches the starter template. Every E3 program exports
  `policy()` beside `fhe_processor`. — `flow-trace/04`
- **CRISP binds bytes, commitment, slot and parent into its leaf, and selects the end of each slot's
  chain.** `CRISPProgram.inputLeaf` is
  `sha256(keccak256(bytes) || commitment || slot || parentIndexPlusOne) mod SNARK_SCALAR_FIELD` and
  `e3_user_program::policy` rebuilds it byte for byte; a divergence makes every root mismatch and
  nothing else would catch it, so both sides pin the same vector (`program/tests/input_leaf.rs`,
  `tests/input-leaf.test.ts`) and `onchain_root_agreement.rs` asserts Rust reproduces a root a real
  contract produced. The tree is append-only because the mask path checks no signature, so anyone
  can write to any census member's slot and update-in-place would let a third party erase a counted
  vote. — `flow-trace/04`
- **A slot's head must be openable by anyone, so selection follows a parent chain rather than a
  mutable pointer.** `chain_head_per_slot` takes an entry only when its bytes reproduce its
  commitment _and_ the entry it names is that slot's current head. `CRISPProgram` cannot check the
  first — the commitment is a Poseidon sponge over CRT limbs and the circuit never sees the
  serialization — so with one mutable head per slot, anyone could publish a valid proof beside
  unusable bytes and leave a head only they can open. A slot nobody can mask is a slot where every
  later input is provably its owner voting again, which is a coercion receipt. Because an unusable
  entry is never the head, it is never a valid parent, and the next honest input names the same
  parent it did.

  The rule takes the **first** usable entry to extend a parent, so a later sibling is dropped and an
  input can be front-run into not counting. Keep it that way: a stale parent cannot be told apart
  from a sibling built a moment earlier, because only the circuit knows whether an entry replaces
  the slot or adds to it. Preferring the later sibling would let a mask on a superseded ciphertext
  restore it over a vote — a silent tally corruption, against a dropped re-vote the voter can see
  and retry. — `flow-trace/04`

- **CRISP's three ballot operations prove one relation and publish one shape.** Voting, updating,
  and masking all prove `published = addend + ballot`, with the addend selected by the private
  `is_mask_vote` and derived as `keep_previous = is_mask_vote & !is_first_vote`. The circuit returns
  `sum_ct_commitment` on every path, the SDK has one code path, and `CrispSDK.prepareBallot` makes
  the same server request either way. Branching any of these apart — a different published
  ciphertext, a different commitment for the digest, a different request — makes the three
  distinguishable on chain, which is what masks exist to prevent. Deriving the selector rather than
  witnessing it is what stops a voter counting their old ballot twice and a masker erasing a vote. —
  `flow-trace/04`
- **CRISP constrains every coefficient of the ballot plaintext, at the real BFV degree.** The
  witness generator reverses the message over the full degree, so the payload sits at
  `k1[D - MAX_MSG_NON_ZERO_COEFFS ..]` with the options back to front;
  `crisp_lib::utils::ballot_layout` derives that offset and both checkers use it. Coefficients
  inside an option segment must be binary, everything outside the ballot region must be zero, and a
  mask's plaintext must be zero everywhere. Indexing as if the polynomial were the message width
  makes both checks read only padding: every vote passes any balance bound, and a mask — which needs
  no signature and may be written to any eligible slot — can carry an arbitrary payload into someone
  else's ballot. Tests must build `k1` at the compiled degree, not at `MAX_MSG_NON_ZERO_COEFFS`. —
  `flow-trace/04`
- **The SAFE ciphertext commitment requires exactly two components.** It covers `c[0]` and `c[1]`
  only, matching the Noir circuit, so `bfv_ciphertext_to_greco` rejects any other component count. A
  padded ciphertext would otherwise share a commitment with its two-component prefix while threshold
  decryption rejects it, failing the round as a `DecryptionTimeout` billed to the ciphernodes. —
  `flow-trace/04`
- **Client PK commitment binding (C-01):** Serialized PK event bytes are an untrusted transport
  hint. Consumers decode the bytes with the request-time threshold BFV parameters. Consumers store
  the key only when its recomputed commitment equals the on-chain (C5-proven) value. Proof-backed
  committee publication never accepts key bytes. Public-key candidates are bounded and gated to
  request-time committee members while the E3 remains in `KeyPublished`. Retained expelled members
  can still repair transport, but their bytes receive no extra trust. Terminal E3s cannot create new
  durable assemblies after cleanup. Consumers accept at most one candidate per member, so an invalid
  candidate cannot block a valid candidate from another member. — INDEX concerns #33, Z-31
- **No proof-disabled bypass (C-02):** both final verifier calls are mandatory in production;
  `skip_proof_aggregation` works only under the `test-only-skip-proof-aggregation` Cargo feature;
  production verifiers reject placeholder C5/C7 proofs. — INDEX concern #32
- Circuit soundness fixes to preserve: `ModU64::div_mod` verifies
  `result*divisor == dividend (mod modulus)` (IF-001); C7 compares **every** decoded coefficient,
  including zeros, to the claimed message (IF-002).

## Node / actor runtime

### Release compatibility

- Before EVM readers and protocol actors start, each enabled ciphernode chain reads the
  governance-selected `NodeReleaseRegistry`, verifies that the compiled compatibility values meet
  the required policy, and acknowledges its exact release ID and values on-chain. A missing
  controller or stale protocol/generation is a startup error. — `e3_evm::node_release`;
  `flow-trace/07`
- `protocol_version` covers incompatible contracts, events, cryptography, protocol behavior, and
  scopes every P2P protocol name. Nodes on different protocol versions do not discover, gossip, or
  synchronize with each other. `node_generation` covers a mandatory node-only release. P2P
  serialization compatibility within one protocol version remains separately gated by
  `GOSSIP_WIRE_MAJOR` and `SYNC_WIRE_MAJOR`. — `crates/config/protocol-release.toml`;
  `flow-trace/07`

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
  unknown canonical result must fail startup. If the E3 exists at chain head but not yet at the
  finalized block, recovery keeps the context and waits; finality lag is not an unknown E3. — INDEX
  concern #48
- EventStore replay preserves durable sequence inside each aggregate. It uses HLC order only to
  choose between the next events of different aggregates. A late event can have an older remote HLC
  and must not move ahead of an earlier local sequence from the same aggregate. — INDEX concern #43
- Snapshot-derived participation state is injected directly. Restart must not append synthetic
  `CiphernodeSelected` or `AggregatorChanged` events. A derived local selection resumes only at the
  fenced `SyncEffect` boundary. — INDEX concern #45
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
  order. Startup fences `EffectsEnabled` → `SyncEffect` → canonical history → `SyncEnded` in that
  order. `ComputeEffectGate` buffers and deduplicates until `EffectsEnabled`. —
  `CRATES_ARCHITECTURE.md`
- Sortition delays, committee-finalization timers, and slash submissions persist their semantic
  inputs before effects run. Restart re-arms them only after `EffectsEnabled`; an additive migration
  may backfill a missing versioned record but must not replace an existing one. — INDEX concern #46
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
  (`generate-verifiers.ts` output), `.active-preset.json`, `crates/support/contracts/ImageID.sol`,
  `crates/support/tests/Elf.sol`.
- **Generated verifiers must match the built VKs** — pre-push checks the canonical pair. CI hydrates
  and compares every supported preset and committee pair. A drift means a deployed verifier accepts
  a different circuit from the tree.
- **`Elf.sol` is never committed.** `crates/support/methods/build.rs` writes it with a machine-local
  guest ELF path, so it is generated per checkout and `.gitignore`d.
- **A release publishes a complete provenance manifest** — `pnpm provenance:manifest`. It ties
  source commit, lockfile digests, pinned revisions, RISC Zero version, builder image tag **and
  digest** (the builder tag is mutable and `RISC0_DOCKER_CONTAINER_TAG` overrides it), guest ELF
  SHA-256, image ID, and the deployed verifier to one record. The generator reports
  `complete: false` with the unresolved fields rather than emitting a partial record that reads as
  verified. The ELF SHA-256 is **not** the image ID: SHA-256 checks binary integrity, the image ID
  is computed from the loaded memory image. Procedure:
  `docs/pages/verifying-the-compute-provider.mdx`.
- Upgradeable-contract storage baselines are committed and CI-gated (missing baselines, compiler
  drift, layout incompatibility, bad gap consumption all fail); baseline creation is an explicit
  maintainer command. — INDEX concern #27
- Contracts CI fails a release if `Interfold` / aggregator-verifier runtime bytecode is within 256
  bytes of the EIP-170 limit. — INDEX concern #22
- BFV circuit-verifier and RISC Zero receipt-verifier constructors require deployed verifier
  contracts. BFV circuit wrappers also require nonzero recursive VK hashes. — INDEX concerns #21,
  Z-15
- CLI secrets are passed over **stdin only** — never argv or environment; private keys are never
  stored in plaintext. — `flow-trace/00`, `01`
- **Deployment writes must be mined, not only sent.** Every configuration transaction in
  `scripts/deployInterfold.ts` goes through the `send()` helper in `scripts/utils.ts`, which awaits
  the receipt and fails on a missing receipt or a non-success status. `send()` also labels a
  rejection from the send or the mining stage and keeps the original error as its `cause`. A bare
  `await contract.setX(...)` resolves when the transaction is dispatched, so on a real network a
  dropped write leaves the reference at `address(0)` while the script still exits zero.
- **A deployment must end with a verified wiring graph.** After configuration, `deployInterfold.ts`
  reads back every cross-contract reference (Interfold, CiphernodeRegistry, BondingRegistry,
  InterfoldTicketToken, SlashingManager, E3RefundManager, FOLD as the BondingRegistry ciphernode
  bond token) plus the BondingRegistry reward-distributor authorization for Interfold, and throws
  with the full list of mismatches. Add a read-back for each new cross-contract setter.
- **A deployment must also enable bonded voting.** `protocol/deployContracts` deploys
  `BondedCheckpoints` (bound to the BondingRegistry **proxy**, not the implementation) and the
  governance batch calls `setBondedCheckpoints` after `initialize`. `BondedVotes` comes later, from
  `--action activate-voting`: its constructor asks the registry which token it bonds, so it cannot
  be built until that batch has executed. `protocol/validate` reads back
  `bonding.bondedCheckpoints()` and `bondedCheckpoints.registry()`, and adds `bondedVotes.token()`,
  `bondedVotes.checkpoints()` and `bondedVotes.registry()` once the adapter exists. Upgrading an
  existing deployment through `upgrade/safeProxyUpgrade` deploys and attaches the pair when none is
  attached yet, and appends a `resyncBondedCheckpoint` call for each `bondedResyncOwners` entry —
  attaching does not backfill, so owners that bonded earlier read as zero until then. Without the
  attachment the upgrade silently ships a disabled feature: the sync is a no-op while unconfigured.

## Known open issues (check before assuming current behavior is correct)

The authoritative list is the "Verified Bugs & Protocol Concerns" table in `flow-trace/00_INDEX.md`.
Known residual gaps:

- `gracePeriod` is dead code in timeout checks (concern #3).
- CLI `activate` actually calls `register` and reverts for registered operators (#4).
- Live EventBus subscriber fan-out still includes unacknowledged `do_send` edges (#11). EventStore
  replay is paged through bounded temporary runs and uses an acknowledged fan-out barrier.
- `ComputeEffectGate` is in-memory only — no durable external-effect outbox yet.
- Residual runtime risks: `e3-evm` in-process nonce serialization without a durable tx outbox or
  full reorg rollback; accusation votes/timers lack complete durable reconstruction;
  `e3-program-server` test endpoint is unauthenticated (never a production boundary); cancellation
  ownership is not uniform across crates. — `CRATES_ARCHITECTURE.md` §Subsystem contracts
