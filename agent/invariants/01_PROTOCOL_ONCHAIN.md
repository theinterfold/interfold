# Invariants — Protocol / on-chain

Scope: `packages/interfold-contracts/contracts/`, deployment and task scripts. Tokens, bonding,
activation, E3 request and committee selection, deadlines, slashing and failure settlement.

Read `00_INDEX.md` first: it carries the meta-invariants and the open-issues list that apply to
every section.

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
- **`BondingRegistry` is at its EIP-170 ceiling.** It is gated at 128 bytes of headroom by
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
  `seed = keccak256(randomWord ‖ chainId ‖ registry ‖ e3Id ‖ requestId)`. New requests keep the best
  submission per request-time bond owner, then the lowest N owner scores. Ties use ascending
  operator address. Each E3 freezes one `IRandomnessProvider` request, response deadline, and
  submission window after the paid request is stored. The production provider uses Chainlink VRF
  v2.5 subscription funding. It never re-requests an E3, checks the configured subscription balance
  floor before requesting, and the Registry rejects responses from the Ethereum request block,
  future-dated responses, and late responses. This release supports Ethereum mainnet, Sepolia, and
  local development chains only. The provider reserves the subscription balance floor for each
  unfulfilled draw, thus a burst of requests in one block cannot all pass the same balance check. A
  request that expires without a usable response sets an advisory `degraded` flag and emits
  `RandomnessCircuitBreakerTripped`. It does not clear the active provider, because that path is
  permissionless and registry-global. Governance reads the flag and re-points the provider, which
  clears it. A timely accepted response remains readable after terminal cleanup so fresh historical
  replay derives the same committee request; late responses remain unusable. Rust reads the accepted
  seed and request context at the fulfillment block. If historical block state is unavailable, it
  accepts retained current state only when the Registry still reports the seed as ready.
  Unverifiable state rejects the log and fails closed for replay. Governance can change the provider
  or response timeout only while requests are paused and all committee obligations are released. The
  E3 computation seed remains separate. — `flow-trace/03`
- **Per-E3 sortition state is immutable:** for request timestamp `T`, the request-time eligible
  count, each operator's eligibility, and each ticket balance come from `T-1`. The request also
  freezes `ticketPrice`, and Rust consumes the same timepoint and price. Current registration and
  activity are additional liveness checks only. The IMT root is snapshotted at request time. —
  `CiphernodeRegistryOwnable.sol`; `flow-trace/03`
- **One selected operator per snapshot bond owner:** new requests freeze the owner-cap policy.
  `bondOwnerAt(operator, T-1)` determines the group; later transfers cannot create a second seat for
  that snapshot owner. Both ownership write paths must checkpoint before assignment. Unchanged
  pre-upgrade owners use a lazy baseline; this history is valid for capped requests, not arbitrary
  pre-upgrade timestamps. Existing requests retain uncapped selection through an appended zero
  policy field. Solidity enforces the cap, independently of the submitting binary. Rust shortlists
  N-plus-buffer distinct owners and retains their eligible operators as backups. An operator-count
  cutoff must not exclude necessary owners. Missing owner history permits all submissions. Formation
  requires N distinct snapshot owners, not merely N submissions. The cap does not establish human
  uniqueness, prevent pre-request wallet splitting, or prevent later collusion. —
  `BondingOwnershipLib.sol`; `RegistrySortitionLib.sol`; `flow-trace/03`
- `finalizeCommittee()` requires the submission window to have closed. The first successful call
  locks the canonical on-chain committee order. A ready committee must finalize by its absolute
  request-time DKG cutoff. Delayed finalization cannot extend the paid lifecycle. — `flow-trace/03`
- **Exit timing strictly covers sortition:** `BondingRegistry.exitDelay` must remain greater than
  `CiphernodeRegistryOwnable.randomnessRequestTimeout + sortitionSubmissionWindow`. Value setters
  and registry-pointer setters enforce the relationship; equality is invalid because ticket
  submission includes the deadline. — `BondingRegistry.sol`; `CiphernodeRegistryOwnable.sol`;
  `flow-trace/02`, `03`
- **One coherent dependency graph:** each request validates and snapshots the complete Interfold,
  registry, bonding, slashing, refund, treasury, and policy graph. Governance must pause requests
  and drain all E3s, committees, bans, and slash routes before it replaces a graph member. Replacing
  the registry, bonding registry, or refund manager also requires an empty operator generation. A
  SlashingManager-only rotation can preserve operators when the registry and bonding proxies stay in
  place, the replacement advertises the supported API, and one atomic transaction commits the
  complete graph before it revokes the old manager. Old and new graphs never serve requests at the
  same time. — `flow-trace/03`, `05`, `07`
- **Candidate and member collateral remains slashable:** committee requests assign their
  request-time registry in `BondingRegistry`. A top-N ticket submission locks its candidate, and a
  better ticket releases the displaced candidate. Finalization retains each winner's obligation.
  `claimExitsFor` cannot pay a locked candidate or member until displacement or terminal committee
  release. A finalized committee releases only after the E3 is terminal **and** the request-time
  slashing manager's accusation submission deadline has passed, so an early-ended round cannot let a
  member withdraw before a valid accusation can still be filed. — `flow-trace/03`, `06`; INDEX
  concerns Z-04, Z-37, ZEN2-09
- **Exit timing covers frozen requests:** `exitDelay` must exceed the current submission window and
  the remaining time for the latest request-time committee deadline. Each request raises a monotonic
  deadline watermark. The time-based floor decreases after old windows expire, and the
  BondingRegistry cannot clear its registry pointer. — `flow-trace/02`, `03`, `06`; INDEX Z-37
- **E3 program allowlist:** production initialization registers one deployed E3 program and assigns
  Interfold ownership to the configured protocol owner. Later registration and retirement are
  owner-only. Retirement closes only new request admission; existing E3s keep their snapshotted
  program. Every registered address must contain runtime code and must advertise both `IE3Program`
  and `IE3ProgramDataAvailability` through ERC-165. Interfold calls `verifyDataAvailability` on
  every output publication, so a program that omits the selector could otherwise brick its own
  rounds after the requester paid. `MockE3Program` is the stateless bootstrap option. It has no
  administrative controls and applies no application rules. Its deterministic test receipt is not
  production data availability, so requests remain paused until a production program is registered
  and wired. The request-time BFV ciphertext verifier and decryption verifier remain mandatory. Its
  mutable failure controls live only in `MockE3ProgramHarness`. A protocol upgrade that makes the
  program interface incompatible must retire every incompatible bootstrap program before requests
  resume. — `Interfold.sol`; `MockE3Program.sol`; `flow-trace/03`
- **Data availability binds per program and per round:** Interfold holds no protocol-level
  data-availability verifier; it delegates to `IE3ProgramDataAvailability(e3Program)`, and a program
  holds its verifier as an immutable. The Avail adapter re-checks `bridge.vectorx() == vectorx` on
  every call, so an external pointer rotation fails closed instead of silently changing a live
  round's trust root. Containment is `unregisterE3Program` for the affected programs only. —
  `flow-trace/08`; INDEX concerns ZEN2-08
- **One round, one data-availability provider.** A verified receipt is a
  `DataReference{contentHash, blockNumber, leafIndex}`. Only `contentHash` reaches storage, as
  `e3.ciphertextOutput`; `blockNumber` and `leafIndex` exist solely in the
  `CiphertextOutputReferencePublished` event, and neither the struct nor the event carries a
  provider identifier. Retrieval coordinates are therefore interpretable only under the single
  verifier the round was bound to. Do not add a settable or governed verifier pointer. Re-pointing
  mid round leaves inputs 1..k proved against the old provider and k+1..n against the new one,
  indistinguishable on chain, so the earlier coordinates become unresolvable without off-chain
  knowledge of the switch, and the aggregate step cannot read a round whose inputs are split across
  providers. A timelock does not help: the defect is the missing provider binding, not the authority
  to rotate. Supporting more than one provider per round requires a persisted provider identifier in
  the reference first. — `flow-trace/08`; INDEX concerns ZEN2-08
- **Do not extend `computeDeadline` to survive a data-availability outage.** `SlashingManager`
  snapshots `slashSubmissionDeadline` from `getE3LifecycleDeadline(e3Id)` at proposal
  initialization, so extending the compute deadline alone lets a round outlive the accusation window
  sized for it, and `releaseCommittee` gates on that same deadline (ZEN2-09). An extension also
  cannot change who pays: `FailurePayerLib.getFailurePayer` reads the failure reason only, and the
  reason follows the stage the round stalled in, so a longer clock yields the same `ComputeTimeout`
  and the same requester-paid settlement. Reallocating that cost is a failure attribution and
  funding decision, not a deadline change. — `flow-trace/05`, `flow-trace/08`; INDEX concerns
  ZEN2-08

### Deadlines

- Every stage has a deadline. Once a deadline is missed, **anyone** may call `markE3Failed(e3Id)`.
  The request snapshots all timeout windows. The randomness response starts the full ticket
  submission window; the DKG deadline equals that resolved committee deadline plus the DKG window.
  The compute deadline starts at the later of key publication and the end of the input window.
  Request validation reserves the full worst-case randomness, sortition, DKG, compute, and
  decryption lifecycle. — `flow-trace/03`
- **The threshold-share checkpoint is not a DKG deadline.** At 75% of the frozen DKG window, a node
  may close collection when it has at least H−1 external shares. Below H−1, it must keep collecting.
  Only the request-frozen on-chain DKG deadline may turn missing threshold shares into `DKGTimeout`.
  Restart must preserve the remaining deadline. — `flow-trace/04`; INDEX concern #54
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
  paths use the recipient frozen at committee finalization. Unclaimed committee allocations stay
  keyed by **operator** in `E3RefundManager._operatorEntitlements` until withdrawal, and every claim
  path re-checks `pendingExpulsions` and `excluded` at claim time, so a proposal opened after
  settlement still holds the allocation and two operators sharing one recipient keep independent
  entitlements. On a **failed** E3 both lanes close expelling-proposal admission at the reporting
  deadline, and every admitted expulsion resolves before `calculateRefund`. The base split uses the
  post-expulsion roster, and the post-settlement reallocation paths (`_takeForfeitedBaseReward`,
  `_redistributeHeldSlash`) are exercised only on successful E3s. Lane A retains its reporting
  deadline, while Lane B permits later completed-round proposals while the dependencies remain
  assigned. — `flow-trace/05`, `flow-trace/06`; INDEX concerns ZEN2-20
- Slash-policy validity: `!requiresProof ⇒ appealWindow > 0`; ≥1 nonzero penalty. The retained
  `failureReason` field is 0 or `InsufficientCommitteeMembers`; execution does not select failure
  attribution from policy data. — `flow-trace/05`; INDEX concerns Z-07, Z-32
- Failure attribution is order independent: the recorded `FailureReason` fixes the payer, so an
  expulsion that drops a round below committee viability reclassifies a **requester-paid** reason to
  `InsufficientCommitteeMembers` even when a caller already marked the round `Failed`. Only the E3's
  request-time slashing manager may reclassify, only before `getRefundDistribution().calculated`,
  and only from a requester-paid reason, so a correction never moves a cost onto the requester and
  never contradicts a settled distribution. The stage stays `Failed` and `activeE3Count` does not
  change. A correction that no longer applies returns without an effect, so it never reverts the
  expulsion. — `flow-trace/05`; INDEX concerns ZEN2-04
- **Failed-E3 settlement waits for the accusations that could move its payer:** `calculateRefund`
  reverts `SettlementBlocked` unless `SlashingManager.settlementOpen(e3Id)`, which is true only when
  the accusation window (`slashSubmissionDeadline`) has closed **and** no `affectsCommittee`
  proposal for the E3 is open (`_openCommitteeProposals`, incremented in `_openProposal` and
  decremented on every terminal path through `_closeProposalCount`). A round that never finalized a
  committee has no member to expel and no payer to move, so it settles at once. Non-expelling
  penalties never gate. Both lanes reject new expelling proposals after the frozen reporting
  deadline for every non-complete E3, including an overdue E3 not yet marked failed. Lane B keeps
  late non-expelling penalties and completed-round proposals. `settlementCutoff` retains its ABI and
  formula (`slashSubmissionDeadline` + `MAX_APPEAL_WINDOW` + `APPEAL_RESOLUTION_GRACE`), but never
  bypasses an open proposal. By that time, each timely proposal can be resolved through
  permissionless execution or unresolved-appeal expiry. Rejected appeals still require execution.
  Settlement waits for those transactions to succeed; time alone does not close a proposal. The
  reporting allowance remains one day after the scheduled lifecycle deadline, not after
  `markE3Failed`. Its operational sufficiency is not established by these checks. A calculated
  refund still never changes: the gate moves _when_ it is calculated, not what it can become. —
  `flow-trace/05`; INDEX concerns ZEN2-04
- **Committee viability loss is atomic:** if an expulsion leaves fewer than H active members, the
  same transaction must fail the affected nonterminal E3 with the supplier-paid
  `InsufficientCommitteeMembers` reason. Reusing this existing reason preserves the persisted enum
  layout. A failed callback rolls back the penalties, ban, and expulsion. Complete and failed E3s
  allow execution of admitted slashes; on a failed E3 the expulsion additionally attempts the
  reclassification above, which is a no-op when it no longer applies. Committee key, ciphertext, and
  plaintext publication all require a currently viable request-time committee. Ciphertext
  publication checks the stage and that viability again after `IE3Program.verify` returns, because
  an application callback can slash a member and record a terminal failure through `onE3Failed`,
  outside the publication reentrancy guard. A failed recheck reverts the complete transaction. —
  `flow-trace/04`, `05`; INDEX concerns Z-32, ZEN2-04, ZEN2-26
- Accusation quorum: `agree_count >= H`; the implementation derives `H` from the committee enum
  because the legacy E3 field `threshold_m` carries circuit threshold `T`. Voters must be active
  committee members, and all votes must agree. Lane A is **attestation-based** (ECDSA per voter),
  not on-chain ZK re-verification. Vote digest / EIP-712 type hashes must match the Solidity
  constants exactly (Rust ↔ Solidity). — `flow-trace/05`; `SlashingManager.sol`
- Staggered slash submission: agreeing voters ranked by ascending address, rank N waits `N × skew`
  (default 30 s); restarts must not reset the fallback delay. — `flow-trace/05`
- **Deferred-slash collateral gate:** every manager atomically records proposal locks in
  `BondingRegistry`. Ticket withdrawal, ciphernode bond unbonding, deregistration, and exit claims
  read the registry's aggregate lock count and stay blocked until resolution. User exits must not
  call a slashing manager. A retained manager cannot be revoked until its E3 assignments, locks,
  bans, and fund routes are clear. — INDEX concerns #1, #26, Z-44; `flow-trace/06`
- Exit queue caps explicit non-empty tranche count; drained single-asset tranches release capacity.
  — INDEX concern #18
