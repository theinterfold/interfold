# Part 2: Tokens, Bonding & Activation

## Overview

Before a node can register, it must stake two types of collateral:

1. **INTF tokens** (license bond) — governance/utility token, staked directly
2. **Stablecoin via ITK tickets** (ticket collateral) — USDC wrapped into non-transferable
   InterfoldTicketToken

---

## Token Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    InterfoldToken (INTF)                     │
│  ERC20 + ERC20Permit + ERC20Votes + AccessControl         │
│  + Ownable2Step                                            │
│                                                           │
│  MAX_SUPPLY: 1,200,000,000 (1.2B with 18 decimals)       │
│  Immutables: CCA_START, CCA_END, CLAIM_SOURCE,            │
│              BONDING_REGISTRY (set at construction)        │
│                                                           │
│  Lifecycle phases (derived from CCA window + TGE):        │
│    Virtual → PublicSale → Cooldown → Live                 │
│    - Virtual: mint() + mintAllocations() allowed           │
│    - PublicSale: CCA bidding window                        │
│    - Cooldown: CCA ended, TGE not yet called               │
│    - Live: TGE fired (permissionless after cooldown)       │
│                                                           │
│  Minting (Virtual phase only):                            │
│    - mint(recipient, amount, label)                        │
│      DEFAULT_ADMIN_ROLE — unlocked tokens                  │
│    - mintAllocations(MintAllocation[])                     │
│      MINTER_ROLE — tokens locked under a policy            │
│                                                           │
│  Pre-TGE transfer gate (phase-based, automatic):          │
│    Allowed: bonding registry, claim source, whitelisted    │
│    Blocked: all other transfers                            │
│    Once TGE fires, all transfers unrestricted              │
│                                                           │
│  Lock system (wallet-level pooled enforcement):           │
│    - createLockPolicy(id, LockPolicy) → write-once         │
│      LOCK_MANAGER_ROLE                                     │
│    - linkClaim(account, amount, policyId)                  │
│      LOCK_MANAGER_ROLE                                     │
│    - LockPolicy: { holdUntil, Curve { anchor, start,      │
│        cliffDuration, vestDuration } }                     │
│    - Anchor: Absolute (fixed start) | Tge (tgeTimestamp)   │
│    - PENDING_LOCK_POLICY_ID for unclassified claims        │
│    - Queued locks consumed by later claims (linkClaim)     │
│                                                           │
│  Lock invariant for transfers:                             │
│    transferable = balance - max(0, lockedBalance -         │
│      BONDING_REGISTRY.totalBonded(account))                │
│    Transfer reverts with InsufficientUnlockedBalance       │
│    if value > transferable                                 │
│                                                            │
│  Lock sunset (NO_MORE_LOCKS, immutable):                   │
│    - Absolute timestamp set at deployment                  │
│    - createLockPolicy rejects any policy that could        │
│      outlast the sunset (curves and holdUntil)             │
│    - From NO_MORE_LOCKS on, _update skips all lock         │
│      accounting (vanilla ERC20); PENDING locks die too     │
│                                                            │
│  Whitelisting:                                             │
│    - setTransferWhitelisted(addr, bool)                    │
│      WHITELIST_ROLE — pre-TGE transfer gate                │
│    - setLockWhitelisted(addr, bool)                        │
│      LOCK_MANAGER_ROLE — exempt from claim-source locks    │
│                                                           │
│  Used as: LICENSE BOND token                              │
└───────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│              InterfoldTicketToken (ITK)                      │
│  ERC20Wrapper over stablecoin (e.g. USDC)                 │
│                                                           │
│  NON-TRANSFERABLE: _update() reverts on transfer          │
│  NO DELEGATION: delegate() reverts                        │
│  NO APPROVALS: approve() reverts                          │
│                                                           │
│  Only BondingRegistry (registry role) can:                │
│    depositFor()  → wrap USDC, mint ITK to operator        │
│    depositFrom() → pull USDC from X, mint ITK to Y       │
│    burnTickets() → burn ITK, NO underlying returned       │
│    withdrawTo()  → burn ITK, return underlying USDC       │
│    payout()      → send underlying from payableBalance    │
│                                                           │
│  Used as: TICKET COLLATERAL token                         │
└───────────────────────────────────────────────────────────┘
```

---

## Step 1: Bond License (`interfold ciphernode license bond`)

**File:** `crates/cli/src/ciphernode/license.rs`

```
User runs: interfold ciphernode license bond --amount 50000
│
├─ 1. ChainContext::new()
│     └─ Loads config, decrypts wallet, connects to BondingRegistry
│
├─ 2. Approve INTF spend:
│     └─ InterfoldToken.approve(bondingRegistry, 50000)
│        → Allows BondingRegistry to pull INTF tokens
│
├─ 3. BondingRegistryContract.bondLicense(50000).send().await
│     │
│     │  ┌─── ON-CHAIN (BondingRegistry.sol) ──────────────────┐
│     │  │                                                      │
│     │  │  bondLicense(uint256 amount) {                       │
│     │  │    1. require(amount > 0)                            │
│     │  │    2. operators[msg.sender].licenseBond += amount    │
│     │  │       → totalBonded(msg.sender) now includes amount  │
│     │  │    3. licenseToken.safeTransferFrom(                 │
│     │  │         msg.sender,   // from operator               │
│     │  │         address(this), // to BondingRegistry         │
│     │  │         amount                                       │
│     │  │       )                                              │
│     │  │       → INTF _update can see the pre-recorded bond   │
│     │  │         and enforce locked-floor accounting          │
│     │  │       → INTF tokens move from operator → contract    │
│     │  │    4. _updateOperatorStatus(msg.sender)              │
│     │  │       → May activate if all conditions now met       │
│     │  │    5. Emit LicenseBondUpdated(msg.sender, newBond)   │
│     │  │  }                                                   │
│     │  └──────────────────────────────────────────────────────┘
│     │
└─ OUTPUT: "Transaction hash: 0x..."
```

### Locked INTF bonding

`BondingRegistry.totalBonded(account)` returns active INTF license bond plus pending INTF exits that
remain slashable/not returned. `InterfoldToken` uses this view for pooled wallet-level locks, so
locked INTF can be self-bonded by the same account without becoming transferable. Delegated
source-aware bonding is not part of the pooled-lock model; license bonds are credited to
`msg.sender` through `bondLicense(amount)`.

### Activation check after bonding:

```
_updateOperatorStatus(operator):
  wasActive = operators[operator].active

  isNowActive = (
    operators[operator].registered == true
    AND operators[operator].licenseBond >= (licenseRequiredBond * licenseActiveBps / 10000)
        // Default: licenseActiveBps = 8000 (80%)
        // So if licenseRequiredBond = 50000, need >= 40000 INTF
    AND ticketToken.balanceOf(operator) / ticketPrice >= minTicketBalance
  )

  if (wasActive && !isNowActive):
    operators[operator].active = false
    numActiveOperators--
    emit OperatorActivationChanged(operator, false)

  if (!wasActive && isNowActive):
    operators[operator].active = true
    numActiveOperators++
    emit OperatorActivationChanged(operator, true)
```

---

## Step 2: Buy Tickets (`interfold ciphernode tickets buy`)

**File:** `crates/cli/src/ciphernode/tickets.rs`

> **IMPORTANT:** The `amount` parameter to `addTicketBalance` is in **underlying stablecoin base
> units** (e.g., USDC wei), NOT in ticket count. The CLI parses the user's input using the
> underlying token's decimals. `ticketPrice` is only used in the activation check
> (`balanceOf / ticketPrice >= minTicketBalance`) and in sortition eligibility — it is NOT used to
> multiply the deposit amount.

```
User runs: interfold ciphernode tickets buy --amount 100
│
├─ 1. ChainContext::new()
│
├─ 2. CLI resolves the ticket token's underlying stablecoin address
│     and its decimals, then parses "100" → 100_000_000 (raw units)
│
├─ 3. Approve stablecoin spend:
│     └─ USDC.approve(ticketTokenAddress, 100_000_000)
│        → Note: approval is to the TicketToken contract (not BondingRegistry)
│        → because depositFrom pulls USDC into the TicketToken wrapper
│
├─ 4. BondingRegistryContract.addTicketBalance(100_000_000).send().await
│     │
│     │  ┌─── ON-CHAIN (BondingRegistry.sol) ──────────────────┐
│     │  │                                                      │
│     │  │  addTicketBalance(uint256 amount) {                  │
│     │  │    1. require(amount > 0)                            │
│     │  │    2. require(operators[msg.sender].registered)      │
│     │  │    3. modifier: require(!exitInProgress(msg.sender)) │
│     │  │    4. ticketToken.depositFrom(                       │
│     │  │         msg.sender,  // pull USDC from operator      │
│     │  │         msg.sender,  // mint ITK to operator         │
│     │  │         amount       // RAW stablecoin units         │
│     │  │       )              // NO ticketPrice multiplication│
│     │  │       │                                              │
│     │  │       │  ┌─ InterfoldTicketToken.depositFrom() ────┐  │
│     │  │       │  │  1. underlying.transferFrom(           │  │
│     │  │       │  │       from, address(this), amount)     │  │
│     │  │       │  │     → USDC moves: operator → ITK       │  │
│     │  │       │  │  2. _mint(to, amount)                  │  │
│     │  │       │  │     → ITK minted 1:1 with USDC         │  │
│     │  │       │  │  3. Auto-delegate to self on first     │  │
│     │  │       │  │     deposit (for voting power tracking)│  │
│     │  │       │  └────────────────────────────────────────┘  │
│     │  │    5. _updateOperatorStatus(msg.sender)              │
│     │  │    6. Emit TicketBalanceUpdated(msg.sender,          │
│     │  │         +amount, newBalance, "DEPOSIT")              │
│     │  │  }                                                   │
│     │  └──────────────────────────────────────────────────────┘
│     │
└─ OUTPUT: "Purchased 100 tickets (tx: 0x...)"
```

### Why tickets are non-transferable:

ITK tokens cannot be transferred between addresses. This ensures:

- An operator's collateral can't be moved to avoid slashing
- The ticket balance is always attributable to the specific operator
- Snapshot-based committee eligibility (checking balance at `requestBlock - 1`) is reliable

---

## Step 3: Unbond License (`interfold ciphernode license unbond`)

```
User runs: interfold ciphernode license unbond --amount 10000
│
├─ BondingRegistryContract.unbondLicense(10000).send().await
│     │
│     │  ┌─── ON-CHAIN ─────────────────────────────────────────┐
│     │  │                                                       │
│     │  │  unbondLicense(uint256 amount) {                      │
│     │  │    1. require(amount > 0)                             │
│     │  │    2. require(operators[msg.sender].licenseBond       │
│     │  │              >= amount)                               │
│     │  │    3. operators[msg.sender].licenseBond -= amount     │
│     │  │    4. _exits.queueLicensesForExit(                   │
│     │  │         msg.sender, exitDelay, amount                 │
│     │  │       )                                               │
│     │  │       → Pending INTF still counts in totalBonded()    │
│     │  │         until claimed or slashed                      │
│     │  │    5. _updateOperatorStatus(msg.sender)               │
│     │  │       → May DEACTIVATE if bond drops below threshold  │
│     │  │    6. Emit LicenseBondUpdated(msg.sender, newBond)    │
│     │  │  }                                                    │
│     │  └───────────────────────────────────────────────────────┘
│
└─ Funds are now LOCKED for exitDelay seconds (time-locked exit)
```

---

## Step 4: Burn Tickets (`interfold ciphernode tickets burn`)

> **IMPORTANT:** Like `addTicketBalance`, the `amount` here is in **raw stablecoin base units** (ITK
> units, which are 1:1 with underlying). There is NO `ticketPrice` multiplication. The CLI parses
> the user's amount using the ticket token's decimals.

```
User runs: interfold ciphernode tickets burn --amount 50
│
├─ CLI parses "50" using ticket token decimals → raw units
│
├─ BondingRegistryContract.removeTicketBalance(rawAmount).send().await
│     │
│     │  ┌─── ON-CHAIN ─────────────────────────────────────────┐
│     │  │                                                       │
│     │  │  removeTicketBalance(uint256 amount) {                │
│     │  │    1. require(amount > 0)                             │
│     │  │    2. require(operators[msg.sender].registered)       │
│     │  │    3. require(ticketToken.balanceOf(msg.sender)       │
│     │  │              >= amount)                               │
│     │  │    4. ticketToken.burnTickets(msg.sender, amount)     │
│     │  │       │  (NO ticketPrice multiplication — raw units)  │
│     │  │       │                                               │
│     │  │       │  ┌─ InterfoldTicketToken ───────────────────┐  │
│     │  │       │  │  burnTickets(operator, amount):        │  │
│     │  │       │  │    payableBalance += amount             │  │
│     │  │       │  │    _burn(operator, amount)             │  │
│     │  │       │  │    → ITK destroyed                     │  │
│     │  │       │  │    → Underlying USDC NOT returned yet  │  │
│     │  │       │  │    → Tracked in payableBalance for     │  │
│     │  │       │  │      later payout()                    │  │
│     │  │       │  └────────────────────────────────────────┘  │
│     │  │    5. _exits.queueTicketsForExit(                    │
│     │  │         msg.sender, exitDelay, amount)                │
│     │  │    6. _updateOperatorStatus(msg.sender)               │
│     │  │       → May DEACTIVATE if tickets drop below minimum  │
│     │  │    7. Emit TicketBalanceUpdated(msg.sender,           │
│     │  │         -amount, newBalance, "WITHDRAW")              │
│     │  │  }                                                    │
│     │  └───────────────────────────────────────────────────────┘
│
└─ Tickets burned, USDC queued for exit after delay
```

---

## Step 5: Claim Exits (`interfold ciphernode license claim`)

```
User runs: interfold ciphernode license claim [--max-ticket 50] [--max-license 10000]
│
├─ BondingRegistryContract.claimExits(50, 10000).send().await
│     │
│     │  ┌─── ON-CHAIN ─────────────────────────────────────────┐
│     │  │                                                       │
│     │  │  claimExits(maxTicket, maxLicense) {                  │
│     │  │    1. (ticketAmount, _) =                             │
│     │  │       _exits.claimAssets(                             │
│     │  │         msg.sender, maxTicket, 0                      │
│     │  │       )                                               │
│     │  │       │                                               │
│     │  │       │  ┌─ ExitQueueLib.claimAssets() ───────────┐  │
│     │  │       │  │  Iterates tranches from head:          │  │
│     │  │       │  │  for each tranche where                │  │
│     │  │       │  │    block.timestamp >= unlockTimestamp:  │  │
│     │  │       │  │      take min(wanted, available)       │  │
│     │  │       │  │      from ticketAmount                  │  │
│     │  │       │  │  Skip locked tranches (future unlock)  │  │
│     │  │       │  │  Clean up empty tranches               │  │
│     │  │       │  │  Update pendingTotals                  │  │
│     │  │       │  └────────────────────────────────────────┘  │
│     │  │                                                       │
│     │  │    2. if ticketAmount > 0:                            │
│     │  │       ticketToken.payout(msg.sender, ticketAmount)    │
│     │  │       │                                               │
│     │  │       │  ┌─ InterfoldTicketToken.payout() ──────────┐  │
│     │  │       │  │  Transfers underlying USDC from        │  │
│     │  │       │  │  payableBalance to operator             │  │
│     │  │       │  │  payableBalance -= amount               │  │
│     │  │       │  │  underlying.safeTransfer(to, amount)    │  │
│     │  │       │  └────────────────────────────────────────┘  │
│     │  │                                                       │
│     │  │    3. licenseAmount = _claimLicenseExits(             │
│     │  │         msg.sender, maxLicense                        │
│     │  │       )                                               │
│     │  │       → Each INTF source pays its withdrawalAddress   │
│     │  │       → Receiver callback gets (operator, amount,     │
│     │  │         sourceId) when supported                      │
│     │  │       → Pending INTF is removed from totalBonded()    │
│     │  │         as returned INTF reaches the wallet           │
│     │  │  }                                                    │
│     │  └───────────────────────────────────────────────────────┘
│
└─ Operator receives back USDC; INTF goes to each source's withdrawal address
```

---

## Activation Thresholds Summary

| Requirement           | Default             | Description                                |
| --------------------- | ------------------- | ------------------------------------------ |
| `licenseRequiredBond` | Configured by owner | Min INTF to register                       |
| `licenseActiveBps`    | 8000 (80%)          | % of required bond to stay active          |
| `minTicketBalance`    | Configured by owner | Min tickets for active status              |
| `ticketPrice`         | Configured by owner | Stablecoin cost per ticket (in base units) |
| `exitDelay`           | Configured by owner | Seconds before exits can be claimed        |

### Activation formula:

```
active = registered
  AND licenseBond >= (licenseRequiredBond * licenseActiveBps / 10000)
  AND (ticketToken.balanceOf(operator) / ticketPrice) >= minTicketBalance
```

---

## Token Flow Diagram

```
                BOND LICENSE                          BUY TICKETS
                ────────────                          ───────────
  Operator                                 Operator
  INTF wallet ──→ BondingRegistry          USDC wallet ──→ InterfoldTicketToken
                  (licenseBond++)                          (wraps USDC → mints ITK)
                                                           ITK → Operator balance

               UNBOND LICENSE                         BURN TICKETS
               ──────────────                         ────────────
  licenseBond -= amount                    ITK burned from operator
  amount → ExitQueue (locked)              USDC stays in ITK contract (payableBalance)
                                           amount → ExitQueue (locked)

                              CLAIM EXITS
                              ───────────
                   After exitDelay seconds:
                   INTF → returned to source withdrawal address
                   USDC → paid out from ITK.payableBalance
```

---

## Audit Cluster 2 Changes (Tokens)

The token contracts were hardened against the following audit findings. All changes are covered by
`packages/interfold-contracts/test/Token/` and have no runtime impact outside the touched contracts.

### InterfoldTicketToken (ITK)

- **H-02 — registry initialization.** The constructor now takes
  `(IERC20 baseToken, address registry_, address initialOwner_)` and assigns `registry = registry_`
  directly (emitting `RegistryChanged(0, registry_)`) instead of requiring the deployer to call
  `setRegistry()` later. Reverts `ZeroAddress` if `registry_ == 0`.
- **H-03 — fee-on-transfer safe deposits.** `depositFor` and `depositFrom` measure the underlying
  balance before/after `safeTransferFrom` and mint the _actual_ amount received. Operators auto
  self-delegate on first deposit.
- **H-16 / H-20 / M-22 — registry swap timelock.** Once `lockRegistry()` is called (one-way,
  `RegistryLockAlreadySet` on repeat) further registry swaps must go through
  `requestRegistryChange(addr)` → wait `REGISTRY_CHANGE_DELAY = 1 day` → `activateRegistryChange()`.
  Errors: `RegistryNotLocked`, `RegistryChangeNotReady`, `NoPendingRegistry`,
  `RegistryAlreadyLocked`. `cancelRegistryChange()` clears the pending swap.
- **M-11 — permit disabled.** `permit()` always reverts `PermitDisabled` so non-transferable tickets
  cannot be moved via off-chain signatures.
- **M-12 — rescueERC20.** `rescueERC20(token, to, amount)` lets the owner recover stray ERC-20s but
  refuses the underlying asset (`CannotRescueUnderlying`).
- **M-25 — delegation locked to self.** `delegate()` only accepts the caller's own address (else
  `DelegationLocked`); `delegateBySig` always reverts.
- **M-29 — EIP-6372 timestamp clock.** `clock() = uint48(block.timestamp)`,
  `CLOCK_MODE() = "mode=timestamp"`.

### InterfoldToken (INTF) — Complete Rewrite

The INTF token was rewritten to implement a CCA-auction-aligned lifecycle with wallet-level lock
enforcement based on immutable policy curves. Key changes:

- **Phase-based lifecycle.** The token derives its phase from immutable `CCA_START` / `CCA_END` and
  the one-way `tge()` call: Virtual → PublicSale → Cooldown → Live. Minting is gated to Virtual
  phase only; TGE is permissionless after `CCA_END + TGE_COOLDOWN` (45 days). The pre-TGE transfer
  gate automatically lifts at TGE — no `disableTransferRestrictions` / `transfersRestricted` flag.
- **Pre-TGE transfer gate.** Before TGE, only bonding-registry transfers, claim-source
  distributions, and whitelisted addresses can transfer. Bonding is always allowed so operators can
  stake during Virtual phase.
- **Immutable constructor parameters.** `CCA_START`, `CCA_END`, `CLAIM_SOURCE`, and
  `BONDING_REGISTRY` are set at construction and cannot change. The BondingRegistry must be deployed
  first (or a placeholder used and fixed via `setLicenseToken`).
- **Lock policy system.** `createLockPolicy(id, LockPolicy)` creates write-once policies with
  `Curve { anchor (Absolute|Tge), start, cliffDuration, vestDuration }` and optional `holdUntil`.
  `linkClaim(account, amount, policyId)` classifies pending claim-source tokens under a real policy.
  `PENDING_LOCK_POLICY_ID` holds unclassified claim tokens until linked.
- **Pooled wallet enforcement.** `lockedBalanceOf(account)` sums active locks (including PENDING).
  `transferableBalanceOf(account) = balance - max(0, locked - BONDING_REGISTRY.totalBonded(account))`.
  Transfers that exceed the transferable balance revert with `InsufficientUnlockedBalance`.
- **Claim-source auto-lock.** Tokens arriving from `CLAIM_SOURCE` are automatically locked as
  PENDING unless the recipient is in `lockWhitelist`. `linkClaim` moves PENDING to a real policy and
  queues unfilled amounts for future claims.
- **EIP-6372 timestamp clock.** `clock()` returns `block.timestamp`, `CLOCK_MODE()` is
  `"mode=timestamp"`.
- **Minting.** `mint(recipient, amount, label)` (DEFAULT_ADMIN_ROLE, unlocked) and
  `mintAllocations(MintAllocation[])` (MINTER_ROLE, locked to a policy) are both Virtual-only.
- **Ownership.** `renounceOwnership()` is disabled. Two-step ownership transfer via Ownable2Step
  syncs all AccessControl roles atomically.

### Registry coordination

- `CiphernodeRegistryOwnable.requestBlock` now stores `block.timestamp` (the storage slot and event
  field names are preserved for backwards compatibility). All callers — including
  `BondingRegistry.getTicketBalanceAtBlock(node, c.requestBlock - 1)` — pass the value through
  unchanged; the parameter is now a timepoint per EIP-6372 rather than a block number, which is
  required for the ITK timestamp clock to be valid.
