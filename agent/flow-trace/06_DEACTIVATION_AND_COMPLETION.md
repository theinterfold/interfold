# Part 6: Deactivation, Deregistration & Completion

## Overview

An operator can voluntarily leave the network by deactivating (withdrawing collateral) and
deregistering (removing from the Merkle tree). The exit is time-locked, and pending exits remain
slashable until claimed.

---

## Voluntary Deactivation

### Via Ticket Withdrawal

```
User runs: interfold ciphernode deactivate --tickets 50
│
├─ ChainContext::new() → loads config, decrypts wallet
│
└─ BondingRegistryContract.removeTicketBalance(50).send().await
    │
    │  ┌─── ON-CHAIN (BondingRegistry.sol) ─────────────────────┐
    │  │                                                         │
    │  │  removeTicketBalance(50):                               │
    │  │    1. require(amount != 0, registered, sufficient ITK)  │
    │  │    2. ticketToken.burnTickets(operator, amount)         │
    │  │       → ITK destroyed, underlying becomes claimable      │
    │  │    3. _exits.queueTicketsForExit(                       │
    │  │         operator, exitDelay, amount                      │
    │  │       )                                                  │
    │  │       → Locked in ExitQueue until now + exitDelay        │
    │  │    4. _updateOperatorStatus(operator)                   │
    │  │       → Active iff registered &&                         │
    │  │         licenseBond >= _minLicenseBond() &&              │
    │  │         (ticketBalance / ticketPrice) >= minTicketBalance│
    │  │         active = false, numActiveOperators--             │
    │  │         Emit OperatorActivationChanged(op, false)        │
    │  │    5. Emit TicketBalanceUpdated(op, -amount, newBal,     │
    │  │       "WITHDRAW")                                         │
    │  │  }                                                      │
    │  └─────────────────────────────────────────────────────────┘
```

### Via License Withdrawal

```
User runs: interfold ciphernode deactivate --license 20000
│
└─ BondingRegistryContract.unbondLicense(20000).send().await
    │
    │  ┌─── ON-CHAIN ───────────────────────────────────────────┐
    │  │                                                         │
    │  │  unbondLicense(20000):                                  │
    │  │    1. require(amount != 0, sufficient bonded INTF)      │
    │  │    2. operators[op].licenseBond -= 20000                │
    │  │    3. _exits.queueLicensesForExit(op, exitDelay, 20000)│
    │  │       → Pending INTF remains in totalBonded(op) for     │
    │  │         token-level locked-floor accounting             │
    │  │    4. _updateOperatorStatus(operator)                   │
    │  │       → If licenseBond <                                │
    │  │         (licenseRequiredBond * licenseActiveBps / 10000)│
    │  │         (default: 80% of required bond):                │
    │  │         active = false, numActiveOperators--             │
    │  │    5. Emit LicenseBondUpdated(op, -amount, newBond,      │
    │  │       "UNBOND")                                          │
    │  │  }                                                      │
    │  └─────────────────────────────────────────────────────────┘
```

### Combined Deactivation

```
User runs: interfold ciphernode deactivate --tickets 50 --license 20000
│
├─ Calls removeTicketBalance(50) first
└─ Then calls unbondLicense(20000)
  → Tickets are queued in ExitQueueLib
  → INTF is queued in ExitQueueLib pending license exits and remains counted in totalBonded()
```

---

## Full Deregistration

```
User runs: interfold ciphernode deregister
│
├─ ChainContext::new()
│
└─ BondingRegistryContract.deregisterOperator().send().await
    │
    │  ┌─── ON-CHAIN (BondingRegistry.sol) ─────────────────────┐
    │  │                                                         │
    │  │  deregisterOperator() {                                  │
    │  │    1. require(operators[msg.sender].registered)         │
    │  │    2. require(!exitInProgress(msg.sender))              │
    │  │       → Cannot deregister if an exit is already pending │
    │  │                                                         │
    │  │    3. operators[msg.sender].registered = false          │
    │  │    4. operators[msg.sender].exitRequested = true        │
    │  │    5. operators[msg.sender].exitUnlocksAt =             │
    │  │         block.timestamp + exitDelay                      │
    │  │                                                         │
    │  │    6. Burn ALL tickets:                                 │
    │  │       fullTicketBalance = ticketToken.balanceOf(op)     │
    │  │       ticketToken.burnTickets(op, fullTicketBalance)    │
    │  │                                                         │
    │  │    7. Queue ALL collateral for exit:                    │
    │  │       licenseBondAmount = operators[op].licenseBond     │
    │  │       operators[op].licenseBond = 0                     │
    │  │       _exits.queueAssetsForExit(                        │
    │  │         op, exitDelay,                                   │
    │  │         fullTicketBalance,  // tickets                   │
    │  │         0                   // license handled below     │
    │  │       )                                                  │
    │  │       _queueLicenseExitFromSources(op, licenseBondAmount)│
    │  │                                                         │
    │  │    8. Remove from Merkle tree:                          │
    │  │       registry.removeCiphernode(msg.sender)             │
    │  │       │                                                  │
    │  │       │  ┌─ CiphernodeRegistryOwnable ──────────────┐  │
    │  │       │  │  removeCiphernode(node):                  │  │
    │  │       │  │    index = ciphernodeTreeIndex[node]      │  │
    │  │       │  │    ciphernodes._update(0, index)          │  │
    │  │       │  │    → Leaf zeroed in Lazy IMT              │  │
    │  │       │  │    numCiphernodes--                       │  │
    │  │       │  │    Emit CiphernodeRemoved(node)           │  │
    │  │       │  └──────────────────────────────────────────┘  │
    │  │                                                         │
    │  │    9. _updateOperatorStatus(msg.sender)                 │
    │  │       → active = false (registered is now false)        │
    │  │       → numActiveOperators--                            │
    │  │       → Emit OperatorActivationChanged(op, false)       │
    │  │                                                         │
    │  │   10. Emit CiphernodeDeregistrationRequested(op)        │
    │  │  }                                                      │
    │  └─────────────────────────────────────────────────────────┘
│
└─ After exitDelay seconds, operator can claim unlocked exits:
    interfold ciphernode license claim
    # optional caps:
    interfold ciphernode license claim --max-ticket X --max-license Y
```

## E3 Completion (Happy Path)

When an E3 completes successfully:

```
publishPlaintextOutput() succeeds
│
├─ ON-CHAIN:
│   ├─ stage = Complete
│   ├─ _distributeRewards(e3Id)
│   │   ├─ (activeNodes, _) = ciphernodeRegistry.getActiveCommitteeNodes(e3Id)
│   │   ├─ perNode = payment / activeNodes.length
│   │   ├─ dust → last member
│   │   ├─ if activeNodes.length == 0: refund payment to requester
│   │   ├─ if payment == 0: only slashed-funds distribution runs
│   │   ├─ bondingRegistry.distributeRewards(token, nodes, amounts)
│   │   │   → Transfers fee tokens to each registered operator
│   │   ├─ e3RefundManager.distributeSlashedFundsOnSuccess(
│   │   │     e3Id, activeNodes, paymentToken
│   │   │   )
│   │   │   → If any escrowed slashed funds exist for this E3:
│   │   │     split by successSlashedNodeBps (default 50%)
│   │   │     nodes portion distributed evenly to activeNodes
│   │   │     remainder sent to protocol treasury
│   │   │   → If no escrowed funds: no-op
│   │   └─ Emit RewardsDistributed(e3Id)
│   └─ Emit PlaintextOutputPublished(e3Id, plaintext, proof), E3StageChanged(Complete)
│
└─ RUST-SIDE (cleanup via E3RequestComplete):
    │
    ├─ E3Router detects PlaintextAggregated (or E3StageChanged(Complete)):
    │   └─ Publishes E3RequestComplete { e3_id }
    │       → Single cleanup signal for all per-E3 actors
    │
    ├─ Sortition: decrements activeJobs for each committee member
    │   → Node becomes available for future E3s
    │   → Removes e3_id from node_state.e3_committees map
    │
    ├─ CiphernodeSelector: removes e3_id from e3_cache, committee, expelled set,
    │  and persisted aggregator designation for the E3
    │
    ├─ Per-E3 actors receive Die / shutdown on completion:
    │   ├─ ThresholdKeyshare: state = Completed, actor stops
    │   ├─ PublicKeyAggregator: actor stops
    │   ├─ ThresholdPlaintextAggregator: actor stops
    │   ├─ KeyshareCreatedFilterBuffer: no new E3 events after context teardown
    │   └─ DecryptionshareCreatedBuffer: no new E3 events after context teardown
    │
    └─ E3Router: removes E3Context for this e3_id
        → All per-E3 state fully cleaned up
```

---

## Rust-Side: Node Shutdown

```
interfold start → running node
│
├─ Ctrl+C / SIGINT / SIGTERM
│
└─ listen_for_shutdown():
    ├─ Signals EventBus to stop
    ├─ Awaits join_handle (main actor system)
    ├─ Persists final state to Sled DB
    └─ Clean exit

On restart:
├─ Sync module replays:
│   1. Load snapshot metadata and hydrate persisted per-E3 state
│      → Extensions must preserve hydrated recipients; replayed committee events
│        must not replace a restored per-E3 actor with a fresh instance
│   2. CiphernodeSelector emits persisted AggregatorChanged state before replay
│   3. Replay EventStore events since last snapshot (effects still disabled)
│   4. Fetch historical EVM events from last known block
│   5. Historical libp2p sync retries failed aggregate fetches after reconnects
│      and also on bounded retry intervals even without a new connection event
│   6. Sort & publish merged events by HLC timestamp
│   7. Enable effects (writers may submit only after this point)
│   8. SyncEnded → live operations begin
└─ Node resumes from where it left off
```

---

## Rust-Side: E3 Lifecycle Coordinator (durable stage tracking)

The node is choreographed — each subsystem reacts to bus events independently — so there is no
single component that _drives_ the protocol. The `E3LifecycleCoordinator` (in `e3-request`) is an
**additive, durable observer** that gives the node a single source of truth for "what stage is each
E3 at?". It never emits protocol events and never drives subsystems; it only records stage and
supports restart-resume and shutdown awareness.

```
E3LifecycleCoordinator::attach(bus, store)   (wired in ciphernode_builder.build())
│
├─ Loads persisted stage map from Repository(StoreKeys::e3_lifecycle())
│   → on restart, every in-flight E3's last known stage is rehydrated
│
├─ Subscribes to lifecycle-bearing events:
│     E3Requested              → Requested
│     CommitteePublished       → CommitteeFinalized
│     CommitteeFinalized       → CommitteeFinalized
│     PublicKeyAggregated      → KeyPublished
│     CiphertextOutputPublished→ CiphertextReady
│     PlaintextAggregated      → Complete
│     PlaintextOutputPublished → Complete
│     E3RequestComplete        → Complete
│     E3Failed                 → Failed (terminal)
│     E3StageChanged           → new_stage (authoritative)
│
├─ Pure E3LifecycleService.observe(event) → LifecycleDecision:
│     • Advance is MONOTONIC (forward-only by stage rank)
│     • Out-of-order earlier-stage events are logged (Regressed) and ignored
│     • Once Complete/Failed, the stage is frozen (Terminal)
│   On Advanced/Terminal the snapshot is persisted (set on Persistable)
│
└─ On Shutdown event:
      logs the set of still-active (non-terminal) E3s and their stages,
      persists the final snapshot, then stops.
```

The coordinator is safe by construction during EventStore replay: observing a replayed lifecycle
event simply re-derives the same monotonic stage, so the restored map is identical whether built
live or from replay.

---

## Exit Queue Timing

```
Time ──────────────────────────────────────────────────────►

│ deregister()     │                    │ claimExits()     │
│ or deactivate()  │   EXIT DELAY       │                  │
│                  │  (configured)       │                  │
│ Assets queued    │                    │ Assets claimable │
│ ITK burned       │  Cannot cancel     │ USDC returned    │
│ INTF locked      │  Can be slashed!   │ INTF returned to │
│                  │                    │ withdrawal addr  │
│                  │                    │                  │

IMPORTANT: Even during the exit delay, slashing can still
reach into the exit queue and take locked assets. There is
no safe harbor for misbehaving operators.
```

### Exit Queue Internals (audit hardening)

- **Per-asset head indices.** `ExitQueueState` tracks `queueHeadIndexTicket` and
  `queueHeadIndexLicense` separately so claiming/slashing one asset class cannot strand the other.
  Previously a single shared head meant `claimAssets({TICKET})` could advance past tranches whose
  license leg was still locked and silently forfeit them (audit C-03).
- **`continue`, not `break`, on locked tranches.** Both `previewClaimableAmounts` and
  `_takeAssetsFromQueue` skip locked tranches instead of stopping, so a later-but-sooner-unlocking
  tranche (created after governance lowered `exitDelay`) is still reachable (audit M-08).
- **Tranche cap.** `queueAssetsForExit` reverts with `TooManyTranches` if more than
  `MAX_ACTIVE_TRANCHES (= 64)` live (post-head) tranches would exist for the operator. This bounds
  the unbounded loop in `previewClaimableAmounts` / `_takeAssetsFromQueue` so an attacker cannot
  grief the operator with an ever-growing queue (audit H-21a).
- **License transfer shortfall.** `claimExits` and `withdrawSlashedFunds` measure the recipient's
  balance delta around `licenseToken.safeTransfer` and emit
  `LicenseTransferShortfall(recipient, expectedAmount, actualAmount)` if the recipient received less
  than expected (e.g. a fee-on-transfer license token). The transfer itself is not reverted —
  booking is already updated — but indexers can detect the discrepancy (audit M-13).

---

## Ban & Unban

```
SLASHING → operator banned:
  banned[operator] = true
    → Cannot call registerOperator() (reverts with CiphernodeBanned)
  → Permanent until governance intervenes

GOVERNANCE lifts ban:
    SlashingManager.updateBanStatus(operator, false, keccak256("reason"))
  → banned[operator] = false
  → Operator can re-register
```

---

## Cluster 6 Audit Addendum (deregistration & bans)

- **Deregistration is blocked while a Lane B slash is open** (H-05).
  `BondingRegistry.deregisterOperator()` calls
  `ISlashingManager(sm).hasOpenLaneBProposal(msg.sender)` and reverts `OperatorUnderSlash()` until
  `executeSlash` or `resolveAppeal(upheld)` unwinds the open-proposal counter. Lane A is permitted
  to proceed through the normal exit queue because Lane A is either atomic or closes within the H-06
  challenge window.

- **Two-step ban** (M-14, M-15): bans now require `proposeBan` → `confirmBan` from a **distinct**
  signer holding `GOVERNANCE_ROLE`. `cancelBan` rescinds an unconfirmed proposal. Legacy direct-set
  via `updateBanStatus(_, true, _)` reverts `BanRequiresConfirmation()`. Unban is single-step
  (`unbanNode`).

- **DEFAULT_ADMIN handover** (M-17): operator-onboarding ops that depend on `DEFAULT_ADMIN_ROLE`
  rotation must use the `AccessControlDefaultAdminRules` two-step flow (`beginDefaultAdminTransfer`
  → wait `defaultAdminDelay() = 2 days` → `acceptDefaultAdminTransfer`).
