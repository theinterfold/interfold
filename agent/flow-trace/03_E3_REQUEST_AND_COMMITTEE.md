# Part 3: E3 Request & Committee Formation

## Overview

An E3 (Encrypted Execution Environment) is the core unit of work in the Interfold protocol. A
requester pays a fee, a committee of ciphernodes is selected via sortition, and the committee
collectively generates encryption keys through DKG.

---

## E3 Lifecycle Stages

```
None → Requested → CommitteeFinalized → KeyPublished → CiphertextReady → Complete
                                                                       ↘ Failed
```

Each transition has a deadline. Missing a deadline allows anyone to call `markE3Failed()`.

---

## Step 1: E3 Request (On-Chain)

**Contract:** `Interfold.sol` → `request(E3RequestParams)`

```
Requester calls: Interfold.request({
  threshold: [M, N],        // M-of-N threshold
  inputWindow: [start, end], // when inputs are accepted
  e3Program: <address>,      // computation program contract
  e3ProgramParams: <bytes>,  // ABI-encoded program parameters
  computeProviderParams: <bytes>,
  customParams: <bytes>
})
│
├─ VALIDATION:
│   ├─ threshold[0] > 0 (M > 0)
│   ├─ threshold[1] >= threshold[0] (N >= M)
│   ├─ inputWindow[0] >= block.timestamp (start in future)
│   ├─ inputWindow[1] >= inputWindow[0] (end after start)
│   ├─ total duration < maxDuration
│   └─ e3Programs[e3Program] == true (program whitelisted)
│
├─ FEE CALCULATION:
│   ├─ fee = getE3Quote() → hardcoded 1 USDC (1e6)
│   ├─ feeToken.transferFrom(requester, address(this), fee)
│   └─ e3Payments[e3Id] = fee  (stored per-E3)
│       _e3FeeTokens[e3Id] = feeToken  (survives global token rotation)
│
├─ E3 CREATION:
│   ├─ e3Id = nexte3Id++
│   ├─ seed = uint256(keccak256(block.prevrandao, e3Id))
│   │   → On chains without `prevrandao`, the value is still deterministic
│   │     per-block; downstream sortition relies on the per-E3 snapshot of
│   │     ticket balances at `requestBlock - 1` for manipulation resistance.
│   │
│   ├─ encryptionSchemeId = e3Program.validate(
│   │     e3Id, seed, e3ProgramParams, computeProviderParams, customParams
│   │   )
│   │   → Program validates params and returns which encryption scheme to use
│   │
│   ├─ decryptionVerifier = decryptionVerifiers[encryptionSchemeId]
│   │   → Must exist (registered by admin for this scheme)
│   │
│   ├─ Store E3 struct:
│   │   e3s[e3Id] = E3 {
│   │     seed, threshold, requestBlock: block.timestamp,  // H-26: EIP-6372 clock
│   │     inputWindow, encryptionSchemeId, e3Program,
│   │     e3ProgramParams, customParams, decryptionVerifier,
│   │     requester: msg.sender
│   │   }
│   │
│   ├─ _e3Requesters[e3Id] = msg.sender
│   └─ _e3Stages[e3Id] = E3Stage.Requested
│
├─ COMMITTEE REQUEST:
│   ├─ ciphernodeRegistry.requestCommittee(e3Id, seed, threshold)
│   │   │
│   │   │  ┌─── CiphernodeRegistryOwnable ──────────────────────┐
│   │   │  │                                                     │
│   │   │  │  requestCommittee(e3Id, seed, threshold) {          │
│   │   │  │    1. require(!committees[e3Id].initialized)        │
│   │   │  │    2. require(threshold[1] <=                       │
│   │   │  │         bondingRegistry.numActiveOperators())       │
│   │   │  │       → Enough active nodes must exist              │
│   │   │  │    3. committees[e3Id] = Committee {                │
│   │   │  │         initialized: true,                          │
│   │   │  │         seed: seed,                                 │
│   │   │  │         requestBlock: block.timestamp, // H-26      │
│   │   │  │         committeeDeadline:                          │
│   │   │  │           block.timestamp + sortitionWindow,        │
│   │   │  │         threshold: threshold                        │
│   │   │  │       }                                             │
│   │   │  │    4. roots[e3Id] = ciphernodes._root()             │
│   │   │  │       → SNAPSHOT the IMT root at this moment        │
│   │   │  │       → Only nodes in tree at request time eligible │
│   │   │  │    5. Emit CommitteeRequested(e3Id, seed, threshold,│
│   │   │  │              requestBlock, committeeDeadline)       │
│   │   │  │  }                                                  │
│   │   │  └─────────────────────────────────────────────────────┘
│   │
│   └─ Set deadlines:
│       _e3Deadlines[e3Id].computeDeadline =
│         inputWindow[1] + _timeoutConfig.computeWindow
│
├─ EMIT: E3Requested(e3Id, e3, e3Program)  // seed & params inside E3 struct
├─ EMIT: E3StageChanged(e3Id, E3Stage.None, E3Stage.Requested)
│
└─ RETURN: (e3Id, e3)
```

---

## Step 2: Sortition — Committee Selection (Rust-Side)

When the running ciphernodes detect `E3Requested` and `CommitteeRequested` events from the chain:

### 2a. E3Requested Event Processing

```
InterfoldSolReader decodes IInterfold::E3Requested log
│
├─ Publishes InterfoldEvent::E3Requested {
│     e3_id, threshold_m, threshold_n,
│     seed, params, error_size, esi_per_ct
│   }
│
├─ FheExtension.on_event():
│   └─ Creates Fhe instance from BFV params
│   └─ Stores as dependency in E3Context
│
├─ PublicKeyAggregatorExtension.on_event():
│   └─ Spins up the per-E3 public-key aggregation pipeline
│   └─ KeyshareCreatedFilterBuffer buffers until this node becomes the active aggregator
│
└─ Sortition actor receives E3Requested:
    │
    ├─ Calculates buffer = calculate_buffer_size(M, N)
    │
    ├─ ScoreBackend.get_committee():
    │   │
    │   ├─ Loads eligible nodes from NodeStateStore
    │   │   (filter: active=true, available tickets > 0)
    │   │
    │   ├─ For EACH eligible node:
    │   │   For EACH ticket t in [1..availableTickets]:
    │   │     score = keccak256(address || t || e3Id || seed)
    │   │     → Deterministic score per (node, ticket, e3)
    │   │
    │   ├─ Per node: keep only the LOWEST scoring ticket
    │   │   (each node's best chance)
    │   │
    │   ├─ Sort ALL nodes by their best score (ascending)
    │   │
    │   └─ Select top N nodes (lowest scores win)
    │       → Returns committee list with party indices
    │
    └─ Sends WithSortitionTicket<E3Requested> to CiphernodeSelector
        │
        ├─ If THIS node is in the selected committee:
        │   ticket_id = Some(TicketId::Score(best_ticket_number))
        │   party_index = Some(index_in_committee)
        │
        └─ If NOT selected: ticket_id = None
```

### 2b. CiphernodeSelector Processing

```
CiphernodeSelector receives WithSortitionTicket<E3Requested>
│
├─ If ticket_id is Some (this node was selected):
│   ├─ Caches E3Meta { e3_id, threshold_m, threshold_n, seed, ... }
│   ├─ Publishes TicketGenerated {
│   │     e3_id,
│   │     ticket_id: TicketId::Score(ticket_number),
│   │     party_index: index_in_local_score_ranking
│   │   }
│   └─ This event triggers on-chain ticket submission
│
└─ If ticket_id is None:
    └─ Does nothing (not selected for this E3)
```

### 2c. On-Chain Ticket Submission

```
CiphernodeRegistrySolWriter receives TicketGenerated event
│
└─ Calls contract.submitTicket(e3Id, ticketNumber).send()
    │
    │  ┌─── ON-CHAIN (CiphernodeRegistryOwnable) ──────────────┐
    │  │                                                         │
    │  │  submitTicket(e3Id, ticketNumber) {                     │
    │  │    1. require(committees[e3Id].initialized)             │
    │  │    2. require(!committees[e3Id].finalized)              │
    │  │    3. require(block.timestamp <= committeeDeadline)     │
    │  │    4. require(!submitted[msg.sender])                   │
    │  │       → Each node submits only once                     │
    │  │    5. require(isCiphernodeEligible(msg.sender))         │
    │  │       → Must be in IMT AND bondingRegistry.isActive()   │
    │  │                                                         │
    │  │    6. _validateNodeEligibility(e3Id, msg.sender,        │
    │  │                                ticketNumber):           │
    │  │       availableTickets =                                │
    │  │         bondingRegistry.getTicketBalanceAtBlock(         │
    │  │           msg.sender, requestBlock - 1                  │
    │  │         ) / bondingRegistry.ticketPrice()               │
    │  │       → Calls ticketToken.getPastVotes() internally     │
    │  │       → Uses SNAPSHOT from block before request         │
    │  │       → Prevents same-block manipulation                │
    │  │       require(ticketNumber >= 1)                        │
    │  │       require(ticketNumber <= availableTickets)          │
    │  │                                                         │
    │  │    7. score = uint256(keccak256(                        │
    │  │         msg.sender, ticketNumber, e3Id, seed            │
    │  │       ))                                                │
    │  │       → SAME formula as Rust-side computation           │
    │  │       → Both sides agree on scores                      │
    │  │                                                         │
    │  │    8. submitted[msg.sender] = true                      │
    │  │       scoreOf[msg.sender] = score                       │
    │  │                                                         │
    │  │    9. _insertTopN(e3Id, msg.sender, score):             │
    │  │       Maintains array of N lowest-scoring nodes:        │
    │  │       - If < N nodes: just insert                       │
    │  │       - If N nodes: replace highest if new score lower  │
    │  │       - O(N) linear scan per insertion                  │
    │  │                                                         │
    │  │   10. Emit TicketSubmitted(e3Id, msg.sender, score)     │
    │  │  }                                                      │
    │  └─────────────────────────────────────────────────────────┘
```

---

## Step 3: Committee Finalization

### 3a. Deadline Timer (Rust-Side, Committee Members)

```
CommitteeFinalizer actor receives CommitteeRequested event
│
├─ Stores the request during replay and waits until ALL of:
│   ├─ local TicketGenerated.party_index is known
│   └─ EffectsEnabled has fired
│
├─ Calculates wait time:
│   wait = max(committeeDeadline - currentTimestamp, 0)
│          + 1 second
│          + party_index * 5 seconds
│
├─ Schedules a staggered timer
│
├─ When timer fires:
│   └─ Publishes CommitteeFinalizeRequested { e3_id }
│
└─ On E3Failed / E3RequestComplete / E3StageChanged(Complete|Failed):
    └─ Cancels pending timer for this e3_id (if any)
        → Prevents stale finalization attempt after E3 is already terminal
```

### 3b. On-Chain Finalization

```
CiphernodeRegistrySolWriter receives CommitteeFinalizeRequested
│
└─ Calls contract.finalizeCommittee(e3Id).send()
    │
    │  ┌─── ON-CHAIN (CiphernodeRegistryOwnable) ──────────────┐
    │  │                                                         │
    │  │  finalizeCommittee(e3Id) {                              │
    │  │    1. require(initialized && !finalized)                │
    │  │    2. require(block.timestamp >= committeeDeadline)     │
    │  │       → Submission window must have closed (>= not >)  │
    │  │                                                         │
    │  │    3. if topNodes.length < threshold[1]:                │
    │  │       → NOT ENOUGH NODES submitted tickets              │
    │  │       committees[e3Id].failed = true                    │
    │  │       interfold.onE3Failed(e3Id,                          │
    │  │         FailureReason.InsufficientCommitteeMembers)     │
    │  │       Emit CommitteeFormationFailed(e3Id)               │
    │  │       RETURN                                            │
    │  │                                                         │
    │  │    4. SUCCESS PATH:                                     │
    │  │       Copy topNodes → committee (ordered by index)      │
    │  │       For each node in committee:                       │
    │  │         active[node] = true                             │
    │  │       activeCount = committee.length                    │
    │  │       finalized = true                                  │
    │  │                                                         │
    │  │    5. interfold.onCommitteeFinalized(e3Id)                │
    │  │       │                                                 │
    │  │       │  ┌─ Interfold.sol ────────────────────────────┐  │
    │  │       │  │  onCommitteeFinalized(e3Id) {            │  │
    │  │       │  │    require(stage == Requested)            │  │
    │  │       │  │    stage = CommitteeFinalized             │  │
    │  │       │  │    dkgDeadline = now + dkgWindow          │  │
    │  │       │  │    Emit E3StageChanged(e3Id,              │  │
    │  │       │  │          CommitteeFinalized)              │  │
    │  │       │  │  }                                       │  │
    │  │       │  └──────────────────────────────────────────┘  │
    │  │                                                         │
    │  │    6. Emit SortitionCommitteeFinalized(e3Id, committee, scores)│
    │  │       [ICiphernodeRegistry event]                       │
    │  │  }                                                      │
    │  └─────────────────────────────────────────────────────────┘
```

### 3c. SortitionCommitteeFinalized Event Processing (Rust-Side)

```text
CiphernodeRegistrySolReader decodes SortitionCommitteeFinalized event
│  [ICiphernodeRegistry.SortitionCommitteeFinalized — NOT IInterfold.CommitteeFinalized]
│
├─ Publishes InterfoldEvent::CommitteeFinalized {
│     e3_id, committee: [addr1, addr2, ..., addrN], scores: [s1, s2, ..., sN], chain_id
│   }
│
├─ Sortition actor:
│   └─ Stores finalized committee as a `Committee` struct in persistent map
│       → Provides O(1) address→party_id lookup for later expulsion handling
│       → `CommitteeFinalized` is normalized into ascending ticket-score order before storage
│
├─ CiphernodeSelector:
│   ├─ Checks if this node's address is in the committee list
│   ├─ If YES:
│   │   party_id = index of this node in committee array
│   │   Publishes CiphernodeSelected {
│   │     e3_id, threshold_m, threshold_n,
│   │     seed, party_id, ...all E3 metadata
│   │   }
│   │   Publishes AggregatorChanged {
│   │     e3_id,
│   │     is_aggregator = (my node has the lowest non-expelled party_id in the
│   │                      score-sorted finalized committee)
│   │   }
│   └─ If NO: does nothing for this E3
│
└─ KeyshareCreatedFilterBuffer:
    └─ Stores committee set
    └─ Keeps buffering until AggregatorChanged(is_aggregator=true)
    └─ Then flushes buffered KeyshareCreated events from verified committee members
```

---

## Timeline & Deadlines

```
Time ──────────────────────────────────────────────────────────►

│ request()      │ sortitionWindow │ dkgWindow     │
│                │                 │               │
│ E3Requested    │ CommitteeDeadline│ DKG Deadline  │
│ CommitteeReq.  │                 │               │
│                │ Ciphernodes     │ Must complete  │
│                │ submit tickets  │ DKG by here    │
│                │                 │               │
│                │ finalizeComm.() │               │
│                │ CommFinalized   │               │
│                │ ───►DKG starts  │               │

If any deadline is missed → anyone can call markE3Failed()
```

---

## Key Design Properties

1. **Deterministic sortition**: Both Rust and Solidity compute
   `keccak256(address, ticket, e3Id, seed)`. The on-chain contract verifies what the off-chain node
   computed.

2. **Snapshot-based eligibility**: Ticket balances are checked at `requestBlock - 1`, preventing
   front-running manipulation.

3. **Runtime committee order**: the Rust runtime normalizes `CommitteeFinalized` into ascending
   ticket-score order before `Sortition` and `CiphernodeSelector` derive `party_id`. That makes
   `party_id` in the runtime equivalent to score order, even though the raw on-chain `topNodes`
   array is not itself score-sorted.

4. **Active aggregator selection**: `CiphernodeSelector` derives `AggregatorChanged` from the
   finalized committee plus enriched `CommitteeMemberExpelled` events. The active aggregator is the
   lowest non-expelled `party_id` in the score-sorted runtime committee.

5. **Permissionless finalization**: Anyone can call `finalizeCommittee()` after the deadline — no
   single point of failure.

6. **IMT root snapshot**: The Merkle tree root is captured at request time. Nodes that join/leave
   after the request don't affect this E3's committee.

---

## Cluster 7 audit additions (post-fix semantics)

### H-04 — snapshot-based eligibility

`CiphernodeRegistryOwnable._validateNodeEligibility` derives the per-node ticket weight from
`bondingRegistry.getTicketBalanceAtBlock(node, committee.requestBlock - 1)`, which reads the
`InterfoldTicketToken` ERC20Votes checkpoint history (EIP-6372 timestamp clock). Same-block or
post-request rebalancing therefore cannot inflate a node's selection weight; the outer
`isCiphernodeEligible(msg.sender)` still gates on the current `isActive` flag for liveness.

### M-33 — `markE3Failed` grace period

When `markFailedGracePeriod > 0` (set via `Interfold.setMarkFailedGracePeriod`), calling
`markE3Failed` within `deadline … deadline + markFailedGracePeriod` is restricted to
`{ original requester, contract owner, any committee member }`. After that window any caller may
finalize the failure. Default `markFailedGracePeriod = 0` preserves the legacy permissionless flow.

### H-26 — timestamp-clock `requestBlock`

`Committee.requestBlock` stores `block.timestamp` (EIP-6372 timestamp mode) so that `getPastVotes` /
`getTicketBalanceAtBlock` lookups against the `InterfoldTicketToken` resolve consistently across L1
and L2 clocks. The field name is preserved for storage / event ABI compatibility.
