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

`BondingRegistry.exitDelay` exceeds the current randomness timeout plus the submission window and
every unexpired frozen committee deadline. Therefore, queued ticket collateral cannot become
claimable while an older request can still accept snapshot-weighted ticket submissions.

A ticket that enters the current top-N opens a collateral obligation immediately. A better ticket
releases the displaced candidate. Finalization retains the winners' obligations until the E3 ends.

Governance configures the fee token, its expected decimals, and every raw-unit pricing term through
`setFeeAssetConfig()`. The update is atomic, and the event contains the complete configuration. The
owner can update only the nonzero flat randomness fee through `setRandomnessFlatFee()`. This narrow
setter preserves the fee token, decimals, treasury, margin, protocol share, and service prices, and
it still emits the complete configuration. The VRF upgrade uses this setter so a governance batch
cannot replace live fee settings with stale deployment-file values. The decimals check confirms the
unit scale only; it does not prove that two tokens have the same economic value. Each request
snapshots the active token, so later fee-asset changes do not alter an existing E3's escrow or
settlement unit. Fee assets must transfer exact amounts and must not rebase account balances.
Interfold checks the custody increase for escrow deposits. Each outbound transfer checks the
recipient increase and the Interfold custody decrease.

Each quote has two parts. The service fee funds ciphernodes and the service protocol share. The flat
randomness fee reimburses the protocol-funded randomness subscription. Interfold credits the flat
fee to the request-time treasury when the request succeeds. It stores only the service fee in
`e3Payments`, so success and failure settlement cannot pay or refund the randomness fee.

Interfold starts with requests paused. Deployment wires and validates one complete dependency
generation before it enables requests. Governance must pause requests and drain the current
generation before it replaces a registry, bonding registry, slashing manager, or refund manager.

An E3 Program can deploy before its Interfold controller. Interfold must register the deployed
program before the program owner binds that controller one time. This order removes the constructor
dependency between Interfold and applications such as CRISP.

---

## Step 1: E3 Request (On-Chain)

**Contract:** `Interfold.sol` → `request(E3RequestParams)`

```
Requester calls: Interfold.request({
  committeeSize: <minimum | micro | small>,
  inputWindow: [start, end], // when inputs are accepted
  e3Program: <address>,      // computation program contract
  paramSet: <uint8>,         // requested BFV parameter set
  computeProviderParams: <bytes>,
  customParams: <bytes>,
  expectedFeeToken: <address>,
  expectedCryptoConfigId: <bytes32>,
  maxFee: <uint256>
})
│
├─ VALIDATION:
│   ├─ requestsPaused == false
│   ├─ Registry, bonding, slashing, refund, and ticket-token pointers form one
│   │  reciprocal dependency graph with matching operator membership
│   ├─ Validate the requested crypto configuration against the chain matrix.
│   │    The caller selects (paramSet, committeeSize); the target chain must support that pair.
│   │    Mainnet supports secure-8192 with minimum, micro, and small committees.
│   │    Sepolia and local chains support insecure-512 and secure-8192 with all committee sizes.
│   │    A different parameter hash, committee shape, or verifier H/T is rejected.
│   │    CI derives and compares the full BFV tuple across deployment code, Rust, and Noir.
│   ├─ inputWindow[0] >= block.timestamp (start in future)
│   ├─ inputWindow[1] >= inputWindow[0] (end after start)
│   ├─ Snapshot the complete timeout configuration
│   ├─ Reserve the later of:
│   │    inputWindow[1], or
│   │    request time + randomnessTimeout + sortitionWindow + dkgWindow
│   ├─ Add computeWindow and decryptionWindow to that reservation
│   ├─ total worst-case lifecycle duration <= maxDuration
│   └─ e3Programs[e3Program] == true (program whitelisted)
│
├─ FEE CALCULATION:
│   ├─ totalFee = getE3Quote()
│   │   → InterfoldPricing validates the requested chain-supported circuit [T, H, N].
│   │   → The quote uses N for committee-wide work and H for required decryption shares.
│   │   → It also uses the time windows,
│   │     proof counts, availability, decryption/publication costs, and margin
│   │   → availability covers at least request time through input-window end
│   │   → a later equal-length input window therefore costs more
│   │   → serviceFee = modeled work cost * (1 + marginBps / 10_000)
│   │   → totalFee = serviceFee + randomnessFlatFee
│   │   → margin does not apply to randomnessFlatFee
│   ├─ Require the current fee token to equal expectedFeeToken
│   ├─ Derive cryptoConfigId from the requested scheme, parameter hash, and circuit version
│   ├─ Require cryptoConfigId == expectedCryptoConfigId
│   ├─ Require totalFee <= maxFee
│   ├─ feeToken.transferFrom(requester, address(this), totalFee)
│   │   → require Interfold receives exactly totalFee
│   ├─ e3Payments[e3Id] = serviceFee  (refundable service escrow)
│   ├─ _pendingTreasury[requestTreasury][feeToken] += randomnessFlatFee
│   │   → emit TreasuryCredited
│   └─ _e3FeeTokens[e3Id] = feeToken  (survives global token rotation)
│
├─ E3 CREATION:
│   ├─ e3Id = nexte3Id++
│   │   → nexte3Id starts at uint160(address(this)) << 96
│   │   → every controller has a separate uint256 namespace
│   ├─ Snapshot Interfold dependencies for this E3:
│   │   registry, bonding registry, refund manager, and slashing manager
│   │   → replacements are blocked until this E3 and its generation drain
│   │   → the slashing manager registers this E3's refund destination in
│   │     BondingRegistry for proposal-scoped ticket-slash routes
│   ├─ snapshottedRefundManager.snapshotE3Policy(e3Id, registry)
│   │   → freezes refund/slash allocation, treasury, policy version,
│   │     request-time Interfold, committee registry, bonding registry,
│   │     and slashing manager
│   ├─ seed = uint256(keccak256(block.prevrandao, e3Id))
│   │   → Shared input for the E3 computation. Committee selection does not use it.
│   │
│   ├─ encryptionSchemeId = e3Program.validate(
│   │     e3Id, seed, paramSetRegistry[paramSet], computeProviderParams, customParams
│   │   )
│   │   → Program validates params and returns which encryption scheme to use
│   ├─ Store e3CryptoConfigIds[e3Id] and snapshot the parameter hash and
│   │  ciphertext verifier used by this E3
│   │
│   ├─ decryptionVerifier = decryptionVerifiers[encryptionSchemeId]
│   │   → Must exist (registered by admin for this scheme)
│   │
│   ├─ Store E3 struct:
│   │   e3s[e3Id] = E3 {
│   │     seed, threshold, requestBlock: block.timestamp,  // H-26: EIP-6372 clock
│   │     inputWindow, encryptionSchemeId, e3Program,
│   │     paramSet, customParams, decryptionVerifier, pkVerifier,
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
│   │   │  │  requestCommittee(e3Id, legacySeed, threshold) {    │
│   │   │  │    → legacySeed is ignored for ticket sortition    │
│   │   │  │    1. require(!committees[e3Id].initialized)        │
│   │   │  │    2. Snapshot request-time Interfold, bonding,     │
│   │   │  │       slashing manager, and fold verifier           │
│   │   │  │       → ask SlashingManager to snapshot its         │
│   │   │  │         bonding, registry, Interfold, refund routes │
│   │   │  │    3. Query eligibilityAt(address(0),               │
│   │   │  │         requestBlock - 1) and require               │
│   │   │  │         threshold[1] <= activeOperatorCount         │
│   │   │  │       → Count and submissions use one boundary      │
│   │   │  │    4. committees[e3Id] = Committee {                │
│   │   │  │         initialized: true,                          │
│   │   │  │         seed: unresolved,                           │
│   │   │  │         requestBlock: block.timestamp, // H-26      │
│   │   │  │         committeeDeadline:                          │
│   │   │  │           block.timestamp + randomnessTimeout,      │
│   │   │  │         threshold: threshold                        │
│   │   │  │       }                                             │
│   │   │  │       → Freeze the configured randomness provider   │
│   │   │  │       → Request one random word for this E3          │
│   │   │  │       → Freeze the response and submission windows  │
│   │   │  │       → Raise the deadline watermark by both windows│
│   │   │  │    5. sortitionTicketPrices[e3Id] =                 │
│   │   │  │         bondingRegistry.ticketPrice()               │
│   │   │  │       → Freeze ticket capacity for this E3          │
│   │   │  │    6. roots[e3Id] = ciphernodes._root()             │
│   │   │  │       → SNAPSHOT the IMT root at this moment        │
│   │   │  │       → Only nodes in tree at request time eligible │
│   │   │  │    7. Emit DkgFoldAttestationContextEstablished(    │
│   │   │  │              e3Id, registry, foldVerifier)          │
│   │   │  │       Emit CommitteeRandomnessRequested(            │
│   │   │  │              e3Id, requestId, provider,             │
│   │   │  │              randomnessDeadline)                    │
│   │   │  │       BondingRegistry records this request-time      │
│   │   │  │       registry as the E3's obligation owner          │
│   │   │  │  }                                                  │
│   │   │  └─────────────────────────────────────────────────────┘
│   │
│   └─ Store the request-time lifecycle limit used by accusation reporting
│
├─ EMIT: E3Requested(e3Id, e3, cryptoConfigId)
├─ EMIT: E3StageChanged(e3Id, E3Stage.None, E3Stage.Requested)
│
└─ RETURN: (e3Id, e3)
```

---

## Step 2: Sortition — Committee Selection (Rust-Side)

When the running ciphernodes detect `DkgFoldAttestationContextEstablished`, `E3Requested`, and the
configured provider's `RandomnessFulfilled` event from the chain:

At startup, each ciphernode loads the saved request-time registry and verifier for every active E3.
It gives this data to the proof actors and registry writers before event replay starts. Events after
the latest snapshot then replay in order and add any newer E3 contexts.

Each ciphernode reads the Registry's provider-set history and current randomness provider. It
watches every returned provider address so that a restart can replay requests that used an older
provider. Governance can rotate the provider only while requests are paused and every committee is
released. Running nodes must restart before requests resume so that they also watch the newly
configured provider. The standard resume script refuses to create an unpause transaction without an
explicit confirmation that the coordinated restart is complete.

### 2a. Request Event Processing

```text
CiphernodeRegistrySolReader decodes DkgFoldAttestationContextEstablished
│
└─ Stores the E3's request-time registry and verifier for signing, validation, and publication
│
├─ Records CommitteeRandomnessRequested as processed; sortition does not start yet
│
RandomnessProviderSolReader decodes RandomnessFulfilled
│
├─ Calls Registry.sortitionSeed(e3Id) at the fulfillment log's block
│  → A successful `ready = false` result proves that the response is unusable
│  → If historical state is unavailable, current state is accepted only when `ready = true`
│  → Registry verification is bounded to 15 seconds
│  → An RPC failure, timeout, or unverifiable result rejects the log so restart replay can retry it
│  → The reader does not poll or silently discard uncertain fulfillment state
│  → Sortition starts only after the Registry accepts the response
│  → Registry accepts only the request-time provider and request ID
│  → A response after randomnessDeadline is not usable
│  → seed = keccak256(randomWord, chainId, registry, e3Id, requestId)
├─ Reads the frozen threshold, request timepoint, ticket price, and submission deadline
└─ Publishes the existing durable CommitteeRequested event for the sortition actors

InterfoldSolReader decodes IInterfold::E3Requested log
│
├─ Preserves the complete uint256 E3 ID as a decimal string through persistence,
│  program-runner requests, compute-proof journals, and webhook responses
│
├─ Rebuilds the crypto configuration ID from the local scheme, BFV parameters,
│  and circuit version; skips participation if it does not match the event
│
├─ If the ABI log is well-formed but its committee-size or BFV-preset enum is newer than this
│  binary supports, records the provider log as internally processed and skips participation;
│  historical ordering advances, while malformed ABI data still fails chain ingestion closed
│
├─ Publishes InterfoldEvent::E3Requested {
│     e3_id, threshold_m, threshold_n,
│     computation_seed, params, error_size, esi_per_ct
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
    ├─ Waits for CommitteeRequested if the delayed committee seed is not ready
    ├─ Loads the request timepoint and frozen ticket price from CommitteeRequested
    ├─ Uses the CommitteeRequested seed for ticket ranking
    ├─ Calculates buffer = calculate_buffer_size(M, N)
    │
    ├─ ScoreBackend.get_committee():
    │   │
    │   ├─ Loads nodes from NodeStateStore at requestBlock - 1
    │   │   (filter: active at that time, historical tickets > 0)
    │   │   → Every node uses the complete request-time ticket range
    │   │   → Local and remote active-job counts do not change this range
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
        │   ├─ Check only this node's voluntary active-job limit
        │   ├─ If capacity remains:
        │   │   ticket_id = Some(TicketId::Score(best_ticket_number))
        │   │   party_index = Some(index_in_committee)
        │   └─ If capacity is exhausted: ticket_id = None
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
    │  │    5. require(isEnabled(msg.sender) AND                 │
    │  │               _bondingFor(e3Id).isActive(msg.sender) AND│
    │  │               activeAtRequest)                          │
    │  │       → Uses the request-time bonding registry          │
    │  │       → Historical eligibility is the selection rule    │
    │  │       → Current activity is an extra liveness check      │
    │  │                                                         │
    │  │    6. _validateNodeEligibility(e3Id, msg.sender,        │
    │  │                                ticketNumber):           │
    │  │       availableTickets =                                │
    │  │         _bondingFor(e3Id).ticketToken().getPastVotes(   │
    │  │           msg.sender, requestBlock - 1                  │
    │  │         ) / sortitionTicketPrices[e3Id]                 │
    │  │       → Uses the timepoint before the request            │
    │  │       → Uses the request-time ticket price               │
    │  │       → Prevents same-block manipulation                │
    │  │       require(ticketNumber >= 1)                        │
    │  │       require(ticketNumber <= availableTickets)          │
    │  │                                                         │
    │  │    7. Resolve the request-time provider response:      │
    │  │       require(fulfilledBlock > requestBlockNumber)     │
    │  │       require(fulfilledBlock <= currentChainBlock)     │
    │  │       require(fulfilledAt <= block.timestamp)          │
    │  │       require(fulfilledAt <= randomnessDeadline)       │
    │  │       seed = keccak256(                                │
    │  │         randomWord, chainId, registry, e3Id, requestId │
    │  │       )                                                │
    │  │       → Store the seed and response-time deadline on   │
    │  │         the first ticket                               │
    │  │       → Every node receives the full submission window │
    │  │                                                         │
    │  │    8. score = uint256(keccak256(                        │
    │  │         msg.sender, ticketNumber, e3Id, seed            │
    │  │       ))                                                │
    │  │       → SAME formula as Rust-side computation           │
    │  │       → Both sides agree on scores                      │
    │  │                                                         │
    │  │    9. submitted[msg.sender] = true                      │
    │  │       scoreOf[msg.sender] = score                       │
    │  │                                                         │
    │  │   10. _insertTopN(e3Id, msg.sender, score):             │
    │  │       Maintains array of N lowest-scoring nodes:        │
    │  │       - If < N nodes: just insert                       │
    │  │       - If N nodes: replace highest if new score lower  │
    │  │       - O(N) linear scan per insertion                  │
    │  │                                                         │
    │  │   11. Emit TicketSubmitted(e3Id, msg.sender, score)     │
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
├─ Calculates wait time (finalization_delay_seconds):
│   wait = max(committeeDeadline - currentTimestamp, 0)
│          + 1 second
│          + party_index * 30 seconds
│   → The 30-second step must exceed one block interval plus the log read.
│     A member cancels its own attempt only after it observes
│     CommitteeFinalized, so a shorter step makes every member send a
│     transaction that reverts. The step is paid only while earlier
│     members stay silent.
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
├─ Preflight: committee_finalization_terminal() (eth_call)
│   └─ Skips the transaction when finalizeCommittee reverts with
│      CommitteeAlreadyFinalized, which covers both the Finalized and the
│      Failed stage. Another member can finalize between the stagger tick
│      and this call, and a transaction sent after that point is mined with
│      a failed receipt and burns gas.
│
└─ Calls contract.finalizeCommittee(e3Id).send()
    │
    │  If the transaction is mined with a failed receipt, the writer runs the
    │  same state check again (send_tx_idempotent in crates/evm/src/helpers.rs).
    │  A terminal state means no chain work remains, so the node logs the
    │  outcome and reports no error. Any other failure stays an error and
    │  retries after 30 seconds.
    │
    │  ┌─── ON-CHAIN (CiphernodeRegistryOwnable) ──────────────┐
    │  │                                                         │
    │  │  finalizeCommittee(e3Id) {                              │
    │  │    1. require(initialized && !finalized)                │
    │  │    2. require(block.timestamp > committeeDeadline)      │
    │  │       → Submission window must have closed              │
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
    │  │    5. Record one unresolved collateral obligation        │
    │  │       for each finalized member in BondingRegistry       │
    │  │                                                         │
    │  │    6. interfold.onCommitteeFinalized(e3Id)                │
    │  │       │                                                 │
    │  │       │  ┌─ Interfold.sol ────────────────────────────┐  │
    │  │       │  │  onCommitteeFinalized(e3Id) {            │  │
    │  │       │  │    require(stage == Requested)            │  │
    │  │       │  │    stage = CommitteeFinalized             │  │
    │  │       │  │    dkgDeadline = committeeDeadline        │  │
    │  │       │  │                  + dkgWindow               │  │
    │  │       │  │    require(now <= dkgDeadline)             │  │
    │  │       │  │    snapshot each member's reward          │  │
    │  │       │  │      recipient in E3RefundManager         │  │
    │  │       │  │    Emit E3StageChanged(e3Id,              │  │
    │  │       │  │          CommitteeFinalized)              │  │
    │  │       │  │  }                                       │  │
    │  │       │  └──────────────────────────────────────────┘  │
    │  │                                                         │
    │  │    7. Emit SortitionCommitteeFinalized(                 │
    │  │         e3Id, committee, scores                         │
    │  │       )                                                 │
    │  │       [ICiphernodeRegistry event]                       │
    │  │  }                                                      │
    │  └─────────────────────────────────────────────────────────┘
```

Ticket submission updates the provisional `topNodes` set. A new top-N candidate receives a
collateral obligation, and the same transaction releases a displaced candidate. Successful
finalization grants membership and `Active` status to the final address-sorted members. Failed
formation grants neither and releases all remaining candidate obligations. Finalization also freezes
each member's current bond owner as its reward recipient for this E3. Later bond-owner transfers
apply to later committees, not to payments earned by this committee. Once Interfold reports
`Complete` or `Failed`, anyone can call `releaseCommittee(e3Id)` on the request-time registry to
release all member obligations atomically.

### 3c. SortitionCommitteeFinalized Event Processing (Rust-Side)

```text
CiphernodeRegistrySolReader decodes SortitionCommitteeFinalized
│  [ICiphernodeRegistry event]
│
├─ Publishes InterfoldEvent::CommitteeFinalized {
│     e3_id, committee: [addr1, addr2, ..., addrN], scores: [s1, s2, ..., sN], chain_id
│   }
│
├─ Sortition actor:
│   └─ Stores finalized committee as a `Committee` struct in persistent map
│       → Provides O(1) address→party_id lookup for later expulsion handling
│       → `CommitteeFinalized` is normalized into ascending address order before storage
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
│   │     is_aggregator = (my node has the lowest eligible party_id in the
│   │                      address-sorted finalized committee)
│   │   }
│   │   Persists an absolute 10-minute deadline while a public-key result is pending
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

│ request()       │ VRF wait        │ sortitionWindow │ dkgWindow     │
│                 │                 │                 │               │
│ E3Requested     │ randomness      │ Committee       │ DKG Deadline  │
│ VRF requested   │ deadline        │ Deadline        │               │
│                 │                 │ Ciphernodes     │ Must complete │
│                 │ VRF response    │ submit tickets  │ DKG by here   │
│                 │ ───────────────►│                 │               │
│                 │                 │ finalizeComm.() │               │
│                 │                 │ CommFinalized   │               │
│                 │                 │ ───►DKG starts  │               │

If a stage deadline is missed → anyone can call `markE3Failed()`.
A ready committee must finalize at or before its absolute DKG deadline.
```

---

## Key Design Properties

1. **Deterministic sortition**: Both Rust and Solidity compute
   `keccak256(address, ticket, e3Id, seed)`. The on-chain contract verifies what the off-chain node
   computed. The Registry derives `seed` from a request-bound Chainlink VRF response and includes
   the chain ID, Registry address, E3 ID, and provider request ID in the domain. The requester
   commits payment before the asynchronous random word exists. The first ticket stores the derived
   seed and response-time deadline.

2. **Snapshot-based eligibility**: The eligible count, operator eligibility, and ticket balances use
   `requestBlock - 1`. The ticket price is frozen in the request transaction. Rust and Solidity
   consume those same values, so later activation, collateral, or price changes cannot alter the
   candidate set. All nodes compute the same buffered winner set. A selected node can decline its
   own submission when its local active-job capacity is exhausted.

3. **Runtime committee order**: both the on-chain registry and Rust runtime normalize the finalized
   committee into ascending address order before deriving `party_id`. This keeps party IDs,
   aggregator failover, proof inputs, and `CommitteeHashLib.hash(topNodes)` aligned.

4. **Active aggregator selection**: `CiphernodeSelector` derives `AggregatorChanged` from the
   finalized committee, enriched exclusion events, and its durable phase-local timeout state. The
   active aggregator is the lowest eligible `party_id` in the address-sorted runtime committee. When
   the expected chain result is absent for 10 minutes, every node promotes the next party in that
   order. The same phase keeps its absolute deadline across restart. Canonical phase progress clears
   the local unresponsive set. The final eligible party remains active after all standby budgets
   expire.

5. **Permissionless finalization**: Anyone can call `finalizeCommittee()` after the submission
   deadline and through the absolute DKG deadline. Delayed finalization reduces the remaining DKG
   time instead of extending the paid lifecycle. After the DKG deadline, anyone can fail an
   unfinalized ready committee. The staggered timers keep one member ahead of the next, and the
   writer reads the chain again before it sends. Both guards can still lose to a transaction that
   lands in the same block, so more than one node can send. The losing transaction reverts with
   `CommitteeAlreadyFinalized`; the writer re-reads the state after the failure and reports no error
   when finalization is terminal.

6. **IMT root snapshot**: The Merkle tree root is captured at request time. Nodes that join/leave
   after the request don't affect this E3's committee. A removed node's current-tree slot can be
   reused, but previously stored roots do not change.

7. **Coherent dependency generations**: A request atomically validates and records its registry,
   bonding, slashing, refund, and Interfold relationships. Governance pauses new requests before a
   replacement. The old generation must have no active E3s, unreleased committees, registered
   operators, bans, or slash assignments before any pointer can change. Governance then wires the
   complete new graph and enables requests. No request can observe a partly updated graph.

8. **Committee collateral follows the E3**: The request-time registry owns the E3's collateral
   obligations. Top-N submissions lock candidates, displacement releases the previous candidate, and
   finalization retains every winner's lock. The generation cannot rotate until all request-time
   committee obligations are released.

9. **Operator identity is unchanged by delegated bonding**: tFOLD is minted to the operator, and
   `submitTicket` is still sent by the operator key. Sortition hashes, eligibility snapshots,
   committee membership, and party IDs never use the bond-owner address.

10. **E3 program bootstrap and governance**: The production deploy requires one deployed E3 program.
    `Interfold.initialize` registers it before it transfers ownership to `protocolOwner`. For
    DAO-owned deployments, `protocolOwner` is the DAO, not a Safe. Every registration rejects an
    address without runtime code. After initialization, only the owner can register or retire a
    program. Retirement closes new request admission without changing existing E3 records. The
    deployment can create `MockE3Program` as the initial program. This stateless program accepts the
    active BFV scheme and applies no application rules. It has no owner, controller, or mutable
    configuration. The request-time ciphertext verifier and decryption verifier still verify the
    protocol proofs. Its deterministic data-availability receipt is only for tests. Requests remain
    paused until a production E3 program is registered and wired, and an interface-incompatible
    bootstrap mock is retired.

---

## Cluster 7 audit additions (post-fix semantics)

### Z-05 — request seed grinding

The E3 computation seed is still created during `Interfold.request`, but it does not rank committee
tickets. The Registry requests one random word from a configured `IRandomnessProvider` after the
paid request is stored. The production provider uses a Chainlink VRF v2.5 subscription. It never
re-requests randomness for an E3, and its callback records valid responses without calling the
Registry or reverting.

Fresh deployment and upgrade validation check the subscription owner, consumer, coordinator limits,
gas lane, and selected payment balance. The balance must meet the configured
`minimumSubscriptionBalance`, in wei for native payment or juels for LINK, before requests resume.
The provider reads the same selected balance before every request and reverts an underfunded request
before the E3 is accepted. The floor is an admission check, not a reservation for concurrent draws,
so production uses a dedicated subscription with balance monitoring. Upgrade preparation also checks
the live exit delay against the planned response timeout and submission window before it deploys any
implementation. The upgrade plan snapshots the effective subscription and provider settings.
Validation records that snapshot, and resume rejects stale implementations, provider settings, fees,
or deployment records.

Each E3 freezes its provider, provider request ID, response deadline, and submission window. Rust
waits for `RandomnessFulfilled`, then asks the Registry for the accepted seed and frozen request
context. The Registry rejects results recorded in the Ethereum request block, results dated in the
future, and results recorded after the response deadline. This release supports Ethereum mainnet,
Sepolia, and local development chains only and uses `block.number`. It derives
`keccak256(randomWord, chainId, registry, e3Id, requestId)`, and the first ticket stores the same
seed and response-time submission deadline. A timely accepted result remains readable after terminal
cleanup. A fresh node can therefore derive the same historical `CommitteeRequested` event even when
it starts after the E3 has failed or completed.

If no usable response arrives, no party can re-request or replace the random word. After the frozen
response deadline, the requester can cancel the E3 or any caller can finalize its timeout. Both
paths classify it as `CommitteeFormationTimeout`, release committee obligations, and return all
service fee escrow to the requester. The flat randomness fee stays charged. The timeout also clears
the active provider. New E3 requests then revert until governance pauses requests, investigates the
failure, and restores a provider. A late callback stays recorded in the request-bound provider but
cannot restart the E3.

The Registry reader acknowledges `RandomnessCircuitBreakerTripped` as a control-plane event. The SDK
also exposes this event and the request-bound provider's `RandomnessFulfilled` event. Consumers use
the provider address, request ID, and E3 ID from `CommitteeRandomnessRequested` to correlate them.

The Rust Registry reader retains the old `CommitteeRequested` block-hash decoder only for historical
log replay. New requests use `CommitteeRandomnessRequested` and the configured provider event.

### H-04 — snapshot-based eligibility

`CiphernodeRegistryOwnable._validateNodeEligibility` derives the per-node ticket weight from the
`InterfoldTicketToken` ERC20Votes checkpoint history at `committee.requestBlock - 1` (EIP-6372
timestamp clock). Same-block or post-request rebalancing therefore cannot inflate a node's selection
weight. `submitTicket` also checks historical eligibility and the current `isActive` flag in the
request-time bonding registry.

### M-28 — immutable per-E3 sortition state

At request timestamp `T`, `BondingRegistry.eligibilityAt` supplies the active count and individual
eligibility from `T-1`. `CiphernodeRegistryOwnable` freezes the current ticket price and emits it in
`CommitteeRequested`. The Rust sortition actor stores that event, reads activity and balances from
`T-1`, and uses the frozen price. Solidity checks the same historical state and price during ticket
submission. Current registry membership and activity remain additional liveness checks.

An upgrade with committees still in the `Requested` stage must backfill
`sortitionTicketPrices[e3Id]` with each E3's request-time price before ticket submission resumes. A
zero value makes every submission revert with `InvalidTicketNumber()`. The VRF upgrade requires
requests to be paused and all old committees to be released, so no live request needs entropy or
ticket-price migration.

### M-33 — `markE3Failed` grace period

When `markFailedGracePeriod > 0` (set via `Interfold.setMarkFailedGracePeriod`), calling
`markE3Failed` within `deadline … deadline + markFailedGracePeriod` is restricted to
`{ original requester, contract owner, active finalized committee member }`. After that window, any
caller can finalize the failure. The default value of `0` preserves the permissionless flow.

### H-26 — timestamp-clock `requestBlock`

`Committee.requestBlock` stores `block.timestamp` (EIP-6372 timestamp mode) so that `getPastVotes`
lookups against the `InterfoldTicketToken` resolve consistently across L1 and L2 clocks. The field
name is preserved for storage and event ABI compatibility.

### Committee observability events

The EVM reader has typed coverage for `CommitteeFormationFailed`, `CommitteeActivationChanged`, and
`CommitteeViabilityUpdated` in addition to ticket submission, finalization, publication, and
expulsion. These facts are stored in the E3's chain aggregate and projected into the dashboard's
committee stage, including submitted/required thresholds and post-expulsion viability.
