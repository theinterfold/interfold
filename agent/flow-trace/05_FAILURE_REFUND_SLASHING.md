# Part 5: Failure, Refunds & Slashing

## Overview

An E3 can fail at any stage due to timeouts, insufficient participants, or misbehavior. Settlement
first attributes economic responsibility from `FailureReason`:

- Requester, data-provider, or compute-provider failures pay completed work and the protocol share
  from service fee escrow; the requester receives the unspent remainder.
- Supplier/ciphernode failures return 100% of service fee escrow to the requester with no protocol
  cut. Honest nodes are compensated from actual ticket collateral slashed from faulty nodes.

The flat randomness fee is a request-time infrastructure charge, not fee escrow. Interfold credits
it to the request-time treasury after an accepted randomness request. No success, failure, or
cancellation path pays this amount to ciphernodes or returns it to the requester.

Slashed assets remain token-specific pull claims. Compensation is therefore limited to collateral
actually slashed and does not require an oracle or relabel one ERC-20 as another.

---

## Failure Detection

### Timeout-Based Failure (Permissionless)

Anyone can call `markE3Failed()` when a deadline is missed. A ready committee remains finalizable
through its absolute DKG deadline. It can fail if it remains unfinalized after that deadline.

The Interfold writer watches every stage that `failureCondition` supports: `Requested`,
`CommitteeFinalized`, `KeyPublished`, and `CiphertextReady`. Startup restores the stage from the
durable lifecycle map and restores the request-time registry from the DKG context. A finalized
committee member staggers its attempt by canonical party ID. A `Requested` E3 has no active
committee yet, so every node waits until the failure grace period ends and uses the permissionless
path. Before submission, the writer confirms that the stage and failure condition still match. A
canonical stage change cancels the old watch and invalidates any older stage-discovery RPC. After a
restart, finalized members keep their party-ID stagger and non-members remain outside the protected
grace window.

If an honest-node allocation is smaller than the node count, the refund manager credits it to the
request-time treasury instead of creating zero-value claims.

A committee-affecting slash policy can use only a supplier-paid failure reason. Policy validation
and refund settlement use the same payer classifier.

During the failure grace period, only active finalized committee members have committee authority.
Expelled members and provisional candidates do not.

Interfold rejects `None`, the enum sentinel, and larger failure reason values before it changes the
E3 stage.

Committee key publication is valid through the DKG deadline. Later publication is rejected as a
supplier-side timeout.

> **NOTE:** The `gracePeriod` is stored in `_timeoutConfig` and validated on config update, but it
> is **NOT added** to the deadline checks in `_checkFailureCondition()`. The actual checks compare
> `block.timestamp` directly against the raw deadlines (which themselves already incorporate the
> window durations). This may be intentional (grace already baked into the window sizes) or a
> missing feature.

```text
Anyone calls: Interfold.markE3Failed(e3Id)
│
├─ Revert if stage == None, Complete, or Failed
│
├─ CHECK 1: Committee Formation Timeout
│   stage == Requested
│   AND either:
│     - threshold is not met and block.timestamp > committeeDeadline
│     - threshold is met and block.timestamp > committeeDeadline + dkgWindow
│   → Reason: CommitteeFormationTimeout
│
├─ CHECK 2: DKG Timeout
│   stage == CommitteeFinalized
│   AND block.timestamp > dkgDeadline
│   → Reason: DkgTimeout
│
├─ CHECK 3: Compute Timeout
│   stage == KeyPublished
│   AND block.timestamp > computeDeadline
│   → Reason: ComputeTimeout
│
├─ CHECK 4: Decryption Timeout
│   stage == CiphertextReady
│   AND block.timestamp > decryptionDeadline
│   → Reason: DecryptionTimeout
│
└─ If ANY check passes:
    _e3Stages[e3Id] = E3Stage.Failed
    _e3FailureReasons[e3Id] = reason
    Emit E3StageChanged(e3Id, currentStage, E3Stage.Failed)
    Emit E3Failed(e3Id, currentStage, reason)
```

### Contract-Triggered Failure

```text
CiphernodeRegistry or SlashingManager calls:
  Interfold.onE3Failed(e3Id, reason)
│
├─ require(caller == ciphernodeRegistry || caller == slashingManager)
├─ _e3Stages[e3Id] = Failed
├─ _e3FailureReasons[e3Id] = reason
└─ Emit E3StageChanged, E3Failed
```

Specific triggers:

- **InsufficientCommitteeMembers**: `finalizeCommittee()` uses this reason when fewer than N nodes
  submitted tickets. SlashingManager also uses it when an expulsion leaves fewer than H active
  members. Reusing the existing supplier-paid reason preserves the persisted enum layout.

### Requester Cancellation

Only the address that created an E3 can call `cancelE3(e3Id)`. Cancellation is a recovery path for
an asynchronous randomness request that did not produce a usable result by its frozen deadline. It
is valid only while the E3 remains in `Requested`, the Registry reports no seed, and the randomness
deadline has passed.

The contract does not allow cancellation while a timely VRF result can still arrive. This prevents a
requester from seeing a pending fulfillment and canceling only when the random word is unfavorable.
The provider never re-requests or deletes randomness for an E3.

```text
Requester calls: Interfold.cancelE3(e3Id)
│
├─ require(msg.sender == request-time requester)
├─ require(stage == Requested)
├─ require(Registry.sortitionSeed(e3Id) is unavailable)
├─ require(block.timestamp > randomnessDeadline)
├─ _e3Stages[e3Id] = Failed
├─ _e3FailureReasons[e3Id] = CommitteeFormationTimeout
├─ Registry.releaseCommittee(e3Id)
│  → release candidate and request obligations
│  → clear the active randomness provider
│  → reject new E3 requests until governance restores a provider
│  → a late provider callback cannot restart sortition
└─ Emit E3StageChanged and E3Failed

Settlement remains separate from cancellation. Any account can call `processE3Failure(e3Id)` after
the state change. `CommitteeFormationTimeout` is supplier-paid, so the requester receives the full
service fee escrow. No node or service protocol allocation is paid from that escrow because no
committee work began. The flat randomness fee stays charged because a late response can still
charge the protocol-funded subscription.
```

---

## Refund Processing

### Step 1: Process Failure

Runtime note: `processE3Failure()` is a permissionless cleanup path. The Rust `InterfoldSolWriter`
may auto-submit it from any effects-enabled node on the same chain, and it must not depend on
active-aggregator designation because failures can happen before committee finalization or while the
current aggregator is offline. A restart restores failed E3 IDs from the durable lifecycle map. The
writer retries transient failures and treats `NoPaymentToRefund` as proof that another account has
already processed the escrow.

```text
Anyone calls: Interfold.processE3Failure(e3Id)
│
├─ require(stage == Failed)
├─ require(e3Payments[e3Id] > 0) → payment exists
│
├─ 1. payment = e3Payments[e3Id]
├─ 2. e3Payments[e3Id] = 0  (prevent double-processing)
│
├─ 3. Get honest nodes:
│     (honestNodes, _) = ciphernodeRegistry.getActiveCommitteeNodes(e3Id)
│     → Returns committee members NOT expelled by slashing plus their ticket scores
│     → Returns empty arrays when committee formation did not finalize
│     → An unexpected registry failure reverts the transaction and restores the payment
│
├─ 4. Transfer payment to E3RefundManager:
│     paymentToken = _e3FeeTokens[e3Id]  (per-E3 token, not current global)
│     paymentToken.transfer(e3RefundManager, payment)
│
├─ 5. e3RefundManager.calculateRefund(
│       e3Id, payment, honestNodes, paymentToken
│     )
│     │
│     │  ┌─── E3RefundManager.calculateRefund() ────────────────┐
│     │  │                                                       │
│     │  │  1. Read FailureReason and call getFailurePayer():    │
│     │  │                                                       │
│     │  │  Requester liability:                                 │
│     │  │    NoInputsReceived, ComputeTimeout,                  │
│     │  │    ComputeProviderExpired/Failed, RequesterCancelled  │
│     │  │                                                       │
│     │  │  Ciphernodes/supply liability:                        │
│     │  │    CommitteeFormationTimeout,                         │
│     │  │    InsufficientCommitteeMembers, DKGTimeout,          │
│     │  │    DKGInvalidShares, DecryptionTimeout,               │
│     │  │    DecryptionInvalidShares, VerificationFailed        │
│     │  │                                                       │
│     │  │  None, _MAX_FAILURE_REASON, and                       │
│     │  │  future unclassified reasons revert                   │
│     │  │  InvalidFailureReason (fail closed).                  │
│     │  │                                                       │
│     │  │  2a. Ciphernodes/supply liability:                    │
│     │  │      requesterAmount = payment (100%)                 │
│     │  │      honestNodeAmount = 0                             │
│     │  │      protocolAmount = 0                               │
│     │  │      → honest-node compensation can come only from    │
│     │  │        actual slashed ticket collateral               │
│     │  │                                                       │
│     │  │  2b. Requester liability: use request-time work BPS:  │
│     │  │      KeyPublished / CiphertextReady defaults:         │
│     │  │      honestNodeAmount = payment * 5000 / 10000        │
│     │  │      requesterAmount = payment * 4500 / 10000         │
│     │  │      protocolAmount = remaining 500 / 10000           │
│     │  │      → if no honest recipient exists, fold the work   │
│     │  │        share back into requesterAmount                │
│     │  │                                                       │
│     │  │  3. Credit any requester-fault protocol amount to the │
│     │  │     snapshotted treasury pull ledger                  │
│     │  │                                                       │
│     │  │  4. Store RefundDistribution {                        │
│     │  │       honestNodeAmount, requesterAmount,              │
│     │  │       protocolAmount, totalSlashed: 0,                │
│     │  │       honestNodeCount, feeToken,                      │
│     │  │       originalPayment, perNodeAmount: 0               │
│     │  │     }                                                 │
│     │  │                                                       │
│     │  │  5. Preserve slashed assets as separate claims:       │
│     │  │     → Each escrow keeps proposalId, target, token,    │
│     │  │       and amount                                      │
│     │  │     → Each proposal settles independently after the   │
│     │  │       E3 reaches a terminal state                     │
│     │  │     → Tokens remain permissionlessly settleable       │
│     │  │       without being relabeled                         │
│     │  │                                                       │
│     │  │  M-09: snapshot the base fee-token per-node payout:   │
│     │  │     if honestNodeCount > 0:                           │
│     │  │       dist.perNodeAmount =                            │
│     │  │         honestNodeAmount / honestNodeCount            │
│     │  │  Every claimHonestNodeReward call returns this        │
│     │  │  immutable snapshot; the last claimant routes the     │
│     │  │  residual dust to _pendingTreasury (pull) instead     │
│     │  │  of inflating their own payout.                       │
│     │  │                                                       │
│     │  │  6. Emit RefundDistributionCalculated(e3Id,           │
│     │  │       honestNodeAmount, requesterAmount, protocolAmt) │
│     │  └───────────────────────────────────────────────────────┘
│
└─ Emit E3FailureProcessed(e3Id)
```

### Step 2: Claim Refunds

```text
REQUESTER claims:
  E3RefundManager.claimRequesterRefund(e3Id)
│
├─ require(distribution calculated)
├─ require(msg.sender == requester from Interfold)
├─ require(!requester refund already claimed)
├─ requesterAmount is either:
│   • 100% of service fee escrow for ciphernodes/supply liability, or
│   • the unspent request-time work allocation for requester liability
├─ Transfer requesterAmount in the per-E3 fee token
└─ Emit RefundClaimed(e3Id, requester, amount)

HONEST NODE'S BOND OWNER claims:
  E3RefundManager.claimHonestNodeReward(e3Id, operator)
│
├─ require(distribution calculated)
├─ require(operator is in honestNodes[e3Id])
├─ load the recipient frozen when this E3's committee was finalized
├─ require(msg.sender == recipient)
├─ If an expelling proposal is unresolved, hold this operator's unclaimed
│  share without blocking other operators, even if settlement happened first
├─ If the operator is expelled, mark any unclaimed base share consumed and
│  reallocate it as later top-up claims for the remaining operators
│  → A base reward claimed before the proposal opened remains final
├─ Otherwise require either an unclaimed base reward or a new top-up
│  → This ledger is independent from the requester-refund claim ledger, so a
│    requester who is also an honest node can receive both entitlements
├─ honestNodeAmount exists only for requester-attributable failures
│  → ciphernodes/supply failures set this base amount to zero
│  → honest nodes claim later ticket slashes through claimSlashedFunds
├─ perNodeAmount = honestNodeAmount / honestNodeCount
│   • SNAPSHOTTED at calculateRefund (M-09) and never changed by
│     slashed assets, even when the slash token equals the fee token.
├─ Last claimer routes the residual dust to _pendingTreasury via
│   TreasurySlashedCredited (pull); the last node never gets a
│   silently-inflated payout, and no per-claim dust is stranded.
├─ Transfer directly to the frozen recipient (not via BondingRegistry)
└─ Emit RefundClaimed(e3Id, recipient, amount)

SLASH RECIPIENT claims a token-specific entitlement:
  E3RefundManager.claimSlashedFunds(e3Id, actualToken)
│
├─ Read _pendingSlashedClaims[e3Id][actualToken][caller]
├─ Clear the claim and reduce actualToken's protected liability
├─ Transfer that exact token; base refunds never consume the protected reserve
└─ Emit SlashedFundsClaimed(e3Id, caller, actualToken, amount)
```

### Refund Example: Requester/Compute-Provider Fault

```text
Scenario: E3 fails at KeyPublished stage (compute timeout)
  Payment: 1,000,000 fee-token units (one token with 6 decimals)
  Honest nodes: 3 (out of 5 committee members, 2 were slashed)

  Work completed:  50% → honestNodeAmount = 500,000
  Work remaining:  45% → requesterAmount  = 450,000
  Protocol fee:     5% → protocolAmount   =  50,000

  Each honest node claims: 500,000 / 3 = 166,666
  The 2-unit division dust is credited to the treasury pull ledger

  Requester claims: 450,000
  Treasury claims: 50,002
```

### Refund Example: Ciphernode Fault

```text
Scenario: E3 fails during DKG because one member supplied invalid shares
  Fee escrow: 1,000,000 fee-token units
  Honest nodes after expulsion: 2
  Faulty node ticket slash: 300,000 TICKET-USD

  Base fee-token claims:
    requester:    1,000,000 fee-token units (100%)
    honest nodes:         0 fee-token units
    protocol:             0 fee-token units

  Separate slash-token claims:
    honest node 1: 150,000 TICKET-USD
    honest node 2: 150,000 TICKET-USD
    requester:          0 TICKET-USD

  If no ticket collateral is actually slashed, honest-node compensation is
  zero; the requester refund never waits for or depends on slash execution.
```

---

## Slashing Mechanism

### Off-Chain Fault Attribution: AccusationManager

**Actor:** `AccusationManager` (`crates/slashing/src/accusation_voting/actor.rs`; the `zk-prover`
path is a compatibility re-export)

**Deterministic workflow:** `crates/slashing/src/accusation_voting/workflow.rs` owns deadlines,
EIP-712 digests, admission, vote/quorum decisions, and re-verification state. The actor owns timers
and executes the workflow's returned `VoteAction`s.

The AccusationManager is a per-E3 actor created when `SortitionCommitteeFinalized` (the
`ICiphernodeRegistry` event) fires. On restart, its extension recreates the actor from the persisted
active committee before replay. It bridges proof verification failures to on-chain slashing through
an off-chain committee quorum protocol.

```text
LIFECYCLE:
  Created by AccusationManagerExtension on SortitionCommitteeFinalized or context hydration
  → Stores committee list, threshold_m, this node's address + signer
  → Actor identity and committee inputs recover from durable committee state
  → In-flight accusations, votes, and timers remain process-local
  → Destroyed by E3RequestComplete (Die signal)
```

A restart does not reconstruct a partially collected vote tally. The actor can accept new valid
messages after hydration, but peers must resend any vote that existed only in the old process.
Signed accusation deadlines bound how long that recovery remains useful.

#### Step 1: Local Proof Failure Detection

```text
ProofVerificationFailed OR CommitmentConsistencyViolation event arrives
│
├─ For ProofVerificationFailed:
│   ├─ 1. Resolve accused address:
│   │     If accused_address == 0x0:
│   │       Look up from committee list by party_id
│   │
│   ├─ 2. Cache verification result:
│   │     received_data[(accused, proof_type)] = { data_hash, passed: false }
│   │
│   ├─ 3. For C3a/C3b proofs: attach signed_payload for re-verification
│   │     → Other nodes need the original proof to independently verify
│   │
│   └─ 4. Delegate to initiate_accusation()
│
├─ For CommitmentConsistencyViolation:
│   ├─ 1. Cache verification result:
│   │     received_data[(accused, proof_type)] = { data_hash, passed: false }
│   │
│   └─ 2. Delegate to initiate_accusation() (no forwarded payload)
│
└─ initiate_accusation() — shared logic:
    │
    ├─ 3. Dedup check:
    │     If (accused, proof_type) already in accused_proofs set:
    │       → Return (already accused, skip)
    │     Else: insert into accused_proofs
    │
    ├─ 4. Create and SIGN accusation:
    │     ProofFailureAccusation {
    │       e3_id, accuser: my_address, accused, accused_party_id,
    │       proof_type, data_hash, issued_at, deadline,
    │       signed_payload (C3 only),
    │       signature: ecSign(accusation_digest)
    │     }
    │
    ├─ 5. Broadcast accusation via P2P gossip
    │
    ├─ 6. Cast own affirmative vote:
    │     AccusationVote {
    │       e3_id, accusation_id, voter: my_address,
    │       data_hash, issued_at, deadline,
    │       signature: ecSign(vote_digest)
    │     }
    │     → Broadcast via P2P gossip
    │
    ├─ 7. Start vote timeout (300 seconds):
    │     → If quorum not reached by timeout, resolve as Inconclusive
    │
    └─ 8. Check for immediate quorum (if threshold_m == 1)
```

#### Step 2: Incoming Accusation Handling

```text
ProofFailureAccusation arrives via P2P from another committee member
│
├─ 1. Verify accuser is a committee member
│
├─ 2. Validate accusation deadline against local policy:
│     - reject if deadline <= now (expired)
│     - reject if issued_at is more than the allowed clock skew in the future
│     - reject if deadline < issued_at
│     - reject if deadline - issued_at > accusationVoteValidity
│     - reject all peer accusations when accusationVoteValidity == 0
│     - `skew` defaults to 30s and is configurable via
│       `ACCUSATION_DEADLINE_SKEW_SECS` on the node process
│
├─ 3. Verify accuser's ECDSA signature on accusation digest
│
├─ 4. Compute accusation_id:
│     keccak256(abi.encodePacked(chainId, e3Id, accused, proofType))
│     → Deterministic: all nodes compute same ID for same accusation
│
├─ 5. Determine own vote based on local verification cache:
│     │
│     ├─ Case A: We already FAILED verification for (accused, proof_type):
│     │   → Vote agrees = true
│     │
│     ├─ Case B: We already PASSED verification for (accused, proof_type):
│     │   → Do not vote
│     │
│     └─ Case C: Unknown (haven't verified yet):
│         ├─ For C3a/C3b: re-verify using signed_payload from accusation
│         │   → Dispatch to ZkActor for local re-verification
│         │   → Vote after re-verification completes
│         └─ For other proofs: do not vote without local evidence
│
├─ 6. Create and SIGN vote:
│     AccusationVote {
│       e3_id, accusation_id, voter: my_address,
│       data_hash, issued_at, deadline,
│       signature: ecSign(vote_digest)
│     }
│     → Broadcast via P2P gossip
│
└─ 7. Check quorum immediately
```

Governance can keep or increase `accusationVoteValidity` immediately. Every reduction, including a
zero-second window, uses the two-day proposal and commit path. A proposal expires two days after it
becomes ready. A direct keep or increase operation clears the pending proposal. A live value of zero
disables new Lane A submissions. Each E3 also snapshots its nonzero maximum signed window and an
objective submission deadline. The objective deadline is the latest possible request lifecycle
deadline plus the one-day reporting window. Governance cannot close the E3 assignment or retire its
slashing manager before that submission deadline passes.

#### Step 3: Vote Digest & Accusation ID (Must Match Solidity)

```text
Accusation ID (deterministic, same on Rust + Solidity):
  accusation_id = keccak256(abi.encodePacked(
    chainId, e3Id, accused_address, proofType
  ))

Vote Digest (EIP-712 signed, verified on-chain):
  struct_hash = keccak256(abi.encode(
    VOTE_TYPEHASH,
    e3Id,
    accusation_id,
    voter_address,
    data_hash,
    issued_at,
    deadline
  ))
  vote_digest = keccak256("\x19\x01" || domain_separator || struct_hash)
  signature = sign_hash(vote_digest, voter_private_key)

CRITICAL: These type hashes MUST match the Solidity constants:
  VOTE_TYPEHASH = keccak256(
    "AccusationVote(uint256 e3Id,bytes32 accusationId,"
    "address voter,bytes32 dataHash,uint256 issuedAt,uint256 deadline)"
  )
```

#### Step 4: Quorum Decision Logic

```text
check_quorum(accusation_id):
│
├─ Count affirmative votes
│
├─ CASE A: agree_count >= threshold_m
│   │
│   ├─ Check for equivocation:
│   │   All agreeing voters have same data_hash?
│   │   ├─ YES → AccusationOutcome::AccusedFaulted (SLASHABLE)
│   │   │   → accused sent the same bad proof to everyone
│   │   └─ NO  → AccusationOutcome::Equivocation (NOT slashable yet)
│   │       → accused sent DIFFERENT data to different nodes
│   │       → the current single-preimage evidence cannot prove every payload
│   │
│   └─ Emit AccusationQuorumReached
│
└─ CASE B: agree_count < threshold_m
    ├─ Continue collecting affirmative votes until the local timeout
    └─ At timeout → AccusationOutcome::Inconclusive (NOT slashable)
```

#### Step 5: On-Chain Slash Submission

```text
AccusationQuorumReached event arrives at SlashingManagerSolWriter
│
├─ Continue only for AccusedFaulted
│     → Equivocation remains local evidence until the on-chain format can
│       prove each distinct signed payload
│
├─ 1. DURABLE OUTBOX AND EFFECT GATE:
│     Store the intent in the versioned per-chain recovery outbox before policy or RPC work
│     Coalesce by the contract replay tuple (chainId, e3Id, accused, proofType)
│     Before EffectsEnabled, retain the intent without sending a transaction
│     After EffectsEnabled, release each retained intent and track it in flight
│     Startup backfills a missing outbox from the EventStore
│
├─ 2. READ THE PROOF-TYPE POLICY ON EVERY COMMITTEE NODE:
│     reason = keccak256(abi.encodePacked(uint256(proofType)))
│     policy = SlashingManager.getSlashPolicy(reason)
│     │
│     ├─ Policy disabled:
│     │   ├─ Do not submit a transaction that can only revert
│     │   ├─ Publish durable CommitteeMemberExcluded { party_id: None }
│     │   ├─ Clear the outbox only after that exclusion is observed
│     │   └─ Stop waiting for the confirmed faulty member in this E3 only
│     │       → No on-chain slash, ban, reward hold, or future-selection change is implied
│     │
│     ├─ Policy enabled but not configured for proof attestations:
│     │   └─ Report a terminal configuration error; do not invent an exclusion
│     │
│     └─ Policy read fails:
│         └─ Do not invent an exclusion; ranked voters retain the transaction path
│
├─ 3. STAGGERED SUBMISSION (enabled policy, fallback submitters):
│     Rank all agreeing voters by address (sorted ascending)
│     My rank = position in sorted list
│     │
│     ├─ Rank 0 (primary): submit immediately
│     ├─ Rank 1: wait 30 seconds, then submit
│     ├─ Rank 2: wait 60 seconds, then submit
│     └─ ... (each rank waits rank × 30 seconds)
│     → Prevents multiple nodes wasting gas on same slash
│     → Higher-rank submitters expect DuplicateEvidence revert
│
├─ 4. Encode attestation evidence:
│     proof = abi.encode(
│       proofType,       // uint256 — which proof failed (C0-C7)
│       voters[],        // address[] — sorted ascending
│       dataHashes[],    // bytes32[] — per-voter data hashes
│       evidence,        // bytes — shared evidence preimage
│       issuedAt,        // uint256 — common signed issue time
│       deadline,        // uint256 — common signed deadline
│       signatures[]     // bytes[] — per-voter ECDSA signatures
│     )
│
├─ 5. Prefer proposeSlashByDkgParty(e3Id, partyId, proof) when the
│     canonical DKG slot resolves; otherwise call proposeSlash(e3Id, accused, proof)
│     → On-chain verification happens (see Lane A below)
│
└─ 6. Handle result:
     ├─ Confirmed receipt: log transaction hash and clear the outbox intent
     ├─ Matching SlashExecuted or CommitteeMemberExcluded: clear the outbox intent
     ├─ DuplicateEvidence / stale committee attribution: terminal and logged as warning
     └─ Temporary RPC, nonce, transport, or unknown failure: keep the outbox intent and retry
        after 30 seconds
```

### Lane A: Attestation-Based Slashing (Permissionless, Atomic)

```text
Anyone calls: SlashingManager.proposeSlash(e3Id, operator, proof)
│
├─ 1. Decode proof:
│     (proofType, voters[], dataHashes[], evidence,
│      issuedAt, deadline, signatures[])
│     = abi.decode(proof, (...))
│
├─ 2. Derive slash reason deterministically:
│     reason = keccak256(abi.encodePacked(proofType))
│     → Eliminates cross-reason replay
│     → Each proofType maps to one policy (E3_BAD_DKG_PROOF, etc.)
│
├─ 3. Load policy:
│     policy = slashPolicies[reason]
│     require(policy.enabled)
│     require(policy.requiresProof)  → Lane A only
│
├─ 4. Verify operator is committee member:
│     require(ciphernodeRegistry.isCommitteeMember(e3Id, operator))
│
├─ 5. Replay protection:
│     evidenceKey = keccak256(abi.encodePacked(chainId, e3Id, operator, proofType))
│     require(!evidenceConsumed[evidenceKey])
│     evidenceConsumed[evidenceKey] = true
│
├─ 6. VERIFY ATTESTATION EVIDENCE:
│     _verifyAttestationEvidence(proof, e3Id, operator)
│     │
│     │  ┌─── Attestation Verification ─────────────────────────┐
│     │  │                                                       │
│     │  │  1. Validate array lengths match                      │
│     │  │                                                       │
│     │  │  2. Require the live vote window is nonzero           │
│     │  │     and the E3 objective submission deadline          │
│     │  │     has not passed                                    │
│     │  │                                                       │
│     │  │  3. Require issuedAt is not too far in the future,    │
│     │  │     deadline >= issuedAt, and                         │
│     │  │     deadline - issuedAt <= the E3 snapshot            │
│     │  │     Require the signed deadline has not passed        │
│     │  │                                                       │
│     │  │  4. Compute accusation_id:                            │
│     │  │     keccak256(abi.encodePacked(                       │
│     │  │       chainId, e3Id, operator, proofType              │
│     │  │     ))                                                │
│     │  │     → SAME formula as Rust AccusationManager          │
│     │  │                                                       │
│     │  │  5. Check quorum: numVotes >= threshold_m             │
│     │  │     → Get threshold from ciphernodeRegistry           │
│     │  │                                                       │
│     │  │  6. Require keccak256(evidence) == dataHashes[0]      │
│     │  │     and every voter uses that same hash               │
│     │  │                                                       │
│     │  │  7. For EACH voter:                                   │
│     │  │     ├─ Ascending order check (prevents duplicates):   │
│     │  │     │   require(voter > prevVoter)                    │
│     │  │     ├─ Conflict check (accused can't vote):           │
│     │  │     │   require(voter != operator)                    │
│     │  │     ├─ Voter must be active committee member:         │
│     │  │     │   require(isCommitteeMemberActive(e3Id, voter)) │
│     │  │     └─ VERIFY ECDSA SIGNATURE:                        │
│     │  │         hash = EIP712Hash(                            │
│     │  │           e3Id, accusationId, voter,                  │
│     │  │           dataHashes[i], issuedAt, deadline           │
│     │  │         )                                             │
│     │  │         require(ECDSA.recover(hash, sig) == voter)    │
│     │  │         → Proves voter actually signed this vote      │
│     │  │                                                       │
│     │  └───────────────────────────────────────────────────────┘
│
├─ 7. Create proposal with SNAPSHOTTED policy values:
│     proposal = SlashProposal {
│       e3Id, operator, reason,
│       ticketAmount: policy.ticketPenalty,
│       ciphernodeBondAmount: policy.ciphernodeBondPenalty,
│       proofVerified: true,          // Lane A marker
│       executableAt: block.timestamp + policy.appealWindow,
│       banNode: policy.banNode,
│       affectsCommittee: policy.affectsCommittee,
│       failureReason: policy.failureReason
│     }
│     → Policy values snapshotted at proposal time
│     → Prevents execution drift if policy changes later
│     → Increment unresolved financial proposal count for operator
│     → If affectsCommittee, open an E3 entitlement hold for this operator
│
└─ 8. If appealWindow == 0, immediately execute; otherwise leave
      the proposal deferred and appealable until executableAt
      │
      │  (see "Slash Execution" below)
```

### Lane B: Evidence-Based Slashing (Delayed, With Appeals)

```text
SLASHER_ROLE calls: SlashingManager.proposeSlashEvidence(
  e3Id, operator, reason, evidence
)
│
├─ 1. Load policy = slashPolicies[reason]
│     require(policy.enabled)
│     require(!policy.requiresProof) → evidence-based only
│     → reason is an explicit bytes32, not derived from proof
│
├─ 2. Require the snapshotted E3 dependency graph exists and
│     registry.isCommitteeMember(e3Id, operator)
│     → Evidence cannot slash an unrelated operator into another E3's escrow
│
├─ 3. Replay protection:
│     evidenceHash = keccak256(abi.encode(e3Id, operator, keccak256(evidence)))
│     require(!evidenceConsumed[evidenceHash])
│     evidenceConsumed[evidenceHash] = true
│
├─ 4. Create proposal with SNAPSHOTTED policy values:
│     proposal = SlashProposal {
│       e3Id, operator, reason,
│       ticketAmount: policy.ticketPenalty,
│       ciphernodeBondAmount: policy.ciphernodeBondPenalty,
│       proofVerified: false,
│       executableAt: block.timestamp + policy.appealWindow,
│       banNode: policy.banNode,
│       affectsCommittee: policy.affectsCommittee,
│       failureReason: policy.failureReason
│     }
│     → NOT executed immediately
│     → Increment the same unresolved financial proposal count
│     → If affectsCommittee, open an E3 entitlement hold for this operator
│
└─ 5. Emit SlashProposed(proposalId, e3Id, operator, reason)

─── APPEAL WINDOW OPENS ─────────────────────────────────────

Operator or its bond owner calls: SlashingManager.fileAppeal(proposalId, evidence)
│
├─ require(msg.sender == proposal.operator OR bondOwnerOf(proposal.operator))
├─ require(block.timestamp < proposal.executableAt)
│   → Must appeal before window closes
├─ require(!proposal.appealed)
│   → Only one appeal per proposal
├─ proposal.appealed = true
├─ proposal.appealEvidence = evidence
└─ Emit AppealFiled(proposalId, evidence)

GOVERNANCE_ROLE resolves: SlashingManager.resolveAppeal(
  proposalId, upheld, resolution
)
│
├─ require(proposal.appealed && !proposal.resolved)
├─ proposal.resolved = true
├─ proposal.appealUpheld = upheld
├─ If upheld:
│   ├─ decrement unresolved proposal count
│   └─ clear the E3 entitlement hold and release the accused share
└─ Emit AppealResolved(proposalId, upheld, resolution)

If governance does not resolve a filed appeal by
`executableAt + APPEAL_RESOLUTION_GRACE`, anyone may call `expireAppeal`.
Expiry conclusively upholds the appeal and releases the collateral gate.
It also clears the E3 entitlement hold.

─── AFTER APPEAL WINDOW ──────────────────────────────────────

Anyone calls: SlashingManager.executeSlash(proposalId)
│
├─ require(!proposal.executed)
├─ require(block.timestamp >= proposal.executableAt)
├─ If appealed:
│   require(proposal.resolved)
│   require(!proposal.appealUpheld)
│   → If appeal was upheld, slash is cancelled
│
├─ Decrement unresolved proposal count (reverts atomically on failure)
└─ _executeSlash(proposalId, lane)
```

### Slash Execution (Both Lanes)

```text
_executeSlash(proposalId):
│
├─ 1. SLASH TICKET BALANCE (if ticketAmount > 0):
│     actualTicketSlashed = bondingRegistry.slashTicketBalance(
│       operator, proposal.ticketAmount, reason
│     )
│     → Returns ACTUAL amount slashed (may be less if balance insufficient)
│     │
│     │  ┌─── BondingRegistry.slashTicketBalance() ─────────────┐
│     │  │                                                       │
│     │  │  1. Slash from ACTIVE balance first:                  │
│     │  │     activeBalance = ticketToken.balanceOf(operator)   │
│     │  │     slashFromActive = min(amount, activeBalance)      │
│     │  │     ticketToken.burnTickets(operator, slashFromActive)│
│     │  │     → Burns tFOLD, underlying stays as payableBalance │
│     │  │                                                       │
│     │  │  2. Remaining from EXIT QUEUE:                        │
│     │  │     remaining = amount - slashFromActive              │
│     │  │     if remaining > 0:                                 │
│     │  │       _exits.slashPendingAssets(                      │
│     │  │         operator, remaining, 0,                       │
│     │  │         includeLockedAssets=true                      │
│     │  │       )                                               │
│     │  │       require(actualPendingSlash == remaining)        │
│     │  │       → Can slash EVEN LOCKED exit tranches           │
│     │  │       → No escaping via queued exits                  │
│     │  │                                                       │
│     │  │  3. slashedTicketBalance += totalSlashed              │
│     │  │     → Tracked for redirect to refund pool or treasury │
│     │  │                                                       │
│     │  │  4. _updateOperatorStatus(operator)                   │
│     │  │     → May deactivate if below thresholds              │
│     │  └───────────────────────────────────────────────────────┘
│
├─ 2. SLASH CIPHERNODE BOND (if ciphernodeBondAmount > 0):
│     actualCiphernodeBondSlashed = bondingRegistry.slashCiphernodeBond(
│       operator, proposal.ciphernodeBondAmount, reason
│     )
│     → Returns ACTUAL amount slashed (may be less if balance insufficient)
│     │
│     │  ┌─── BondingRegistry.slashCiphernodeBond() ─────────────────────┐
│     │  │                                                               │
│     │  │  1. Compute active + pending FOLD total                       │
│     │  │                                                               │
│     │  │  2. Slash active bond first, then pending exits               │
│     │  │     → Active slash decrements operators[op].ciphernodeBond    │
│     │  │     → Pending slash decrements pending ciphernode bond totals │
│     │  │     → totalBonded(bondOwner) drops immediately; if            │
│     │  │       the owner has token locks, wallet FOLD may become       │
│     │  │       encumbered until the locked floor decays/top-up         │
│     │  │                                                               │
│     │  │  3. slashedCiphernodeBond += totalSlashed                     │
│     │  │  4. _updateOperatorStatus(operator)                           │
│     │  └───────────────────────────────────────────────────────────────┘
│
├─ 3. BAN NODE (if proposal.banNode):
│     banned[operator] = true
│     Emit NodeBanUpdated(operator, true, reason, address(this))
│     → BondingRegistry refreshes the registered operator
│     → Active status and numActiveOperators update immediately
│     → Banned nodes cannot submit new tickets or re-register
│     → Only governance can lift ban
│
├─ 4. COMMITTEE EXPULSION (if proposal.affectsCommittee):
│     (activeCount, thresholdM) =
│       ciphernodeRegistry.expelCommitteeMember(
│         e3Id, operator, reason
│       )
│     │
│     │  ┌─── CiphernodeRegistry.expelCommitteeMember() ────────┐
│     │  │                                                       │
│     │  │  1. If already expelled: return (no-op, idempotent)   │
│     │  │  2. committees[e3Id].active[operator] = false         │
│     │  │  3. committees[e3Id].activeCount--                    │
│     │  │  4. Emit CommitteeMemberExpelled(e3Id, operator)      │
│     │  │  5. Return (activeCount, threshold[0])                │
│     │  └───────────────────────────────────────────────────────┘
│     │
│     └─ If activeCount < thresholdM:
│         ├─ Read the E3 stage from its request-time Interfold contract
│         ├─ Complete or Failed: allow the later slash without another callback
│         └─ Any other stage: call onE3Failed with InsufficientCommitteeMembers
│            → No catch-all suppression
│            → Callback failure rolls back penalties, ban, and expulsion
│            → The E3 and committee cannot commit inconsistent states
│
│     Resolve the E3 entitlement hold as expelled:
│       → the accused operator cannot claim its held share
│       → held fee and slash-funded shares move to remaining operators
│
│
├─ 5. SLASHED FUNDS ESCROWING (if actualTicketSlashed > 0):
│     │
│     │  Always escrows — regardless of E3 stage.
│     │  Destination decided later at terminal state.
│     │
│     ├─ Reserve and record BEFORE attempting the route:
│     │    bondingRegistry.reserveSlashedTicketFunds(
│     │      proposalId, e3Id, amount
│     │    )
│     │    pendingSlashRoutes[proposalId] = {
│     │      e3Id, token: ticketToken.underlying(), amount,
│     │      pending: true, operator
│     │    }
│     │    → Reservation belongs only to (slashingManager, proposalId)
│     │    → Its refund manager was frozen during E3 dependency setup
│     │    → Other managers and treasury withdrawal cannot spend it
│     │    → Emit SlashRoutePending
│     │
│     │  Bounded self-call for initial atomic attempt:
│     │  try this.routePendingSlashFunds(proposalId)
│     │  │
│     │  │  ┌─── routePendingSlashFunds() ───────────────────────┐
│     │  │  │  require(msg.sender == address(this))              │
│     │  │  │  → Self-call only (for try/catch atomicity)        │
│     │  │  │  require(route.pending)                            │
│     │  │  │  route.pending = false before interactions         │
│     │  │  │  → Callback cannot consume the reserve twice       │
│     │  │  │  → Any later revert restores pending=true          │
│     │  │  │                                                    │
│     │  │  │  Step A: Move collateral from BondingRegistry      │
│     │  │  │    bondingRegistry.redirectReservedSlashedTicketFunds(
│     │  │  │      proposalId                                     │
│     │  │  │    )                                                │
│     │  │  │    ├─ Load the exact amount and frozen destination  │
│     │  │  │    │  for (manager, proposalId)                     │
│     │  │  │    ├─ reservedSlashedTicketBalance -= amount        │
│     │  │  │    ├─ slashedTicketBalance -= amount                │
│     │  │  │    └─ ticketToken.payout(e3RefundManager, amount)   │
│     │  │  │       → Transfers the underlying collateral asset   │
│     │  │  │         to the E3RefundManager contract             │
│     │  │  │       → Reverts unless the manager receives the     │
│     │  │  │         complete amount                             │
│     │  │  │       → Uses payableBalance incremented by          │
│     │  │  │         burnTickets() during slashTicketBalance     │
│     │  │  │                                                     │
│     │  │  │  Step B: Update escrow accounting                   │
│     │  │  │    interfold.escrowSlashedFunds(                    │
│     │  │  │      e3Id, proposalId, operator, token, amount      │
│     │  │  │    )                                                │
│     │  │  │    → e3RefundManager.escrowSlashedFunds(            │
│     │  │  │        e3Id, proposalId, operator, token, amount)   │
│     │  │  │      │                                              │
│     │  │  │      ├─ Record the proposal target, token, and amount│
│     │  │  │      ├─ _pendingSlashedByToken[e3Id][token] += amt  │
│     │  │  │      ├─ tokenLiability[token] += amount             │
│     │  │  │      │   → Require balance >= protected liability   │
│     │  │  │      │                                              │
│     │  │  │      └─ If refund distribution IS calculated:       │
│     │  │  │          settle this proposal's pull claims now     │
│     │  │  │          → Never mutate fee-token refund buckets    │
│     │  │  │                                                     │
│     │  │  │  If EITHER step reverts → both revert together      │
│     │  │  │  → Route remains pending and funds stay reserved    │
│     │  │  │  → Slash itself still proceeds                      │
│     │  │  │  On success emit SlashRouteCompleted                │
│     │  │  └────────────────────────────────────────────────────┘
│     │
│     └─ catch: emit RoutingFailed(e3Id, actualTicketSlashed)
│        → Slash is NOT rolled back; anyone may retry the route
│
├─ 6. PERMISSIONLESS ROUTE RETRY (only after an initial failure):
│     anyone calls retrySlashRoute(proposalId)
│     ├─ pending == false → return false (idempotent no-op)
│     └─ pending == true → self-call routePendingSlashFunds
│        → transfer + accounting succeed atomically, or all state reverts
│
└─ 7. Emit SlashExecuted(proposalId, e3Id, operator, reason,
       actualTicketSlashed, actualCiphernodeBondSlashed, banned)
```

> **Asset transfer policy.** Fee and bonding assets must transfer exact amounts and must not rebase
> account balances. Ticket payouts, ciphernode bond transfers, refund-manager funding, and every
> claimant payment measure the recipient increase and custody decrease. A mismatch reverts the
> complete accounting transaction and preserves the other pooled liabilities.

### Proposal-Aware Slashed Funds Settlement (Failure Path)

```text
settleSlashedFunds(e3Id, proposalId):
│
├─ Read and clear the proposal's target, actual token, and exact amount
│
├─ Read current active committee nodes from the request-time registry
│   → Faulty operators expelled by failure-triggering policies are excluded
│
├─ If active honest nodes exist:
│   divide the proposal amount among them
│   → exclude this proposal's target from its own penalty proceeds
│   → hold only a recipient share covered by an unresolved expulsion
│   → other recipients receive their claims immediately
│   → deterministic last-node dust assignment
│
├─ Otherwise:
│   credit the whole actualToken amount to the snapshotted treasury
│   → no requester windfall beyond return of their original fee escrow
│
├─ Credit _pendingSlashedClaims[e3Id][actualToken][recipient]
│   → Base fee-token RefundDistribution fields never change
│   → Decimal/unit differences cannot corrupt the base refund
│
└─ Emit SlashedFundsApplied(e3Id, actualToken,
       0, toHonestNodes)

Design rationale:
  Supplier/ciphernode failures already return 100% of the requester's service
  fee escrow. Ticket slashes compensate honest service providers in the slash
  asset itself. No trusted conversion price is needed, and requester-fault
  failures do not gain a slash-funded rebate for costs they caused.
```

### Slashed Funds Distribution (Success Path): distributeSlashedFundsOnSuccess()

```text
distributeSlashedFundsOnSuccess(e3Id, paymentToken):
│
├─ Called by Interfold._distributeRewards() when E3 completes successfully
│
├─ Mark success settlement ready
├─ Every proposal settles independently via
│   settleSlashedFunds(e3Id, proposalId)
│
├─ Load the immutable E3PolicySnapshot captured by Interfold.request
│   (allocation, treasury, Interfold, registry, bonding registry, policy version)
├─ Read activeNodes from the request-time registry at settlement time
│   → Expelled nodes cannot receive a later slash-funded bonus
│   → The proposal target cannot receive its own penalty proceeds
│   → An unresolved accused share is held without blocking peer claims
├─ Split using snapshot.allocation.successSlashedNodeBps (default 5000):
│   toNodes = escrowed * successSlashedNodeBps / 10000
│   toTreasury = escrowed - toNodes
│   → Each proposal is rounded separately
│   → Percentage remainder goes to the treasury
│
├─ Credit (pull-payment, H-01/M-02) — funds are NOT pushed here:
│   for node in activeNodes:
│       perNode = toNodes / eligibleNodes
│       division remainder → final eligible node in canonical address order
│       recipient = rewardRecipient[e3Id][node]
│       _pendingSlashedClaims[e3Id][actualToken][recipient] += perNode
│       Emit SlashedFundsCredited(e3Id, recipient, actualToken, perNode)
│
├─ Credit treasury for protocol share:
│   _pendingTreasury[snapshot.treasury][actualToken] += toTreasury
│   Emit TreasurySlashedCredited(snapshot.treasury, actualToken, toTreasury)
│
└─ Emit SlashedFundsDistributedOnSuccess(e3Id, actualToken,
       toNodes, toTreasury)

Claim flow (separate transactions, pull-only):
  bond owner      → e3RefundManager.claimSlashedFunds(e3Id, actualToken)
                    → Emits SlashedFundsClaimed(e3Id, owner, token, amt)
  protocol treasury → e3RefundManager.treasuryClaim(token)
                    → Emits TreasurySlashedClaimed(treasury, token, amt)

Design rationale:
  On success the requester got their computation. Slashed funds are
  split between honest committee members (reward for completing despite
  a slashed peer) and the protocol treasury. Both shares use a per-recipient
  pull ledger so a single failing recipient (e.g. blacklisted ERC-20 address)
  cannot brick the success-path or strand other claimants' funds.
  Governance changes to the live allocation or treasury increment policyVersion
  and apply only to later E3 requests; existing snapshots never migrate implicitly.

Rounding policy:
  Every slash proposal settles as a separate route. The node percentage uses
  floor division for that route, and the treasury receives its percentage
  remainder. This can give nodes at most one fewer base unit per additional
  route than one aggregate calculation. The node share is then divided in
  canonical committee order. The final eligible node receives that division
  remainder on both success and failure paths. This bounded bias avoids extra
  remainder and cursor state, and no token value is lost.
```

### Dependency generation replacement

The protocol does not run old and new registry generations concurrently. Governance uses this
sequence:

1. Pause new E3 requests.
2. Let every active E3 reach `Complete` or `Failed`.
3. Release every terminal committee and close every terminal slashing assignment.
4. Deregister all operators, settle matured ticket exits, clear bans, and finish slash routes.
5. Replace the dependency pointers and ticket-token registry only after all drain counters are zero.
6. Wire the complete reciprocal graph, validate it, and enable requests.

`Interfold` rejects every request while paused and validates the full dependency graph before each
accepted request. The graph includes reciprocal Interfold, committee registry, bonding registry,
slashing manager, refund manager, and ticket-token pointers. It also requires the committee and
bonding registries to report the same operator count. Component setters reject a replacement while
their generation still owns live state. This prevents mixed-generation membership, slash routing,
callbacks, and eligibility.

Each E3 still snapshots its graph for internal routing. That snapshot protects lifecycle calls
during the drain. It is not permission to enable a replacement generation early.

### Slashed Funds Ordering: Escrow → Terminal State Resolution

```text
Slashing always records a proposal route and its token aggregate, regardless of the current E3
stage. Settlement never substitutes the E3 fee token.

── FAILURE PATH ──────────────────────────────────────────────

Case 1: Slash happens BEFORE processE3Failure
  → escrowSlashedFunds sees !dist.calculated
  → Funds remain on their proposal route with their actual token protected
  → After processE3Failure, anyone settles that proposal by proposalId

Case 2: Slash happens AFTER processE3Failure
  → escrowSlashedFunds sees dist.calculated
  → proposal-specific honest-node/treasury pull credits are created immediately
  → Base refund claims may already have started; ledgers remain independent

Case 3: Multiple slashes on same E3 (failure)
  → Each slash independently escrows funds
  → Every proposal retains its target, token, amount, and independent settlement
  → Every token retains an independent claim and liability ledger

── SUCCESS PATH ──────────────────────────────────────────────

Case 4: E3 completes successfully with escrowed slashed funds
  → _distributeRewards calls distributeSlashedFundsOnSuccess
  → Enables per-proposal permissionless settlement
  → Reads active nodes from the request-time registry when each proposal settles
  → Nodes receive successSlashedNodeBps portion (default 50%)
  → Treasury receives the remainder
```

### Slash Policy Configuration

```text
SlashPolicy {
  ticketPenalty:    uint256   // tickets to slash (in base units)
  ciphernodeBondPenalty:   uint256   // FOLD to slash
  requiresProof:   bool      // Lane A (true) or Lane B (false)
  proofVerifier:    address   // verifier address (Lane A: used in policy lookup)
  banNode:          bool      // permanently ban operator
  appealWindow:     uint256   // seconds; required for Lane B, optional for Lane A
  enabled:          bool      // policy active
  affectsCommittee: bool      // expel from E3 committee
  failureReason:    uint8     // retained ABI field: 0 or InsufficientCommitteeMembers
}

Constraints:
- If requiresProof: appealWindow may be 0 (atomic) or > 0 (deferred challenge)
- If !requiresProof: appealWindow must be > 0 (delayed execution, with appeal)
- At least one penalty must be non-zero
- failureReason is 0 or `InsufficientCommitteeMembers`
- a nonzero failureReason requires affectsCommittee=true
- execution always uses `InsufficientCommitteeMembers` when an expulsion breaks viability
  → stored policies with older supplier reasons remain readable, but cannot change attribution

Slash Reasons (derived from ProofType for Lane A):
  reason = keccak256(abi.encodePacked(proofType))
  ┌─────────────────┬──────────────────────────┐
  │ ProofType       │ Slash Reason             │
  ├─────────────────┼──────────────────────────┤
  │ C0, C1-C4       │ E3_BAD_DKG_PROOF         │
  │ C5              │ E3_BAD_PK_AGGREGATION    │
  │ C6              │ E3_BAD_DECRYPTION_PROOF   │
  │ C7              │ E3_BAD_AGGREGATION_PROOF │
  └─────────────────┴──────────────────────────┘
```

### End-to-End: Proof Failure → On-Chain Slash

```text
┌─────────────────────────────────────────────────────────────────┐
│              Complete Proof-to-Slash Pipeline                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. PROOF GENERATION (each committee member)                   │
│     ProofRequestActor generates & signs C0-C7 proofs           │
│     → Broadcasts signed proofs via P2P gossip                  │
│                                                                │
│  2. PROOF VERIFICATION (each receiving committee member)       │
│     ProofVerificationActor (C0) / ShareVerificationActor       │
│     (C2/C3/C4/C6)                                              │
│     ├─ Phase 1: ECDSA signature validation (inline)            │
│     └─ Phase 2: ZK proof verification (multithread)            │
│                                                                │
│  3. FAILURE DETECTION                                          │
│     If verification fails → SignedProofFailed event            │
│                                                                │
│  4. ACCUSATION (AccusationManager, per-E3 actor)               │
│     ├─ Create ProofFailureAccusation (signed, broadcast)       │
│     ├─ Cast own vote (agrees=true)                             │
│     └─ Start 300s timeout                                      │
│                                                                │
│  5. VOTING (all committee members)                             │
│     ├─ Receive accusation via P2P                              │
│     ├─ Check own verification cache                            │
│     ├─ Cast AccusationVote (signed, broadcast)                 │
│     └─ Each vote independently verified by all nodes           │
│                                                                │
│  6. QUORUM (AccusationManager)                                 │
│     ├─ votes_for >= threshold_m → AccusedFaulted/Equivocation  │
│     └─ AccusationQuorumReached event published                 │
│                                                                │
│  7. ON-CHAIN SUBMISSION (SlashingManagerSolWriter)             │
│     ├─ Defers replayed intents until EffectsEnabled            │
│     ├─ Coalesces the contract replay tuple while in flight     │
│     ├─ Staggered: rank 0 submits immediately                   │
│     │   ranks 1+ wait rank×30s as fallback                     │
│     ├─ Encodes attestation evidence (votes + signatures)       │
│     └─ Calls SlashingManager.proposeSlash(e3Id, operator, proof)│
│                                                                │
│  8. ON-CHAIN VERIFICATION (Lane A, atomic)                     │
│     ├─ Verify each voter's ECDSA signature                     │
│     ├─ Verify quorum (numVotes >= threshold_m)                 │
│     ├─ Verify voters are active committee members              │
│     └─ Execute slash immediately (no appeal)                   │
│                                                                │
│  9. PENALTIES                                                  │
│     ├─ Ticket balance slashed (active + exit queue)            │
│     ├─ Ciphernode bond slashed (active + exit queue)           │
│     ├─ Node banned (if policy requires)                        │
│     ├─ Committee member expelled                               │
│     └─ Slashed ticket collateral escrowed in E3RefundManager   │
│                                                                │
│  10. FUND DISTRIBUTION (at E3 terminal state)                  │
│      ├─ Failure: fee refund is fault-attributed; slashes pay   │
│      │           active honest nodes                           │
│      └─ Success: nodes + treasury split                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Slashed Funds: Escrow Model & Final Destinations

Slashed ticket funds are always escrowed first. Their final destination depends on the E3's terminal
state:

Before an upgrade that introduces proposal-scoped reservations, retry every legacy pending route
until `reservedSlashedTicketBalance` is zero. Fresh deployments need no route migration because each
reservation already records its manager, proposal, amount, and destination.

```text
STEP 1: ESCROWING (always, at slash time)
  Triggered by: _executeSlash → reserve + routePendingSlashFunds
  When: Any slash with actualTicketSlashed > 0, regardless of E3 stage
  Flow: BondingRegistry.redirectReservedSlashedTicketFunds(proposalId)
    → loads the proposal's frozen refund manager and exact amount
    → ticketToken.payout(refundManager, amount)
    → require the full ticket underlying amount reaches E3RefundManager
    → preserve (e3Id, proposalId, target, actualToken, amount)
    → _pendingSlashedByToken[e3Id][actualToken] += amount
    → tokenLiability[actualToken] protects the balance
  Effect: slashedTicketBalance goes UP (during slash) then DOWN (during redirect)
  Failure: route stays pending and the same amount remains reserved against
    other managers and treasury withdrawal until permissionless retry succeeds

STEP 2a: E3 FAILS → Token-specific compensation
  Triggered by: terminal escrow or permissionless settleSlashedFunds
  Flow: settleSlashedFunds(e3Id, proposalId)
    → The proposal's actual-token slash is divided among active honest nodes
    → The target is excluded only from its own penalty proceeds
    → Shares under unresolved expulsion proposals remain held
    → If there are no honest recipients, the slash goes to the
      snapshotted treasury
    → Credits stay in actualToken; fee-token refund buckets are unchanged
  Claims: claimSlashedFunds(e3Id, actualToken)

STEP 2b: E3 SUCCEEDS → Nodes + Treasury split
  Triggered by: _distributeRewards → distributeSlashedFundsOnSuccess
  Flow: each proposal amount split by successSlashedNodeBps
    → Nodes receive their share evenly (with dust to last)
    → Proposal targets and expelled operators do not receive slash proceeds
    → Only an unresolved accused share waits for its outcome
    → Treasury receives the remainder
  Effect: the proposal route is cleared and its token aggregate decreases

FALLBACK: RETRY, NOT OWNER RELABELING
  Failed routes remain reserved in BondingRegistry and retryable by anyone.
  E3RefundManager has no owner function that accepts an arbitrary token to
  relabel an untyped amount. Its transfer helper preserves each token's
  protected slash liability after base refunds and treasury claims, and it
  reverts unless each claimant receives the complete recorded amount.

Ciphernode bond slashes always go to treasury (no escrow routing for FOLD).
```

---

## Rust-Side Handling

```text
When CommitteeMemberExpelled event arrives from EVM:
│
├─ Event initially has party_id: None (not resolved yet)
│
├─ Sortition actor (party_id enrichment):
│   ├─ Receives raw CommitteeMemberExpelled { party_id: None }
│   ├─ Looks up the expelled node's address in the stored Committee
│   │   → Committee::party_id_for(addr) provides O(1) lookup
│   ├─ Re-publishes enriched CommitteeMemberExpelled { party_id: Some(id) }
│   └─ Ignores already-enriched events (party_id.is_some()) to avoid loops
│
├─ ThresholdKeyshare (receives enriched event):
│   ├─ Ignores raw events (party_id: None) — waits for Sortition enrichment
│   ├─ On enriched event (party_id: Some(id)):
│   │   ├─ Removes party_id from EncryptionKeyCollector
│   │   │   → May trigger aggregation if enough keys remain
│   │   └─ Removes party_id from ThresholdShareCollector
│   │       → May trigger share processing with reduced set
│   └─ Does NOT hold committee state — fully delegated to Sortition
│
├─ PublicKeyAggregator (aggregator, receives raw event):
│   ├─ Only processes raw events (party_id: None)
│   ├─ Ignores enriched events (party_id: Some) to avoid double-processing
│   └─ Reduces threshold_n
│   └─ May trigger aggregation if enough keyshares collected
│
├─ KeyshareCreatedFilterBuffer (aggregator):
│   ├─ Only processes raw events (party_id: None)
│   └─ Stores the expelled node as `alloy::Address` and removes/blocks keyshares by parsed
│       address, so differently cased self-reported node strings cannot bypass expulsion
│
└─ When a terminal non-slashing E3Failed / E3StageChanged(Complete) arrives:
    │
    ├─ E3Router (central cleanup orchestrator):
    │   ├─ E3Failed with a timeout, requester, or external-provider reason
    │   │   (CommitteeFormationTimeout, DKGTimeout, ComputeTimeout,
    │   │   DecryptionTimeout, NoInputsReceived, ComputeProviderExpired,
    │   │   ComputeProviderFailed, RequesterCancelled) → publishes E3RequestComplete
    │   │   → Single cleanup signal for all per-E3 actors
    │   │   NOTE: E3Failed with a misbehaviour reason (DKGInvalidShares, etc.) does
    │   │   NOT trigger E3RequestComplete — the accusation/slashing lifecycle must
    │   │   complete first.
    │   └─ E3StageChanged(Failed) and the same non-slashing E3Failed arriving after teardown
    │       are silently ignored (expected on-chain lag)
    │
    ├─ CommitteeFinalizer (direct handler — semantic work):
    │   └─ Cancels any pending committee-finalization timer for this e3_id
    │       → Prevents stale timer from firing after E3 is already terminal
    │
    ├─ Sortition (direct handler — semantic work):
    │   ├─ Decrements active job counts for each committee member
    │   │   → Frees up sortition tickets for future E3s
    │   └─ Removes e3_id from finalized_committees map
    │       → Prevents unbounded memory growth
    │
    └─ E3RequestComplete propagates to all per-E3 actors:
        ├─ ThresholdKeyshare: receives Die → actor stops
        ├─ PublicKeyAggregator: receives Die → actor stops
        ├─ ThresholdPlaintextAggregator: receives Die → actor stops
        ├─ KeyshareCreatedFilterBuffer: receives Die → actor stops
        ├─ CiphernodeSelector: cleans e3_cache entry for this e3_id
        └─ E3Router: removes E3Context for this e3_id
```

When a proof-fault quorum is reached while its on-chain policy is disabled, the writer publishes a
separate `CommitteeMemberExcluded` event. Sortition resolves its stable `party_id` from the same
immutable `CommitteeFinalized` roster and republishes the enriched event. The keyshare collectors,
public-key aggregator, plaintext aggregator, and active-aggregator selector then treat that party as
unavailable for this E3. The final DKG proof still receives all N canonical committee addresses from
`CommitteeFinalized`; it never derives the proof-bound roster from the reduced keyshare set.

This fallback is availability-only. The excluded operator remains an active on-chain committee
member, can remain eligible for future E3s, and can receive any reward that the contracts still
assign to it. Enable the matching slash policy when the deployment requires economic punishment, an
on-chain reward hold, or registry expulsion.

---

## Cluster 6 Audit Addendum (SlashingManager Hardening)

Applied audit findings: **C-05, H-05, H-06, H-07, H-09, H-10, H-24, M-14, M-15, M-17, M-24, M-36**.

### Role & access (C-05, H-24, M-17)

- `SLASHER_ROLE` is administered by `GOVERNANCE_ROLE`, not `DEFAULT_ADMIN_ROLE`.
  `getRoleAdmin(SLASHER_ROLE) == GOVERNANCE_ROLE`. `addSlasher` / `removeSlasher` require
  `GOVERNANCE_ROLE` and emit only the standard `RoleGranted` / `RoleRevoked` events.
- Deploy scripts grant `GOVERNANCE_ROLE` explicitly (no implicit default-admin shortcut).
- `DEFAULT_ADMIN_ROLE` uses `AccessControlDefaultAdminRules(2 days, admin)` — two-step
  `beginDefaultAdminTransfer` → wait 2 days → `acceptDefaultAdminTransfer`.

### EIP-712 domain (H-10, M-24)

- SlashingManager declares `EIP712("InterfoldSlashing", "1")` so accusation signatures are bound to
  `verifyingContract` _and_ `chainId`. Signatures produced against a different deployment or chain
  are rejected with `InvalidSigner()`. Cross-deployment / cross-chain replay is blocked.

### Lane A challenge window (H-06)

- `proposeSlash` no longer auto-executes when the policy's `appealWindow > 0`. The proposal is
  recorded with `executableAt = block.timestamp + appealWindow` and an event with `lane = LaneA (0)`
  is emitted. The operator or its bond owner can call `fileAppeal` during that window; otherwise
  anyone may call `executeSlash` once it elapses.

### Unified open-proposal collateral gate (H-05, AUD H-03)

- `SlashingManager` tracks `_openProposalCount[operator]` for observability. It also opens one
  proposal-scoped lock in `BondingRegistry`. Successful execution, an upheld appeal, or terminal
  appeal expiry closes both records atomically.
- `BondingRegistry` reverts `OperatorUnderSlash()` on `removeTicketBalance`, `unbondCiphernode`,
  `deregisterOperator`, and `claimExits` while the gate is raised. Both active collateral and assets
  already queued for exit therefore remain slashable.
- For a split position, the equivalent owner-only `...For(operator)` calls have the same gate.
  Proposals, bans, evidence signatures, and slash execution remain keyed by the hot operator
  address; a ciphernode bond slash reduces the authorized owner's aggregate `totalBonded` credit.
  Separating keys therefore protects withdrawal authority but does not create a slashing escape
  hatch.
- The registry checks one local aggregate. It does not call current or retained managers during an
  exit. Rotation therefore cannot release collateral for an old manager's in-flight proposal, and a
  broken manager cannot freeze unrelated operators. Governance revokes an old manager only after its
  E3 assignments, proposal locks, bans, and pending routes are clear.
- A filed appeal cannot freeze collateral indefinitely: after the policy appeal window plus the
  seven-day governance resolution grace, `expireAppeal` permissionlessly upholds it and clears its
  gate.

Fresh deployments authorize only API-versioned managers that are already bound to the registry.
Before upgrading an existing deployment, drain or explicitly migrate every legacy proposal and ban;
an empty registry-owned aggregate must not replace live callback-only state.

### Pull-payment slashed funds (H-01, H-07, H-09)

- Slashed funds use their own `(e3Id, token, recipient)` pull-payment ledger rather than the normal
  reward or refund bucket. Node allocations use the recipient frozen at committee finalization.
  Recipients call `claimSlashedFunds(e3Id, token)`; failed-transfer recipients cannot grief other
  claims, different token decimals never mix, and late credits remain independently claimable.

### Two-step ban (M-14, M-15)

- `proposeBan` records the intent; `confirmBan` requires a **distinct** signer (M-14) before
  `BanStatus` flips. `cancelBan` rescinds the proposal. Legacy `updateBanStatus(_, true, _)` reverts
  `BanRequiresConfirmation()`. Unban remains single-step under `GOVERNANCE_ROLE`.

### Event lane field (M-36)

- `SlashProposed` and `SlashExecuted` carry a `Lane lane` field (`LaneA = 0`, `LaneB = 1`) so
  off-chain indexers can disambiguate the two paths without re-deriving from policy bits.

The Rust minimal ABI matches the current `SlashExecuted` signature, including `bool executed` and
`Lane lane` (`uint8` at the ABI boundary). The typed actor event keeps the fields required for
expulsion handling; the full contract log is also retained by the raw EVM observability fallback.

### Upgrade posture

- `SlashingManager` is **non-upgradeable** by design (transparent proxy removed). Migrations require
  redeployment + GOVERNANCE_ROLE rotation on `BondingRegistry`/`Interfold`.
- Install the entitlement-aware `E3RefundManager` only when no E3 or expelling proposal is in
  flight. Existing policy snapshots do not contain a slashing-manager address, and existing
  proposals cannot be backfilled safely. Fresh deployments need no migration.
