# Interfold Protocol — Complete Flow Trace

## Index

| #   | File                                                                   | Covers                                                                                                                                                                                                                                                                                                                                                                |
| --- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | [01_REGISTRATION.md](01_REGISTRATION.md)                               | `setup`, `register`, `activate`, `status` CLI commands. On-chain registration into BondingRegistry → CiphernodeRegistry IMT. Rust-side event detection.                                                                                                                                                                                                               |
| 2   | [02_TOKENS_AND_ACTIVATION.md](02_TOKENS_AND_ACTIVATION.md)             | FOLD license bonding, USDC→tFOLD ticket purchasing, unbonding, burning, exit queue, claiming. Activation thresholds and the `_updateOperatorStatus` formula.                                                                                                                                                                                                          |
| 3   | [03_E3_REQUEST_AND_COMMITTEE.md](03_E3_REQUEST_AND_COMMITTEE.md)       | E3 request on-chain flow, fee payment, committee request, IMT snapshot. Rust-side sortition (score-based), on-chain ticket submission, committee finalization, `CiphernodeSelected` event.                                                                                                                                                                            |
| 4   | [04_DKG_AND_COMPUTATION.md](04_DKG_AND_COMPUTATION.md)                 | Full DKG with ZK proof pipeline: BFV keygen → C0 proof → encryption key exchange → TrBFV share generation → C1/C2/C3 proofs → share verification → Shamir secret sharing → encrypted share broadcast → C4 proofs → decryption key reconstruction. C5 proof for PK aggregation. Ciphertext output → C6 proof for decryption shares → C7 proof for plaintext → rewards. |
| 5   | [05_FAILURE_REFUND_SLASHING.md](05_FAILURE_REFUND_SLASHING.md)         | Timeout-based failure detection, `markE3Failed`, `processE3Failure`. Refund calculation (work-value allocation). Off-chain AccusationManager quorum protocol (proof failure → accusation → voting → quorum). Lane A (attestation-based, atomic) and Lane B (evidence-based, with appeals) slashing. Ticket/license slashing. Slashed funds escrow and routing.        |
| 6   | [06_DEACTIVATION_AND_COMPLETION.md](06_DEACTIVATION_AND_COMPLETION.md) | Voluntary deactivation (ticket/license withdrawal), full deregistration (IMT removal), E3 happy-path completion, node shutdown, sync/restart, exit queue timing, ban/unban.                                                                                                                                                                                           |

---

## End-to-End Happy Path Summary

```
1. SETUP        interfold ciphernode setup
                  → Config, password, private key stored locally

2. BOND         interfold ciphernode license bond --amount N
                  → FOLD tokens locked in BondingRegistry

3. TICKETS      interfold ciphernode tickets buy --amount N
                  → USDC → InterfoldTicketToken (non-transferable)

4. REGISTER     interfold ciphernode register
                  → BondingRegistry.registerOperator()
                  → CiphernodeRegistry.addCiphernode() (IMT insert)
                  → If bond+tickets meet thresholds → active=true

5. START        interfold start
                  → Node boots, syncs historical events, starts listening

6. E3 REQUEST   Requester calls Interfold.request(params)
                  → Fee paid, committee requested, IMT root snapshot

7. SORTITION    Ciphernodes compute scores, submit tickets on-chain
                  → Top N lowest scores selected

8. FINALIZE     Committee members schedule staggered finalizeCommittee() calls
                  → first successful call locks committee in canonical on-chain order

9. DKG          Selected nodes perform distributed key generation:
                  a. BFV keygen → C0 proof (proves keypair valid)
                  b. Exchange BFV public keys (C0 verified on receipt)
                  c. TrBFV key + Shamir shares → C1/C2a/C2b/C3a/C3b proofs
                  d. Broadcast ThresholdShareCreated (all proofs attached)
                  e. Collect shares → verify C2/C3 proofs (2-phase)
                  f. Decrypt shares → calc decryption key → C4a/C4b proofs
                  g. Exchange DecryptionKeyShared → verify C4 proofs
                  h. Publish KeyshareCreated → all committee members buffer it

10. PK AGG      All committee members buffer keyshares
                  → Rust normalizes finalized committee into ascending ticket-score order
                  → active aggregator = lowest non-expelled party_id in that normalized order
                  → active aggregator aggregates pk_shares → C5 proof
                  → permissionless publishCommittee() on-chain → KeyPublished stage

11. COMPUTE     Data encrypted with aggregate PK, computation runs
                  → Ciphertext output published on-chain

12. DECRYPT     Committee members produce decryption shares
                  → C6 proof per share (proves share correctly derived)
                  → broadcast to all committee members for buffering

13. AGGREGATE   Active aggregator combines M+1 shares → plaintext
                  → C7 proof (proves reconstruction correct)

14. COMPLETE    Active aggregator permissionlessly calls publishPlaintextOutput()
                  → rewards distributed
                  → Each active committee member gets fee / N
                  → Any escrowed slashed funds split:
                    nodes (successSlashedNodeBps) + treasury

15. DEREGISTER  interfold ciphernode deregister --proof X
                  → All collateral queued for exit
                  → Removed from IMT
                  → After exitDelay: claim USDC + FOLD back
```

## End-to-End Failure Path Summary

```
1-9.  Same as happy path through DKG (proofs generated at each step)

10.   PROOF FAIL  A committee member submits an invalid proof (C0-C7)
                    → ProofVerificationActor / ShareVerificationActor detects
                    → SignedProofFailed triggers AccusationManager
                  OR: Commitment consistency mismatch detected (cross-circuit)
                    → CommitmentConsistencyChecker publishes CommitmentConsistencyViolation
                    → Also triggers AccusationManager

11.   ACCUSATION  AccusationManager creates ProofFailureAccusation
                    → Signed and broadcast via P2P gossip
                    → Accuser casts own vote (agrees=true)

12.   VOTING      Committee members receive accusation
                    → Check own verification cache
                    → Cast signed AccusationVote (agree/disagree)
                    → Broadcast via P2P gossip

13.   QUORUM      AccusationManager detects quorum:
                    → votes_for >= threshold_m → AccusedFaulted/Equivocation
                    → Publishes AccusationQuorumReached

14.   SLASH SUB   SlashingManagerSolWriter submits on-chain:
                    → Staggered: rank 0 immediately, rank N waits N×30s
                    → Calls SlashingManager.proposeSlash(e3Id, operator, proof)

15.   ON-CHAIN    SlashingManager verifies attestation evidence:
                    → ECDSA signature verification per voter
                    → Quorum check (numVotes >= threshold_m)
                    → Atomic execution: slash + ban + expel

──────── OR: TIMEOUT-BASED FAILURE ────────────────────────────

10b.  TIMEOUT     A deadline is missed (committee, DKG, compute, or decryption)
                    → Anyone calls markE3Failed(e3Id)

──────── THEN: REFUND PROCESSING ──────────────────────────────

16.   PROCESS     Anyone calls processE3Failure(e3Id)
                    → Payment transferred to E3RefundManager
                    → Work-value allocation calculated (BPS-based)

17.   REFUND      Requester claims proportional refund
                    Honest nodes claim proportional compensation
                    Protocol treasury gets 5%

18.   SLASHED $   If slashed funds escrowed:
                    → Failure: requester filled FIRST, surplus → honest nodes
                    → Success: nodes + treasury split (successSlashedNodeBps)
```

## Contract Interaction Map

```
┌──────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   Interfold    │────→│ CiphernodeRegistry   │────→│ BondingRegistry │
│  (orchestr.) │←────│  (IMT, committees)   │←────│ (stakes, exits) │
└──────┬───────┘     └──────────┬───────────┘     └────────┬────────┘
       │                        │                          │
       │              ┌─────────┴──────────┐     ┌─────────┴────────┐
       │              │  SlashingManager   │────→│ InterfoldTicketTkn │
       │              │  (fault, penalties) │     │ (USDC wrapper)   │
       │              └─────────┬──────────┘     └──────────────────┘
       │                        │
       │                        │ escrowSlashedFundsToRefund:
       │                        │   BondingRegistry.redirectSlashedTicketFunds
       │                        │   → ticketToken.payout(refundMgr, USDC)
       │                        │   Interfold.escrowSlashedFunds
       │                        ▼
       ├────→ E3Program (validate, verify computation)
       ├────→ DecryptionVerifier (verify plaintext)
       └────→ E3RefundManager (failure refunds + slashed funds escrow/distribution)
                    │
                    └────→ Requester + Honest Nodes (claim refunds)
                           Active Nodes + Treasury (slashed funds on success)
```

---

## Verified Bugs & Protocol Concerns

_Found during source-code cross-referencing of these trace documents._

### Critical Doc Inaccuracies (now fixed)

| #   | Description                                                                                                                                                                                                                                                    | Where                             | Fix Applied     |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | --------------- |
| 1   | `addTicketBalance` does NOT multiply by `ticketPrice` — raw stablecoin units are passed directly to `ticketToken.depositFrom()`. `ticketPrice` is only used in the activation check.                                                                           | BondingRegistry.sol:371           | 02_TOKENS       |
| 2   | `removeTicketBalance` does NOT multiply by `ticketPrice` — raw amount passed to `ticketToken.burnTickets()`.                                                                                                                                                   | BondingRegistry.sol:395           | 02_TOKENS       |
| 3   | `gracePeriod` is NOT added to deadline checks in `_checkFailureCondition()`. All timeout checks compare `block.timestamp` directly against the raw deadline. `gracePeriod` is only validated in `_setTimeoutConfig` but never referenced in failure detection. | Interfold.sol:860-887             | 05_FAILURE      |
| 4   | `activate()` calls `register()` → `registerOperator()` which has `require(!registered, AlreadyRegistered())`. So activate **reverts** for already-registered operators. It only works for re-registration after deregistration.                                | BondingRegistry.sol:308           | 01_REGISTRATION |
| 5   | `E3Requested` event is `(uint256 e3Id, E3 e3, IE3Program indexed e3Program)` — seed and params are inside the E3 struct, not separate parameters.                                                                                                              | IInterfold.sol:82                 | 03_E3_REQUEST   |
| 6   | `finalizeCommittee()` checks `>=` deadline, not `>`.                                                                                                                                                                                                           | CiphernodeRegistryOwnable.sol     | 03_E3_REQUEST   |
| 7   | `publishCommittee()` is now permissionless. The effective access control is DKG proof verification plus the single-publish guard `publicKeyHashes[e3Id] == 0`; the old `onlyOwner` note is obsolete.                                                           | CiphernodeRegistryOwnable.sol     | 04_DKG          |
| 8   | `CommitteePublished` event emits `(e3Id, nodes, publicKey, pkCommitment, proof)` — full PK bytes, pkCommitment, and proof bytes (DkgAggregator when proof aggregation is enabled), not just pkHash.                                                            | CiphernodeRegistryOwnable.sol     | 04_DKG          |
| 9   | `_validateNodeEligibility` calls `bondingRegistry.getTicketBalanceAtBlock()` (not `ticketToken.getPastVotes()` directly).                                                                                                                                      | CiphernodeRegistryOwnable.sol:668 | 03_E3_REQUEST   |
| 10  | Lane A slashing uses **attestation-based** verification (committee quorum votes), not direct ZK proof re-verification on-chain. `proposeSlash()` decodes voter addresses, agrees, data hashes, and ECDSA signatures — not ZK proofs.                           | SlashingManager.sol               | 05_FAILURE      |

### Protocol Design Concerns

| #   | Concern                                    | Severity | Detail                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --- | ------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Deregister-before-slash race**           | Accepted | SlashingManager Lane B (evidence+appeal) has a window during which the operator can deregister and claim their exit. If they do, the slash executes against 0 funds. The contract comments acknowledge this as an accepted tradeoff for the appeal window design.                                                                                                                                                                                                                                                                                                                             |
| 2   | **Committee publication decentralized**    | Resolved | `publishCommittee()` is permissionless. Off-chain role selection chooses the active aggregator, while on-chain C5 proof verification and the single-publish guard prevent invalid or duplicate committee publication.                                                                                                                                                                                                                                                                                                                                                                         |
| 3   | **`gracePeriod` is dead code**             | Medium   | `gracePeriod` is stored and validated during config updates but never actually used in any timeout check. Either the deadlines already bake in sufficient buffer, or this is a missing feature.                                                                                                                                                                                                                                                                                                                                                                                               |
| 4   | **`activate` CLI command is misleading**   | Low      | Named "activate" but actually calls "register" — will fail for already-registered operators. There's no standalone way to trigger re-evaluation of active status; instead, `_updateOperatorStatus()` runs automatically inside `addTicketBalance()`, `bondLicense()`, etc.                                                                                                                                                                                                                                                                                                                    |
| 5   | **Active-job load balancing bug fixed**    | Info     | The Rust `NodeStateStore.available_tickets()` subtracts `active_jobs` from total tickets, reducing the chance of busy nodes being selected for new E3s. Previously, the `Sortition` actor's `Handler<InterfoldEvent>` was missing match arms for `E3Failed` and `E3StageChanged`, causing these events to fall to the default `_ => ()` — the typed handlers for decrementing jobs were dead code. This has been fixed: E3Failed and E3StageChanged are now routed to their handlers, and `finalized_committees` is cleaned up in `decrement_jobs_for_e3` to prevent unbounded memory growth. |
| 6   | **Committee member expulsion**             | Info     | `SlashingManager` can call `expelCommitteeMember()` mid-DKG. The `Sortition` actor enriches the raw `CommitteeMemberExpelled` event with the expelled member's `party_id` (resolved from its stored `Committee` list) and re-publishes it. `ThresholdKeyshare` then uses the enriched `party_id` to update its collectors, potentially completing DKG with fewer parties. `ThresholdKeyshare` itself does not hold committee state.                                                                                                                                                           |
| 7   | **ProofRequestActor failure bridge fixed** | Info     | `ProofRequestActor` no longer leaves proof publication suppressed under log-only "will not be published" exits. `ComputeRequestError` and local proof-signing failures for DKG-path proofs (`C0` through `C5`) now emit `E3Failed { failed_at_stage: CommitteeFinalized, reason: DKGInvalidShares }`, while decryption-path proofs (`C6` and `C7`) emit `E3Failed { failed_at_stage: CiphertextReady, reason: DecryptionInvalidShares }`.                                                                                                                                                     |
| 8   | **Settlement receipts isolated**           | Resolved | Durable EVM receipts such as `RewardCredited` and `RewardClaimed` are global audit/projection facts. The E3 router no longer sends them into a completed per-E3 context, so reward fan-out cannot reopen a finished E3 or produce false `AlreadyCompleted` failures.                                                                                                                                                                                                                                                                                                                          |
| 9   | **Replay-safe compute effects**            | Resolved | `ComputeEffectGate` subscribes before EventStore replay, buffers `ComputeRequest`s while effects are disabled, deduplicates equivalent requests, prefers the newest hydrated retry, cancels terminal E3 work, and releases pending effects only after `EffectsEnabled`. This closes the mid-E3 compute-loss window without changing durable event order.                                                                                                                                                                                                                                      |
| 10  | **DKG crash recovery (byte-identical)**    | Resolved | The DKG collectors (`ThresholdShareCollector`, encryption-key, decryption-key-share) wait for **all N** committee members and only short-circuit on an on-chain `CommitteeMemberExpelled`, never on a plain crash — so one silently-missing member would stall the whole DKG to its phase timeout. A restarted committee member now recovers **byte-identically only** (regenerating a share is unsafe: C3 re-randomises BFV encryption → equivocation/slashing). Three pieces: (1) `ThresholdKeyshare::resume_in_flight_work` publishes a `DkgDocumentResyncRequest` for in-flight DKG phases; (2) `NetSyncManager` answers it (and its own, on resume) by re-announcing the node's already-produced documents verbatim from the EventStore (`EncryptionKeyCreated`/`ThresholdShareCreated`/`DecryptionKeyShared`) + re-gossiping forwardable artifacts, so each member re-fetches the peer shares whose ephemeral DHT notifications it missed and re-delivers its own; (3) `CommitmentConsistencyChecker` rehydrates its verified-proof cache from the EventStore on startup (it is created late, on `CommitteeFinalized` replay) and buffers checks until rehydrated, so cross-circuit links (C0→C3) no longer false-accuse honest peers. Verified end-to-end: kill a committee member mid-DKG, restart → `KeyPublished`/`CommitteePublished`, zero `proposeSlash`/`E3Failed`. Residual: a crash in the brief window *before* a node's own share is ever produced/broadcast is a stall (nothing to re-announce; never a slash); the collectors still fail rather than tolerate a genuinely absent member. |
