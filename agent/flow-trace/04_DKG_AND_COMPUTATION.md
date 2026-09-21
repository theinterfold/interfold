# Part 4: DKG, Computation & Decryption

## Overview

After committee finalization, the selected ciphernodes perform Distributed Key Generation (DKG)
using threshold BFV (TrBFV) cryptography. This produces a collective public key without any single
party knowing the full secret key. Later, the committee produces decryption shares; all committee
members buffer them, and the active aggregator combines them. The runtime first normalizes the
finalized committee into ascending address order. The active aggregator is the lowest eligible
`party_id`. A party can be ineligible because of an on-chain expulsion, a proof-fault exclusion, or
a phase-local aggregator progress timeout.

Delegated bonding does not alter cryptographic identity. Every ECDSA proof signature is still made
by the hot operator key and verified against the operator address snapshotted into the committee.
The bond owner never signs DKG, key-publication, computation, or decryption messages.

---

## Phase 1: DKG — Distributed Key Generation

### Step 1: CiphernodeSelected → BFV Key Generation

**Actor:** `ThresholdKeyshare` (created by `ThresholdKeyshareExtension`)

```
CiphernodeSelected event arrives at ThresholdKeyshare
│
├─ Read `getDeadlines(e3Id)` and `getE3TimeoutConfig(e3Id)` from Interfold.
│  Require the E3 to be at `CommitteeFinalized`. Persist the frozen DKG
│  deadline and window before creating keys or collectors. Retry the read
│  if the RPC is unavailable; do not use a local window as a fallback.
│
├─ handle_ciphernode_selected():
│   │
│   ├─ 1. Generate fresh BFV keypair:
│   │     (secret_key, public_key) = BFV::keygen(share_encryption_preset)
│   │     → This is the node's SHARE ENCRYPTION key
│   │     → Used to encrypt Shamir shares sent to this node
│   │
│   ├─ 2. Encrypt BFV secret key at rest:
│   │     encrypted_sk = Cipher.encrypt(secret_key)
│   │     → Stored locally, password-protected
│   │
│   ├─ 3. State transition: Init → CollectingEncryptionKeys
│   │
│   ├─ 4. Publish EncryptionKeyPending {
│   │     e3_id, party_id, bfv_public_key
│   │   }
│   │   → ZK proof actor picks this up
│   │
│   ├─ 5. Create child actors:
│   │     ├─ EncryptionKeyCollector (accepts all N keys or at least H at cutoff)
│   │     └─ ThresholdShareCollector (accepts all N−1 external shares or at least H−1 at cutoff)
│   │     → These collectors start immediately so early peer keys/shares can
│   │       be buffered while this node is still finishing earlier DKG phases
│   │
│   └─ Collector schedules use the frozen per-E3 window and absolute deadline:
│         ├─ EncryptionKeyCollector: hard cutoff at 10% of the window
│         ├─ ThresholdShareCollector: soft cutoff at 75% of the window
│         └─ DecryptionKeySharedCollector: hard cutoff at the on-chain DKG deadline
│      Restart uses the remaining time, not a new full window. Optional
│      per-collector env values can advance a cutoff but cannot extend it.
│      At the threshold-share cutoff, a node that has at least H−1 external shares
│      starts verification from that snapshot and keeps the collector open. Later
│      shares extend the verified dealer set until all N−1 arrive or the on-chain
│      DKG deadline expires.
```

### Step 2: C0 Proof Generation → EncryptionKeyCreated

**Actor:** `ProofRequestActor` (`crates/zk-prover/src/proof_request/actor.rs`)

**Deterministic workflow:** pending proof state and canonical dispatch sequence planning live in
`crates/zk-prover/src/proof_request/{state,workflow,transitions}.rs`; `handlers.rs` owns mailbox
entry and the semantic files below `effects/` own correlation, signing, and compute dispatch.

```
ProofRequestActor receives EncryptionKeyPending
│
├─ 1. Creates ZK proof request:
│     ComputeRequest::zk(ZkRequest::PkBfv {
│       bfv_public_key, party_id, bfv_params
│     })
│     → Circuit: PkBfv (C0 — proves BFV keypair was generated correctly)
│
├─ 2. ZkActor (IO layer) receives ComputeRequest:
│     ├─ Writes witness data to temp directory
│     ├─ Spawns: bb prove -b circuit.json -w witness.gz -k vk -o proof/
│     │   → Barretenberg (bb) binary generates ZK proof
│     └─ Returns: Proof { data, public_signals }
│
├─ 3. ProofRequestActor receives ComputeResponse:
│     ├─ Signs proof via sign_proof():
│     │   digest = keccak256(abi.encode(
│     │     PROOF_PAYLOAD_TYPEHASH,
│     │     chainId, e3Id, proofType(C0),
│     │     keccak256(proof.data),
│     │     keccak256(proof.public_signals)
│     │   ))
│     │   signature = ecSign(digest, operator_private_key)
│     │   → 65-byte ECDSA signature (r||s||v)
│     │
│     └─ Publishes EncryptionKeyCreated {
│          e3_id, party_id, bfv_public_key,
│          signed_proof: SignedProofPayload { proof, signature }
│        }
│        → Broadcast to all nodes via libp2p gossip
│
└─ RECEIVING NODES verify C0 proof:
     ProofVerificationActor receives EncryptionKeyReceived (from P2P)
     │
     ├─ Resolves canonical party ownership plus BFV preset/committee artifact scope
     │   from startup-recovered verifier context; live lifecycle events refresh both caches
     ├─ Recovers ECDSA signer address from signed proof
     ├─ Dispatches ZK verification to ZkActor:
     │   ZkActor runs: bb verify -k vk -p proof.data
     │
     ├─ If verification PASSES:
     │   ├─ Publishes EncryptionKeyCreated (locally trusted)
     │   └─ Publishes ProofVerificationPassed (cached by AccusationManager)
     │
     └─ If verification FAILS:
         └─ Publishes SignedProofFailed { accused, proof_type: C0 }
            → Triggers accusation pipeline (see Part 5)
```

### Step 3: Collect Encryption Keys

```
EncryptionKeyCollector collects verified EncryptionKeyCreated events
│
├─ On each arrival: store the first (party_id → bfv_public_key) message;
│  replay keeps that same first message if a later duplicate arrives
│
├─ On TIMEOUT (derived DKG-phase cutoff):
│   ├─ With at least H keys, including this party's key:
│   │    send AllEncryptionKeysCollected with the available keys
│   └─ Otherwise send EncryptionKeyCollectionFailed to parent ThresholdKeyshare
│      ├─ ThresholdKeyshare persists KeyshareState::Failed {
│      │    failed_at_stage: CommitteeFinalized,
│      │    reason: DKGTimeout
│      │  }
│      ├─ ThresholdKeyshare republishes EncryptionKeyCollectionFailed for telemetry
│      ├─ ThresholdKeyshare emits E3Failed {
│      │    failed_at_stage: CommitteeFinalized,
│      │    reason: DKGTimeout
│      │  }
│      └─ ThresholdKeyshare actor stops
│
└─ When ALL N collected before cutoff:
    └─ Send AllEncryptionKeysCollected to parent ThresholdKeyshare
```

### Step 4: Generate TrBFV Key Shares + Shamir Secret Shares

```
ThresholdKeyshare receives AllEncryptionKeysCollected
│
├─ State: CollectingEncryptionKeys → GeneratingThresholdShare
├─ Stores the verified BFV public keys available at the cutoff
│
├─ COMPUTE REQUEST 1: GenPkShareAndSkSss
│   │
│   │  ┌─── TrBFV Computation ──────────────────────────────────┐
│   │  │                                                         │
│   │  │  Inputs: BFV params, party_id, threshold_m, threshold_n│
│   │  │                                                         │
│   │  │  Steps:                                                 │
│   │  │  1. Generate TrBFV secret key (sk) & public key share  │
│   │  │     → sk is this node's portion of the collective key   │
│   │  │     → pk_share is the public contribution               │
│   │  │                                                         │
│   │  │  2. Create Shamir Secret Shares of sk (sk_sss):        │
│   │  │     ShareManager::create_shares(sk, T, N)               │
│   │  │     → Splits sk into N shares; T+1 reconstruct         │
│   │  │     → One share per committee member                    │
│   │  │                                                         │
│   │  │  3. Generate smudging noise (e_sm_raw):                │
│   │  │     → Statistical security parameter                    │
│   │  │     → Prevents information leakage during decryption    │
│   │  │                                                         │
│   │  │  4. Extract raw polynomials for ZK proof:              │
│   │  │     pk0_share_raw, sk_raw, eek_raw                     │
│   │  │                                                         │
│   │  │  5. Encrypt all secrets with node's Cipher              │
│   │  │                                                         │
│   │  │  Output: pk_share, sk_sss[N], e_sm_raw, raw_polys     │
│   │  └─────────────────────────────────────────────────────────┘
│
└─ COMPUTE REQUEST 2: GenEsiSss (immediately after)
    │
    │  ┌─── TrBFV Computation ──────────────────────────────────┐
    │  │                                                         │
    │  │  Generate Shamir shares of Error Smudging Info (ESI):  │
    │  │  → Multiple sets, one per ciphertext                    │
    │  │  → Each set: N shares, T+1 threshold to reconstruct    │
    │  │                                                         │
    │  │  Output: esi_sss[num_ciphertexts][N]                   │
    │  └─────────────────────────────────────────────────────────┘
```

During restart replay, the durable `GenPkShareAndSkSss` and `GenEsiSss` responses can reach
`ThresholdKeyshare` before the rebuilt encryption-key collector reports completion. While effects
are disabled, the actor holds those exact responses. It applies them when their prerequisites are
restored instead of dispatching new randomized computations. An identical replay is idempotent; a
different response for the same stage fails closed.

    │
    ├─ ThresholdKeyshare tracks the correlation id for both TrBFV requests:
    │   ├─ `GenPkShareAndSkSss`
    │   └─ `GenEsiSss`
    │   → If the worker returns `ComputeRequestError` for either request,
    │     `ThresholdKeyshare` now emits `E3Failed {
    │       failed_at_stage: CommitteeFinalized,
    │       reason: DKGInvalidShares
    │     }` and stops instead of remaining stuck in `GeneratingThresholdShare`

### Step 5: Encrypt & Broadcast Shares (with C1, C2, C3 Proofs)

```
Both GenPkShareAndSkSss and GenEsiSss complete
    │
    ├─ `ThresholdKeyshare` tracks the `CalculateDecryptionKey` correlation id:
    │   → `ComputeRequestError` for this request now emits
    │     `E3Failed {
    │       failed_at_stage: CommitteeFinalized,
    │       reason: DKGInvalidShares
    │     }` and stops before C4 proof dispatch
│
├─ handle_shares_generated():
│   │
│   ├─ 1. Build an N-slot C3 fan-out in finalized committee order:
│   │     For each party with a collected C0 key, encrypt that party's share under its key.
│   │     For a party without a collected C0 key, encrypt its share under the sender's
│   │     C0 key to fill the C3 proof slot. Do not deliver that placeholder share.
│   │     Leave the sender's own slot empty (own plaintext rides locally into C4).
│   │     → BfvEncryptedShares::encrypt_all_extended_for_share_indices()
│   │     → C3 still proves all N-1 non-own slots; only parties with C0 keys get shares.
│   │
│   ├─ 2. Build ThresholdShare struct:
│   │     {
│   │       party_id,
│   │       pk_share,          // public key share (public)
│   │       encrypted_sk_sss,  // encrypted for each target party
│   │       encrypted_esi_sss  // encrypted for each target party
│   │     }
│   │
│   ├─ 3. Build proof requests for FIVE circuit types:
│   │     ├─ C1: PkGenerationProofRequest
│   │     │   → Proves TrBFV pk_share was generated correctly from sk
│   │     ├─ C2a: ShareComputationProofRequest (SK)
│   │     │   → Proves Shamir shares of sk were computed correctly
│   │     ├─ C2b: ShareComputationProofRequest (ESM)
│   │     │   → Proves Shamir shares of smudging noise were computed correctly
│   │     ├─ C3a: ShareEncryptionProofRequests (SK, one per recipient × row)
│   │     │   → Proves each sk_sss share was encrypted correctly under recipient's BFV key
│   │     └─ C3b: ShareEncryptionProofRequests (ESM, one per ESI × recipient × row)
│   │         → Proves each esi_sss share was encrypted correctly
│   │
│   ├─ 4. Publish ThresholdSharePending {
│   │       full_share, proof_request(C1),
│   │       sk_share_computation_request(C2a),
│   │       e_sm_share_computation_request(C2b),
│   │       sk_share_encryption_requests(C3a[]),
│   │       e_sm_share_encryption_requests(C3b[]),
│   │       recipient_party_ids // parties with collected C0 keys, not placeholder slots
│   │     }
│   │     → ProofRequestActor picks this up
│   │
│   └─ State: GeneratingThresholdShare → AggregatingDecryptionKey
```

### Step 5a: C1 + C2 + C3 Proof Generation

**Actor:** `ProofRequestActor`

```
ProofRequestActor receives ThresholdSharePending
│
├─ 1. Creates PendingThresholdProofs tracker:
│     expected = 1 (C1) + 1 (C2a) + 1 (C2b) + SK_ENC_COUNT (C3a) + ESM_ENC_COUNT (C3b)
│     → All proofs must complete before publishing ThresholdShareCreated
│
├─ 2. Dispatches ALL proof requests in parallel:
│     ├─ C1:  ComputeRequest::zk(ZkRequest::PkGeneration {...})
│     ├─ C2a: ComputeRequest::zk(ZkRequest::ShareComputation { kind: SK })
│     ├─ C2b: ComputeRequest::zk(ZkRequest::ShareComputation { kind: ESM })
│     ├─ C3a[i]: ComputeRequest::zk(ZkRequest::ShareEncryption { recipient, row })
│     │   → One per recipient party × modulus row
│     └─ C3b[i]: ComputeRequest::zk(ZkRequest::ShareEncryption { esi_idx, recipient, row })
│         → One per ESI × recipient party × modulus row
│
├─ 3. ZkActor generates proofs via bb binary (in parallel via multithread):
│     → Each proof takes 1-10 seconds depending on circuit complexity
│
├─ 4. As each ComputeResponse arrives:
│     ├─ Store proof in PendingThresholdProofs map
│     ├─ Check is_complete():
│     │   all of: pk_generation_proof(C1), sk_share_computation_proof(C2a),
│     │           e_sm_share_computation_proof(C2b),
│     │           ALL sk_share_encryption_proofs(C3a),
│     │           ALL e_sm_share_encryption_proofs(C3b)
│     └─ When ALL proofs complete (is_complete() → true):
│
├─ 5. Sign all proofs via sign_and_group_proofs():
│     → Each proof gets its own SignedProofPayload with ECDSA signature
│     → C3a/C3b proofs indexed by (real recipient_party_id, row_index)
│
├─ 6. Publish events:
│     ├─ PkGenerationProofSigned { e3_id, party_id, signed_proof(C1) }
│     ├─ DkgProofSigned { signed_proof } × (C2a, C2b, each C3a, each C3b)
│     └─ ThresholdShareCreated for each recipient with a collected C0 key {
│          e3_id, party_id, target_party_id,
│          threshold_share,               // pk_share + this recipient's encrypted shares
│          signed_sk_computation_proof,    // C2a
│          signed_esm_computation_proof,   // C2b
│          signed_sk_encryption_proofs,    // C3a[] for this recipient
│          signed_esm_encryption_proofs    // C3b[] for this recipient
│        }
│        → Broadcast to nodes via libp2p gossip; the recipient filters by target_party_id
│
└─ IMPORTANT: ThresholdShareCreated is NOT published until ALL proofs complete
   → Ensures no incomplete data is gossiped
```

**C2 proofs:** For each C2a/C2b request, the prover builds a **recursive** proof for
`sk_share_computation` / `e_sm_share_computation`. That `Proof` is what `PendingThresholdProofs`
stores and what gets ECDSA-signed for gossip (`ProofType::C2aSkShareComputation` /
`C2bESmShareComputation`). The old generic `recursive_aggregation/wrapper/*` circuits and two-proof
`recursive_aggregation/fold` were removed; aggregation is done by ad-hoc Noir bins under
`circuits/bin/recursive_aggregation/` (e.g. `c2ab_fold`, `c3ab_fold`, `c6_fold`, `node_fold`,
`nodes_fold`, `dkg_aggregator`, `decryption_aggregator` — `nodes_fold` chains `H` `node_fold` proofs
for `dkg_aggregator`; `decryption_aggregator` folds C6 via non-ZK `c6_fold` then checks C7 with ZK).
The per-circuit `wrapper/` Noir step was removed; aggregator response structs no longer carry a
`wrapped_proof` field — the inner recursive proof itself is what flows between stages.

**Ciphernode / aggregator integration:** `ZkRequest::FoldProofs` was removed. The multithread actor
implements `ZkRequest::NodeDkgFold` (full per-node pipeline to a `NodeFold` proof),
`ZkRequest::DkgAggregation` (`NodesFold` + C5 + `DkgAggregator`), and
`ZkRequest::DecryptionAggregation` (per-ciphertext `C6Fold` + C7 + `DecryptionAggregator`).
`NodeProofAggregator` prebuffers `DKGInnerProofReady` proofs that arrive before
`ThresholdSharePending`, drains those buffered proofs into collection state once
`ThresholdSharePending` arrives, and issues one `NodeDkgFold` request when the full ordered proof
set is available. It persists each proof, the fold metadata, and a completed output before
publication. Restart restores the ordered proofs and reissues an incomplete fold after
`EffectsEnabled`. A local worker failure keeps the saved node-fold data. The compute scheduler
retries the exact request until the E3 becomes terminal. A canonical `KeyPublished` stage or a
terminal E3 event removes the saved node-fold data. `PublicKeyAggregator` and
`ThresholdPlaintextAggregator` dispatch the aggregator requests instead of pairwise folding.

**Failure boundary:** A local prover or verifier process failure is not proof that a peer supplied
invalid data. The compute scheduler retries `ProofGenerationFailed` requests. Attempts after the
first use Barretenberg low-memory mode. Pending proof inputs and correlation IDs remain available
for restart replay. A local worker failure does not emit `DKGInvalidShares` or
`DecryptionInvalidShares`. Cryptographically invalid proofs and incomplete proof sets keep their
existing protocol-failure paths. Local proof-signing failures also keep their explicit terminal
failure paths.

### Step 6: Collect Threshold Shares (with C2/C3 Verification)

```
ThresholdShareCollector collects this recipient's shares from the other N−1 parties
│
├─ Each ThresholdShareCreated arrives via libp2p P2P network
│
├─ ThresholdKeyshare.handle_threshold_share_created():
│   ├─ Filters: only process shares where target_party_id == MY party_id
│   │   → Each published share contains this recipient's encrypted material
│   └─ Forwards filtered share to ThresholdShareCollector
│
├─ At the 75% soft cutoff:
│   ├─ With at least H−1 external shares:
│   │    send AllThresholdSharesCollected with the available snapshot
│   │    and keep collecting later shares
│   └─ Below H−1: keep collecting; the next share that reaches H−1 starts verification
│
├─ At the canonical on-chain DKG deadline:
│   ├─ With at least H−1 external shares:
│   │    send AllThresholdSharesCollected with the available shares
│   └─ Otherwise send ThresholdShareCollectionFailed to parent ThresholdKeyshare
│      ├─ ThresholdKeyshare persists KeyshareState::Failed {
│      │    failed_at_stage: CommitteeFinalized,
│      │    reason: DKGTimeout
│      │  }
│      ├─ ThresholdKeyshare republishes ThresholdShareCollectionFailed for telemetry
│      ├─ ThresholdKeyshare emits E3Failed {
│      │    failed_at_stage: CommitteeFinalized,
│      │    reason: DKGTimeout
│      │  }
│      └─ ThresholdKeyshare actor stops
│
└─ When all N−1 external shares arrive:
    ├─ Send AllThresholdSharesCollected to ThresholdKeyshare
    │
    └─ DISPATCH C2/C3 VERIFICATION:
        ThresholdKeyshare.dispatch_c2_c3_verification()
        │
        └─ Publishes ShareVerificationDispatched {
             kind: ShareProofs,
             party_proofs: [all C2a, C2b, C3a, C3b proofs per party],
             pre_dishonest: [parties with missing/incomplete proofs]
           }
           → ShareVerificationActor picks this up
```

### Step 6a: C2/C3 Share Proof Verification

**Actor:** `ShareVerificationActor` (`crates/zk-prover/src/share_verification/actor.rs`)

**Deterministic workflow:** signature/slot validation, replay normalization, consistency filtering,
and result tallying live in `crates/zk-prover/src/share_verification/{state,workflow}.rs`. The
capability's `handlers.rs` owns mailbox entry and its semantic effect files own correlation state
and publish returned decisions.

```
ShareVerificationActor receives ShareVerificationDispatched(kind=ShareProofs)
│
├─ PHASE 1: Lightweight ECDSA Validation (workflow service):
│   │
│   ├─ For EACH party's proofs:
│   │   ├─ Verify e3_id matches
│   │   ├─ Recover ECDSA signer address from each signed proof
│   │   ├─ Verify signer consistency: all proofs from same address
│   │   ├─ Validate circuit names match expected ProofType::circuit_names()
│   │   │
│   │   ├─ If ANY ECDSA check fails:
│   │   │   └─ Emit SignedProofFailed { accused, proof_type }
│   │   │      → Triggers accusation pipeline (see Part 5)
│   │   │
│   │   └─ If ECDSA passes: cache recovered address, proceed
│   │
│   └─ Store PendingConsistencyCheck {
│        ecdsa_dishonest, pre_dishonest, dispatched_party_ids,
│        recovered_addresses, party_proofs (for ZK dispatch)
│      }
│
├─ PHASE 2: Commitment Consistency Check (dispatched to per-E3 checker):
│   │
│   ├─ Publishes CommitmentConsistencyCheckRequested {
│   │     correlation_id, kind, party_proofs: [(party_id, address, proofs)]
│   │   }
│   │
│   ├─ CommitmentConsistencyChecker (per-E3 actor) receives this:
│   │   ├─ Caches each party's (address, proof_type) → {public_signals, data_hash}
│   │   ├─ Persists the complete proof cache and accepted H-roster in the same
│   │   │  snapshot batch as the event that changed them
│   │   │  → Hydration restores both before recovered proof checks resume
│   │   ├─ Evaluates all registered CommitmentLinks:
│   │   │     C0→C3   (SourceMustExistInTargets): local-cache absence accusations are disabled;
│   │   │                                          each recipient checks its own C0 against C3
│   │   │     C1→C2a  (SameParty):                C1's sk_commitment == C2a's expected_secret_commitment
│   │   │     C1→C2b  (SameParty):                C1's e_sm_commitment == C2b's expected_secret_commitment
│   │   │     C1→C5   (CrossParty):               C1's pk_commitment ∈ C5 expected pk inputs
│   │   │     C2→C3   (SameParty):                C3's expected_message_commitment ∈ C2's share commitments
│   │   │     C2→C4   (SourceMustExistInTargets): after all selected C4 targets arrive,
│   │   │                                          C2's L share commitments for recipient R match
│   │   │                                          C4_R's row for sender X in the H-roster order
│   │   │     C4a→C6  (SameParty):                C4a's commitment == C6's expected_sk_commitment
│   │   │     C4b→C6  (SameParty):                C4b's commitment == C6's expected_e_sm_commitment
│   │   │     C6→C7   (CrossParty):               C6's d_commitment matches C7's expected_d_commitment
│   │   │     (on-chain / E3 state)              C3/C6 ciphertext commitments are checked against their ciphertext witnesses;
│   │   │                                      the final decryption proof exposes the SAFE commitment and the wrapper compares it with
│   │   │                                      the commitment stored at ciphertext publication. Keccak(raw output) remains separate.
│   │   │
│   │   ├─ On mismatch: publishes CommitmentConsistencyViolation
│   │   │   → AccusationManager initiates accusation quorum (see Part 5)
│   │   └─ Responds with CommitmentConsistencyCheckComplete { inconsistent_parties }
│   │
│   └─ On CommitmentConsistencyCheckComplete:
│       ├─ Merge inconsistent_parties into dishonest set
│       └─ Proceed to Phase 3 with remaining honest parties
│
├─ PHASE 3: Heavy ZK Verification (dispatched to multithread):
│   │
│   ├─ Publishes ComputeRequest::zk(VerifyShareProofsRequest {
│   │     party_proofs, // consistency-passing parties' ZK proof data
│   │   })
│   │
│   ├─ Multithread ZK verify: `bb verify` on inner recursive circuits (same path as
│   │   `ZkProver::verify_proof`)
│   │   → Returns per-party pass/fail results
│   │
│   └─ On ComputeResponse:
│       ├─ Cross-check: all dispatched parties accounted for
│       ├─ For each party:
│       │   ├─ all_verified → Emit ProofVerificationPassed
│       │   └─ NOT all_verified → Emit SignedProofFailed
│       │
│       └─ Publish ShareVerificationComplete {
│            kind: ShareProofs,
│            dishonest_parties: {pre_dishonest ∪ ecdsa_fails ∪ consistency_fails ∪ zk_fails}
│          }
│
└─ ThresholdKeyshare receives ShareVerificationComplete:
    ├─ Excludes failed C2/C3 proofs and C3 proofs that target a different
    │  recipient key
    ├─ Saves the verified dealer IDs and their exact contribution hashes
    ├─ Publishes a signed DkgCoordination::Ready list when at least H dealers,
    │  including this party, remain
    ├─ Re-verifies each strict late-share superset and publishes a new signed Ready list
    ├─ If fewer than H pass locally, stays outside C4 without failing the E3
    └─ Waits for one H-dealer roster before Step 7

The active aggregator selects H parties whose signed Ready lists all contain the same selected
dealer contributions. `AggregatorChanged` carries the active party ID, and threshold-keyshare
persists that ID. A receiver keeps one authenticated roster per proposer. It can accept a roster
from the active proposer or an earlier proposer whose failover budget has already elapsed locally.
The proposer must have published a matching Ready list, the receiver's own Ready list must contain
the roster, and every Ready list already held for a selected dealer must support it. Before C4
starts, a roster from a lower party ID replaces a roster from a higher party ID. After C4 starts,
the roster is fixed. A promoted aggregator re-proposes the accepted dealer list instead of deriving
a different list from its local delivery order.

Once a node can derive a valid roster, or receives a supported roster that it cannot yet derive
from every peer Ready report, it starts the existing 10-minute active-aggregator budget for the
DKG-roster phase. If the active aggregator does not publish a roster, the selector promotes the
next eligible committee member and publishes its new party ID. The promoted member uses the
accepted dealer list or its saved Ready map; there is no second leader election. Roster acceptance
ends that phase and clears its local failover skips. The later C5 public-key aggregation starts a
new failover budget only after its own inputs are durable.

The network actor keeps the latest local Ready and Roster message for each open E3. It sends the
same signed protocol event in a fresh transport envelope every 30 seconds. The fresh delivery ID
bypasses the libp2p duplicate cache. The stable embedded event ID preserves EventBus deduplication.
Key publication or a terminal E3 removes the cached messages.

Dealer identity binds the E3, proof type, circuit, and public signals. It excludes randomized proof
bytes, so replaying the same valid statement cannot create a second dealer identity. Replacing a
same-E3 proof plan invalidates the old correlation IDs before the new plan starts. A late response
from the old plan therefore cannot enter the replacement bundle.

This coordination is not Byzantine agreement. The active aggregator can choose any roster that
satisfies the mutually ready H-set rule. The proof and on-chain single-publish checks prevent
different rosters from producing two accepted keys, but a malicious active aggregator can still
withhold progress until failover.
If a selected party stops permanently after the roster is accepted, this path does not select a
replacement or rebuild C4. The E3 can fail even when other committee members remain online.
If a selected party is expelled or excluded, the public-key aggregator fails the DKG immediately;
the fixed H-row proof cannot remove that party after roster selection.
The cutoff omits missing nodes but does not accuse or slash them: a local timeout is not proof
that a peer failed to publish.
```

### Step 7: Calculate Decryption Key (with C4 Proofs & Verification)

```
ThresholdKeyshare accepts an H-dealer roster after C2/C3 verification
│
├─ 1. Each selected party decrypts its shares from the selected dealers:
│     For each other selected party j:
│       sk_sss_j = BFV::decrypt(encrypted_sk_sss_j, my_bfv_sk)
│       esi_sss_j = BFV::decrypt(encrypted_esi_sss_j, my_bfv_sk)
│
├─ 2. COMPUTE REQUEST: CalculateDecryptionKey
│     │
│     │  ┌─── TrBFV Computation ──────────────────────────────┐
│     │  │                                                     │
│     │  │  Inputs: selected sk_sss and esi_sss shares       │
│     │  │                                                     │
│     │  │  1. Reconstruct summed secret key polynomial:       │
│     │  │     sk_poly_sum = Shamir::reconstruct(              │
│     │  │       [sk_sss_j for j in the accepted H roster]   │
│     │  │     )                                               │
│     │  │     → This is NOT the full secret key               │
│     │  │     → It's this node's PORTION of the summed key    │
│     │  │                                                     │
│     │  │  2. Reconstruct summed ESI polynomials:             │
│     │  │     es_poly_sum = Shamir::reconstruct(              │
│     │  │       [esi_sss_j for j in the accepted H roster]  │
│     │  │     )                                               │
│     │  │                                                     │
│     │  │  Output: (sk_poly_sum, es_poly_sum)                 │
│     │  │  → Stored encrypted locally for later decryption    │
│     │  └─────────────────────────────────────────────────────┘
│
├─ 2b. ACCEPTED H ROSTER:
│     Use the saved, sorted H-dealer roster for the C4 witness. Do not choose
│     the lowest H entries in a node's local share cache. A party outside the
│     accepted roster can create C4 only when it holds all H selected shares.
│     Its C4 does not add a dealer row to the C5 key.
│
├─ 3. PUBLISH C4 PROOF REQUESTS:
│     DecryptionShareProofsPending {
│       sk_request:   DkgShareDecryptionProofRequest (C4a),
│       esm_requests: Vec<DkgShareDecryptionProofRequest> (C4b, one per ESI),
│       sk_poly_sum, es_poly_sum  // decrypted aggregates for proof inputs
│     }
│     → ProofRequestActor picks this up
│
├─ 4. C4 PROOF GENERATION (ProofRequestActor):
│     │
│     │  ├─ Creates PendingDecryptionProofs:
│     │  │   expected = 1 (C4a for SK) + num_esi (C4b for each ESM)
│     │  │
│     │  ├─ Dispatches proof requests:
│     │  │   C4a: ComputeRequest::zk(ZkRequest::DkgShareDecryption { kind: SK })
│     │  │   C4b[i]: ComputeRequest::zk(ZkRequest::DkgShareDecryption { kind: ESM, esi_idx })
│     │  │   → Proves share decryption was performed correctly
│     │  │   → Proves the reconstructed key portion is valid
│     │  │
│     │  ├─ ZkActor generates all C4 proofs
│     │  │
│     │  └─ When is_complete() (all C4a + C4b proofs):
│     │      ├─ Signs all proofs
│     │      └─ Publishes DecryptionKeyShared {
│     │           e3_id, party_id,
│     │           sk_poly_sum, es_poly_sum,        // protocol data
│     │           signed_sk_decryption_proof,       // C4a
│     │           signed_esm_decryption_proofs[]    // C4b per ESI
│     │         }
│     │         → Broadcast to all committee nodes via P2P gossip
│     │         → This is Protocol Exchange #3 (decryption key sharing)
│
├─ 5. COLLECT C4 SHARES FROM THE ACCEPTED ROSTER:
│     Each selected party waits for DecryptionKeyShared from the other H−1
│     selected parties
│     On restart, rebuild the collector from the saved roster and feed it saved
│     peer shares before new shares arrive. A valid new share also creates the
│     collector if it is still absent.
│     After all selected peer shares arrive, ignore late duplicates so they do
│     not start another collector and cause a false timeout.
│     The saved replay map also keeps the first C4 message from each party,
│     matching the live collector.
│     │
│     ├─ On timeout:
│     │  ├─ Persist KeyshareState::Failed {
│     │  │    failed_at_stage: CommitteeFinalized,
│     │  │    reason: DecryptionTimeout
│     │  │  }
│     │  ├─ Emit the matching E3Failed event
│     │  └─ Stop the ThresholdKeyshare actor
│     │
│     └─ When all selected shares are collected → AllDecryptionKeySharesCollected
│
├─ 6. C4 VERIFICATION:
│     ThresholdKeyshare.dispatch_c4_verification()
│     │
│     └─ Publishes ShareVerificationDispatched {
│          kind: DecryptionProofs,
│          party_proofs: [C4a + C4b proofs per party]
│        }
│        → ShareVerificationActor performs same 2-phase verification:
│          Phase 1: ECDSA signature recovery
│          Phase 2: Commitment consistency check (C2→C4, C4a→C6, C4b→C6)
│          Phase 3: ZK proof verification via bb binary
│        → On failure: SignedProofFailed → accusation pipeline
│        → On pass: ProofVerificationPassed (cached)
│
├─ 7. State: AggregatingDecryptionKey → ReadyForDecryption
│
└─ 8. Publish KeyshareCreated {
       e3_id, party_id,
       pk_share,        // public key share
       signed_proof     // ZK proof of correct generation
     }
    → Broadcast to committee members via P2P
```

Each fatal collector path commits `KeyshareState::Failed` before it publishes `E3Failed`. A later
transition cannot change the saved stage or reason. If the process stops between these operations,
startup hydrates the terminal state. `EffectsEnabled` then publishes the same failure payload.
Event-ID deduplication makes this redrive idempotent, and the actor cannot resume an earlier DKG
phase.

---

## Phase 2: Public Key Aggregation (Committee-Buffered, Active Aggregator Submits)

```
  All committee members receive KeyshareCreated events
│
├─ KeyshareCreatedFilterBuffer validates events:
  │   └─ Only accepts KeyshareCreated from verified committee members
  │   └─ Compares committee, keyshare, and exclusion identities as parsed EVM addresses;
  │      EIP-55 casing differences cannot bypass an exclusion or its buffered-share purge
  │   └─ Buffers only until CommitteeFinalized provides the canonical party-slot map
  │   └─ Then forwards every valid keyshare into each committee member's persisted actor state
│
  ├─ Committee members buffer received keyshares and the accepted H roster
  │
  ├─ When every member of the accepted H roster has submitted a keyshare:
│   │   → Persist VerifyingC1 before publishing AggregationInputsReady(PublicKey)
│   │   → CiphernodeSelector starts the 10-minute failover budget only now
│   │
│   ├─ Only the active aggregator starts C1 verification and later proof/compute effects
│   │   → A promoted standby resumes from its persisted phase; it does not need a RAM buffer
│   │   → A demoted node ignores late worker results and cannot publish a stale aggregate
│   ├─ C1 verification runs over the exact H selected submitters; failures stop DKG
│   │
│   ├─ Honest-set selection (compile-time H from `committee::active`, may be < N):
│   │     • Require valid C1 proofs from all H roster members; otherwise E3Failed
│   │     • Preserve the accepted roster order for NodeFold and C5 inputs
│   │
│   ├─ 1. Aggregate public key shares (H honest keyshares):
│   │     aggregate_pk = Fhe::get_aggregate_public_key(
│   │       [pk_share for each of the H canonical honest parties]
│   │     )
│   │     → Uses PublicKeyShare::aggregate()
│   │     → Produces the COLLECTIVE public key
│   │     → Anyone can encrypt with this key
│   │     → Only T+1 members of the accepted DKG roster can decrypt together
│   │
│   ├─ 2. Build C5 proof request (H canonical honest keyshares):
│   │     proof_request.keyshare_bytes = [pk_share for each H party]
│   │     proof_request.aggregated_pk_bytes = aggregate_pk
│   │     proof_request.committee_n = N
│   │     proof_request.committee_h = H
│   │     proof_request.committee_threshold = T
│   │     (per-share compute_pk_commitment already checked against C1; aggregate
│   │      commitment is proved as a C5 public output, not pre-published here)
│   │
│   ├─ 3. REQUEST C5 PROOF:
│   │     Publish PkAggregationProofPending {
│   │       proof_request,              // H keyshares + aggregate_pk (see step 2)
│   │       public_key: aggregate_pk,
│   │       nodes: honest_nodes         // H canonical subset
│   │     }
│   │
│   ├─ 4. C5 PROOF GENERATION (ProofRequestActor):
│   │     ├─ Dispatches ComputeRequest::zk(ZkRequest::PkAggregation {...})
│   │     │   → Circuit: PkAggregation (C5)
│   │     │   → Proves aggregate PK was correctly computed from the H canonical honest keyshares
│   │     ├─ ZkActor generates proof via bb binary
│   │     ├─ Signs proof
│   │     └─ Publishes PkAggregationProofSigned {
│   │          e3_id, party_id, signed_proof(C5)
│   │        }
│   │
│   ├─ 5. DKG AGGREGATION REQUEST (when proof aggregation is enabled):
│   │     ├─ PublicKeyAggregator buffers one optional NodeFold proof per honest party from
│   │     │   DKGRecursiveAggregationComplete
│   │     ├─ Dispatches ComputeRequest::zk(ZkRequest::DkgAggregation {
│   │     │     node_fold_proofs, c5_proof, party_ids, params_preset
│   │     │   })
│   │     │   → exactly H NodeFold proofs and H unique party ids
│   │     │   → exactly N ordered committee addresses from `CommitteeFinalized` (`topNodes`),
│   │     │     including a member excluded before it submitted a keyshare
│   │     │   → Rust validates both dimensions before invoking the compiled circuit
│   │     │   → `dkg_aggregator` uses each selected party ID for N-wide C3 and C2 recipient slots;
│   │     │     H-wide C4 sender slots use the selected party's fold-row position
│   │     │   → The circuit requires H distinct, ascending, in-range party IDs
│   │     ├─ Tracks the in-flight correlation id
│   │     ├─ A local ComputeRequestError preserves the aggregation input and correlation ID
│   │     │   for automatic retry or restart replay
│   │     └─ A mixed Some/None honest NodeFold-proof set is treated as a terminal DKG
│   │         failure instead of only surfacing as InterfoldError telemetry
│   │
│   └─ 6. Publish PublicKeyAggregated {
│         e3_id, pubkey: aggregate_pk, pk_commitment, nodes,
│         committee_addresses,          // length N — full on-chain topNodes binding
│         honest_committee_addresses,  // length H — canonical honest subset
│         dkg_aggregator_proof
│       }
│         → forwarded to peers so every committee member can bind C6 proofs to the aggregated key
│
└─ CiphernodeRegistrySolWriter receives PublicKeyAggregated:
  ├─ Accepts publication intents only from locally produced events; peer copies only distribute
  │  protocol state
  ├─ During live operation, requires active_aggregators[e3_id] == true when admitting the intent
  ├─ During startup replay, can retain one durable local intent while the persisted role is restored
  ├─ Starts a retained submission only while active_aggregators[e3_id] == true
  ├─ Defers and coalesces retained intents until EffectsEnabled
  ├─ Uses the registry from DkgFoldAttestationContextEstablished, including after a rotation
  ├─ Reads chain state to determine whether the proof-backed commitment is unset
  ├─ Encodes the DkgAggregator proof in production
  ├─ Feature-gated test/CI nodes with `skip_proof_aggregation` reuse the non-empty C5 proof as a
  │  mock-verifier placeholder; this does not bypass contract verification
  │  and every node in a test swarm must use the same flag value
  ├─ Calls contract.publishCommittee(
  │    e3_id, pkCommitment, proof, dkgAttestationBundle
  │  ) when the commitment is unset
  │  └─ If that transaction is mined with a failed receipt, the writer reads the
  │     commitment again. An equal commitment from another aggregator completes
  │     the step; a different commitment stays an error
  └─ Splits the serialized key into deterministic 90 KiB chunks and calls
     contract.publishCommitteePublicKey(e3_id, candidateHash, index, count,
     totalLength, chunk) for every chunk after the commitment is available
     → A terminal result clears the in-memory intent; a retryable failure keeps it and retries
       after 30s
     → RPC request-size rejection and permanent contract or payload errors are terminal for the
       running writer. They produce one final error instead of an unbounded 30-second retry loop
     → A restart replays the intent, so an unfinished publication still reaches the chain.
       E3RequestComplete that arrives before EffectsEnabled comes from that same replay and
       drops the intent: a completed request published its candidate in an earlier run, and
       repeating it only spends gas
        │
        │  ┌─── ON-CHAIN (CiphernodeRegistryOwnable) ──────────┐
        │  │                                                     │
        │  │  publishCommittee(                                  │
        │  │    e3Id, pkCommitment, proof, attestations          │
        │  │  ) {                                                │
        │  │    1. require(stage == Finalized)                   │
        │  │    2. require(activeCount >= threshold[0])          │
        │  │       → A non-viable committee cannot publish a key │
        │  │    3. require(c.publicKey == 0) — publish once      │
        │  │    4. committeeHash = keccak256(abi.encodePacked(c.topNodes)) │
        │  │       c.committeeHash = committeeHash               │
        │  │    5. require(proof.length > 0)                    │
        │  │       require(e3.pkVerifier.verify(                │
        │  │         e3Id, committeeRoot, c.topNodes,            │
        │  │         pkCommitment, committeeHash, proof          │
        │  │       ), InvalidProof())                            │
        │  │       → BFV: `BfvPkVerifier` (DkgAggregator Honk)  │
        │  │         • M-34: immutable nodesFold / C5 VK hashes  │
        │  │           checked against publicInputs[0..1]        │
        │  │         • C-08: committee_hash_hi/lo (slots         │
        │  │           [2+H] & [3+H]) vs committeeHash           │
        │  │         • last PI == pkCommitment                   │
        │  │         • M-35: revert on failure (no `bool false`) │
        │  │       and verify/store per-node fold attestations   │
        │  │    6. c.publicKey = pkCommitment                    │
        │  │       publicKeyHashes[e3Id] = pkCommitment          │
        │  │    7. interfold.onCommitteePublished(e3Id, pkCommitment) │
        │  │       │                                             │
        │  │       │  ┌─ Interfold.sol ────────────────────────┐  │
        │  │       │  │  onCommitteePublished(e3Id, pk) {   │  │
        │  │       │  │    require(stage==CommitteeFinalized) │  │
        │  │       │  │    require(now <= dkgDeadline)       │  │
        │  │       │  │    require(block.timestamp <=         │  │
        │  │       │  │      inputWindow[1])                  │  │
        │  │       │  │    e3.committeePublicKey = pk         │  │
        │  │       │  │    stage = KeyPublished               │  │
        │  │       │  │    computeDeadline = max(now,         │  │
        │  │       │  │      inputWindowEnd) + snapshotted    │  │
        │  │       │  │      computeWindow                    │  │
        │  │       │  │    Emit E3StageChanged(KeyPublished)  │  │
        │  │       │  │  }                                   │  │
        │  │       │  └──────────────────────────────────────┘  │
        │  │    8. Emit CommitteeProofPublished(                │
        │  │         e3Id, c.topNodes, pkCommitment, proof)     │
        │  │                                                     │
        │  │  publishCommitteePublicKey(e3Id, hash, i, n, len, chunk) { │
        │  │    1. require the proven commitment                │
        │  │    2. require caller is a request-time committee member │
        │  │    3. require len <= 512 KiB and canonical 90 KiB chunks │
        │  │    4. Emit CommitteePublicKeyChunkPublished        │
        │  │  }                                                  │
        │  └─────────────────────────────────────────────────────┘
```

The committee hash is `keccak256` over each ordered member's complete 20-byte address. Solidity,
Rust, and Noir use the same unpadded bytes.

Each E3 request freezes its registry and fold verifier. The `DkgFoldAttestationContextEstablished`
event carries both addresses before DKG starts. Event replay restores them after a node restart.
Each NodeFold signer includes the frozen registry in the EIP-712 attestation and uses the frozen
verifier as the EIP-712 verifying contract. The aggregator checks both addresses before it accepts
an attestation. The registry uses the same frozen verifier when the committee publishes its key. An
attestation from another registry or verifier therefore fails even when both registries use the same
E3 ID and committee.

The serialized key is transported in Ethereum event chunks; it is not on-chain authority. Only a
request-time committee member can emit chunks while the E3 remains in `KeyPublished`. This includes
a retained expelled member, whose bytes receive no extra trust but can still repair availability.
Terminal E3s reject new chunks, so late publishers cannot recreate assemblies after cleanup.
Consumers accept the first candidate hash from each member. The ciphernode coordinator and
`e3-indexer` group the canonical chunks by E3, publisher, and candidate hash. They require a
complete sequence, check `keccak256(serializedKey) == candidateHash`, decode the BFV key, recompute
the circuit's public-key commitment with the request-time parameter set, and require equality with
the proven on-chain `pkCommitment`. Only then do they produce the existing `CommitteePublished`
runtime event or store the key for encryption. Invalid candidates do not consume another committee
member's candidate. Production also verifies the C5-backed final DKG proof on-chain; the explicit
test/CI skip mode works only with mock verifiers.

> **C-08 (BfvPkVerifier domain binding) — implemented** The wrapper exposes a
> `verify(e3Id, committeeRoot, sortedNodes, pkCommitment, committeeHash, proof)` signature.
> `committeeHash` (computed on-chain as `keccak256(abi.encodePacked(c.topNodes))`) is split into
> 128-bit Noir field limbs and checked against `publicInputs[committeeHashHiIdx]` and
> `publicInputs[committeeHashLoIdx]`, binding the proof to the specific committee. The contextual
> params `(e3Id, committeeRoot, sortedNodes)` are forwarded for interface compatibility and future
> circuit-level binding.

> **Verifier deployment anchors:** `BfvPkVerifier` and `BfvDecryptionVerifier` constructors reject
> zero/EOA circuit-verifier addresses and zero recursive VK hashes. Production deployment tooling
> additionally compares the immutable VK hashes with the version-controlled circuit artifacts.

The decryption wrapper exposes
`verify(e3Id, decryptionDomain, plaintextOutputHash, committeeHash, ciphertextCommitment, proof)`.
`Interfold` recomputes `decryptionDomain` over
`(chainId, Interfold address, e3Id, committeeHash, ciphertextOutputHash, committeePublicKey)`. The
wrapper checks the domain limbs and SAFE ciphertext commitment in the final proof, then uses the
separate `e3Id` to resolve the registry's stored DKG anchors and compares every surfaced party ID,
secret-key commitment, and smudging-noise commitment. The party IDs are circuit-side 1-indexed
Shamir coordinates and are translated to the registry's 0-indexed committee slots for this
comparison.

---

## Phase 3: Encrypted Computation

### Input Submission (External)

```
Data providers submit encrypted inputs:
│
├─ Server validates the Noir proof and durably stores the exact ciphertext
├─ Server signs the chain-bound input ID only after storage succeeds
├─ e3Program.publishInput(e3Id, proofCommitment)
│  → Must be before inputCommitmentDeadline
│  → Verifies the Noir proof, content hash, SAFE commitment, and server signature
│  → Reserves the input leaf and index immediately
│  → Emits InputCommitted and increments pendingInputCount
├─ Server publishes the stored ciphertext to Avail with submit_data
├─ VectorX anchors that Avail block on Ethereum
└─ e3Program.finalizeInput(e3Id, inputTuple, vectorXProof)
   → Verifies availability of the exact keccak256(ciphertext)
   → Emits InputPublished and decrements pendingInputCount
   → Can be called by anyone; the voter does not stay online
```

The final three hours of the input window accept finalizations but no new proof commitments. The
input leaf is reserved in the first transaction so later masks and revotes can extend it while
VectorX is pending. Computation waits for the original input-window end and for
`pendingInputCount == 0`. See [08_DATA_AVAILABILITY.md](08_DATA_AVAILABILITY.md) for the exact
deadlines, recovery flow, and remaining trust.

### Ciphertext Output Publication

The support host sends raw bincode input by default. `BOUNDLESS_INPUT_ENCODING=risc0-serde` selects
the older byte-vector wrapper for an external Boundless guest and requires `PROGRAM_URL`. The
embedded guest always receives raw bincode. This compatibility setting does not change the guest or
its image ID. The selected external guest must match the deployed verifiers and produce the same
journal as the host for the round inputs.

The RISC Zero guest commits nine 32-byte fields in this order: chain ID, Interfold address, E3 ID,
encryption scheme ID, committee public key, output hash, SAFE commitment, parameter hash, and input
root. RISC Zero serializes these fields as a 1,188-byte journal. The support app returns the seal,
parameter hash, and input root in one ABI-encoded proof.

The request-time scheme verifier reconstructs the protocol fields from on-chain state. The E3
program reconstructs the application fields from its state. Both contracts verify the same receipt.
An application verifier cannot create a decryption duty unless the scheme verifier also accepts it.
The RISC Zero wrapper accepts only a receipt-verifier address that contains deployed code. An EOA
cannot satisfy the verifier's void-return call with empty return data. The input root uses the
smallest binary Poseidon tree that can hold the submitted SAFE ciphertext commitments, with a
minimum depth of one. The compute provider and E3 program must use this same leaf value, order, zero
value, and depth rule.

The guest derives the input root from the ciphertexts it processed. `ComputeInput` holds only
`fhe_inputs`, and `ComputeInput::process` calls `MerkleTreeBuilder::compute_leaf_hashes` over those
ciphertexts before it builds the tree (`crates/compute-provider/src/compute_input.rs`). The leaves
are therefore a function of the processed set, not a separate prover-supplied value.

This binding matters because nothing else supplies it. `Risc0BfvCiphertextVerifier` takes the input
root from the proof envelope and never constrains it, so the only check on the root is the
comparison an E3 program performs against its own on-chain root (`CRISPProgram.verify`,
`MyProgram.verify`). If the guest accepted the leaves as an independent input, that comparison would
pass for a tally computed over ciphertexts that were never submitted: a prover would replay the
genuine on-chain leaves while processing its own ciphertexts. Publication is unpermissioned
(`Interfold.publishCiphertextOutput` has no authorization modifier) and one-shot, so any party could
do this, and no dispute path exists.

Two rules follow for anyone changing this path:

- **An E3 program must compare the proof's input root against its own root.** The protocol verifier
  will not do it.
- **A Secure Process must derive its leaves, never receive them.**
  `MerkleTreeBuilder::with_leaf_hashes` is `#[cfg(test)]` for that reason.

`ComputeManager` proves the whole input set in one guest run. The former `start_parallel` path
proved per chunk and set the final leaves to sub-tree roots, which produced a tree of sub-tree roots
rather than the flat input root an E3 program compares against. It was unreachable — every call site
passed `use_parallel = false` — and it is removed. Restoring batching requires first defining what a
leaf means on that path.

### Ciphertext component count

The SAFE ciphertext commitment covers `c[0]` and `c[1]` only, matching the Noir circuit.
`bfv_ciphertext_to_greco` rejects any ciphertext whose component count is not exactly two
(`crates/zk-helpers/src/circuits/threshold/user_data_encryption/utils.rs`). Without that check a
ciphertext padded with a third polynomial commits to the same value as its two-component prefix, so
the input root and the output commitment stay identical while threshold decryption rejects the
padded output — `ShareManager` requires exactly two components. The round would then fail as a
`DecryptionTimeout`, which `FailurePayerLib` bills to the ciphernodes. Seed-compressed ciphertexts
are unaffected: `TryConvertFrom` expands the seed into `c[1]` before the converter sees it.

```
Compute provider runs computation on encrypted data:
│
├─ Publish the aggregate ciphertext bytes to Avail
├─ Wait for the VectorX proof
└─ Interfold.publishCiphertextOutput(e3Id, encodedOutputReference)
    │
    │  ┌─── ON-CHAIN (Interfold.sol) ─────────────────────────────┐
    │  │                                                         │
│  │  publishCiphertextOutput(e3Id, encodedReference) {        │
    │  │    0. enter the shared publication reentrancy guard      │
    │  │    1. require(stage == KeyPublished)                    │
    │  │    2. require(block.timestamp <= computeDeadline)       │
    │  │    3. require(block.timestamp >= inputWindow[1])        │
    │  │       → Input window must have closed                   │
    │  │    4. require(e3.ciphertextOutput == 0)                │
    │  │       → Can only publish once                           │
    │  │    5. require(activeCount >= threshold[0])              │
    │  │       → The request-time committee is still viable      │
│  │    6. E3 program verifies the VectorX/Avail receipt      │
│  │       and requires receipt.contentHash == output hash    │
│  │    7. schemeVerifier.verify(...)                         │
│  │       → Checks the protocol fields in the compute receipt│
│  │       → Must return true                                 │
│  │    8. e3Program.verify(...)                              │
│  │       → Checks the application fields in the same receipt│
│  │       → Must return true                                 │
│  │       → Cannot re-enter ciphertext or plaintext publication│
│  │    8b. Re-read stage from storage: must be KeyPublished  │
│  │       Re-check request-time committee viability          │
│  │       → An application callback can slash a member and   │
│  │         record Failed through onE3Failed, which is        │
│  │         outside this reentrancy guard. A revert here      │
│  │         rolls back that failure and its settlement.       │
│  │    9. Save output hash and SAFE commitment               │
│  │       Set stage and decryption deadline                  │
│  │   10. Emit CiphertextOutputReferencePublished(...)       │
│  │   11. Emit E3StageChanged(CiphertextReady)                │
    │  │  }                                                      │
    │  └─────────────────────────────────────────────────────────┘
```

`IE3Program.verify` is an application hook that can change state (Zenith `ZEN2-26`). Step 8b
therefore repeats the stage read and the committee-viability check after the application returns.
Without it, a verifier callback that executes a mature expelling slash could record `Failed`,
decrement `activeE3Count`, and release the committee, and publication would then overwrite the
terminal state and leave the counter low. This keeps the "Committee viability loss is atomic"
invariant true for the output-publication path.

The data-availability adapter rejects a zero content hash (Zenith `ZEN2-05`). Avail pads its
submitted-data Merkle tree with zero leaves, so a zero expected hash would accept a padding leaf as
proof of publication.

The accepted event records the content hash and stable Avail coordinates, not the ciphertext bytes.
Ciphernodes replay that durable reference without network access. After recovery enables effects,
they fetch the named Avail block, find bytes with the exact Keccak hash, and emit the existing
runtime `CiphertextOutputPublished` event. Failed retrieval is retried and never substitutes bytes.

`onCommitteePublished` stores the committee key and starts the compute clock. The compute deadline
is `max(block.timestamp, inputWindow[1]) + requestTimeComputeWindow`. A late key publication does
not consume the compute provider's allotted window, and publication still waits until the input
window closes. The request-time timeout snapshot prevents later governance changes from changing an
active E3's deadlines.

`onCommitteePublished` also refuses a key that arrives after `inputWindow[1]`, with
`InputWindowClosedBeforeKeyPublication` (ZEN2-03). Such a round reaches `KeyPublished` but can never
receive an input, so it fails as a requester-paid `ComputeTimeout` instead of a committee-paid
`DKGTimeout`. The DKG deadline alone does not stop this, because `dkgDeadline` can fall after
`inputWindow[1]`. The refusal keeps failure attribution on the committee.

`publishCiphertextOutput` calls `IE3ProgramDataAvailability.verifyDataAvailability` on the
request-time program without a fallback. A program that omits that selector cannot publish an
output. `Interfold.registerE3Program` therefore probes the candidate program with ERC-165 for
`IE3Program` and `IE3ProgramDataAvailability` and reverts with `E3ProgramInterfaceMissing`
(ZEN2-01). The probe is bounded to 30000 gas and treats a failed, short, or false answer as missing.

---

## Phase 4: Decryption Share Generation (Each Committee Member, with C6 Proof)

Before proof verification, the BFV wrapper requires every public input to use its canonical BN254
field representation. Message coefficients must also fit exactly in 64 bits. This second check is
defense in depth because the wrapper does not store the BFV plaintext modulus for each parameter
set.

```
InterfoldSolReader decodes CiphertextOutputPublished event
│
└─ ThresholdKeyshare receives CiphertextOutputPublished:
    │
    ├─ State: ReadyForDecryption → Decrypting
    │
    ├─ COMPUTE REQUEST: CalculateDecryptionShare
    │   │
    │   │  ┌─── TrBFV Computation ──────────────────────────────┐
    │   │  │                                                     │
    │   │  │  Inputs:                                            │
    │   │  │    - ciphertext (encrypted computation output)      │
    │   │  │    - sk_poly_sum (this node's secret key portion)   │
    │   │  │    - es_poly_sum (this node's smudging noise)       │
    │   │  │                                                     │
    │   │  │  Compute:                                           │
    │   │  │    decryption_share = ShareManager::compute_share(  │
    │   │  │      ciphertext, sk_poly_sum, es_poly_sum           │
    │   │  │    )                                                │
    │   │  │    → One decryption share polynomial per ciphertext │
    │   │  │    → Smudging noise prevents info leakage           │
    │   │  │    → Share alone reveals NOTHING about plaintext    │
    │   │  │                                                     │
    │   │  │  Output: Vec<decryption_share_polynomial>           │
    │   │  └─────────────────────────────────────────────────────┘
      │
      ├─ `ThresholdKeyshare` tracks the `CalculateDecryptionShare` correlation id:
      │   → `ComputeRequestError` for this request now emits
      │     `E3Failed {
      │       failed_at_stage: CiphertextReady,
      │       reason: DecryptionInvalidShares
      │     }` and stops before C6 proof generation
    │
    ├─ REQUEST C6 PROOF:
    │   Publish ShareDecryptionProofPending {
    │     proof_request: ThresholdShareDecryptionProofRequest,
    │     decryption_shares
    │   }
    │
    ├─ C6 PROOF GENERATION (ProofRequestActor):
    │   ├─ Dispatches ComputeRequest::zk(ZkRequest::ThresholdShareDecryption {...})
    │   │   → Circuit: ThresholdShareDecryption (C6)
    │   │   → Proves decryption share was correctly computed from
    │   │     sk_poly_sum, es_poly_sum, and ciphertext
    │   │   → Publicly commits to the E3 decryption-domain limbs:
    │   │     keccak256(abi.encode(
    │   │       chainId, Interfold address, e3Id, committeeHash,
    │   │       ciphertextOutputHash, committeePublicKey
    │   │     ))
    │   │   → Fiat-Shamir transcript absorbs full `d` (all coefficients per CRT limb)
    │   ├─ ZkActor generates proof via bb binary
    │   ├─ Signs proof
    │   └─ Publishes signed C6 proof
    │
    ├─ Publish DecryptionshareCreated {
    │     e3_id, party_id,
    │     decryption_share: Vec<polynomial>,
    │     signed_proof: SignedProofPayload(C6),
    │     node: address
    │   }
    │   → Broadcast via P2P to committee members for buffering
    │
    └─ State: Decrypting → Completed
```

---

## Phase 5: Plaintext Aggregation (Committee-Buffered, Active Aggregator Submits)

```
  All committee members receive DecryptionshareCreated events
│
  ├─ DecryptionshareCreatedBuffer validates exclusion state:
  │   ├─ Tracks parties excluded by on-chain expulsion or the disabled-policy fallback
  │   └─ Forwards every valid share into each committee member's persisted plaintext actor
  │
  ├─ ThresholdPlaintextAggregator persists shares on active and standby nodes
  │   ├─ Verifies sender is in committee
  │   ├─ Adds the share if verified
  │   └─ Ignores non-members or excluded parties
│
  ├─ Once all required honest shares are durable:
  │   ├─ Persist VerifyingC6 before publishing AggregationInputsReady(Plaintext)
  │   ├─ Start the 10-minute failover budget only at this readiness boundary
  │   └─ A promoted standby resumes the persisted phase
│
  ├─ C6 VERIFICATION (per-share, active aggregator only):
│   ShareVerificationActor receives C6 signed proofs
│   ├─ ECDSA recovery + ZK verification (same 2-phase as C2/C3)
│   ├─ On failure: SignedProofFailed → accusation pipeline
│   └─ On pass: ProofVerificationPassed (cached)
│
├─ When T+1 shares are collected (threshold met):
│   │
│   ├─ State → Computing
│   │
│   ├─ COMPUTE REQUEST: CalculateThresholdDecryption
│   │   │
│   │   │  ┌─── TrBFV Computation ──────────────────────────────┐
│   │   │  │                                                     │
│   │   │  │  Inputs:                                            │
│   │   │  │    - ciphertext output                              │
│   │   │  │    - T+1 decryption shares from different parties   │
│   │   │  │    - party IDs                                      │
│   │   │  │                                                     │
│   │   │  │  Compute:                                           │
│   │   │  │  1. Lagrange interpolation on share polynomials     │
│   │   │  │     → Shamir threshold reconstruction               │
│   │   │  │  2. Combine to recover full decryption              │
│   │   │  │  3. BFV decode plaintext to output bytes            │
│   │   │  │                                                     │
│   │   │  │  Output: plaintext_bytes                            │
│   │   │  └─────────────────────────────────────────────────────┘
│   │
│   ├─ ThresholdPlaintextAggregator tracks the `CalculateThresholdDecryption` correlation id:
│   │   ├─ `ComputeRequestError` preserves the pending input for restart replay
│   │   └─ Fatal C6 filtering failures (too few honest shares or post-proof commitment
│   │       mismatches) emit the same terminal failure instead of only trapping locally
│   │
│   ├─ REQUEST C7 PROOF:
│   │   Publish AggregationProofPending {
│   │     proof_request: DecryptedSharesAggregationProofRequest,
│   │     plaintext: Vec<plaintext_bytes>,
│   │     shares: Vec<(party_id, Vec<decryption_share>)>
│   │   }
│   │
│   ├─ C7 PROOF GENERATION (ProofRequestActor):
│   │   ├─ Dispatches ComputeRequest::zk(
│   │   │     ZkRequest::DecryptedSharesAggregation {...}
│   │   │   )
│   │   │   → Circuit: DecryptedSharesAggregation (C7)
│   │   │   → Proves plaintext was correctly reconstructed from T+1 shares
│   │   ├─ ZkActor generates proof(s) via bb binary
│   │   ├─ Signs each C7 proof (one per ciphertext index)
│   │   └─ Publishes AggregationProofSigned {
│   │        e3_id, party_id, signed_proof(C7)
│   │      }
│   │
│   ├─ DECRYPTION AGGREGATION REQUEST:
│   │   ├─ ThresholdPlaintextAggregator stores the signed C7 proofs plus the honest C6 inner
│   │   │   proofs for the first `T + 1` parties after sorting by `party_id`
│   │   ├─ Dispatches ComputeRequest::zk(ZkRequest::DecryptionAggregation {
│   │   │     c6_total_slots, jobs, params_preset
│   │   │   })
│   │   ├─ Each job folds the selected C6 proofs for one ciphertext index, requires every
│   │   │   C6 leaf to carry the same E3 domain, and checks them against the matching C7 proof
│   │   │   inside `DecryptionAggregator`
│   │   ├─ `DecryptionAggregator` exposes that C6-authenticated domain as two public
│   │   │   128-bit limbs in the final EVM proof
│   │   ├─ `DecryptionAggregator` requires 1-indexed, strictly increasing party IDs;
│   │   │   zero, out-of-range, and duplicate reconstruction slots are rejected
│   │   ├─ Tracks the in-flight correlation id
│   │   ├─ ComputeRequestError preserves the pending aggregation input for recovery
│   │   ├─ Missing C6 inner proofs or C7/decryption-aggregator proof-count mismatches emit
│   │   │   `E3Failed { failed_at_stage: CiphertextReady, reason: DecryptionInvalidShares }`
│   │   └─ On success, stores `decryption_aggregator_proofs`
│   │
│   └─ Publish PlaintextAggregated {
│         e3_id, decrypted_output, decryption_aggregator_proofs
│       }
│
└─ InterfoldSolWriter receives PlaintextAggregated:
  ├─ Accepts publication intents only from locally produced events
  ├─ During live operation, requires active_aggregators[e3_id] == true when admitting the intent
  ├─ During startup replay, can retain one durable local intent while the persisted role is restored
  ├─ Starts a retained submission only while active_aggregators[e3_id] == true
  ├─ Defers and coalesces retained intents until EffectsEnabled
  ├─ Reads chain state to confirm plaintextOutput is still empty
  ├─ Encodes the final DecryptionAggregator proof in production
  ├─ Feature-gated test/CI nodes with `skip_proof_aggregation` reuse the non-empty C7 proof as a
  │  mock-verifier placeholder; this does not bypass contract verification
  │  and every node in a test swarm must use the same flag value
  └─ Calls contract.publishPlaintextOutput(e3Id, output, proof)
     → A terminal result clears the intent; a retryable failure keeps it and retries after 30s
        │
        │  ┌─── ON-CHAIN (Interfold.sol) ─────────────────────────┐
        │  │                                                     │
        │  │  publishPlaintextOutput(e3Id, output, proof) {      │
        │  │    1. require(stage == CiphertextReady)             │
        │  │    2. require(now <= decryptionDeadline)            │
        │  │    3. require(activeCount >= threshold[0])          │
        │  │       → The request-time committee is still viable  │
        │  │    4. require(proof.length > 0), recompute          │
        │  │       decryptionDomain = keccak256(abi.encode(      │
        │  │         chainId, address(this), e3Id,               │
        │  │         committeeHash, ciphertextOutput,            │
        │  │         committeePublicKey                          │
        │  │       )), then require decryptionVerifier.verify(   │
        │  │         e3Id, decryptionDomain, keccak256(output),  │
        │  │         committeeHash, ciphertextCommitment, proof  │
        │  │       ) == true                                     │
        │  │       → C-03: final proof domain must match the      │
        │  │         domain already committed by every C6 leaf.  │
         │  │       → IF-003: e3Id resolves stored DKG anchors;  │
         │  │       │  proof party IDs and SK/ESM commitments match.│
         │  │       → M-34: c6Fold / C7 VK hashes are immutable.  │
        │  │       → M-35: revert path only (no `bool false`).   │
        │  │    5. stage = Complete                              │
        │  │    6. _distributeRewards(e3Id)                      │
        │  │       │                                             │
        │  │       │  ┌─ Reward Distribution (pull, H-01/M-02) ┐  │
        │  │       │  │  1. Get active committee nodes:        │  │
        │  │       │  │     nodes = ciphernodeRegistry         │  │
        │  │       │  │       .getActiveCommitteeNodes(e3Id)   │  │
        │  │       │  │  2. If no active nodes:                │  │
        │  │       │  │     → push refund to requester         │  │
        │  │       │  │  3. Split payment:                     │  │
        │  │       │  │     protocolAmount = total * shareBps  │  │
        │  │       │  │     cnAmount       = total - protocol  │  │
        │  │       │  │     perNode = cnAmount / nodes.length  │  │
        │  │       │  │     dust → nodes[e3Id % n] (M-07:      │  │
        │  │       │  │       rotates dust slot per E3 so the  │  │
        │  │       │  │       same physical node is not always │  │
        │  │       │  │       favored)                         │  │
        │  │       │  │  4. Credit treasury (no push):         │  │
        │  │       │  │     _pendingTreasury[treasury][token]  │  │
        │  │       │  │       += protocolAmount                │  │
        │  │       │  │     Emit TreasuryCredited(...)         │  │
        │  │       │  │  5. Load each node's recipient frozen │  │
        │  │       │  │     at committee finalization, then    │  │
        │  │       │  │     credit it (no push):               │  │
        │  │       │  │     _pendingRewards[e3Id][recipient]   │  │
        │  │       │  │       += perNode                       │  │
        │  │       │  │     Emit RewardCredited(...)           │  │
        │  │       │  │  6. Emit RewardsDistributed (compat)   │  │
        │  │       │  │  7. e3RefundManager                    │  │
        │  │       │  │       .distributeSlashedFundsOnSuccess │  │
        │  │       │  │       (e3Id, nodes, token)             │  │
        │  │       │  │       (also pull-based; see flow-05)   │  │
        │  │       │  └────────────────────────────────────────┘  │
        │  │    7. Emit PlaintextOutputPublished(e3Id, output, C7 proof) │
        │  │    8. Emit E3StageChanged(Complete)                 │
        │  │  }                                                  │
        │  │                                                     │
        │  │  // Funds are NOT pushed at publish-time.           │
        │  │  // Bond-owner recipients must call:                │
        │  │  //   - interfold.claimReward(e3Id) or                │
        │  │  //     interfold.claimRewards(e3Ids[])               │
        │  │  //   - interfold.treasuryClaim(token)                │
        │  │  // emitting RewardClaimed / TreasuryClaimed.       │
        │  └─────────────────────────────────────────────────────┘
```

---

## ZK Proof Type Summary (C0–C7)

```
┌──────┬────────────────────────────┬───────────────────┬──────────────────────────────┐
│ Code │ Name                       │ Stage             │ What It Proves               │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C0   │ BFV Public Key             │ DKG: Key Gen      │ BFV keypair generated        │
│      │                            │                   │ correctly                    │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C1   │ TrBFV PK Generation        │ DKG: Share Gen    │ Threshold pk_share derived   │
│      │                            │                   │ correctly from sk; outputs   │
│      │                            │                   │ sk_commitment, pk_commitment,│
│      │                            │                   │ e_sm_commitment              │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C2a  │ SK Share Computation       │ DKG: Share Gen    │ Shamir shares of sk computed │
│      │                            │                   │ correctly                    │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C2b  │ ESM Share Computation      │ DKG: Share Gen    │ Shamir shares of smudging    │
│      │                            │                   │ noise computed correctly     │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C3a  │ SK Share Encryption        │ DKG: Share Gen    │ sk_sss encrypted correctly   │
│      │                            │                   │ under recipient's BFV key   │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C3b  │ ESM Share Encryption       │ DKG: Share Gen    │ esi_sss encrypted correctly  │
│      │                            │                   │ under recipient's BFV key   │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C4a  │ SK Decryption Share (T2)   │ DKG: Key Calc     │ Verifies H decrypted shares  │
│      │                            │                   │ match C2a commitments; sums  │
│      │                            │                   │ and normalises (reduce mod   │
│      │                            │                   │ q, reverse, center) before   │
│      │                            │                   │ hashing; output commitment   │
│      │                            │                   │ consumed by C6               │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C4b  │ ESM Decryption Share (T2)  │ DKG: Key Calc     │ Same as C4a for e_sm branch; │
│      │                            │                   │ output commitment consumed   │
│      │                            │                   │ by C6                        │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C5   │ PK Aggregation             │ Aggregation       │ Aggregate PK correctly       │
│      │                            │                   │ computed from H canonical    │
│      │                            │                   │ honest keyshares (not all N) │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C6   │ Threshold Share Decryption │ Decryption        │ Decryption share correctly   │
│      │ (T5)                       │                   │ derived from sk + ciphertext;│
│      │                            │                   │ public output: commitment to │
│      │                            │                   │ first MAX_MSG_NON_ZERO_COEFFS│
│      │                            │                   │ coeffs of d per CRT limb     │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C7   │ Decrypted Shares Agg.      │ Final Aggregation │ Plaintext correctly          │
│      │                            │                   │ reconstructed from shares    │
│      │                            │                   │ (modular decode over t);     │
│      │                            │                   │ public inputs: C6 `d`         │
│      │                            │                   │ commitments + party IDs + msg;│
│      │                            │                   │ in-circuit equality vs        │
│      │                            │                   │ commitments from witness      │
│      │                            │                   │ decryption shares             │
└──────┴────────────────────────────┴───────────────────┴──────────────────────────────┘

Slash Reasons by Proof Type:
  C0–C4:  E3_BAD_DKG_PROOF
  C5:     E3_BAD_PK_AGGREGATION_PROOF
  C6:     E3_BAD_DECRYPTION_PROOF
  C7:     E3_BAD_AGGREGATION_PROOF
```

### Compute resource recovery

The production scheduler starts with two compute jobs and two reserved logical CPUs. It reduces the
job limit when the host or cgroup memory limit cannot support two 13 GiB prover budgets. An explicit
higher job limit remains subject to the same CPU and memory limits. Startup fails before protocol
participation when the detected limit cannot cover the 4 GiB node reserve and one prover budget.

| Failure scenario                                                       | Detection                                                                      | Recovery                                                                                                    | Verification                                                                                    |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| The configured job count exceeds the CPU or memory limit.              | Startup computes CPU and memory job limits.                                    | The scheduler uses the smallest safe limit. It refuses startup if no prover fits.                            | `memory::tests::*` and the configuration default test cover 16 GiB, 32 GiB, and 122 GiB limits. |
| `bb prove` exits, receives a signal, or reports an allocation failure. | `ZkProver` returns `ProofGenerationFailed`.                                    | The scheduler retries the same request. Attempts after the first use `--slow_low_memory`.                   | The retry-policy and low-memory flag tests cover this path.                                     |
| `bb verify` does not report the explicit invalid-proof result.         | `ZkProver` returns a verifier-process error instead of `false`.                | The scheduler retries locally and does not accuse the proof sender.                                         | Prover and share-verification tests separate process errors from invalid proofs.                |
| A Rayon task panics or its result channel closes.                      | `TaskPool` returns a structured pool error.                                    | The scheduler retries ZK work with the same E3 task group.                                                  | Task-pool panic and retry-policy tests cover this path.                                         |
| Resource pressure continues.                                           | The retry delay reaches a five-minute cap.                                     | Retries continue until success or a terminal E3 event cancels the task group.                               | The capped schedule and task-group cancellation tests cover this path.                          |
| Many proof requests fail together.                                     | A node-scoped retry-log limiter counts suppressed messages.                    | The node emits at most one retry warning per minute. Other attempts use DEBUG logs.                         | The retry-log limiter test verifies the warning window and count.                               |
| The process exits during proof work.                                   | The supervisor restarts the node.                                              | EventStore replay restores the exact pending input. `ComputeEffectGate` reissues it after `EffectsEnabled`. | Proof actors test that local errors retain pending inputs and correlation IDs.                  |
| The process restarts after a proof result was already durable.         | Node-proof recovery loads proofs by canonical sequence, including completed folds. | The proof actor republishes a complete recovered share bundle or computes only missing sequences.        | Unit tests cover full and partial recovery. A full-proof restart run confirms no recomputation. |
| A proof attempt leaves output files.                                   | A per-job directory guard observes scope exit or finds a stale restart path.    | The prover removes the attempt directory after exit and before a restarted process reuses that path.         | Prover tests cover normal cleanup and a stale directory after process restart.                   |
| A pre-v0.16 snapshot has stale registered-node membership.             | `interfold node validate` compares both sortition projections with EventStore. | `interfold node validate --repair` rebuilds only derived membership and missing member history.             | Validator tests cover detection, reconstruction, preservation, and removal.                     |

The retry path does not regenerate randomized TrBFV contributions. Their durable responses must be
reused exactly after restart. A canonical E3 timeout remains the authority when local recovery does
not finish before the protocol deadline.

### Proof Infrastructure

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ZK Proof Infrastructure                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ProofRequestActor (Business Layer)                                 │
│  ├─ Subscribes to *Pending events (proof requests)                 │
│  ├─ Dispatches ComputeRequest::zk to ZkActor                      │
│  ├─ Collects responses, signs proofs (ECDSA EIP-191)               │
│  ├─ Manages pending proof state (C1–C3 and C4 proof bundles per E3) │
│  └─ Publishes *Created / *Signed events when all proofs complete   │
│                                                                     │
│  ProofVerificationActor (C0 Verification)                          │
│  ├─ EncryptionKeyReceived → ECDSA recovery + ZK verify            │
│  ├─ On pass → EncryptionKeyCreated (locally trusted)               │
│  └─ On fail → SignedProofFailed → AccusationManager                │
│                                                                     │
│  ShareVerificationActor (C2/C3/C4/C6 Verification)                │
│  ├─ Two-phase: ECDSA inline + ZK dispatched to multithread        │
│  ├─ Defense-in-depth: cross-checks dispatched vs returned parties  │
│  └─ On fail → SignedProofFailed → AccusationManager                │
│                                                                     │
│  ZkActor (IO Layer)                                                │
│  ├─ Manages Barretenberg (bb) binary and circuit files             │
│  ├─ Spawns child processes: bb prove / bb verify                   │
│  └─ Returns Proof { data, public_signals }                         │
│                                                                     │
│  AccusationManager (see Part 5 for full detail)                    │
│  ├─ Receives SignedProofFailed → creates accusations               │
│  ├─ Off-chain voting quorum among committee members                │
│  └─ AccusationQuorumReached → on-chain slash submission            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Complete DKG Data Flow

```
Party 1                    Party 2                    Party 3
───────                    ───────                    ───────
Generate BFV keypair       Generate BFV keypair       Generate BFV keypair
  (sk₁, pk₁)                (sk₂, pk₂)                (sk₃, pk₃)

Broadcast pk₁ ──────────→ Receive pk₁ ──────────→ Receive pk₁
Receive pk₂ ←──────────── Broadcast pk₂ ──────────→ Receive pk₂
Receive pk₃ ←──────────── Receive pk₃ ←──────────── Broadcast pk₃

Generate TrBFV key:        Generate TrBFV key:        Generate TrBFV key:
  (SK₁, PK_share₁)          (SK₂, PK_share₂)          (SK₃, PK_share₃)

Shamir split SK₁:         Shamir split SK₂:         Shamir split SK₃:
  s₁₁, s₁₂, s₁₃            s₂₁, s₂₂, s₂₃            s₃₁, s₃₂, s₃₃

Encrypt & send:            Encrypt & send:            Encrypt & send:
  Enc(s₁₂, pk₂) → P2        Enc(s₂₁, pk₁) → P1        Enc(s₃₁, pk₁) → P1
  Enc(s₁₃, pk₃) → P3        Enc(s₂₃, pk₃) → P3        Enc(s₃₂, pk₂) → P2

Receive & decrypt:         Receive & decrypt:         Receive & decrypt:
  s₂₁ = Dec(_, sk₁)         s₁₂ = Dec(_, sk₂)         s₁₃ = Dec(_, sk₃)
  s₃₁ = Dec(_, sk₁)         s₃₂ = Dec(_, sk₂)         s₂₃ = Dec(_, sk₃)

Reconstruct:               Reconstruct:               Reconstruct:
  dk₁ = sum(s₁₁,s₂₁,s₃₁)   dk₂ = sum(s₁₂,s₂₂,s₃₂)   dk₃ = sum(s₁₃,s₂₃,s₃₃)

═══════════════════════════════════════════════════════════════
Each party now has dk_i (decryption key portion)
No party knows the full secret key
Any T+1 members of the accepted DKG roster can collaboratively decrypt

ACTIVE AGGREGATOR collects PK_share₁ + PK_share₂ + PK_share₃
  → Produces aggregate_PK (public, published on-chain)
  → Anyone can encrypt, only committee can decrypt
```

## Durable flow tracing

The dashboard renders event ID, causation ID, origin ID, HLC timestamp, block watermark, aggregate,
and source exactly as the local EventStore recorded them. Observability does not change the
sequencing or gossip path. Local cause/effect chains are exact; received network events follow the
protocol's established receiver-local context semantics.

`InputPublished`, `RewardsDistributed`, `RewardCredited`, and `RewardClaimed` have typed EVM
translations. `CommitteePublished` and `PlaintextOutputPublished` are also translated from their
canonical on-chain logs. Every current interface signature is catalogued: logs without a
protocol-driving typed decoder become named, lossless `EvmLogObserved` facts, while a signature not
present in the running ABI catalog is exposed as `UnknownEvmLog` with raw topics/data.

During restart, `ComputeEffectGate` observes replay before compute workers are effects-enabled. It
buffers and deduplicates `ComputeRequest`s, prefers the newest regenerated request, cancels terminal
E3 work, and releases pending jobs only after `EffectsEnabled`. The gate starts with the durable E3
lifecycle snapshot. If an E3 has already reached `KeyPublished`, it discards replayed DKG and DKG
proof jobs because the chain has made that work obsolete; decryption jobs remain eligible. C1-C3 and
C6 verification share one compute-request variant, so the gate uses the signed proof type to keep C6
threshold-decryption verification eligible. The gate changes effect timing, not durable event order
or audit state. If restart gives the same compute operation a new correlation ID, the gate forwards
the work once and sends its response or error to each waiting ID. A later duplicate receives the
saved outcome.

A crash can leave the public-key snapshot in `Collecting` while the durable C1 verification request
has already entered the event log. Its replayed result can then arrive before historical keyshares
restore `VerifyingC1`. The active aggregator holds one such result with the saved selected roster
and applies it when the same roster's keyshares are ready. It discards the result if the roster
changed, and it ignores duplicate C1 results after C1 completed.

A terminal E3 event also cancels that E3's compute jobs that have already reached the shared task
pool but have not started. The cancellation key includes the local ciphernode address, so one node's
local failure cannot cancel another node's work when an integration test or embedding shares one
pool across nodes. A proof that is already executing runs to completion because the Rayon worker
cannot be preempted safely; its late result cannot revive the terminal E3. This prevents a failed
round's queued proof plan from delaying proof work for a later active round.

If a decryption-share response arrives after `ThresholdKeyshare` has left `Decrypting`, the actor
ignores that late response. The share and C6 proof request from the first response remain in the
saved state; a replay does not report a false state error or start the work again.

`CiphernodeSelector` also observes replay before it enables failover effects. Its versioned
repository stores a readiness-gated phase, assigned party, absolute deadline, and locally
unresponsive party IDs. DKG roster selection, public-key aggregation, and plaintext aggregation use
separate failover phases. `CommitteeFinalized` and `CiphertextOutputPublished` identify the current
protocol stage but do not start a progress budget. A persisted actor publishes
`AggregationInputsReady` only after all inputs for its phase are durable. Accepting a DKG roster
moves the selector to the public-key phase without starting that phase's timer. An unchanged ready
phase and assignment preserve the original deadline. A new assignment gets the full budget.
`EffectsEnabled` re-arms the remaining duration or processes an overdue deadline immediately.
Protocol progress cancels the old timer and clears the phase-local skip set. Startup rejects an
unsupported failover schema; operators must clear pre-release protocol-v4 state before rollout.

The Interfold and registry writers also subscribe before EventStore replay. A locally sourced
`PlaintextAggregated` or `PublicKeyAggregated` event is the durable publication intent. Each writer
coalesces the intent by E3, waits for `EffectsEnabled`, checks chain state before submitting, and
keeps retryable failures for a later attempt. `E3RequestComplete` does not erase an unfinished
publication, and only an active aggregator can start a retained submission. `PlaintextAggregated` is
not gossiped or returned by historical peer sync; only the producing node can create this EVM write
intent.

The document publisher rebuilds its active outbox and received-document set from the durable event
log before network effects start. Document publication and receipt events use their E3's chain
aggregate. Recovery scans one event at a time to bound memory. During DKG, it repeats DHT
publication and gossip announcements after transient failures, including when no peer subscribed to
the topic at the first attempt. A receiver holds early notifications until its committee slot is
known, retries failed DHT reads, and suppresses duplicate documents. A canonical `KeyPublished`
stage stops DKG-document announcements and prunes local DHT records. C4 `DecryptionKeyShared` is a
DKG document; later `DecryptionshareCreated` events use event gossip, not the DHT document path.
Recovery retains the DKG closure across restart. A local `E3RequestComplete` does not mean that the
contract has reached a terminal stage.

The CRISP server writes its request record at `E3Requested` and writes the generic E3 record only
after the indexer verifies the committee public key against the on-chain commitment. Current-round
lookup uses the request record, so a round remains visible while its key is pending. CRISP activates
the round only when both records exist. Either handler can complete the activation after their
records converge, and deferred checks cover slow live-handler ordering. Duplicate request and
committee events do not reset the round, replace indexed output, or resubmit an already-matching
Merkle root. The shared Interfold contract also emits requests for other E3 programs. The CRISP
indexer ignores those requests before it creates a round or makes a program-specific RPC call. An
old program's historical round therefore cannot stop a fresh CRISP backfill.

Startup rebuilds deadline callbacks for active and expired rounds and releases an interrupted
compute submission for retry. The compute transition is atomic, and a synchronous program-server
request error releases the claim to `Expired` so a later deadline callback can retry it. Compute
submission is at-least-once across a restart because the HTTP response or webhook can be lost. A
retry can repeat proof work, but it cannot publish a second result: `Interfold` accepts ciphertext
output only from `KeyPublished`, and the callback treats an E3 that already reached
`CiphertextReady` or `Complete` as success.

Secure-8192 committee public-key bytes do not use one oversized transaction. `publishCommittee`
first records the proof-backed commitment. The selected publisher then sends the bytes through
bounded `publishCommitteePublicKey` chunks. Readers assemble one canonical chunk set and accept the
key only when its recomputed commitment equals the value already stored on chain. `KeyPublished`
alone therefore does not mean that a client has usable key bytes. The application becomes ready only
after the complete key publication arrives and passes that commitment check.

### What the compute-provider crate guarantees, and what an E3 program decides

`e3-compute-provider` is shared by every E3 program, so it holds only what is true for all of them:

- leaves are **derived** from the ciphertexts the Secure Process consumed, never received alongside
  them;
- **every** published input contributes a leaf, whatever is computed over.

The leaf layout and which inputs are computed over come from the program, as an `InputPolicy`:

```rust
pub struct InputPolicy {
    pub leaf: fn(&PublishedInput) -> Result<String, ComputeError>,
    pub select: fn(&[PublishedInput]) -> Vec<usize>,
}
```

Both are program-specific. A leaf must equal what that program builds on-chain, and no two programs
need agree. Selection answers "what does a second input for the same participant mean?", which CRISP
answers differently from a program where every input counts.

`InputPolicy::default()` is the behaviour that predates policies — the leaf is the ciphertext's own
commitment and every input is computed over — and matches the starter template, whose
`MyProgram.publishInput` inserts the commitment directly. Every E3 program exports `policy()` beside
`fhe_processor`, so the guest and the dev runner need not know which program they are running.

The published support image embeds the CRISP guest from `crates/support/program`. The reference app
keeps the same guest in `examples/CRISP/program`. A CRISP policy change must update both copies and
regenerate `crates/support/contracts/ImageID.sol` before the support image is published.

`interfold program start` sends each configured Boundless offer parameter through the project
support launcher to the container. The container maps these values to the environment variables that
build the on-chain offer. An omitted parameter uses the host's built-in default.

`PublishedData` carries what the program published per input: the stored commitment, and opaque
`metadata` the crate never interprets. CRISP puts its 20-byte slot address and the 5-byte parent
index there, laid out as `abi.encodePacked(address, uint40)`.

### Input leaf binding and per-slot selection

An E3 program verifies a proof over the ciphertext **commitment** when an input is committed. The
proof also exposes the Keccak hash of the serialized ciphertext, split across two field elements.
The contract cannot deserialize the ciphertext or reproduce its Poseidon commitment. The guest is
the first place both representations exist at once.

`CRISPProgram.inputLeaf` therefore binds four values:

```text
leaf = sha256(keccak256(encryptedVote) || encryptedVoteCommitment || slotAddress || parentIndexPlusOne)
       mod SNARK_SCALAR_FIELD
```

- the **content hash**, so a submitter cannot pair a valid commitment with unrelated bytes;
- the **commitment**, so any commitment cannot be paired with any ciphertext;
- the **slot**, because the tree is append-only and the guest selects per slot — an unbound slot
  would let a prover re-group entries and change which one wins;
- the **parent**, because the guest walks each slot's chain by it — an unbound parent would let a
  prover re-point entries and change which one holds the slot.

`MerkleTreeBuilder::compute_leaf_hashes` rebuilds exactly that layout. Both sides pin the same test
vector (`program/tests/input_leaf.rs` and `tests/input-leaf.test.ts`), and
`examples/CRISP/program/tests/onchain_root_agreement.rs` asserts Rust reproduces a root a real
contract produced, from a fixture generated by `tests/input-tree-e2e.test.ts`. A one-byte divergence
would make every root mismatch and nothing else would detect it.

Keccak is used for the serialized ciphertext so the digest can match a content hash exposed by an
external data-availability receipt. SHA-256 remains the outer hash because the zkVM accelerates it
inline. The guest recomputes both hashes from the ciphertext bytes that it consumes.

**The input tree is append-only.** `_processVote` always inserts and never updates in place. That is
a security property, not a storage choice: the mask path requires no signature, so anyone can write
to any census member's slot. With update-in-place, a third party could replace the bytes of a vote
that had already been counted and erase it silently while the round still completed. Appending
leaves the earlier entry in the tree.

Every input names the entry it extends. `publishInput` takes `parentIndexPlusOne` in its calldata,
reads that entry's commitment out of the per-slot history, and hands it to the circuit as
`prev_ct_commitment`; zero means the input extends nothing, which the circuit reads as
`is_first_vote`.

For each slot the Secure Process computes over the **end of that slot's chain of usable entries**
(`chain_head_per_slot`). Walking in index order, an entry becomes the slot's head only when both
hold:

- its bytes reproduce its commitment, so it is a ciphertext anyone can read; and
- the entry it names is the slot's current head.

Entries that fail either rule keep their leaf — removing one would change the root — but are
skipped. The rule is a function of values the root binds, so any prover holding the same published
data reaches the same set and none can choose what to drop.

Why the chain rather than "the most recent usable entry": `CRISPProgram` cannot tell that a
submitter's bytes disagree with the commitment they published — only the Secure Process can, and
only after the input window closes. With a single mutable slot head, anyone could therefore leave a
slot whose head only they can open, and a slot nobody can mask is a slot where every later input is
provably its owner voting again. That is a coercion receipt, and a cleaner one than the receipt
masks exist to destroy. Because an unusable entry is never the head, it is never a valid parent
either, so the next honest input names the same parent it did and masking continues.

The resulting properties:

- a malformed input costs one entry, not the round;
- an append with bad bytes cannot erase a counted vote, and cannot freeze the slot against masking;
- an entry naming a stale parent is dropped, so a mask cannot restore a superseded ciphertext over a
  later vote;
- an honest re-vote still replaces the earlier ballot, because it extends the head and adds to
  nothing;
- a mask preserves the tally, since the circuit forces its plaintext to zero everywhere
  (`check_coefficient_zero`) and proves `sum = head + zero`.

**What the rule costs.** Two entries naming the same parent are siblings, and the first usable one
takes the head; the second is dropped. So an input can be front-run into being dropped — an attacker
who sees a re-vote in the mempool can land a mask on the same parent first, and the re-vote is not
counted.

That is the deliberate side of a genuine trade-off, not an oversight. A stale parent is
indistinguishable from a sibling that was simply built a moment earlier: both name an entry that is
no longer the head, and only the circuit knows whether an entry _replaces_ the slot or _adds_ to it
— which is precisely what `is_mask_vote` keeps private. Favour the earlier sibling and a re-vote can
be delayed; favour the later one and a mask built on a superseded ciphertext can restore it over a
vote. The first is visible to the voter (the server resolves the chain, so the client can see its
input was not taken) and is fixed by submitting again. The second is a silent tally corruption that
nobody can detect or undo. Submitting through the CRISP server's relayer also keeps the transaction
out of a public mempool, which is where the race would be won.

Closing the gap entirely would need the guest to tell a replace from an add, which means publishing
that distinction — the thing the whole design exists to hide.

Capacity: `TREE_DEPTH = 20` gives 2^20 entries, against a physical ceiling of roughly three writes
per block at the secure preset — append-only is not capacity-bound.

A round where _every_ entry is unusable fails at the output commitment, because the processor's
empty ciphertext does not deserialize. That is only reachable when no honest input exists, and is
indistinguishable from a round that received none, which the protocol resolves as
`NoInputsReceived`.

`InputCommitted` carries the slot, commitment, content hash, parent, and reserved index. The later
`InputPublished` event repeats the tuple with the VectorX-verified Avail coordinates. Neither event
carries the ciphertext bytes. Indexers fetch those bytes and reject them unless their Keccak hash
matches the on-chain content hash.

### One relation for voting, updating, and masking

The ballot circuit proves the same statement for all three operations:

```text
published ciphertext = addend + ballot ciphertext
```

The ballot is a fresh BFV encryption of `k1`, covered by the recursive `user_data_encryption` proof.
The addend is the slot's current head for a mask, and the zero ciphertext for a vote, a re-vote, or
any input to an empty slot. `is_mask_vote` chooses between them and is **private**, and the selector
is derived (`keep_previous = is_mask_vote & !is_first_vote`) rather than taken as a witness — so a
voter cannot add their new ballot on top of their old one and count twice, and a masker cannot
discard the head and erase a vote.

The circuit returns `sum_ct_commitment` on every path, so the public inputs, the stored commitment,
the ballot digest, and the published ciphertext have the same shape whichever operation ran. Telling
them apart would mean distinguishing a fresh BFV ciphertext from a sum, which the encryption scheme
hides. The SDK has one code path for all three, and `CrispSDK.prepareBallot` makes the same
`state/previous-ciphertext` request either way, so the request pattern says nothing either.

The plaintext is fully constrained on both branches. `check_coefficient_values_with_balance` binds
every coefficient of `k1`: those inside an option segment must be binary, and every coefficient
outside the ballot region must be zero. `check_coefficient_zero` requires the whole polynomial to be
zero for a mask. Both read the payload at `k1[D - MAX_MSG_NON_ZERO_COEFFS ..]`, because the witness
generator reverses the message over the full BFV degree — the ballot occupies the **last** 100
coefficients, and the options appear back to front.
