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
│   ├─ 1. Create child actors:
│   │     ├─ EncryptionKeyCollector (accepts all N keys or at least H at cutoff)
│   │     └─ ThresholdShareCollector (accepts all N−1 external shares or at least H−1 at cutoff)
│   │     → These collectors start immediately so early peer keys/shares can
│   │       be buffered while this node is still finishing earlier DKG phases
│   │     → A peer key that arrives in `Init` is only recorded.
│   │       `replay_encryption_keys` sends every recorded key to the new
│   │       EncryptionKeyCollector, as restart recovery does
│   │
│   ├─ 2. Generate fresh BFV keypair:
│   │     (secret_key, public_key) = BFV::keygen(share_encryption_preset)
│   │     → This is the node's SHARE ENCRYPTION key
│   │     → Used to encrypt Shamir shares sent to this node
│   │
│   ├─ 3. Encrypt BFV secret key at rest:
│   │     encrypted_sk = Cipher.encrypt(secret_key)
│   │     → Stored locally, password-protected
│   │
│   ├─ 4. State transition: Init → CollectingEncryptionKeys
│   │
│   ├─ 5. Publish EncryptionKeyPending {
│   │     e3_id, party_id, bfv_public_key
│   │   }
│   │   → ZK proof actor picks this up
│   │
│   └─ Collector schedules use the frozen per-E3 window and absolute deadline:
│         ├─ EncryptionKeyCollector: hard cutoff at 10% of the window
│         ├─ ThresholdShareCollector: soft cutoff at 75% of the window
│         └─ DecryptionKeySharedCollector: hard cutoff at the on-chain DKG deadline
│      Restart uses the remaining time, not a new full window. A restart after
│      the encryption-key cutoff but before the canonical deadline creates that
│      collector without a timer, and the collector applies the cutoff to the
│      recorded keys (Step 3). Optional per-collector env values can advance a
│      cutoff but cannot extend it.
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
│     ├─ With proof aggregation on, publishes DKGInnerProofReady { seq: 0 } (own C0) first,
│     │   so NodeProofAggregator persists C0 before EncryptionKeyCreated can end key collection
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
     ├─ Hydration scans durable events, including the snapshot prefix, for unresolved C0 inputs
     │   and applies the live signature and commitment checks. Local results and completed E3s
     │   clear pending inputs. Dispatch waits until EffectsEnabled, also during replay
     ├─ Recovers ECDSA signer address from signed proof
     ├─ Dispatches ZK verification to ZkActor:
     │   ZkActor runs: bb verify -k vk -p proof.data
     │
     ├─ If verification PASSES:
     │   ├─ Publishes EncryptionKeyCreated (locally trusted)
     │   └─ Publishes ProofVerificationPassed (cached by AccusationManager)
     │
     ├─ If a completed check returns Invalid:
     │   └─ Publishes SignedProofFailed and ProofVerificationFailed for C0
     │      → Triggers accusation pipeline (see Part 5)
     │
     └─ On InfrastructureError (local verifier, verification key, or I/O unavailable):
         ├─ Keeps the authenticated input and event context in the pending map
         ├─ Retries after 5 seconds, doubling the delay to a 60-second cap, with one timer per input
         ├─ Logs each failed attempt at WARN with its attempt count and next delay
         └─ Publishes no peer-failure evidence; E3RequestComplete cancels pending retries
```

### Step 3: Collect Encryption Keys

```
EncryptionKeyCollector collects verified EncryptionKeyCreated events
│
├─ On each arrival: store the first (party_id → bfv_public_key) message;
│  replay keeps that same first message if a later duplicate arrives
│
├─ A key that arrives while the keyshare is in `Init` is only recorded in the
│  recovery state: the collector needs the frozen DKG timing that the node reads
│  at its own selection. `handle_ciphernode_selected` sends every recorded key to
│  the collector
│
├─ A new collector (this one or the ThresholdShareCollector) first receives every
│  expulsion that the keyshare recorded (ExpelPartyFromKeyCollection,
│  ExpelPartyFromShareCollection), then its inputs. It ignores the input of an
│  expelled party and does not wait for it. A running collector receives each
│  later expulsion
│
├─ A live key after the cutoff is recorded but does not reach the collector, even
│  if the collector's relative timer has not fired yet. A late input is expected,
│  so the keyshare does not report it as an error; a failed write is reported as
│  InterfoldError
│
├─ Restart in CollectingEncryptionKeys (`resume_in_flight_work`):
│   ├─ Sends every recorded key to the collector, then EncryptionKeysReplayed
│   ├─ If the cutoff passed while the node was down, but the canonical deadline
│   │  has not, the collector has no timer. It applies the cutoff when it
│   │  receives EncryptionKeysReplayed, so only the keys recorded before the
│   │  restart count. Historical sync does not carry keys: a missed key comes
│   │  back only when its sender announces the document again, after
│   │  EffectsEnabled. A key whose proof check had not finished also misses
│   │  this cutoff
│   └─ Rebuilds the ThresholdShareCollector, as every recovery state that
│      replays shares does, and sends it every recorded share. A peer can send
│      its share while this node still collects encryption keys
│
├─ On TIMEOUT (derived DKG-phase cutoff):
│   ├─ With at least H keys, including this party's key:
│   │    send AllEncryptionKeysCollected with the available keys
│   └─ Otherwise send EncryptionKeyCollectionFailed to parent ThresholdKeyshare
│      ├─ Ignore a different E3 or a failure after encryption-key collection ends
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

For `secure-8192`, the threshold key uses plaintext modulus 1,000,000 and three 59-bit CRT primes
(`0x0400000000c00001`, `0x0400000000a40001`, `0x0400000000990001`). The paired share-encryption key
uses plaintext modulus 288230376164294657 and two 61-bit primes (`0x1000000000024001`,
`0x1000000000054001`). Both use ring degree 8192 and statistical security parameter 45. The
threshold encryption error variance is 17723039943798878305460955570711717478400. These values bind
the C1-C7 witness dimensions and the on-chain BFV parameter hash. C7 uses
`Q_INVERSE_MOD_T = 663169`, the inverse of the product of the three threshold primes modulo
1,000,000. New secure E3s use on-chain parameter-set index 2. Index 1 retains the previous secure
tuple for historical requests. C3 share encryption and user-data encryption use non-centered `k1`
residues in `[0, t - 1]`; the Rust witness, Noir equation, and quotient bounds must agree.

```
ThresholdKeyshare receives AllEncryptionKeysCollected
│
├─ Removes keys from expelled parties: an expulsion can reach the keyshare after
│  the collector completes. With fewer than H keys, or without this node's key,
│  the keyshare fails as at a cutoff with too few keys (Step 3)
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
│   │  │     → Uses the preset's lambda and additive depth 0      │
│   │  │     → Bound: 2^(lambda + 1) × degree × B_C              │
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
    │   → A local worker or task-pool failure retries the same live request.
    │   → Retry warnings are limited to one per minute.
    │   → The node does not report local failure as invalid committee data.

### Step 5: Encrypt & Broadcast Shares (with C1, C2, C3 Proofs)

```
Both GenPkShareAndSkSss and GenEsiSss complete
    │
    ├─ `ThresholdKeyshare` tracks the `CalculateDecryptionKey` correlation id:
    │   → A local worker or task-pool failure retries the same request.
    │   → An unexpected terminal local error is logged without reporting invalid shares.
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
│       → Verifies a C2/C3 batch recorded before this transition (also on restart resume)
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

`node_fold::assert_c3_recipient_keys` pins every non-self recipient limb to that recipient's
limb-zero key. It also requires C3a and C3b keys to match in every slot. The fold exports limb zero,
and `dkg_aggregator::assert_selected_c0_c3_links` binds that export to the recipient's C0 key. The
node's own recipient slot is exempt because its exported key comes directly from C0. The per-circuit
`wrapper/` Noir step was removed; aggregator response structs no longer carry a `wrapped_proof`
field — the inner recursive proof itself is what flows between stages.

Sequential C3, C6, and nodes folds expose the fixed `(leaf, fold, genesis)` VK hashes before
`is_first_step` and `slot_index`. `predecessor_key_hash` requires the predecessor to carry the same
three hashes. The first step verifies the genesis VK. Each continuation verifies the fold VK. The
final consumer also requires the declared fold hash to match the VK that verified its proof.

`compute_vk_hash` uses the SAFE `DS_VK_HASH` sponge and preserves input order. The DKG trust anchor
includes every descendant key:

```text
C2 tree    = hash(C2a, C2b)
C3 chain   = hash(c3_fold, c3_fold_kernel, C3)
C3 tree    = hash(C3a chain, C3b chain)
C4 tree    = hash(C4a, C4b)
node tree  = hash(C0, C1, c2ab_fold, C2 tree, c3ab_fold, C3 tree, c4ab_fold, C4 tree)
nodes tree = hash(nodes_fold, nodes_fold_kernel, node_fold, node tree)
C6 tree    = hash(c6_fold, c6_fold_kernel, C6)
```

The builder derives `nodes_fold.vk_tree_hash` and `c6_fold.vk_tree_hash` from each complete artifact
pair. `dkg_aggregator` requires every folded node row to carry the same node-tree hash. Both final
aggregators expose their complete tree anchor at public input zero. The immutable wrapper pin comes
from the matching tree-hash file, not the immediate fold VK. Public input one retains the separate
C5 or C7 non-ZK recursive VK hash. The final EVM public-input layouts do not change.

**Ciphernode / aggregator integration:** `ZkRequest::FoldProofs` was removed. The multithread actor
implements `ZkRequest::NodeDkgFold` (full per-node pipeline to a `NodeFold` proof),
`ZkRequest::DkgAggregation` (`NodesFold` + C5 + `DkgAggregator`), and
`ZkRequest::DecryptionAggregation` (per-ciphertext `C6Fold` + C7 + `DecryptionAggregator`).
`NodeProofAggregator` prebuffers `DKGInnerProofReady` proofs that arrive before
`ThresholdSharePending` (the own C0 always does), drains those buffered proofs into collection state
once `ThresholdSharePending` arrives, and issues one `NodeDkgFold` request when the full ordered
proof set is available. It persists each proof, the fold metadata, and a completed output before
publication. Restart restores the ordered proofs and reissues an incomplete fold after
`EffectsEnabled`. A local worker failure keeps the saved node-fold data. The compute scheduler
retries the exact request until the E3 becomes terminal. A canonical `KeyPublished` stage or a
terminal E3 event removes the saved node-fold data. `PublicKeyAggregator` and
`ThresholdPlaintextAggregator` dispatch the aggregator requests instead of pairwise folding.

**Failure boundary:** A local prover, verifier, signer, parameter builder, attestation builder, or
worker failure is not proof that a peer supplied invalid data. The compute scheduler retries
`ProofGenerationFailed` and keyshare-owned TrBFV work. ZK attempts after the first use Barretenberg
low-memory mode. Pending inputs and correlation IDs remain available for restart replay. A completed
NodeFold waits for its request-time attestation context when that context is late. These local
failures do not emit `DKGInvalidShares` or `DecryptionInvalidShares`. Cryptographically invalid
proofs and incomplete proof sets keep their protocol-failure paths.

`ProofRequestActor` signs each recipient's complete `ThresholdShareCreated` before publication. The
signature digest is a type-separated ABI encoding of the E3 hash, dealer ID, recipient ID, share
hash, and proof-bundle hash. The hashes use Keccak256 over positional bincode encodings. The
proof-bundle encoding includes its order, optional fields, proof bytes, signals, and signatures.
`external` is excluded because network receipt changes it. `DecryptionKeyShared` uses a separate
type prefix and binds its E3 hash, dealer ID, node-address hash, and ordered C4 bundle hash.

### Step 6: Collect Threshold Shares (with C2/C3 Verification)

```
ThresholdShareCollector collects this recipient's shares from the other N−1 parties
│
├─ Each ThresholdShareCreated arrives via libp2p P2P network
│
├─ ThresholdKeyshare.handle_threshold_share_created():
│   ├─ Filters: only process shares where target_party_id == MY party_id
│   │   → Each published share contains this recipient's encrypted material
│   ├─ Before record_threshold_share or collection: recovers the whole-message signature
│   │   and requires the finalized committee address for the claimed dealer and this E3
│   │   → The signature binds E3, dealer, recipient, share bytes, and the complete proof bundle
│   │   → A rejected message reserves no slot and produces no accusation
│   ├─ After the canonical DKG deadline: records the authenticated share, but does not forward it
│   ├─ Seeds every new collector with saved expulsions, then all retained authenticated shares
│   │   → This also applies when a later share starts collection after restart
│   └─ Forwards filtered share to ThresholdShareCollector
│
├─ When local key calculation completes or the keyshare actor stops:
│   └─ Stop the threshold-share collector and its cutoff and deadline timers
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
│      ├─ Ignore a different E3 or a failure after threshold-share collection ends
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
    │   → Before its own shares exist, ThresholdKeyshare only records the batch (see Step 5)
    │
    └─ DISPATCH C2/C3 VERIFICATION:
        ThresholdKeyshare.dispatch_c2_c3_verification()
        │
        └─ Publishes ShareVerificationDispatched {
             kind: ShareProofs,
             party_proofs: [all C2a, C2b, C3a, C3b proofs per party],
             pre_dishonest: [parties with missing/incomplete proofs]
           }
           → ShareVerificationActor picks this up, including an empty proof list
           → If all dealers fail local prechecks, it emits the pre_dishonest outcome without ZK work
           → Keyshare saves that outcome and can dispatch a larger batch when another dealer arrives
           → A restarted keyshare grows the batch from saved share references too
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
│   │   │   └─ Exclude the bundle from this batch without emitting fault evidence
│   │   │      → Unauthenticated labels and signatures cannot accuse a claimed party
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
│          Its delivery ID includes the dispatch event that caused it, so equal verdicts for
│          different batches, such as a batch and its later growth, are both delivered.
│
└─ ThresholdKeyshare receives ShareVerificationComplete:
    ├─ Until a C2/C3 result is recorded, applies each one to the first batch. After that,
    │  it applies a result only if its dispatch is one that this node sent for the current
    │  batch. The recovery state keeps those dispatch IDs, so replay applies such a result
    │  where it applied before a restart. When the logged dispatch reaches the node and
    │  holds every live dealer of the current batch and no other, the node saves the ID
    │  again at the dispatch's own position, also when it already holds it. A batch that
    │  EffectsEnabled sends again has no logged cause, and its first save uses the last
    │  saved context, which the store can refuse as stale: a later snapshot cut then keeps
    │  the ID, and replay from an earlier cut restores it from the log. It keeps any other
    │  result and applies it when it sends a dispatch with that ID, as when a restart
    │  sends the saved batch again. A result of an earlier batch therefore cannot count a
    │  dealer that only a grown batch holds as verified
    ├─ Excludes failed C2/C3 proofs and C3 proofs that target a different
    │  recipient key
    ├─ Saves the verified dealer IDs and their exact contribution hashes
    ├─ Publishes a signed DkgCoordination::Ready list when at least H dealers,
    │  including this party, remain
    ├─ Re-verifies each late-share batch that, without its expelled dealers, holds every
    │  dealer of the saved batch that is not expelled, plus at least one more. An expelled
    │  dealer in the new batch is not growth. It publishes a new signed Ready list only
    │  when the list keeps every dealer of the earlier one that is not expelled and adds at
    │  least one dealer that is not expelled, so a Ready list drops only expelled dealers
    │  File: crates/keyshare/src/threshold_keyshare/effects/coordinate_roster.rs (ready_update)
    ├─ If fewer than H pass locally, stays outside C4 without failing the E3
    └─ Waits for one H-dealer roster before Step 7

The active aggregator selects H parties whose signed Ready lists all contain the same selected
dealer contributions. `AggregatorChanged` carries the active party ID, and threshold-keyshare
persists that ID. A receiver keeps one authenticated roster per proposer. It can accept a roster
from the active proposer or an earlier proposer whose failover budget has already elapsed locally.
The proposer must have published a matching Ready list, the receiver's own Ready list must contain
the roster, and every Ready list already held for a selected dealer must support it.

A receiver applies a peer's Ready update with the same rule. It holds each refused update that adds
a dealer but lacks a dealer of the held report, at most one per committee member for each reporter,
in its saved recovery state: the reporter can have seen expulsions that the receiver has not seen
yet, and the network resends the same events, which EventBus deduplication drops. After each
expulsion, and when effects resume after a restart, the receiver applies the held updates that the
expulsions now explain, one after another, and drops the ones that can no longer apply. It settles
held updates only in the DKG phases, so a saved failure is redriven first. A roster
that held Ready reports contradict stays held in the same way. Acceptance checks the roster's support
again and that neither its proposer nor a selected dealer is expelled; a held roster with an
expelled member is dropped. A later roster from the same proposer replaces a held roster that the
local Ready state does not support. Before C4
starts, a roster from a lower party ID replaces a roster from a higher party ID. An accepted
roster is never dropped, so the commitment checker keeps its selection; until C4 starts, an
expelled dealer is not an honest party, also when a restart restores the roster, and a fixed
roster is restored with every dealer. C4 starts when the node sends its decryption-key
calculation. It saves that fact with the selected parties. The logged calculation request saves
the state again at its own position, also when the store refused the dispatch write as stale and
memory already holds the fact, and replay delivers that request again, so a restart that loses the
calculation keeps the roster fixed. A held
roster with an expelled member gives way to a later roster of the same proposer. A promoted
aggregator re-proposes the accepted dealer list instead of deriving
a different list from its local delivery order.

Once a node can derive a valid roster, or receives a supported roster that it cannot yet derive
from every peer Ready report, it starts the existing 10-minute active-aggregator budget for the
DKG-roster phase. If the active aggregator does not publish a roster, the selector promotes the
next eligible committee member and publishes its new party ID. The promoted member uses the
accepted dealer list or its saved Ready map; there is no second leader election. Roster acceptance
ends that phase and clears its local failover skips. The later C5 public-key aggregation starts a
new failover budget only after its own inputs are durable.

The network actor keeps the latest local Ready and Roster message for each open E3. It sends the
same signed protocol event in a fresh transport envelope 30 seconds after the message is cached,
then doubles the wait up to 5 minutes, with up to 10 % jitter. A newer message for the same E3,
party, and kind replaces the cached one and restarts the schedule. The fresh delivery ID bypasses
the libp2p duplicate cache. The stable embedded event ID preserves EventBus deduplication, and a
receiver does not store a copy of an event that it has already stored. Key publication or a terminal
E3 removes the cached messages. A cached message is also dropped 8 hours after it was cached. The
node remembers the last 1,024 E3s whose terminal stage came from the chain, also from replayed
history, and does not cache their messages. After a restart, local replay caches the messages again
in log order, and nothing is sent again before that replay finishes. The restart re-broadcast then
sends each recent message once, skips the remembered E3s, and caches nothing.

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
Before canonical key publication, a selected party's expulsion or exclusion fails the DKG
immediately: the fixed H-row proof cannot remove that party after roster selection.
After `CommitteePublished`, or `E3StageChanged` to `KeyPublished`, `CiphertextReady`, or `Complete`,
the public-key aggregator ignores raw expulsion and exclusion events for DKG work. This rule also
applies to a standby that remains in `VerifyingC1`. Chain failures remain authoritative, and
plaintext aggregation still requires T+1 valid roster shares.
File: crates/aggregator/src/public_key_aggregation/effects/mod.rs (handle_member_expelled)
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
├─ 3. PERSIST C4 PROOF REQUESTS, ENTER ReadyForDecryption, THEN PUBLISH:
│     DecryptionShareProofsPending {
│       sk_request:   DkgShareDecryptionProofRequest (C4a),
│       esm_requests: Vec<DkgShareDecryptionProofRequest> (C4b, one per ESI),
│       sk_poly_sum, es_poly_sum  // decrypted aggregates for proof inputs
│     }
│     → ProofRequestActor picks this up
│
├─ 4. C4 PROOF GENERATION (ProofRequestActor):
│     │
│     │  ├─ With proof aggregation on, holds the request until ThresholdSharePending sets
│     │  │   the seq layout, so C4a/C4b take the seqs after C0-C3
│     │  │
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
│     │      ├─ Signs all proofs, then signs the complete C4 message
│     │      └─ Publishes DecryptionKeyShared {
│     │           e3_id, party_id, node,
│     │           signed_sk_decryption_proof,       // C4a
│     │           signed_e_sm_decryption_proofs[],  // C4b per ESI
│     │           signature                       // complete message, excluding transport origin
│     │         }
│     │         → Broadcast to all committee nodes via P2P gossip
│     │         → This is Protocol Exchange #3 (decryption key sharing)
│
├─ 5. COLLECT C4 SHARES FROM THE ACCEPTED ROSTER:
│     Each selected party waits for DecryptionKeyShared from the other H−1
│     selected parties
│     Before saving or collecting a C4 message, require its whole-message signature from
│     the finalized dealer address. It binds the E3, dealer, node address, and ordered proof bundle.
│     Rejected messages leave the slot free and produce no accusation.
│     On restart, rebuild the collector from the saved roster and feed it saved
│     peer shares before new shares arrive. A valid new share also creates the
│     collector if it is still absent.
│     After all selected peer shares arrive, ignore late duplicates so they do
│     not start another collector and cause a false timeout.
│     The saved replay map also keeps the first C4 message from each party,
│     matching the live collector.
│     │
│     ├─ On timeout:
│     │  ├─ Ignore a different E3 or a failure after C4 collection is superseded
│     │  ├─ Persist KeyshareState::Failed {
│     │  │    failed_at_stage: CommitteeFinalized,
│     │  │    reason: DKGTimeout
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
├─ 7. C4 verification authorizes KeyshareCreated; state remains ReadyForDecryption
│
└─ 8. Publish KeyshareCreated {
       e3_id, party_id,
       pk_share,        // public key share
       signed_proof     // ZK proof of correct generation
     }
    → Broadcast to committee members via P2P
```

`crates/keyshare/src/threshold_keyshare/handlers.rs` checks the E3 and collection lifecycle before
clearing a collector reference or publishing a failure. Encryption-key failures apply in `Init` and
`CollectingEncryptionKeys`. Threshold-share failures apply from `Init` through
`AggregatingDecryptionKey`, including while local share generation is unfinished. They cannot
replace `ReadyForDecryption` or later states. C4 failures apply in `ReadyForDecryption` only before
C4 verification completes or keyshare publication is authorized. Canonical key publication
supersedes all three collectors. A `PublicKeyAggregated` intent and its saved public-key context do
not suppress a current collector failure. `CommitteePublished`, `E3StageChanged(KeyPublished)` and
later successful stages record publication for the matching E3 without waiting for
`PublicKeyAggregated`. An earlier stage cannot clear that fact.
`ThresholdKeyshareExtension::hydrate` in `crates/keyshare/src/ext.rs` restores it from the existing
E3 lifecycle projection before the actor starts. The other checks use the persisted state and
recovery record.

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
│   │   → A demoted node that dispatched C1 verification finishes that work and publishes its
│   │     key; the first valid committee publication on chain wins. Once a key is on chain,
│   │     the demoted node stops, and any node ignores a late C1 result: it neither fails the
│   │     E3 nor accuses a dealer. A node that did not start the work ignores worker results
│   │     File: crates/aggregator/src/public_key_aggregation/actor.rs (started_as_aggregator)
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
│   │     └─ A mixed Some/None honest NodeFold-proof set is a local configuration mismatch.
│   │         The aggregator keeps its inputs and does not report invalid committee shares.
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
  ├─ Has no role gate: a local intent exists only when this node computed the key as the active
  │  aggregator, and a later failover demotion does not stop its submission
  ├─ During startup replay, retains one durable local intent
  ├─ Defers and coalesces retained intents until EffectsEnabled
  ├─ Uses the registry from DkgFoldAttestationContextEstablished, including after a rotation
  ├─ Reads chain state to determine whether the proof-backed commitment is unset
  ├─ Encodes the DkgAggregator proof in production
  ├─ Feature-gated test/CI nodes with `skip_proof_aggregation` wrap C5 bytes in a mock placeholder
  │  with the final roster, committee hash, and key commitment fields for confirmed ingestion
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
       The public-key aggregator also sends its saved publication again when effects resume,
       whatever its role now, since replay can start after the publication event; the writer
       skips a commitment that is already on chain and finishes the chunks.
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
        │  │         • M-34: immutable nodes tree / C5 VK hashes │
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
`fhe_inputs`, and `ComputeInput::run_batched` calls `MerkleTreeBuilder::compute_leaf_hashes_batched`
over those ciphertexts before it builds the tree (`crates/compute-provider/src/compute_input.rs`).
The leaves are therefore a function of the processed set, not a separate prover-supplied value.

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
rather than the flat input root an E3 program compares against. It is removed.

Batching now covers only the per-input commitment recomputation. `Batching::Parallel` schedules that
pure function across a Rayon pool behind the `parallel` feature; without the feature it falls back
to the sequential schedule. The policy still sees every entry in global index order in one call, and
each leaf keeps its global position, so the root does not depend on the schedule
(`batching_does_not_change_the_root`). `ComputeManager::start` and `ComputeInput::run` use
`Batching::Sequential`. The zkVM guest is single threaded and takes the crate without the feature.

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

`CanonicalKeyProjection` derives key authority from confirmed, chain-sourced observations.
`CommitteeProofPublished`, retained as `EvmLogObserved`, supplies the ordered committee, key
commitment, honest party IDs, and SK/ESM anchors from the verified proof. The request supplies the
BFV preset and committee size. The configured deployment supplies the Interfold address. The
projection updates before EventBus domain delivery. The request router performs no registry reads.

`ThresholdKeyshare` accepts `PublicKeyAggregated` only when its commitment and both rosters match
that projection. It also decodes the key and recomputes its commitment. It keeps the first valid key
and derives the decryption domain from chain facts. Early peer publications supply bounded candidate
bytes until the chain observation arrives. Durable chunks or `CommitteePublished` supply validated
bytes independently of gossip. Ciphertext received before the key remains in `Decrypting`; first key
admission resumes share calculation. A matching publication cannot resume an already-retained key.
The plaintext extension derives both rosters from the projection.

Before C6 intent deduplication, `ProofRequestActor` repairs the public key, domain, preset, and
committee size from this authority. It retains intents while authority is unavailable.
`ComputeEffectGate` rejects logged C6 requests whose public inputs differ from that authority before
it releases compute work or reuses a response.

File: `crates/request/src/canonical_key.rs`, `crates/evm/src/canonical_key.rs`,
`crates/keyshare/src/threshold_keyshare/effects/route_events.rs`, `crates/aggregator/src/ext.rs`,
`crates/zk-prover/src/proof_request/effects/decryption_share_proofs.rs`,
`crates/multithread/src/effect_gate.rs`.

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
      ├─ `ThresholdKeyshare` issues one share calculation and one C6 proof intent per process:
      │   → Repeated key publications, chain observations, ciphertexts, and resume signals
      │     cannot create another outstanding request for either phase.
      │   → Hydration clears these process-local markers; `EffectsEnabled` resumes retained work.
      │   → A local worker or task-pool failure retries the same request and correlation ID.
      │   → The node does not report a local failure as invalid decryption shares.
      │   → EventBus fan-out can lose a request or its result. When a phase's result has not
      │     arrived 5 minutes after its last request, the keyshare sends the request again, at
      │     most 6 times per phase: a share calculation under a new correlation ID, and a C6
      │     intent with a fresh random `redelivery` value. Only the first intent has zero, and a
      │     restart cannot repeat a value that replay brings back. A terminal event stops
      │     redelivery at once, also while its cleanup retries.
      │   → `ComputeEffectGate` runs one compute per request payload and answers every
      │     correlation ID. A request under a new ID whose result has not reached the gate 10
      │     minutes after it went to the worker goes to the worker again.
      │   → `ProofRequestActor` asks for the proof again for each new nonzero `redelivery`, also
      │     after the proof completed, and ignores copies. `DecryptionShareProofSigned` carries
      │     the `redelivery` it answers, so EventBus deduplication passes a second completion.
      │     After an E3 ends, its C6 intents are ignored.
      │     File: crates/keyshare/src/threshold_keyshare/effects/create_decryption_share.rs
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
    │   → The network actor re-sends the node's own share in a fresh transport envelope
    │     60 seconds later, then doubles the wait up to 10 minutes, until the E3 fails or
    │     completes (at most 8 hours). A local E3Failed stops the current re-sends only; a
    │     terminal stage from the chain also stops later ones, for the last 1,024 such E3s.
    │     After a restart, local replay schedules the re-sends again in log order, and
    │     nothing is re-sent before it finishes. The restart re-broadcast sends the share
    │     once unless the E3 is one of those remembered as ended. An E3 that ended while
    │     the node was down can get its share again until that chain history arrives.
    │     Receivers keep the first share from each party.
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
  │   ├─ Checks the sender's canonical party ID against the accepted H-member DKG roster
  │   ├─ Checks each C6 signature, E3, proof type, raw-share commitment, and ciphertext position
  │   ├─ Checks every C6 domain against canonical key authority and the matching ciphertext hash
  │   ├─ Stores the first share/proof bundle from each eligible party
  │   └─ Ignores unauthenticated bundles without reserving or excluding the claimed party
  │       Hydration applies these checks to saved collection and backup shares. It also checks
  │       retained C6 inputs in Computing, GeneratingC7Proof, and Complete before resuming effects.
  │       Invalid work clears cached verification results, C7 proofs, and final proofs. Collection
  │       is rebuilt from signed event history, so a corrected share can occupy the same party slot.
  │       Empty collectors also recover shares before snapshot cursors. A saved actor waits dormant
  │       for missing chain authority, retaining its snapshot, a history range, and one EffectsEnabled
  │       signal. Deferred payloads stay in the event log and resume through bounded pages.
  │       File: crates/aggregator/src/plaintext_aggregation/effects/recovery.rs
│
  ├─ Once T+1 distinct roster shares are durable (10 for Small, not all 14):
  │   ├─ Persist VerifyingC6 before publishing AggregationInputsReady(Plaintext)
  │   ├─ Start the 10-minute failover budget only at this readiness boundary
  │   ├─ A promoted standby resumes the persisted phase
  │   └─ A demoted node that dispatched C6 verification finishes that work and publishes the
  │      plaintext; after a restart it resumes from Computing, GeneratingC7Proof, or Complete
  │      File: crates/aggregator/src/plaintext_aggregation/actor.rs (started_as_aggregator)
  │
  ├─ Shares that arrive during C6 verification remain in a durable backup queue:
  │   ├─ The in-flight batch stays unchanged
  │   ├─ Reject duplicate parties and previously excluded parties
  │   └─ After a failed proof or raw-share commitment check, use backups and verify again
  │       Wait for replacements if at least T+1 roster parties can still provide valid shares
│
  ├─ C6 VERIFICATION (per-share, active aggregator only):
│   ShareVerificationActor receives C6 signed proofs
│   ├─ ECDSA recovery + ZK verification (same 2-phase as C2/C3)
│   ├─ On failure: SignedProofFailed → accusation pipeline
│   └─ On pass: ProofVerificationPassed (cached)
│   Local completion results are bound to the exact dispatch event ID. Equal verdicts for
│   different batches have different delivery IDs. Results persist through replay and standby;
│   only the active aggregator, or a demoted node that dispatched them, can apply them after
│   EffectsEnabled.
│   A saved result resumes through a fresh PlaintextVerificationResumed event in the E3's
│   chain aggregate. Its new sequence permits snapshot writes after the recovery watermark.
│   Admission and post-verification checks use the same C6ShareVerifier for raw-share commitments.
│
├─ When at least T+1 shares pass C6 verification and each output's raw-share commitment check:
│   │
│   ├─ State → Computing
│   │
│   ├─ COMPUTE REQUEST: CalculateThresholdDecryption
│   │   Live execution and restart recovery use the same dispatch_threshold_decryption helper.
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
│   │   ├─ Deduplicates the exact request; a replacement batch invalidates old worker correlations
│   │   ├─ Signs each C7 proof (one per ciphertext index)
│   │   └─ Publishes AggregationProofSigned {
│   │        e3_id, party_id, signed_proof(C7)
│   │      }
│   │
│   ├─ DECRYPTION AGGREGATION REQUEST:
│   │   ├─ ThresholdPlaintextAggregator stores the signed C7 proofs plus the honest C6 inner
│   │   │   proofs for the first `T + 1` parties after sorting by `party_id`
│   │   ├─ Admits C7 only when its ordered share commitments, party IDs, and plaintext match
│   │   │   that batch. A stale result requests matching work. Hydration applies the same check
│   │   │   to retained C7 proofs, including Complete, before it reuses a final proof
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
  ├─ Checks final-proof domain limbs against confirmed key authority and retained ciphertext hashes
  ├─ Defers admission while authority is missing; discards a mismatched intent before deduplication
  ├─ Keeps one durable-history sequence range per waiting E3 and reads it in bounded pages
  ├─ Discards intents for recovered terminal E3s; confirmed terminal stages retire pending work
  │  and prevent later intents from restarting publication
  ├─ Keeps the first admitted intent and permits a corrected result after a rejected one
  ├─ Submits admitted local work even if failover demoted the producing aggregator
  ├─ Defers and coalesces retained intents until EffectsEnabled
  ├─ Reads chain state to confirm plaintextOutput is still empty
  ├─ Encodes the final DecryptionAggregator proof in production
  ├─ Requires a domain-bound DecryptionAggregator payload in every mode. Test-only placeholders
  │  carry the verified C6 domain and C7 proof bytes; production verifiers reject those bytes
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
          │  │       → M-34: C6 tree / C7 VK hashes are immutable. │
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
│      │                            │                   │ correctly from sk; bounds    │
│      │                            │                   │ e_sm over the integers via   │
│      │                            │                   │ e_sm_lifted + CRT quotients; │
│      │                            │                   │ outputs sk_commitment,       │
│      │                            │                   │ pk_commitment,               │
│      │                            │                   │ e_sm_commitment (residues)   │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C2a  │ SK Share Computation       │ DKG: Share Gen    │ Shamir shares of sk computed │
│      │                            │                   │ correctly                    │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C2b  │ ESM Share Computation      │ DKG: Share Gen    │ Shamir shares of smudging    │
│      │                            │                   │ noise computed correctly     │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C3a  │ SK Share Encryption        │ DKG: Share Gen    │ sk_sss encrypted correctly   │
│      │                            │                   │ under recipient's BFV key;   │
│      │                            │                   │ e0 used directly, no CRT     │
│      │                            │                   │ split (e0_bound < q_i/2)     │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C3b  │ ESM Share Encryption       │ DKG: Share Gen    │ esi_sss encrypted correctly  │
│      │                            │                   │ under recipient's BFV key;   │
│      │                            │                   │ same e0 handling as C3a      │
├──────┼────────────────────────────┼───────────────────┼──────────────────────────────┤
│ C4a  │ SK Decryption Share (T2)   │ DKG: Key Calc     │ Verifies H decrypted shares  │
│      │                            │                   │ match C2a commitments; sums  │
│      │                            │                   │ reverses and centre-reduces  │
│      │                            │                   │ in one bounded division      │
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

| Failure scenario                                                                    | Detection                                                                                                        | Recovery                                                                                                    | Verification                                                                                    |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| The configured job count exceeds the CPU or memory limit.                           | Startup computes CPU and memory job limits.                                                                      | The scheduler uses the smallest safe limit. It refuses startup if no prover fits.                           | `memory::tests::*` and the configuration default test cover 16 GiB, 32 GiB, and 122 GiB limits. |
| `bb prove` exits, receives a signal, or reports an allocation failure.              | `ZkProver` returns `ProofGenerationFailed`.                                                                      | The scheduler retries the same request. Attempts after the first use `--slow_low_memory`.                   | The retry-policy and low-memory flag tests cover this path.                                     |
| `bb verify` does not report the explicit invalid-proof result.                      | `ZkProver` returns a verifier-process error instead of `false`.                                                  | The scheduler retries locally and does not accuse the proof sender.                                         | Prover and share-verification tests separate process errors from invalid proofs.                |
| `bb prove` or `bb verify` runs longer than `bb_timeout_secs` (12 hours by default). | `ZkProver` kills the process and returns a timeout error that names the elapsed time and the end of bb's stderr. | The scheduler retries the same request, as for any other prover process failure.                            | A prover test kills a hung stand-in process at its time limit.                                  |
| A keyshare-owned TrBFV operation returns a local error.                             | The worker returns a typed TrBFV error.                                                                          | The scheduler retries the same live request before any successful response becomes durable.                 | Retry-policy and keyshare-routing tests cover this path.                                        |
| A Rayon task panics or its result channel closes.                                   | `TaskPool` returns a structured pool error.                                                                      | The scheduler retries ZK and keyshare-owned TrBFV work with the same E3 task group.                         | Task-pool panic and retry-policy tests cover this path.                                         |
| Resource pressure continues.                                                        | The retry delay reaches a five-minute cap.                                                                       | Retries continue until success or a terminal E3 event cancels the task group and interrupts the delay.      | The capped delay and task-group cancellation tests cover this path.                             |
| Many proof requests fail together.                                                  | A node-scoped retry-log limiter counts suppressed messages.                                                      | The node emits at most one retry warning per minute. Other attempts use DEBUG logs.                         | The retry-log limiter test verifies the warning window and count.                               |
| The process exits during proof work.                                                | The supervisor restarts the node.                                                                                | EventStore replay restores the exact pending input. `ComputeEffectGate` reissues it after `EffectsEnabled`. | Proof actors test that local errors retain pending inputs and correlation IDs.                  |
| The process restarts after a proof result was already durable.                      | Node-proof recovery loads proofs by canonical sequence, including completed folds.                               | The proof actor republishes a complete recovered share bundle or computes only missing sequences.           | Unit tests cover full and partial recovery. A full-proof restart run confirms no recomputation. |
| A proof attempt leaves output files.                                                | A per-job directory guard observes scope exit or finds a stale restart path.                                     | The prover removes the attempt directory after exit and before a restarted process reuses that path.        | Prover tests cover normal cleanup and a stale directory after process restart.                  |
| A pre-v0.16 snapshot has stale registered-node membership.                          | `interfold node validate` compares both sortition projections with EventStore.                                   | `interfold node validate --repair` rebuilds only derived membership and missing member history.             | Validator tests cover detection, reconstruction, preservation, and removal.                     |

A failed live randomized TrBFV attempt can retry because it has not published a protocol
contribution. After a successful response becomes durable, replay reuses that exact response and
does not regenerate it. A canonical E3 timeout remains the authority when local recovery does not
finish before the protocol deadline.

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
│  ├─ On Invalid → SignedProofFailed + ProofVerificationFailed      │
│  └─ On InfrastructureError → retain input and retry after 5 s     │
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
publication. The plaintext writer admits final proofs against the canonical decryption domain before
deduplication and submission. A rejected intent cannot displace a corrected one.
`PlaintextAggregated` is not gossiped or returned by historical peer sync; only the producing node
can create this EVM write intent.

The document publisher rebuilds its active outbox and received-document set from the durable event
log before network effects start. Its DHT store is in memory, so at `SyncEnded` it also stores
received broadcast documents in that store again, one at a time, and prunes them with the other
records of their E3. A document with a party filter is not restored: its filter names this node, so
no peer fetches it from here. This restore is best effort. Recovery chooses the candidates while it
reads the local log: at most 512 documents and 128 MiB, the ones received last in event-log order.
The chain history then drops the documents of E3s that closed while the node was offline, but those
documents can already have taken the place of an open E3's document, which is then not restored.
Expired documents, and documents that do not fit in a full store, are skipped. Document publication
and receipt events use their E3's chain aggregate. Recovery reads the log in pages of at most 1,024
events and 16 MiB; a page holds at least one event, also a larger one. During DKG, the publisher
first stores each document in its own DHT store, so that a peer whose lookup reaches this node can
fetch it from here, and then gossips a small notification that names it. The inbound put handler in
`crates/net/src/net_interface.rs` preserves records that this node published. An inbound put can
extend a replica's expiry, but cannot shorten it or replace its publisher. A record without an
expiry keeps its unlimited lifetime. A lookup asks the about 20 peers closest to the key, so it
reliably reaches the publisher only in a network of about that size; other peers fetch the document
once an upload succeeds. The publisher announces the document again 30 seconds later, doubling the
wait up to 5 minutes; these announcements store the document locally again and send only the
notification. An announcement waits until the local store holds the document. Publications start
only at `SyncEnded`, after the chain history, so a restarted node does not announce or upload a
document of an E3 that closed while it was offline. The chain gateway releases the events that it
buffered live during startup in its own `SyncEnded` handler, so a `KeyPublished` seen live during
startup reaches the publisher after publications started, and one announcement or upload of that E3
can still go out. Separately, the publisher uploads the full document to the DHT peers closest to
its key, and again every 30 minutes until the DKG ends; a failing upload never delays an
announcement. It starts one upload at a time, and each put has two attempts. Kademlia acknowledges
an inbound put before the receiver decides to store it, so the network interface counts a put as
stored only when, after the upload, a lookup of the key returns the record from another peer; a put
whose lookup finds no other peer's copy fails as not replicated. A put returns once a peer serves
the record back, so its uploads to other peers can overlap the next upload. The interface owns each
put until its result, at most 16 at once. The put command carries a deadline 240 s after the
publisher sends it, and the interface reports the put expired then, also when it takes the command
late, before the publisher's 270 s wait ends. The Kademlia library's own hourly replication of
stored records is disabled. A failed upload or announcement is retried after 15 seconds, doubling up
to 5 minutes, including when no peer subscribed to the topic at the first attempt. A failed
announcement does not upload the document again. Before gossip acceptance, the wire decoder checks
the notification's key and E3 identifier lengths, party-filter shape, and expiry. Malformed messages
get `Reject`. A well-formed but expired notification gets `Ignore`, without a relay score penalty.
Valid notifications for other parties still relay. No per-peer message-count or byte-rate throttle
discards valid relay traffic, and ingress does not wait for a DHT fetch. A receiver holds early
notifications until its committee slot is known, one per peer, document, and party filter with the
latest expiry, and checks expiry again after that wait. Transient ingress metadata retains the
propagation peer through buffering. `ingress_limits.rs` sizes early buffering for four N=19 E3s with
a 2x margin: 3,040 notifications. New ingress removes expired entries. Fetches run outside the
network ingress loop, with at most 8 active reads and 512 queued documents (above the 432-document
workload floor). A due peer with the fewest active reads gets the next slot; ties rotate. A lone
peer can use all idle capacity. Each GET releases its slot after one attempt, within 90 seconds.
Failed fetches return to the fair queue with backoff until the document arrives, its E3 closes, or
its notifications expire. A document retains up to 128 announcers through queueing, active reads,
and retries. At that limit, new announcers replace the oldest ones after the first. Any retained
announcer can supply its next fair slot, charged to that peer, with only one fetch per document.
Duplicate announcements preserve the retry deadline. Queue ownership uses the retained announcer
with the least queued work, including on retry. Before eviction, shared work moves to a less loaded
announcer. Each eviction search moves a document at most once and recalculates the donor after each
move. Early and fetch queues have no hard per-peer cap. At global capacity, a peer below its fair
share can reclaim space from the largest owner. Otherwise, the fetch queue can replace only that
peer's work with more failures. Overflow waits for a later announcement. Document deduplication and
the serialized notification stay unchanged. A fetch accepts only the record for the requested key,
and the document is accepted under the first waiting notification whose metadata matches its
payload, so a forged notification cannot displace a correct one. It suppresses duplicate documents.
A canonical `KeyPublished` stage stops DKG-document announcements and uploads, with their scheduled
retries, and prunes the DHT records that this node published. The Kademlia query of a put in its
upload phase ends too. This is not a full cancel: requests that the query already gave to the libp2p
connection handlers, queued or in progress, still go out, and a put that still looks up its closest
peers runs on, because Kademlia uploads the record when that lookup ends. A full cancel needs
Kademlia support and is follow-up work. The publisher sends these cleanup commands, put cancels and
record removals, through one queue of at most 4,096 keys with one waiting send, so a busy network
command queue delays them. A full cleanup queue drops its oldest entries with a warning; their
records expire and their puts time out on their own. C4 `DecryptionKeyShared` is a DKG document;
later `DecryptionshareCreated` events use event gossip, not the DHT document path. Recovery retains
the DKG closure across restart. A local `E3RequestComplete` does not mean that the contract has
reached a terminal stage. Each new publication request first removes the expired publications, so
the expired documents that replay brings back cannot fill the outbox while publications wait for
`SyncEnded`. Recovery reads only the receipts of the E3s in the committee snapshot, which can
predate a selection in the log, so the receipts that replay delivers before `SyncEnded` join the
restore queue too.

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

The guest links `risc0-zkvm` with `heap-embedded-alloc`. The default bump allocator never frees, so
each input's temporary Greco form stayed allocated and a secure-preset round aborted out of memory
at about 500 inputs. The allocator is part of the guest ELF: changing it changes the image ID, and
`ImageID.sol`, the ciphertext verifier and every deployed `CRISPProgram.imageId` must move with it.

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

`MerkleTreeBuilder::compute_leaf_hashes_batched` rebuilds exactly that layout. Both sides pin the
same test vector (`program/tests/input_leaf.rs` and `tests/input-leaf.test.ts`), and
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
vote. The first is visible to the voter and is fixed by submitting again. The second is a silent
tally corruption that nobody can detect or undo. Submitting through the CRISP server's relayer also
keeps the transaction out of a public mempool, which is where the race would be won.

**How a voter sees a dropped input.** `POST /voting/selection` takes the input's slot, commitment,
content hash, and parent, and replays the slot's chain with the Secure Process's own rule: the
server calls `chain_head_per_slot` from the CRISP program crate for this and for `get_slot_head`
(`InputSnapshot::slot_head`, `InputSnapshot::selection`). The rule compares a parent only with the
head of the entry's own slot, so only the entries of that slot are replayed. It answers `selected`
when the input became the head at its turn, which stays true when a later mask or re-vote extends
it, so the check follows chain ancestry, not head equality. It answers `excluded` with the reason
(`earlier_sibling`, `stale_parent`, `unusable`), and `selection_pending` while any lower tree index
is missing from the server's index, because an earlier entry can still take the slot.

Both routes read the round's inputs through a cache in the server process (`indexed_inputs`). The
round's input generation, kept under `_e3:crisp_inputs:{id}` in a sled tree of its own, holds a
random epoch and counts the changes to the input fields that started and that finished:
`modify_inputs` counts a change as started before it writes the round record and as finished after.
A read is cached only under a settled generation, with the counts equal, and served only while the
generation is unchanged. A change that starts later raises `started` for good, so a cached read
never outlives the inputs it was built from. A change that fails after it started leaves the round
unsettled, and the round is read from the store until `settle_input_generation` makes the counts
equal at the next start, before the indexer runs. Each selection call costs 1 in the caller's read
window (`ChainRateLimiter`), and the refusal is logged without the caller.

The SDK combines that answer with the availability job (`getSubmissionStage`): a committed ballot is
`selection_pending`, then `availability_pending` or `counted`, or `excluded`. The CRISP client keeps
the input identity in local storage, resumes the check after a reload, marks the round as voted only
at `counted`, and offers a new proof against the current head while the commitment deadline is
ahead. The server indexes from the chain head, so a reorganization can still change an answer. The
client therefore keeps asking for the selection until a `selected` answer comes at least 30 minutes
after the first one, past Ethereum finality. A different answer, or a job that is no longer
committed, starts the 30 minutes again.

The gap that remains: the voter learns of a drop only while a client checks, and after the
commitment deadline there is no retry. The answer is only as complete as the server's index: a
server that lost its database, or one of several instances, can report `not_indexed` or
`selection_pending` for an input the chain holds. The governance apps do not run this check.

Closing the gap entirely would need the guest to tell a replace from an add, which means publishing
that distinction — the thing the whole design exists to hide.

Capacity: `TREE_DEPTH = 20` gives 2^20 entries, against a physical ceiling of roughly three writes
per block at the secure preset — append-only is not capacity-bound.

**Plaintext modulus bound.** The committee decrypts each tally coefficient modulo the plaintext
modulus `t` of the round's BFV parameters: 100 for insecure-512 and 1,000,000 for secure-8192. Every
ballot coefficient is 0 or 1 and the tally adds one ballot per selected slot, so a coefficient
counts the ballots that set that bit, and the decoded count is exact only while fewer than `t`
ballots set it. `CRISPProgram` does not enforce the bound, and the input tree (`2^20` entries) does
not prevent a round past it. At secure-8192 a wrong count needs a million ballots in one round; at
insecure-512 it needs 100, so a round on that preset with 100 or more voters for one option can
decode a wrong result with every proof valid.

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
The SDK passes the WASM-generated reduction quotients as `r` for ct0 and `r_ct1` for ct1.
`CRISPProgram._verifyInputProof` supplies `e3.committeePublicKey` as `noirPublicInputs[8]`. This
anchors the ballot proof's public-key commitment to the C5-proven key for that round. The caller
cannot supply a replacement key. The ballot circuits bound both public-key components before
commitment generation, so their packed openings are injective.

The addend is the slot's current head for a mask, and the zero ciphertext for a vote, a re-vote, or
any input to an empty slot. `is_mask_vote` chooses between them and is **private**, and the selector
is derived (`keep_previous = is_mask_vote & !is_first_vote`) rather than taken as a witness — so a
voter cannot add their new ballot on top of their old one and count twice, and a masker cannot
discard the head and erase a vote.

Both ballot circuits prove it through one function,
`crisp_lib::ciphertext_addition::verify_slot_update`, which asserts
`published = ballot + addend + q_i * r` at every coefficient of every CRT limb, with `r` in
`[-1, 1]`. There is no Fiat-Shamir challenge. The three commitments pack coefficients with the
non-injective `pack`, so a prover can open them to other coefficients, and a check at one point
derived from the commitments accepted a mask that published its ballot alone: the prover picked a
second opening of the parent commitment that satisfied the single equation. A per-coefficient linear
relation, aligned across three ciphertexts that pack with the same `BIT_CT`, proves the same
statement for the committed coefficients under any opening that keeps the carriers, so the circuit
needs no `pack_checked` digit asserts. At secure-8192 the `crisp` circuit is 1,844,049 gates and
`crisp_onchain` 1,824,326, under the `2^21` browser ceiling. With the checked helper on the three
commitments, the secure `crisp` circuit measured 2,520,034 gates.

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
