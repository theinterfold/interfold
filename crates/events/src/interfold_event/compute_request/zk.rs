// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Proof, SignedProofPayload};
use alloy::primitives::Address;
use derivative::Derivative;
use e3_crypto::SensitiveBytes;
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::{computation::DkgInputType, CiphernodesCommitteeSize};
use serde::{Deserialize, Serialize};

/// ZK proof generation request variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZkRequest {
    /// Generate proof for BFV public key (C0).
    PkBfv(PkBfvProofRequest),
    /// Generate proof for PK generation (C1).
    PkGeneration(PkGenerationProofRequest),
    /// Generate proof for share and esm computation (C2a and C2b).
    ShareComputation(ShareComputationProofRequest),
    /// Generate proof for share encryption (C3a/C3b).
    ShareEncryption(ShareEncryptionProofRequest),
    /// Generate proof for DKG share decryption (C4a/C4b).
    DkgShareDecryption(DkgShareDecryptionProofRequest),
    /// Batch-verify C2/C3 proofs from other parties.
    VerifyShareProofs(VerifyShareProofsRequest),
    /// Batch-verify C4 proofs from DecryptionKeyShared events.
    VerifyShareDecryptionProofs(VerifyShareDecryptionProofsRequest),
    /// Generate proof for public key aggregation (C5).
    PkAggregation(PkAggregationProofRequest),
    /// Generate proof(s) for threshold share decryption (C6).
    ThresholdShareDecryption(ThresholdShareDecryptionProofRequest),
    /// Generate proof for decrypted shares aggregation (C7).
    DecryptedSharesAggregation(DecryptedSharesAggregationProofRequest),
    /// Per-node DKG recursive fold (C2abFold → … → NodeFold).
    NodeDkgFold(NodeDkgFoldRequest),
    /// Single step of the streaming cross-node nodes_fold accumulation.
    NodesFoldStep(NodesFoldStepRequest),
    /// Cross-node DKG aggregator (NodesFold + C5 + DkgAggregator).
    DkgAggregation(DkgAggregationRequest),
    /// Phase-7 decryption aggregator (C6Fold + C7 + DecryptionAggregator).
    DecryptionAggregation(DecryptionAggregationRequest),
}

/// Inputs for a single ciphertext index inside [`ZkRequest::DecryptionAggregation`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecryptionAggregationJobRequest {
    pub c6_inner_proofs: Vec<Proof>,
    pub c6_slot_indices: Vec<u32>,
    pub c7_proof: Proof,
}

/// Full per-node DKG fold (all inner recursive proofs for one party).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeDkgFoldRequest {
    pub c0_proof: Proof,
    pub c1_proof: Proof,
    pub c2a_proof: Proof,
    pub c2b_proof: Proof,
    pub c3a_inner_proofs: Vec<Proof>,
    pub c3b_inner_proofs: Vec<Proof>,
    pub c4a_proof: Proof,
    pub c4b_proof: Proof,
    pub c3_slot_indices_a: Vec<u32>,
    pub c3_slot_indices_b: Vec<u32>,
    pub c3_total_slots: usize,
    pub party_id: u64,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Single step of the streaming cross-node nodes_fold accumulation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodesFoldStepRequest {
    /// The `node_fold` proof for this slot.
    pub inner_proof: Proof,
    /// The prior accumulator proof, or `None` for the first step.
    pub prior_accumulator: Option<Proof>,
    /// Slot index for this honest party (position in ascending `party_id` order).
    pub slot_index: u32,
    /// Total honest-party count H.
    pub total_slots: usize,
    /// E3 identifier used for job namespacing.
    pub e3_id: String,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Cross-node DKG aggregation (NodesFold + C5 + DkgAggregator).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgAggregationRequest {
    pub node_fold_proofs: Vec<Proof>,
    /// Pre-computed nodes_fold accumulator proof. When present the prover skips the
    /// sequential fold and uses this directly as input to the DkgAggregator circuit.
    pub nodes_fold_proof: Option<Proof>,
    pub c5_proof: Proof,
    pub party_ids: Vec<u64>,
    /// Ordered committee addresses (`topNodes`) for `committee_hash_*` public inputs.
    pub committee_addresses: Vec<Address>,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Decryption aggregation: sequential C6 fold + DecryptionAggregator per job.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecryptionAggregationRequest {
    pub c6_total_slots: usize,
    pub jobs: Vec<DecryptionAggregationJobRequest>,
    /// Ordered committee addresses (`topNodes`) for `committee_hash_*` public inputs.
    pub committee_addresses: Vec<Address>,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Request to generate a proof for public key aggregation (C5).
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct PkAggregationProofRequest {
    /// Serialized PublicKeyShare bytes per party.
    pub keyshare_bytes: Vec<ArcBytes>,
    /// Serialized aggregated PublicKey bytes.
    pub aggregated_pk_bytes: ArcBytes,
    /// BFV preset for parameter resolution.
    pub params_preset: BfvPreset,
    /// Total committee size (N).
    pub committee_n: usize,
    /// Honest committee size (H) — number of shares being aggregated.
    pub committee_h: usize,
    /// Threshold (T).
    pub committee_threshold: usize,
}

/// Request to generate a proof for share computation (C2a or C2b).
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct ShareComputationProofRequest {
    /// Raw secret polynomial bytes (sk or e_sm — witness, encrypted at rest).
    pub secret_raw: SensitiveBytes,
    /// Bincode-serialized SharedSecret containing Shamir shares (witness, encrypted at rest).
    pub secret_sss_raw: SensitiveBytes,
    /// Which secret type (SecretKey or SmudgingNoise).
    pub dkg_input_type: DkgInputType,
    /// BFV preset for parameter resolution.
    pub params_preset: BfvPreset,
    /// The size of the committee.
    pub committee_size: CiphernodesCommitteeSize,
}

/// Request to generate a proof for share encryption (C3a or C3b).
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct ShareEncryptionProofRequest {
    /// Bincode-serialized Vec<u64> share row coefficients (witness — encrypted at rest).
    pub share_row_raw: SensitiveBytes,
    /// Serialized BFV Ciphertext bytes (via fhe_traits::Serialize).
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub ciphertext_raw: ArcBytes,
    /// Serialized recipient BFV PublicKey bytes.
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub recipient_pk_raw: ArcBytes,
    /// Serialized u_rns Poly bytes (witness — encrypted at rest).
    pub u_rns_raw: SensitiveBytes,
    /// Serialized e0_rns Poly bytes (witness — encrypted at rest).
    pub e0_rns_raw: SensitiveBytes,
    /// Serialized e1_rns Poly bytes (witness — encrypted at rest).
    pub e1_rns_raw: SensitiveBytes,
    /// SecretKey or SmudgingNoise.
    pub dkg_input_type: DkgInputType,
    /// Threshold BFV preset (handler derives DKG params via build_pair_for_preset).
    pub params_preset: BfvPreset,
    /// Committee size.
    pub committee_size: CiphernodesCommitteeSize,
    /// Recipient index (for correlation tracking).
    pub recipient_party_id: usize,
    /// Modulus row index (for correlation tracking).
    pub row_index: usize,
    /// ESI index (for C3b only; 0 for C3a). Disambiguates proofs across multiple ESI entries.
    pub esi_index: usize,
}

impl ShareEncryptionProofRequest {
    /// Slot index used by the C3 fold accumulator: `recipient_party_id * n_moduli + row_index`.
    ///
    /// This is a protocol invariant shared between the proof-request producer and the C3 fold
    /// driver; it is defined here (next to the request type) so all callers reference one
    /// formula.
    pub fn c3_slot_index(&self, n_moduli: usize) -> u32 {
        (self.recipient_party_id as u32) * (n_moduli as u32) + (self.row_index as u32)
    }
}

/// Request to generate a proof for DKG share decryption (C4a or C4b).
///
/// Proves that a node correctly decrypted (H − 1) external honest parties' BFV-encrypted
/// Shamir shares using its own BFV secret key, and that its own (un-encrypted) share row
/// matches the C2-bound commitment for its slot. The own slot is supplied as plaintext
/// because parties no longer self-encrypt during DKG.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct DkgShareDecryptionProofRequest {
    /// BFV secret key used for decryption (witness — encrypted at rest).
    pub sk_bfv: SensitiveBytes,
    /// BFV ciphertexts from the (H − 1) external honest parties, flattened
    /// `[(H − 1) * L]` in ascending external-party_id order (own party skipped).
    /// Layout: ext party 0 mod 0, ext party 0 mod 1, ..., ext party 1 mod 0, ...
    pub honest_ciphertexts_raw: Vec<ArcBytes>,
    /// Total number of honest parties (H), counting the own slot.
    pub num_honest_parties: usize,
    /// Number of CRT moduli (L).
    pub num_moduli: usize,
    /// Position of the own party within the H ascending-party_id ordering. The prover
    /// splices `own_share_raw` into this slot when assembling C4 inputs.
    pub own_plaintext_idx: usize,
    /// Bincode-serialised `Vec<Vec<u64>>` of shape `[L][N]` — the own party's plaintext
    /// share row per modulus (witness — encrypted at rest).
    pub own_share_raw: SensitiveBytes,
    /// SecretKey or SmudgingNoise.
    pub dkg_input_type: DkgInputType,
    /// BFV preset for parameter resolution.
    pub params_preset: BfvPreset,
    /// Committee size for circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
}

/// Request to generate a proof for BFV public key generation (C0).
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct PkBfvProofRequest {
    /// The BFV public key bytes.
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub pk_bfv: ArcBytes,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Request to generate a proof for PK share generation (C1).
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct PkGenerationProofRequest {
    /// Raw pk0 share polynomial bytes (public statement).
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub pk0_share: ArcBytes,
    /// Raw secret key polynomial bytes (witness — encrypted at rest).
    pub sk: SensitiveBytes,
    /// Raw error polynomial bytes (witness — encrypted at rest).
    pub eek: SensitiveBytes,
    /// Raw smudging noise polynomial bytes (witness — encrypted at rest).
    pub e_sm: SensitiveBytes,
    /// BFV preset for parameter resolution.
    pub params_preset: BfvPreset,
    /// The size of the committee
    pub committee_size: CiphernodesCommitteeSize,
}

impl PkBfvProofRequest {
    pub fn new(
        pk_bfv: impl Into<ArcBytes>,
        params_preset: BfvPreset,
        committee_size: CiphernodesCommitteeSize,
    ) -> Self {
        Self {
            pk_bfv: pk_bfv.into(),
            params_preset,
            committee_size,
        }
    }
}

impl PkGenerationProofRequest {
    pub fn new(
        pk0_share: impl Into<ArcBytes>,
        sk: SensitiveBytes,
        eek: SensitiveBytes,
        e_sm: SensitiveBytes,
        params_preset: BfvPreset,
        committee_size: CiphernodesCommitteeSize,
    ) -> Self {
        Self {
            pk0_share: pk0_share.into(),
            sk,
            eek,
            params_preset,
            e_sm,
            committee_size,
        }
    }
}

/// ZK proof generation response variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZkResponse {
    /// Proof for BFV public key (C0).
    PkBfv(PkBfvProofResponse),
    /// Proof for PK generation (C1).
    PkGeneration(PkGenerationProofResponse),
    /// Proof for share and esm computation (C2a and C2b).
    ShareComputation(ShareComputationProofResponse),
    /// Proof for share encryption (C3a/C3b).
    ShareEncryption(ShareEncryptionProofResponse),
    /// Proof for DKG share decryption (C4a/C4b).
    DkgShareDecryption(DkgShareDecryptionProofResponse),
    /// Batch verification results for C2/C3 proofs.
    VerifyShareProofs(VerifyShareProofsResponse),
    /// Batch verification results for C4 proofs.
    VerifyShareDecryptionProofs(VerifyShareDecryptionProofsResponse),
    /// Proof for public key aggregation (C5).
    PkAggregation(PkAggregationProofResponse),
    /// Proof(s) for threshold share decryption (C6).
    ThresholdShareDecryption(ThresholdShareDecryptionProofResponse),
    /// Proof for decrypted shares aggregation (C7).
    DecryptedSharesAggregation(DecryptedSharesAggregationProofResponse),
    /// Output of [`ZkRequest::NodeDkgFold`].
    NodeDkgFold(NodeDkgFoldResponse),
    /// Output of [`ZkRequest::NodesFoldStep`].
    NodesFoldStep(NodesFoldStepResponse),
    /// Output of [`ZkRequest::DkgAggregation`].
    DkgAggregation(DkgAggregationResponse),
    /// Output of [`ZkRequest::DecryptionAggregation`].
    DecryptionAggregation(DecryptionAggregationResponse),
}

/// Response from [`ZkRequest::NodeDkgFold`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeDkgFoldResponse {
    pub proof: Proof,
}

/// Response from [`ZkRequest::NodesFoldStep`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodesFoldStepResponse {
    pub accumulator_proof: Proof,
}

/// Response from [`ZkRequest::DkgAggregation`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgAggregationResponse {
    pub proof: Proof,
}

/// Response from [`ZkRequest::DecryptionAggregation`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecryptionAggregationResponse {
    pub proofs: Vec<Proof>,
}

/// Response containing a generated proof for public key aggregation (C5).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PkAggregationProofResponse {
    pub proof: Proof,
}

/// Request to generate proof(s) of correct threshold share decryption (C6).
/// One proof is generated per ciphertext index.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct ThresholdShareDecryptionProofRequest {
    /// Serialized ciphertext bytes, one per output index.
    pub ciphertext_bytes: Vec<ArcBytes>,
    /// Serialized aggregated PublicKey bytes.
    pub aggregated_pk_bytes: ArcBytes,
    /// Aggregated secret key polynomial (encrypted at rest).
    pub sk_poly_sum: SensitiveBytes,
    /// Aggregated smudging error polynomials (encrypted at rest), one per output index.
    pub es_poly_sum: Vec<SensitiveBytes>,
    /// Computed decryption share polynomials, one per output index.
    pub d_share_bytes: Vec<ArcBytes>,
    /// BFV preset for parameter resolution.
    pub params_preset: BfvPreset,
    /// Committee size for per-committee circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
}

/// Response containing generated proofs for threshold share decryption (C6).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdShareDecryptionProofResponse {
    /// One C6 proof per ciphertext index.
    pub proofs: Vec<Proof>,
}

/// Response containing a generated share computation proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareComputationProofResponse {
    pub proof: Proof,
    pub dkg_input_type: DkgInputType,
}

/// Response containing a generated share encryption proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareEncryptionProofResponse {
    pub proof: Proof,
    pub dkg_input_type: DkgInputType,
    pub recipient_party_id: usize,
    pub row_index: usize,
    /// ESI index (for C3b only; 0 for C3a).
    pub esi_index: usize,
}

/// Response containing a generated BFV public key proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PkBfvProofResponse {
    pub proof: Proof,
}

/// Response containing a generated PK generation proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PkGenerationProofResponse {
    pub proof: Proof,
}

/// Response containing a generated DKG share decryption proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgShareDecryptionProofResponse {
    pub proof: Proof,
    pub dkg_input_type: DkgInputType,
}

impl DkgShareDecryptionProofResponse {
    pub fn new(proof: Proof, dkg_input_type: DkgInputType) -> Self {
        Self {
            proof,
            dkg_input_type,
        }
    }
}

impl ShareComputationProofResponse {
    pub fn new(proof: Proof, dkg_input_type: DkgInputType) -> Self {
        Self {
            proof,
            dkg_input_type,
        }
    }
}

impl PkBfvProofResponse {
    pub fn new(proof: Proof) -> Self {
        Self { proof }
    }
}

impl PkGenerationProofResponse {
    pub fn new(proof: Proof) -> Self {
        Self { proof }
    }
}

/// Request to batch-verify C2/C3 proofs received from other parties.
///
/// Grouped by sender so the verifier can report honest/dishonest per party.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifyShareProofsRequest {
    /// Proofs grouped by sender party_id.
    pub party_proofs: Vec<PartyProofsToVerify>,
    /// BFV preset for parameter resolution (determines circuit artifact directory).
    pub params_preset: BfvPreset,
    /// Committee size for per-committee circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
}

/// All signed proofs from a single sender to verify.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PartyProofsToVerify {
    /// The party that generated these proofs.
    pub sender_party_id: u64,
    /// Signed proofs to verify (C2a, C2b, C3a×L, C3b×L).
    pub signed_proofs: Vec<SignedProofPayload>,
}

/// Batch verification results for C2/C3 proofs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifyShareProofsResponse {
    /// Per-party verification results.
    pub party_results: Vec<PartyVerificationResult>,
}

/// Verification result for all proofs from a single sender.
///
/// Used for both C2/C3 and C4 verification results.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PartyVerificationResult {
    /// The party whose proofs were verified.
    pub sender_party_id: u64,
    /// Whether ALL proofs from this party verified successfully.
    pub all_verified: bool,
    /// If any proof failed: the signed payload for fault attribution.
    pub failed_signed_payload: Option<SignedProofPayload>,
    /// ECDSA-recovered address of the signer (set during verification).
    pub recovered_address: Option<Address>,
}

/// Request to batch-verify C4 proofs from DecryptionKeyShared events.
///
/// Grouped by sender so the verifier can report honest/dishonest per party.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifyShareDecryptionProofsRequest {
    /// C4 proofs grouped by sender party_id.
    pub party_proofs: Vec<PartyShareDecryptionProofsToVerify>,
    /// BFV preset for parameter resolution (determines circuit artifact directory).
    pub params_preset: BfvPreset,
    /// Committee size for per-committee circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
}

/// C4 proofs from a single sender to verify.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PartyShareDecryptionProofsToVerify {
    /// The party that generated these proofs.
    pub sender_party_id: u64,
    /// Signed C4a proof (SecretKey decryption).
    pub signed_sk_decryption_proof: SignedProofPayload,
    /// Signed C4b proofs (SmudgingNoise decryption), one per smudging noise index.
    pub signed_e_sm_decryption_proofs: Vec<SignedProofPayload>,
}

/// Batch verification results for C4 proofs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifyShareDecryptionProofsResponse {
    /// Per-party verification results.
    pub party_results: Vec<PartyVerificationResult>,
}

// --- C7 proof generation ---

/// Request to generate proof(s) for decrypted shares aggregation (C7).
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct DecryptedSharesAggregationProofRequest {
    /// Decryption shares per party: (party_id, shares_per_ct_index).
    pub d_share_polys: Vec<(u64, Vec<ArcBytes>)>,
    /// Decoded plaintext per ciphertext index.
    pub plaintext: Vec<ArcBytes>,
    /// BFV preset (parameters for witness / circuit config).
    pub params_preset: BfvPreset,
    /// Threshold required for decryption.
    pub threshold_m: u64,
    /// Committee size (N).
    pub threshold_n: u64,
    /// Committee size for per-committee circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
}

/// Response containing generated proofs for decrypted shares aggregation (C7).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecryptedSharesAggregationProofResponse {
    /// One C7 proof per ciphertext index.
    pub proofs: Vec<Proof>,
}

/// ZK-specific error variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZkError {
    /// Proof generation failed.
    ProofGenerationFailed(String),
    /// Witness generation failed.
    WitnessGenerationFailed(String),
    /// Invalid parameters.
    InvalidParams(String),
}

impl std::fmt::Display for ZkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkError::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {}", msg),
            ZkError::WitnessGenerationFailed(msg) => {
                write!(f, "Witness generation failed: {}", msg)
            }
            ZkError::InvalidParams(msg) => write!(f, "Invalid parameters: {}", msg),
        }
    }
}

impl std::error::Error for ZkError {}
