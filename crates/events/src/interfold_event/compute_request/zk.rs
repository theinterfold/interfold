// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Proof, SignedProofPayload};
use alloy::primitives::Address;
use derivative::Derivative;
use e3_committee::CiphernodesCommitteeSize;
use e3_committee_hash::{
    hash_lbfv_accepted_party_set, hash_lbfv_proof_session, DecryptionDomainContext,
    DkgSetupContext, LbfvProofDomainContext,
};
use e3_crypto::SensitiveBytes;
use e3_fhe_params::{BfvPreset, BfvProfile};
use e3_trbfv::gen_lbfv_key_shares::{GenLbfvKeySharesRequest, GenLbfvKeySharesResponse};
use e3_trbfv::lbfv_operation::{digest_lbfv_public_artifacts, LbfvOperationId, LbfvOperationKind};
use e3_trbfv::synchronized::SealedPrfKeys;
use e3_utils::utility_types::ArcBytes;
use e3_zk_config::DkgInputType;
use e3_zk_witness::threshold::rlk_aggregation::RlkAggregationComponent;
use serde::{Deserialize, Serialize};

/// ZK proof generation request variants.
///
/// Bincode encodes this enum by variant order. Add new variants at the end.
/// Keep existing variants and payloads unchanged for compatibility.
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
    /// Per-node DKG recursive fold (C2abChunkFold → … → NodeFold).
    NodeDkgFold(NodeDkgFoldRequest),
    /// Single step of the streaming cross-node nodes_fold accumulation.
    NodesFoldStep(NodesFoldStepRequest),
    /// Cross-node DKG aggregator (NodesFold + C5 + DkgAggregator).
    DkgAggregation(DkgAggregationRequest),
    /// Phase-7 decryption aggregator (C6 Chonk root + C7 + DecryptionAggregator).
    DecryptionAggregation(DecryptionAggregationRequest),
    /// Re-verify a C3a/C3b proof that an accusation forwards. It is accusation work, so it still
    /// runs after the E3 fails, until the request completes. Its response is
    /// `ZkResponse::VerifyShareProofs`.
    ReverifyAccusedProof(VerifyShareProofsRequest),
    /// Separate synchronized dealer/recipient/publication graph, never SS/ESM folding.
    SynchronizedDkg(Box<super::SynchronizedDkgProofRequest>),
    /// Generate one row proof for an l-BFV public-key share.
    LbfvPkGeneration(LbfvPkGenerationProofRequest),
    /// Generate all limb proofs and the terminal proof for one RLK row.
    RlkGeneration(RlkGenerationProofRequest),
    /// Generate one row proof for l-BFV public-key aggregation.
    LbfvPkAggregation(LbfvPkAggregationProofRequest),
    /// Generate one row proof for RLK aggregation.
    RlkAggregation(RlkAggregationProofRequest),
    /// Fold the five l-BFV generation rows.
    LbfvGenerationFold(LbfvGenerationFoldRequest),
    /// Fold one legacy node proof and its l-BFV generation proof.
    NodeDkgFoldV2(NodeDkgFoldV2Request),
    /// Fold one node proof into the secure-16384 cross-node accumulator.
    NodesFoldV2Step(NodesFoldV2StepRequest),
    /// Fold the five l-BFV aggregation rows.
    LbfvAggregationFold(LbfvAggregationFoldRequest),
    /// Aggregate the secure-16384 DKG proof chain.
    DkgAggregationV2(DkgAggregationV2Request),
    /// Per-node DKG fold of the l-BFV path, which has no C1 proof. Its response is
    /// `ZkResponse::NodeDkgFold`.
    LbfvNodeDkgFold(LbfvNodeDkgFoldRequest),
    /// C4 share-decryption proof of the l-BFV path, which names the recipient party. Its response
    /// is `ZkResponse::DkgShareDecryption`.
    LbfvDkgShareDecryption(LbfvDkgShareDecryptionProofRequest),
}

impl ZkRequest {
    /// Return the stable identity for an l-BFV request.
    pub fn lbfv_operation_id(&self) -> Option<LbfvOperationId> {
        match self {
            Self::LbfvPkGeneration(request) => request
                .validate_operation_id()
                .is_ok()
                .then_some(request.operation_id),
            Self::RlkGeneration(request) => request
                .validate_operation_id()
                .is_ok()
                .then_some(request.operation_id),
            Self::LbfvPkAggregation(request) => request
                .validate_operation_id()
                .is_ok()
                .then_some(request.operation_id),
            Self::RlkAggregation(request) => request
                .validate_operation_id()
                .is_ok()
                .then_some(request.operation_id),
            _ => None,
        }
    }
}

/// Request to prove one l-BFV public-key share row.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct LbfvPkGenerationProofRequest {
    pub operation_id: LbfvOperationId,
    pub proof_domain: LbfvProofDomainContext,
    pub party_id: u32,
    /// Serialized `fhe::trlbfv::PublicKeyShare` bytes.
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub public_key_share_bytes: ArcBytes,
    /// The encrypted level-0 secret-key polynomial that the row proof binds.
    #[derivative(Debug = "ignore")]
    pub secret_key_bytes: SensitiveBytes,
    pub row_index: u32,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Request to prove all limbs and finalize one RLK share row.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct RlkGenerationProofRequest {
    pub operation_id: LbfvOperationId,
    pub proof_domain: LbfvProofDomainContext,
    pub party_id: u32,
    /// Serialized `fhe::trlbfv::RelinKeyShare` bytes.
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub rlk_share_bytes: ArcBytes,
    /// The encrypted level-0 secret-key polynomial that the row proof binds.
    #[derivative(Debug = "ignore")]
    pub secret_key_bytes: SensitiveBytes,
    /// Serialized ephemeral RLK secret key bytes, encrypted at rest.
    #[derivative(Debug = "ignore")]
    pub r_bytes: SensitiveBytes,
    /// Serialized `d0` error rows in gadget-row order, encrypted at rest.
    #[derivative(Debug = "ignore")]
    pub errors_d0_bytes: Vec<SensitiveBytes>,
    /// Serialized `d2` error rows in gadget-row order, encrypted at rest.
    #[derivative(Debug = "ignore")]
    pub errors_d2_bytes: Vec<SensitiveBytes>,
    pub row_index: u32,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Request to aggregate exactly H l-BFV public-key shares for one row.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct LbfvPkAggregationProofRequest {
    pub operation_id: LbfvOperationId,
    pub proof_domain: LbfvProofDomainContext,
    pub aggregator_party_id: u32,
    /// Canonical party IDs in the same order as `share_bytes`.
    pub party_ids: Vec<u32>,
    /// Serialized shares in canonical party order.
    pub share_bytes: Vec<ArcBytes>,
    pub row_index: u32,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Request to aggregate one component of exactly H RLK shares for one row. Each row takes one
/// request per component.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct RlkAggregationProofRequest {
    pub operation_id: LbfvOperationId,
    pub proof_domain: LbfvProofDomainContext,
    pub aggregator_party_id: u32,
    /// Canonical party IDs in the same order as `share_bytes`.
    pub party_ids: Vec<u32>,
    /// Serialized shares in canonical party order.
    pub share_bytes: Vec<ArcBytes>,
    pub row_index: u32,
    pub component: RlkAggregationComponent,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

fn validate_lbfv_generation_row(
    source: &GenLbfvKeySharesRequest,
    response: &GenLbfvKeySharesResponse,
    row_index: u32,
) -> anyhow::Result<()> {
    source.validate_operation_id()?;
    anyhow::ensure!(
        source.operation_id == response.operation_id,
        "l-BFV key-share response operation ID does not match its request"
    );
    let expected_rows = source.params_preset.metadata().num_moduli;
    anyhow::ensure!(
        response.witness.errors_d0_bytes.len() == expected_rows
            && response.witness.errors_d2_bytes.len() == expected_rows,
        "the encrypted RLK witness must contain exactly {expected_rows} d0 and d2 error rows"
    );
    anyhow::ensure!(
        usize::try_from(row_index)
            .ok()
            .is_some_and(|row| row < expected_rows),
        "l-BFV proof row index {row_index} is out of range"
    );
    Ok(())
}

fn validate_lbfv_proof_request_domain(
    proof_domain: LbfvProofDomainContext,
    party_id: u32,
    row_index: u32,
    params_preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        e3_fhe_params::supports_lbfv(params_preset),
        "l-BFV proof requests require a preset with l-BFV parameters"
    );
    e3_zk_witness::threshold::lbfv_proof_domain::lbfv_proof_session(proof_domain)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let committee = committee_size.values();
    anyhow::ensure!(
        usize::try_from(party_id).is_ok_and(|party| party < committee.n),
        "l-BFV proof party ID {party_id} must be less than {}",
        committee.n
    );
    anyhow::ensure!(
        usize::try_from(row_index).is_ok_and(|row| row < params_preset.metadata().num_moduli),
        "l-BFV proof row index {row_index} is out of range"
    );
    Ok(())
}

impl LbfvPkGenerationProofRequest {
    /// Build one public-key row proof request from a local TrBFV result.
    pub fn from_lbfv_key_shares(
        source: &GenLbfvKeySharesRequest,
        response: &GenLbfvKeySharesResponse,
        proof_domain: LbfvProofDomainContext,
        row_index: u32,
        committee_size: CiphernodesCommitteeSize,
    ) -> anyhow::Result<Self> {
        validate_lbfv_generation_row(source, response, row_index)?;
        anyhow::ensure!(
            hash_lbfv_proof_session(proof_domain).0 == source.session_id,
            "l-BFV proof domain does not match the key-share session"
        );
        let mut request = Self {
            operation_id: LbfvOperationId([0; 32]),
            proof_domain,
            party_id: source.party_id,
            public_key_share_bytes: response.public_key_share_bytes.clone(),
            secret_key_bytes: source.secret_key_bytes.clone(),
            row_index,
            params_preset: source.params_preset,
            committee_size,
        };
        request.operation_id = request.expected_operation_id();
        Ok(request)
    }

    /// Recompute the operation identity from the complete public request semantics.
    pub fn expected_operation_id(&self) -> LbfvOperationId {
        LbfvOperationId::new(
            hash_lbfv_proof_session(self.proof_domain).0,
            self.party_id,
            LbfvOperationKind::PkGeneration,
            Some(self.row_index),
            None,
            Some(digest_lbfv_public_artifacts(
                [&*self.public_key_share_bytes],
            )),
        )
    }

    pub fn validate_operation_id(&self) -> anyhow::Result<()> {
        validate_lbfv_proof_request_domain(
            self.proof_domain,
            self.party_id,
            self.row_index,
            self.params_preset,
            self.committee_size,
        )?;
        anyhow::ensure!(
            self.operation_id == self.expected_operation_id(),
            "l-BFV public-key generation operation ID does not match the request semantics"
        );
        Ok(())
    }
}

impl RlkGenerationProofRequest {
    /// Build one RLK row proof request from a local TrBFV result.
    pub fn from_lbfv_key_shares(
        source: &GenLbfvKeySharesRequest,
        response: &GenLbfvKeySharesResponse,
        proof_domain: LbfvProofDomainContext,
        row_index: u32,
        committee_size: CiphernodesCommitteeSize,
    ) -> anyhow::Result<Self> {
        validate_lbfv_generation_row(source, response, row_index)?;
        anyhow::ensure!(
            hash_lbfv_proof_session(proof_domain).0 == source.session_id,
            "l-BFV proof domain does not match the key-share session"
        );
        let mut request = Self {
            operation_id: LbfvOperationId([0; 32]),
            proof_domain,
            party_id: source.party_id,
            rlk_share_bytes: response.rlk_share_bytes.clone(),
            secret_key_bytes: source.secret_key_bytes.clone(),
            r_bytes: response.witness.r_bytes.clone(),
            errors_d0_bytes: response.witness.errors_d0_bytes.clone(),
            errors_d2_bytes: response.witness.errors_d2_bytes.clone(),
            row_index,
            params_preset: source.params_preset,
            committee_size,
        };
        request.operation_id = request.expected_operation_id();
        Ok(request)
    }

    /// Recompute the operation identity from the complete public request semantics.
    pub fn expected_operation_id(&self) -> LbfvOperationId {
        LbfvOperationId::new(
            hash_lbfv_proof_session(self.proof_domain).0,
            self.party_id,
            LbfvOperationKind::RlkGeneration,
            Some(self.row_index),
            None,
            Some(digest_lbfv_public_artifacts([&*self.rlk_share_bytes])),
        )
    }

    pub fn validate_operation_id(&self) -> anyhow::Result<()> {
        validate_lbfv_proof_request_domain(
            self.proof_domain,
            self.party_id,
            self.row_index,
            self.params_preset,
            self.committee_size,
        )?;
        anyhow::ensure!(
            self.operation_id == self.expected_operation_id(),
            "RLK generation operation ID does not match the request semantics"
        );
        Ok(())
    }
}

impl LbfvPkAggregationProofRequest {
    /// Recompute the operation identity from the complete public request semantics.
    pub fn expected_operation_id(&self) -> anyhow::Result<LbfvOperationId> {
        let committee = self.committee_size.values();
        let accepted = hash_lbfv_accepted_party_set(&self.party_ids, committee.n, committee.h)
            .map_err(anyhow::Error::msg)?;
        Ok(LbfvOperationId::new(
            hash_lbfv_proof_session(self.proof_domain).0,
            self.aggregator_party_id,
            LbfvOperationKind::PkAggregation,
            Some(self.row_index),
            Some(accepted.0),
            Some(digest_lbfv_public_artifacts(
                self.share_bytes.iter().map(|bytes| &**bytes),
            )),
        ))
    }

    pub fn validate_operation_id(&self) -> anyhow::Result<()> {
        validate_lbfv_proof_request_domain(
            self.proof_domain,
            self.aggregator_party_id,
            self.row_index,
            self.params_preset,
            self.committee_size,
        )?;
        anyhow::ensure!(
            self.operation_id == self.expected_operation_id()?,
            "l-BFV public-key aggregation operation ID does not match the request semantics"
        );
        Ok(())
    }
}

impl RlkAggregationProofRequest {
    /// Recompute the operation identity from the complete public request semantics.
    pub fn expected_operation_id(&self) -> anyhow::Result<LbfvOperationId> {
        let committee = self.committee_size.values();
        let accepted = hash_lbfv_accepted_party_set(&self.party_ids, committee.n, committee.h)
            .map_err(anyhow::Error::msg)?;
        Ok(LbfvOperationId::new(
            hash_lbfv_proof_session(self.proof_domain).0,
            self.aggregator_party_id,
            match self.component {
                RlkAggregationComponent::D0 => LbfvOperationKind::RlkD0Aggregation,
                RlkAggregationComponent::D2 => LbfvOperationKind::RlkD2Aggregation,
            },
            Some(self.row_index),
            Some(accepted.0),
            Some(digest_lbfv_public_artifacts(
                self.share_bytes.iter().map(|bytes| &**bytes),
            )),
        ))
    }

    pub fn validate_operation_id(&self) -> anyhow::Result<()> {
        validate_lbfv_proof_request_domain(
            self.proof_domain,
            self.aggregator_party_id,
            self.row_index,
            self.params_preset,
            self.committee_size,
        )?;
        anyhow::ensure!(
            self.operation_id == self.expected_operation_id()?,
            "RLK aggregation operation ID does not match the request semantics"
        );
        Ok(())
    }
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
    pub params_profile: BfvProfile,
    pub committee_size: CiphernodesCommitteeSize,
}

/// [`NodeDkgFoldRequest`] without a required C1 proof: the l-BFV node fold takes no C1, so it is
/// `None` there. The l-BFV path proves its node fold with this request
/// ([`ZkRequest::LbfvNodeDkgFold`]); the trBFV request keeps its persisted layout.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvNodeDkgFoldRequest {
    pub c0_proof: Proof,
    pub c1_proof: Option<Proof>,
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
    pub params_profile: BfvProfile,
    pub committee_size: CiphernodesCommitteeSize,
}

/// The prover handles both fold requests with one handler, so it lifts the trBFV request here.
impl From<NodeDkgFoldRequest> for LbfvNodeDkgFoldRequest {
    fn from(request: NodeDkgFoldRequest) -> Self {
        Self {
            c0_proof: request.c0_proof,
            c1_proof: Some(request.c1_proof),
            c2a_proof: request.c2a_proof,
            c2b_proof: request.c2b_proof,
            c3a_inner_proofs: request.c3a_inner_proofs,
            c3b_inner_proofs: request.c3b_inner_proofs,
            c4a_proof: request.c4a_proof,
            c4b_proof: request.c4b_proof,
            c3_slot_indices_a: request.c3_slot_indices_a,
            c3_slot_indices_b: request.c3_slot_indices_b,
            c3_total_slots: request.c3_total_slots,
            party_id: request.party_id,
            params_profile: request.params_profile,
            committee_size: request.committee_size,
        }
    }
}

impl LbfvNodeDkgFoldRequest {
    /// The request to dispatch: the trBFV one whenever it can represent this fold, so that trBFV
    /// bytes stay as they were.
    pub fn into_zk_request(self) -> ZkRequest {
        match self.c1_proof {
            Some(c1_proof) => ZkRequest::NodeDkgFold(NodeDkgFoldRequest {
                c0_proof: self.c0_proof,
                c1_proof,
                c2a_proof: self.c2a_proof,
                c2b_proof: self.c2b_proof,
                c3a_inner_proofs: self.c3a_inner_proofs,
                c3b_inner_proofs: self.c3b_inner_proofs,
                c4a_proof: self.c4a_proof,
                c4b_proof: self.c4b_proof,
                c3_slot_indices_a: self.c3_slot_indices_a,
                c3_slot_indices_b: self.c3_slot_indices_b,
                c3_total_slots: self.c3_total_slots,
                party_id: self.party_id,
                params_profile: self.params_profile,
                committee_size: self.committee_size,
            }),
            None => ZkRequest::LbfvNodeDkgFold(self),
        }
    }
}

/// Single step of the streaming cross-node nodes_fold accumulation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodesFoldStepRequest {
    /// The `node_fold` proofs this step folds, at most `nodes_fold`'s leaf count.
    pub inner_proofs: Vec<Proof>,
    /// The prior accumulator proof, or `None` for the first step.
    pub prior_accumulator: Option<Proof>,
    /// Slot index of each proof (its party's position in ascending `party_id` order).
    pub slot_indices: Vec<u32>,
    /// Total honest-party count H.
    pub total_slots: usize,
    /// E3 identifier used for job namespacing.
    pub e3_id: String,
    pub params_profile: BfvProfile,
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
    pub params_profile: BfvProfile,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Decryption aggregation: C6 Chonk root + DecryptionAggregator per job.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecryptionAggregationRequest {
    pub c6_total_slots: usize,
    pub jobs: Vec<DecryptionAggregationJobRequest>,
    /// Ordered committee addresses (`topNodes`) for `committee_hash_*` public inputs.
    pub committee_addresses: Vec<Address>,
    pub params_profile: BfvProfile,
    pub committee_size: CiphernodesCommitteeSize,
}

/// One step of the l-BFV generation-row fold. `prior_accumulator` is absent for row zero.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvGenerationFoldRequest {
    pub pk_proof: Proof,
    pub rlk_proof: Proof,
    pub prior_accumulator: Option<Proof>,
    pub row_index: u32,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Secure-16384 per-node fold with the terminal generation-row accumulator.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeDkgFoldV2Request {
    pub legacy_node_fold_proof: Proof,
    pub generation_proof: Proof,
    pub party_id: u64,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// One step of the secure-16384 cross-node fold.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodesFoldV2StepRequest {
    pub inner_proof: Proof,
    pub prior_accumulator: Option<Proof>,
    pub slot_index: u32,
    pub total_slots: usize,
    pub e3_id: String,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// One step of the secure-16384 aggregation-row fold. `prior_accumulator` is absent for row zero.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvAggregationFoldRequest {
    pub pk_proof: Proof,
    /// The row's RLK aggregation proofs for components 0 (`d0`) and 1 (`d2`).
    pub rlk_d0_proof: Proof,
    pub rlk_d2_proof: Proof,
    pub prior_accumulator: Option<Proof>,
    pub row_index: u32,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
}

/// Final secure-16384 recursive DKG aggregation request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgAggregationV2Request {
    pub nodes_fold_proof: Proof,
    pub aggregation_fold_proof: Proof,
    pub party_ids: Vec<u64>,
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
    /// Request-time profile for parameters and artifact resolution.
    pub params_profile: BfvProfile,
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
    /// Request-time profile for threshold parameters and artifact resolution.
    pub params_profile: BfvProfile,
    /// The size of the committee.
    pub committee_size: CiphernodesCommitteeSize,
    pub synchronized: Option<SynchronizedShareComputation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SynchronizedProofContext {
    pub setup: DkgSetupContext,
    pub party_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SynchronizedShareComputation {
    pub context: SynchronizedProofContext,
    pub outgoing_keys: SealedPrfKeys,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SynchronizedShareDecryption {
    pub context: SynchronizedProofContext,
    pub dealer_ids: Vec<u32>,
    pub expected_outgoing_root: [u8; 32],
    pub expected_commitments: Vec<Vec<[u8; 32]>>,
    pub outgoing_keys: SealedPrfKeys,
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
    /// Request-time profile selects the paired DKG parameters and artifacts.
    pub params_profile: BfvProfile,
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

#[cfg(test)]
mod tests {
    use super::*;
    use e3_zk_config::CircuitName;

    fn proof(marker: u8) -> Proof {
        Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[marker]),
            ArcBytes::from_bytes(&[marker, marker]),
        )
    }

    fn trbfv_fold() -> NodeDkgFoldRequest {
        NodeDkgFoldRequest {
            c0_proof: proof(0),
            c1_proof: proof(1),
            c2a_proof: proof(2),
            c2b_proof: proof(3),
            c3a_inner_proofs: vec![proof(4)],
            c3b_inner_proofs: vec![proof(5)],
            c4a_proof: proof(6),
            c4b_proof: proof(7),
            c3_slot_indices_a: vec![8],
            c3_slot_indices_b: vec![9],
            c3_total_slots: 10,
            party_id: 11,
            params_profile: BfvProfile::SsInsecure64,
            committee_size: CiphernodesCommitteeSize::Minimum,
        }
    }

    fn lbfv_fold(c1_proof: Option<Proof>) -> LbfvNodeDkgFoldRequest {
        let r = trbfv_fold();
        LbfvNodeDkgFoldRequest {
            c0_proof: r.c0_proof,
            c1_proof,
            c2a_proof: r.c2a_proof,
            c2b_proof: r.c2b_proof,
            c3a_inner_proofs: r.c3a_inner_proofs,
            c3b_inner_proofs: r.c3b_inner_proofs,
            c4a_proof: r.c4a_proof,
            c4b_proof: r.c4b_proof,
            c3_slot_indices_a: r.c3_slot_indices_a,
            c3_slot_indices_b: r.c3_slot_indices_b,
            c3_total_slots: r.c3_total_slots,
            party_id: r.party_id,
            params_profile: r.params_profile,
            committee_size: r.committee_size,
        }
    }

    /// The bincode bytes of the trBFV node fold request, written out by field type (little-endian
    /// fixed-width integers, `u64` length prefixes, `u32` variant indexes) as earlier releases
    /// stored them: the C1 proof is required, not optional. A field that is added, reordered or
    /// retyped fails here.
    #[test]
    fn the_trbfv_node_fold_keeps_its_encoded_layout() {
        // `proof(marker)`: `CircuitName::PkBfv` (variant 0), then the data and the public signals.
        let proof_bytes = |marker: u8| {
            [
                &0u32.to_le_bytes()[..],
                &1u64.to_le_bytes(),
                &[marker],
                &2u64.to_le_bytes(),
                &[marker, marker],
            ]
            .concat()
        };
        let mut expected = Vec::new();
        for marker in 0..4 {
            expected.extend(proof_bytes(marker)); // c0, c1, c2a, c2b
        }
        for marker in [4, 5] {
            expected.extend(1u64.to_le_bytes()); // one inner proof
            expected.extend(proof_bytes(marker)); // c3a, c3b
        }
        expected.extend(proof_bytes(6)); // c4a
        expected.extend(proof_bytes(7)); // c4b
        for slot in [8u32, 9] {
            expected.extend(1u64.to_le_bytes()); // one slot
            expected.extend(slot.to_le_bytes()); // c3_slot_indices_a, c3_slot_indices_b
        }
        expected.extend(10u64.to_le_bytes()); // c3_total_slots
        expected.extend(11u64.to_le_bytes()); // party_id
        expected.extend(0u32.to_le_bytes()); // BfvProfile::SsInsecure64
        expected.extend(0u32.to_le_bytes()); // CiphernodesCommitteeSize::Minimum

        assert_eq!(bincode::serialize(&trbfv_fold()).unwrap(), expected);
    }

    #[test]
    fn a_fold_with_a_c1_proof_is_dispatched_as_the_trbfv_request() {
        let lbfv = lbfv_fold(Some(proof(1)));
        assert_eq!(lbfv.into_zk_request(), ZkRequest::NodeDkgFold(trbfv_fold()));

        let no_c1 = lbfv_fold(None);
        assert_eq!(
            no_c1.clone().into_zk_request(),
            ZkRequest::LbfvNodeDkgFold(no_c1)
        );
    }

    fn trbfv_c4() -> DkgShareDecryptionProofRequest {
        DkgShareDecryptionProofRequest {
            sk_bfv: SensitiveBytes::from_encrypted(&[1]),
            honest_ciphertexts_raw: vec![ArcBytes::from_bytes(&[2])],
            num_honest_parties: 3,
            num_moduli: 4,
            own_plaintext_idx: Some(5),
            own_share_raw: Some(SensitiveBytes::from_encrypted(&[6])),
            dkg_input_type: DkgInputType::SecretKey,
            params_profile: BfvProfile::SsInsecure64,
            committee_size: CiphernodesCommitteeSize::Minimum,
            synchronized: None,
        }
    }

    /// The bincode bytes of the trBFV C4 request, written out by field type as earlier releases
    /// stored them. The request has no recipient field. A field that is added, reordered or
    /// retyped fails here.
    #[test]
    fn the_trbfv_share_decryption_request_keeps_its_encoded_layout() {
        let expected = [
            &1u64.to_le_bytes()[..],
            &[1], // sk_bfv
            &1u64.to_le_bytes(),
            &1u64.to_le_bytes(),
            &[2],                // honest_ciphertexts_raw: one ciphertext
            &3u64.to_le_bytes(), // num_honest_parties
            &4u64.to_le_bytes(), // num_moduli
            &[1],
            &5u64.to_le_bytes(), // own_plaintext_idx: Some(5)
            &[1],
            &1u64.to_le_bytes(),
            &[6],                // own_share_raw: Some
            &0u32.to_le_bytes(), // DkgInputType::SecretKey
            &0u32.to_le_bytes(), // BfvProfile::SsInsecure64
            &0u32.to_le_bytes(), // CiphernodesCommitteeSize::Minimum
            &[0],                // synchronized: None
        ]
        .concat();

        assert_eq!(bincode::serialize(&trbfv_c4()).unwrap(), expected);
    }

    /// New request variants go after main's last one, so every stored trBFV request keeps its
    /// index.
    #[test]
    fn the_lbfv_node_fold_request_is_appended() {
        let index = |request: ZkRequest| {
            u32::from_le_bytes(
                bincode::serialize(&request).unwrap()[..4]
                    .try_into()
                    .unwrap(),
            )
        };
        let no_c1 = lbfv_fold(None);
        assert_eq!(index(ZkRequest::NodeDkgFold(trbfv_fold())), 10);
        assert_eq!(index(ZkRequest::LbfvNodeDkgFold(no_c1)), 25);
        assert_eq!(index(ZkRequest::DkgShareDecryption(trbfv_c4())), 4);
        assert_eq!(
            index(ZkRequest::LbfvDkgShareDecryption(
                LbfvDkgShareDecryptionProofRequest {
                    request: trbfv_c4(),
                    recipient_party_id: 2,
                }
            )),
            26
        );
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
    /// BFV ciphertexts from the selected external parties, flattened in
    /// ascending party-id order. The count is `H - 1` when the sender is
    /// selected and `H` otherwise.
    /// Layout: ext party 0 mod 0, ext party 0 mod 1, ..., ext party 1 mod 0, ...
    pub honest_ciphertexts_raw: Vec<ArcBytes>,
    /// Total number of selected parties (H).
    pub num_honest_parties: usize,
    /// Number of CRT moduli (L).
    pub num_moduli: usize,
    /// Own party's row in the selected order, if the party contributed to the key.
    pub own_plaintext_idx: Option<usize>,
    /// Own plaintext share, present only when `own_plaintext_idx` is present.
    /// The encrypted witness contains a bincode `Vec<Vec<u64>>` of shape `[L][N]`.
    pub own_share_raw: Option<SensitiveBytes>,
    /// SecretKey or SmudgingNoise.
    pub dkg_input_type: DkgInputType,
    /// Request-time profile for the paired threshold/DKG parameters and artifacts.
    pub params_profile: BfvProfile,
    /// Committee size for circuit artifact resolution.
    pub committee_size: CiphernodesCommitteeSize,
    pub synchronized: Option<SynchronizedShareDecryption>,
}

/// [`DkgShareDecryptionProofRequest`] of an l-BFV E3 ([`ZkRequest::LbfvDkgShareDecryption`]). The
/// chunked l-BFV C4 commits each share under the recipient's row, so the request names the
/// recipient. The trBFV circuit does not read it, and the trBFV request keeps its persisted
/// layout. Its response is `ZkResponse::DkgShareDecryption`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvDkgShareDecryptionProofRequest {
    pub request: DkgShareDecryptionProofRequest,
    /// Zero-based recipient party ID whose share row each C4 proof decrypts.
    pub recipient_party_id: u64,
}

/// Request to generate a proof for BFV public key generation (C0).
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct PkBfvProofRequest {
    /// The BFV public key bytes.
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub pk_bfv: ArcBytes,
    /// Request-time profile; threshold bytes alone cannot select the DKG statement.
    pub params_profile: BfvProfile,
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
    pub e_sm: Option<SensitiveBytes>,
    /// Request-time profile for threshold parameters and artifact resolution.
    pub params_profile: BfvProfile,
    /// The size of the committee
    pub committee_size: CiphernodesCommitteeSize,
    pub synchronized: Option<SynchronizedProofContext>,
}

impl PkBfvProofRequest {
    pub fn new(
        pk_bfv: impl Into<ArcBytes>,
        params_profile: BfvProfile,
        committee_size: CiphernodesCommitteeSize,
    ) -> Self {
        Self {
            pk_bfv: pk_bfv.into(),
            params_profile,
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
        params_profile: BfvProfile,
        committee_size: CiphernodesCommitteeSize,
    ) -> Self {
        Self {
            pk0_share: pk0_share.into(),
            sk,
            eek,
            params_profile,
            e_sm: Some(e_sm),
            committee_size,
            synchronized: None,
        }
    }
}

/// ZK proof generation response variants.
///
/// Bincode encodes this enum by variant order. Add new variants at the end.
/// Keep existing variants and payloads unchanged for compatibility.
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
    SynchronizedDkg(super::SynchronizedDkgProofResponse),
    /// Output of [`ZkRequest::LbfvPkGeneration`].
    LbfvPkGeneration(LbfvPkGenerationProofResponse),
    /// Output of [`ZkRequest::RlkGeneration`].
    RlkGeneration(RlkGenerationProofResponse),
    /// Output of [`ZkRequest::LbfvPkAggregation`].
    LbfvPkAggregation(LbfvPkAggregationProofResponse),
    /// Output of [`ZkRequest::RlkAggregation`].
    RlkAggregation(RlkAggregationProofResponse),
    /// Output of [`ZkRequest::LbfvGenerationFold`].
    LbfvGenerationFold(LbfvGenerationFoldResponse),
    /// Output of [`ZkRequest::NodeDkgFoldV2`].
    NodeDkgFoldV2(NodeDkgFoldV2Response),
    /// Output of [`ZkRequest::NodesFoldV2Step`].
    NodesFoldV2Step(NodesFoldV2StepResponse),
    /// Output of [`ZkRequest::LbfvAggregationFold`].
    LbfvAggregationFold(LbfvAggregationFoldResponse),
    /// Output of [`ZkRequest::DkgAggregationV2`].
    DkgAggregationV2(DkgAggregationV2Response),
}

impl ZkResponse {
    /// Return the stable identity for an l-BFV response.
    pub fn lbfv_operation_id(&self) -> Option<LbfvOperationId> {
        match self {
            Self::LbfvPkGeneration(response) => Some(response.operation_id),
            Self::RlkGeneration(response) => Some(response.operation_id),
            Self::LbfvPkAggregation(response) => Some(response.operation_id),
            Self::RlkAggregation(response) => Some(response.operation_id),
            _ => None,
        }
    }
}

/// Row-correlated l-BFV public-key generation proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvPkGenerationProofResponse {
    pub operation_id: LbfvOperationId,
    pub proof: Proof,
    pub row_index: u32,
}

/// Row-correlated terminal RLK generation proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RlkGenerationProofResponse {
    pub operation_id: LbfvOperationId,
    /// The terminal proof. Limb proofs remain local to the worker.
    pub proof: Proof,
    pub row_index: u32,
}

/// Row-correlated l-BFV public-key aggregation proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvPkAggregationProofResponse {
    pub operation_id: LbfvOperationId,
    pub proof: Proof,
    pub row_index: u32,
    pub party_ids: Vec<u32>,
}

/// Row- and component-correlated RLK aggregation proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RlkAggregationProofResponse {
    pub operation_id: LbfvOperationId,
    pub proof: Proof,
    pub row_index: u32,
    pub component: RlkAggregationComponent,
    pub party_ids: Vec<u32>,
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvGenerationFoldResponse {
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeDkgFoldV2Response {
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodesFoldV2StepResponse {
    pub accumulator_proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvAggregationFoldResponse {
    pub proof: Proof,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DkgAggregationV2Response {
    pub proof: Proof,
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
    /// Stable E3 context cryptographically bound into every C6 proof.
    pub decryption_domain: DecryptionDomainContext,
    /// Request-time profile for parameters and artifact resolution.
    pub params_profile: BfvProfile,
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
    /// Request-time profile selects the circuit artifact namespace.
    pub params_profile: BfvProfile,
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
    /// Request-time profile selects the circuit artifact namespace.
    pub params_profile: BfvProfile,
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
    /// Request-time profile for parameters and artifact resolution.
    pub params_profile: BfvProfile,
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

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use crate::CircuitName;
    use e3_trbfv::gen_lbfv_key_shares::{EncryptedRlkWitness, GenLbfvKeySharesResponse};

    fn proof_domain() -> LbfvProofDomainContext {
        e3_zk_samples::lbfv_proof_domain::sample_lbfv_proof_domain()
    }

    fn generation_operation_id(domain: LbfvProofDomainContext, party_id: u32) -> LbfvOperationId {
        LbfvOperationId::new(
            hash_lbfv_proof_session(domain).0,
            party_id,
            LbfvOperationKind::GenKeyShares,
            None,
            None,
            None,
        )
    }

    fn bytes(value: &[u8]) -> ArcBytes {
        ArcBytes::from_bytes(value)
    }

    fn sensitive(value: &[u8]) -> SensitiveBytes {
        SensitiveBytes::from_encrypted(value)
    }

    fn operation_id(value: u8) -> LbfvOperationId {
        LbfvOperationId([value; 32])
    }

    /// Row count of the secure l-BFV preset used by these requests.
    fn secure_row_count() -> usize {
        e3_fhe_params::lbfv_row_count(BfvPreset::SecureThreshold16384).unwrap()
    }

    fn proof(circuit: CircuitName) -> Proof {
        Proof::new(circuit, bytes(&[1]), bytes(&[2]))
    }

    #[test]
    fn legacy_request_payload_and_variant_index_are_unchanged() {
        const LEGACY_FIXTURE: &[u8] = &[
            0, 0, 0, 0, // ZkRequest::PkBfv
            0, 0, 0, 0, 0, 0, 0, 0, // empty pk_bfv
            1, 0, 0, 0, // BfvProfile::SsSecure8192
            1, 0, 0, 0, // CiphernodesCommitteeSize::Micro
        ];
        let request = ZkRequest::PkBfv(PkBfvProofRequest::new(
            bytes(&[]),
            BfvProfile::SsSecure8192,
            CiphernodesCommitteeSize::Micro,
        ));

        assert_eq!(bincode::serialize(&request).unwrap(), LEGACY_FIXTURE);
        assert_eq!(
            bincode::deserialize::<ZkRequest>(LEGACY_FIXTURE).unwrap(),
            request
        );
    }

    #[test]
    fn lbfv_request_variants_are_appended_and_round_trip() {
        let requests = [
            ZkRequest::LbfvPkGeneration(LbfvPkGenerationProofRequest {
                operation_id: operation_id(1),
                proof_domain: proof_domain(),
                party_id: 0,
                public_key_share_bytes: bytes(&[1]),
                secret_key_bytes: sensitive(&[2]),
                row_index: 3,
                params_preset: BfvPreset::SecureThreshold16384,
                committee_size: CiphernodesCommitteeSize::Minimum,
            }),
            ZkRequest::RlkGeneration(RlkGenerationProofRequest {
                operation_id: operation_id(2),
                proof_domain: proof_domain(),
                party_id: 0,
                rlk_share_bytes: bytes(&[3]),
                secret_key_bytes: sensitive(&[4]),
                r_bytes: sensitive(&[5]),
                errors_d0_bytes: vec![sensitive(&[6])],
                errors_d2_bytes: vec![sensitive(&[7])],
                row_index: 2,
                params_preset: BfvPreset::SecureThreshold16384,
                committee_size: CiphernodesCommitteeSize::Minimum,
            }),
            ZkRequest::LbfvPkAggregation(LbfvPkAggregationProofRequest {
                operation_id: operation_id(3),
                proof_domain: proof_domain(),
                aggregator_party_id: 0,
                party_ids: vec![0, 1],
                share_bytes: vec![bytes(&[8]), bytes(&[9])],
                row_index: 1,
                params_preset: BfvPreset::SecureThreshold16384,
                committee_size: CiphernodesCommitteeSize::Minimum,
            }),
            ZkRequest::RlkAggregation(RlkAggregationProofRequest {
                operation_id: operation_id(4),
                proof_domain: proof_domain(),
                aggregator_party_id: 0,
                party_ids: vec![0, 1],
                share_bytes: vec![bytes(&[10]), bytes(&[11])],
                row_index: 4,
                component: RlkAggregationComponent::D2,
                params_preset: BfvPreset::SecureThreshold16384,
                committee_size: CiphernodesCommitteeSize::Minimum,
            }),
        ];

        for (offset, request) in requests.into_iter().enumerate() {
            let encoded = bincode::serialize(&request).unwrap();
            assert_eq!(&encoded[..4], &((16 + offset) as u32).to_le_bytes());
            assert_eq!(
                bincode::deserialize::<ZkRequest>(&encoded).unwrap(),
                request
            );
        }
    }

    #[test]
    fn lbfv_response_variants_are_appended_and_preserve_row_metadata() {
        let responses = [
            ZkResponse::LbfvPkGeneration(LbfvPkGenerationProofResponse {
                operation_id: operation_id(1),
                proof: proof(CircuitName::LbfvPkGeneration),
                row_index: 1,
            }),
            ZkResponse::RlkGeneration(RlkGenerationProofResponse {
                operation_id: operation_id(2),
                proof: proof(CircuitName::RlkGeneration),
                row_index: 2,
            }),
            ZkResponse::LbfvPkAggregation(LbfvPkAggregationProofResponse {
                operation_id: operation_id(3),
                proof: proof(CircuitName::LbfvPkAggregation),
                row_index: 3,
                party_ids: vec![0, 1],
            }),
            ZkResponse::RlkAggregation(RlkAggregationProofResponse {
                operation_id: operation_id(4),
                proof: proof(CircuitName::RlkAggregation),
                row_index: 4,
                component: RlkAggregationComponent::D2,
                party_ids: vec![0, 1],
            }),
        ];

        for (offset, response) in responses.into_iter().enumerate() {
            let encoded = bincode::serialize(&response).unwrap();
            assert_eq!(&encoded[..4], &((15 + offset) as u32).to_le_bytes());
            assert_eq!(
                bincode::deserialize::<ZkResponse>(&encoded).unwrap(),
                response
            );
        }
    }

    #[test]
    fn lbfv_key_share_response_builds_each_row_request() {
        let proof_domain = proof_domain();
        let session_id = hash_lbfv_proof_session(proof_domain).0;
        let source = GenLbfvKeySharesRequest {
            operation_id: generation_operation_id(proof_domain, 0),
            session_id,
            party_id: 0,
            secret_key_bytes: sensitive(&[1]),
            generation_seed: sensitive(&[7]),
            params_preset: BfvPreset::SecureThreshold16384,
            ciphertext_level: 0,
            key_level: 0,
        };
        let response = GenLbfvKeySharesResponse {
            operation_id: source.operation_id,
            public_key_share_bytes: bytes(&[2]),
            rlk_share_bytes: bytes(&[3]),
            witness: EncryptedRlkWitness {
                r_bytes: sensitive(&[4]),
                errors_d0_bytes: vec![sensitive(&[5]); secure_row_count()],
                errors_d2_bytes: vec![sensitive(&[6]); secure_row_count()],
            },
        };

        for row_index in 0..secure_row_count() as u32 {
            let pk = LbfvPkGenerationProofRequest::from_lbfv_key_shares(
                &source,
                &response,
                proof_domain,
                row_index,
                CiphernodesCommitteeSize::Minimum,
            )
            .unwrap();
            let rlk = RlkGenerationProofRequest::from_lbfv_key_shares(
                &source,
                &response,
                proof_domain,
                row_index,
                CiphernodesCommitteeSize::Minimum,
            )
            .unwrap();
            pk.validate_operation_id().unwrap();
            rlk.validate_operation_id().unwrap();
            assert_eq!(rlk.errors_d0_bytes.len(), secure_row_count());
            assert_eq!(rlk.errors_d2_bytes.len(), secure_row_count());
        }

        assert!(LbfvPkGenerationProofRequest::from_lbfv_key_shares(
            &source,
            &response,
            proof_domain,
            secure_row_count() as u32,
            CiphernodesCommitteeSize::Minimum,
        )
        .is_err());
    }

    #[test]
    fn lbfv_operation_ids_bind_complete_request_semantics() {
        let proof_domain = proof_domain();
        let source = GenLbfvKeySharesRequest {
            operation_id: generation_operation_id(proof_domain, 1),
            session_id: hash_lbfv_proof_session(proof_domain).0,
            party_id: 1,
            secret_key_bytes: sensitive(&[1]),
            generation_seed: sensitive(&[2]),
            params_preset: BfvPreset::SecureThreshold16384,
            ciphertext_level: 0,
            key_level: 0,
        };
        let response = GenLbfvKeySharesResponse {
            operation_id: source.operation_id,
            public_key_share_bytes: bytes(&[3]),
            rlk_share_bytes: bytes(&[4]),
            witness: EncryptedRlkWitness {
                r_bytes: sensitive(&[5]),
                errors_d0_bytes: vec![sensitive(&[6]); secure_row_count()],
                errors_d2_bytes: vec![sensitive(&[7]); secure_row_count()],
            },
        };
        let mut generation = LbfvPkGenerationProofRequest::from_lbfv_key_shares(
            &source,
            &response,
            proof_domain,
            2,
            CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();
        generation.validate_operation_id().unwrap();
        assert_eq!(
            ZkRequest::LbfvPkGeneration(generation.clone()).lbfv_operation_id(),
            Some(generation.operation_id)
        );
        generation.row_index = 3;
        assert!(generation.validate_operation_id().is_err());
        assert_eq!(
            ZkRequest::LbfvPkGeneration(generation).lbfv_operation_id(),
            None
        );

        let mut aggregation = LbfvPkAggregationProofRequest {
            operation_id: LbfvOperationId([0; 32]),
            proof_domain,
            aggregator_party_id: 2,
            party_ids: vec![0, 2],
            share_bytes: vec![bytes(&[8]), bytes(&[9])],
            row_index: 4,
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        aggregation.operation_id = aggregation.expected_operation_id().unwrap();
        aggregation.validate_operation_id().unwrap();
        aggregation.share_bytes[1] = bytes(&[10]);
        assert!(aggregation.validate_operation_id().is_err());
        assert_eq!(
            ZkRequest::LbfvPkAggregation(aggregation).lbfv_operation_id(),
            None
        );

        // The two component requests of one RLK row are distinct operations.
        let mut rlk = RlkAggregationProofRequest {
            operation_id: LbfvOperationId([0; 32]),
            proof_domain,
            aggregator_party_id: 2,
            party_ids: vec![0, 2],
            share_bytes: vec![bytes(&[8]), bytes(&[9])],
            row_index: 4,
            component: RlkAggregationComponent::D0,
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        rlk.operation_id = rlk.expected_operation_id().unwrap();
        rlk.validate_operation_id().unwrap();
        rlk.component = RlkAggregationComponent::D2;
        assert!(rlk.validate_operation_id().is_err());
        assert_ne!(rlk.expected_operation_id().unwrap(), rlk.operation_id);
    }

    #[test]
    fn compute_wrappers_do_not_debug_lbfv_secrets() {
        let proof_domain = proof_domain();
        let source = GenLbfvKeySharesRequest {
            operation_id: generation_operation_id(proof_domain, 0),
            session_id: hash_lbfv_proof_session(proof_domain).0,
            party_id: 0,
            secret_key_bytes: sensitive(b"secret-key"),
            generation_seed: sensitive(b"generation-seed"),
            params_preset: BfvPreset::SecureThreshold16384,
            ciphertext_level: 0,
            key_level: 0,
        };
        let response = GenLbfvKeySharesResponse {
            operation_id: source.operation_id,
            public_key_share_bytes: bytes(&[]),
            rlk_share_bytes: bytes(&[]),
            witness: EncryptedRlkWitness {
                r_bytes: sensitive(b"r-secret"),
                errors_d0_bytes: vec![sensitive(b"d0-secret"); secure_row_count()],
                errors_d2_bytes: vec![sensitive(b"d2-secret"); secure_row_count()],
            },
        };
        let request = crate::ComputeRequest::trbfv(
            e3_trbfv::TrBFVRequest::GenLbfvKeyShares(source),
            crate::CorrelationId::new(),
            crate::E3id::new("7", 1),
        );
        let response = crate::ComputeResponse::trbfv(
            e3_trbfv::TrBFVResponse::GenLbfvKeyShares(response),
            crate::CorrelationId::new(),
            crate::E3id::new("7", 1),
        );

        let debug = format!("{request:?} {response:?}");
        for field in [
            "secret_key_bytes",
            "generation_seed",
            "witness",
            "r_bytes",
            "errors_d0_bytes",
            "errors_d2_bytes",
        ] {
            assert!(!debug.contains(field));
        }
    }
}
