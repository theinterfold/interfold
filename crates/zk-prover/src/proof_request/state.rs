// SPDX-License-Identifier: LGPL-3.0-only

//! Per-E3 pending proof state and canonical proof identifiers.

use super::*;

/// Identifies which threshold (C1/C2/C3) proof a response corresponds to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ThresholdProofKind {
    PkGeneration,
    SkShareComputation,
    ESmShareComputation,
    SkShareEncryption {
        recipient_party_id: usize,
        row_index: usize,
    },
    ESmShareEncryption {
        esi_index: usize,
        recipient_party_id: usize,
        row_index: usize,
    },
}

/// Identifies which C4 (DkgShareDecryption) proof a response corresponds to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecryptionProofKind {
    SecretKey,
    SmudgingNoise { esi_idx: usize },
}

/// Per-E3 metadata for streaming DKG inner proof aggregation.
#[derive(Clone, Debug)]
pub(crate) struct NodeAggregationMeta {
    pub(crate) party_id: u64,
    pub(crate) total_expected: usize,
    /// Buffered C0 proof, if it arrived before meta was stored.
    pub(crate) pending_c0: Option<Proof>,
    /// `DKGInnerProofReady { seq: 0 }` has already gone out in this process. Distinguishes
    /// the live path (C0 finished after `ThresholdSharePending`) from a restart, where the
    /// pre-crash C0 must be re-seeded from the durable record.
    pub(crate) c0_emitted: bool,
}

impl NodeAggregationMeta {
    /// Total expected inner proofs for streaming aggregation:
    /// C0..C4 (4 + sk + esm + 2). Mirrors the node-fold collector sizing.
    pub(crate) fn total_expected_for(sk_enc_count: usize, e_sm_enc_count: usize) -> usize {
        4 + sk_enc_count + e_sm_enc_count + 2
    }

    /// Base `seq` for the first C4 proof: just after all C0..C3 proofs.
    pub(crate) fn c4_base_seq(&self) -> usize {
        self.total_expected.saturating_sub(2)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PendingProofRequest {
    pub(crate) e3_id: E3id,
    pub(crate) key: Arc<EncryptionKey>,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingThresholdProofs {
    pub(crate) e3_id: E3id,
    pub(crate) full_share: Arc<ThresholdShare>,
    pub(crate) ec: EventContext<Sequenced>,
    pub(crate) pk_generation_proof: Option<Proof>,
    pub(crate) sk_share_computation_proof: Option<Proof>,
    pub(crate) e_sm_share_computation_proof: Option<Proof>,
    /// C3a proofs: keyed by (recipient_party_id, row_index)
    pub(crate) sk_share_encryption_proofs: HashMap<(usize, usize), Proof>,
    pub(crate) expected_sk_enc_count: usize,
    /// C3b proofs: keyed by (esi_index, recipient_party_id, row_index)
    pub(crate) e_sm_share_encryption_proofs: HashMap<(usize, usize, usize), Proof>,
    pub(crate) expected_e_sm_enc_count: usize,
    /// Maps positional index to real party_id (from ThresholdSharePending).
    pub(crate) recipient_party_ids: Vec<u64>,
}

impl PendingThresholdProofs {
    pub(crate) fn new(
        e3_id: E3id,
        full_share: Arc<ThresholdShare>,
        ec: EventContext<Sequenced>,
        expected_sk_enc_count: usize,
        expected_e_sm_enc_count: usize,
        recipient_party_ids: Vec<u64>,
    ) -> Self {
        Self {
            e3_id,
            full_share,
            ec,
            pk_generation_proof: None,
            sk_share_computation_proof: None,
            e_sm_share_computation_proof: None,
            sk_share_encryption_proofs: HashMap::new(),
            expected_sk_enc_count,
            e_sm_share_encryption_proofs: HashMap::new(),
            expected_e_sm_enc_count,
            recipient_party_ids,
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.pk_generation_proof.is_some()
            && self.sk_share_computation_proof.is_some()
            && self.e_sm_share_computation_proof.is_some()
            && self.sk_share_encryption_proofs.len() == self.expected_sk_enc_count
            && self.e_sm_share_encryption_proofs.len() == self.expected_e_sm_enc_count
    }

    pub(crate) fn store_proof(&mut self, kind: &ThresholdProofKind, proof: Proof) {
        match kind {
            ThresholdProofKind::PkGeneration => self.pk_generation_proof = Some(proof),
            ThresholdProofKind::SkShareComputation => self.sk_share_computation_proof = Some(proof),
            ThresholdProofKind::ESmShareComputation => {
                self.e_sm_share_computation_proof = Some(proof)
            }
            ThresholdProofKind::SkShareEncryption {
                recipient_party_id,
                row_index,
            } => {
                self.sk_share_encryption_proofs
                    .insert((*recipient_party_id, *row_index), proof);
            }
            ThresholdProofKind::ESmShareEncryption {
                esi_index,
                recipient_party_id,
                row_index,
            } => {
                self.e_sm_share_encryption_proofs
                    .insert((*esi_index, *recipient_party_id, *row_index), proof);
            }
        }
    }

    pub(crate) fn total_expected(&self) -> usize {
        3 + self.expected_sk_enc_count + self.expected_e_sm_enc_count
    }

    pub(crate) fn total_received(&self) -> usize {
        let base = [
            self.pk_generation_proof.is_some(),
            self.sk_share_computation_proof.is_some(),
            self.e_sm_share_computation_proof.is_some(),
        ]
        .iter()
        .filter(|&&v| v)
        .count();
        base + self.sk_share_encryption_proofs.len() + self.e_sm_share_encryption_proofs.len()
    }
}

/// Pending C4 (DkgShareDecryption) proof generation state.
#[derive(Clone, Debug)]
pub(crate) struct PendingDecryptionProofs {
    pub(crate) party_id: u64,
    pub(crate) node: String,
    pub(crate) ec: EventContext<Sequenced>,
    pub(crate) sk_proof: Option<Proof>,
    pub(crate) esm_proofs: HashMap<usize, Proof>,
    pub(crate) expected_esm_count: usize,
}

impl PendingDecryptionProofs {
    pub(crate) fn is_complete(&self) -> bool {
        self.sk_proof.is_some()
            && self.esm_proofs.len() == self.expected_esm_count
            && (0..self.expected_esm_count).all(|i| self.esm_proofs.contains_key(&i))
    }
}

/// Pending C5 (PkAggregation) proof generation state.
#[derive(Clone, Debug)]
pub(crate) struct PendingPkAggregationProof {
    pub(crate) ec: EventContext<Sequenced>,
    #[allow(dead_code)]
    pub(crate) request: PkAggregationProofRequest,
}

/// Pending C6 (ShareDecryptionProof) proof generation state.
#[derive(Clone, Debug)]
pub(crate) struct PendingShareDecryptionProof {
    pub(crate) party_id: u64,
    pub(crate) node: String,
    pub(crate) decryption_share: Vec<ArcBytes>,
    pub(crate) ec: EventContext<Sequenced>,
}

/// Pending C7 (DecryptedSharesAggregation) proof generation state.
#[derive(Clone, Debug)]
pub(crate) struct PendingAggregationProof {
    pub(crate) ec: EventContext<Sequenced>,
}
