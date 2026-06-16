// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, synchronous domain logic for proof-request dispatch and completion.
//!
//! The [`crate::actors::proof_request::ProofRequestActor`] is a thin transport
//! shell: it owns the event bus and signer and performs all publish/sign I/O.
//! This module owns the business logic — the per-E3 pending-proof state machines
//! (which proofs have arrived, when a set is complete) and the deterministic
//! dispatch *planning* (which proof requests to emit, in what order, with which
//! `seq` index). It has NO actix / `BusHandle` / signing concerns.

use std::collections::HashMap;
use std::sync::Arc;

use e3_events::{
    DkgShareDecryptionProofRequest, E3id, EncryptionKey, EventContext, PkAggregationProofRequest,
    PkGenerationProofRequest, Proof, Sequenced, ShareComputationProofRequest,
    ShareEncryptionProofRequest, ThresholdShare, ZkRequest,
};
use e3_utils::utility_types::ArcBytes;

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
    /// When false, skip emitting DKGInnerProofReady (no recursive DKG aggregation).
    pub(crate) proof_aggregation_enabled: bool,
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

/// A single planned threshold (C1/C2/C3) proof request: which proof, its `seq`
/// index for streaming aggregation, and the [`ZkRequest`] to dispatch.
pub(crate) struct ThresholdDispatchItem {
    pub(crate) kind: ThresholdProofKind,
    pub(crate) seq: usize,
    pub(crate) request: ZkRequest,
}

/// Build the deterministic, ordered set of C1/C2/C3 proof requests for a
/// `ThresholdSharePending` event. Pure: assigns the canonical `seq` indices
/// (C1=1, C2a=2, C2b=3, C3a[i]=4+i, C3b[j]=4+sk_count+j) and wraps each request.
pub(crate) fn plan_threshold_dispatch(
    proof_request: PkGenerationProofRequest,
    sk_share_computation_request: ShareComputationProofRequest,
    e_sm_share_computation_request: ShareComputationProofRequest,
    sk_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
    e_sm_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
) -> Vec<ThresholdDispatchItem> {
    let sk_enc_count = sk_share_encryption_requests.len();
    let mut items = Vec::with_capacity(3 + sk_enc_count + e_sm_share_encryption_requests.len());

    items.push(ThresholdDispatchItem {
        kind: ThresholdProofKind::PkGeneration,
        seq: 1,
        request: ZkRequest::PkGeneration(proof_request),
    });
    items.push(ThresholdDispatchItem {
        kind: ThresholdProofKind::SkShareComputation,
        seq: 2,
        request: ZkRequest::ShareComputation(sk_share_computation_request),
    });
    items.push(ThresholdDispatchItem {
        kind: ThresholdProofKind::ESmShareComputation,
        seq: 3,
        request: ZkRequest::ShareComputation(e_sm_share_computation_request),
    });

    for (i, req) in sk_share_encryption_requests.into_iter().enumerate() {
        let kind = ThresholdProofKind::SkShareEncryption {
            recipient_party_id: req.recipient_party_id,
            row_index: req.row_index,
        };
        items.push(ThresholdDispatchItem {
            kind,
            seq: 4 + i,
            request: ZkRequest::ShareEncryption(req),
        });
    }

    for (j, req) in e_sm_share_encryption_requests.into_iter().enumerate() {
        let kind = ThresholdProofKind::ESmShareEncryption {
            esi_index: req.esi_index,
            recipient_party_id: req.recipient_party_id,
            row_index: req.row_index,
        };
        items.push(ThresholdDispatchItem {
            kind,
            seq: 4 + sk_enc_count + j,
            request: ZkRequest::ShareEncryption(req),
        });
    }

    items
}

/// A single planned C4 (DkgShareDecryption) proof request.
pub(crate) struct DecryptionDispatchItem {
    pub(crate) kind: DecryptionProofKind,
    pub(crate) seq: usize,
    pub(crate) request: ZkRequest,
}

/// Build the ordered set of C4 proof requests (SecretKey then SmudgingNoise[i]).
/// `c4_base_seq` is the streaming-aggregation `seq` of the C4a (SecretKey) proof;
/// each C4b proof follows at `c4_base_seq + 1 + esi_idx`.
pub(crate) fn plan_decryption_dispatch(
    sk_request: DkgShareDecryptionProofRequest,
    esm_requests: Vec<DkgShareDecryptionProofRequest>,
    c4_base_seq: usize,
) -> Vec<DecryptionDispatchItem> {
    let mut items = Vec::with_capacity(1 + esm_requests.len());
    items.push(DecryptionDispatchItem {
        kind: DecryptionProofKind::SecretKey,
        seq: c4_base_seq,
        request: ZkRequest::DkgShareDecryption(sk_request),
    });
    for (esi_idx, esm_req) in esm_requests.into_iter().enumerate() {
        items.push(DecryptionDispatchItem {
            kind: DecryptionProofKind::SmudgingNoise { esi_idx },
            seq: c4_base_seq + 1 + esi_idx,
            request: ZkRequest::DkgShareDecryption(esm_req),
        });
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_crypto::SensitiveBytes;
    use e3_events::CircuitName;
    use e3_fhe_params::BfvPreset;
    use e3_trbfv::shares::BfvEncryptedShares;
    use e3_zk_helpers::{computation::DkgInputType, CiphernodesCommitteeSize};

    fn ec() -> EventContext<Sequenced> {
        use e3_events::{InterfoldEventData, TestEvent, Unsequenced};
        EventContext::<Unsequenced>::from(InterfoldEventData::from(TestEvent::new("x", 0)))
            .sequence(0)
    }

    fn sensitive() -> SensitiveBytes {
        SensitiveBytes::from_encrypted(&[])
    }

    fn full_share() -> Arc<ThresholdShare> {
        Arc::new(ThresholdShare {
            party_id: 0,
            pk_share: ArcBytes::from_bytes(&[]),
            sk_sss: BfvEncryptedShares::default(),
            esi_sss: vec![],
        })
    }

    fn share_computation_req() -> ShareComputationProofRequest {
        ShareComputationProofRequest {
            secret_raw: sensitive(),
            secret_sss_raw: sensitive(),
            dkg_input_type: DkgInputType::SecretKey,
            params_preset: BfvPreset::default(),
            committee_size: CiphernodesCommitteeSize::Micro,
        }
    }

    fn pk_generation_req() -> PkGenerationProofRequest {
        PkGenerationProofRequest {
            pk0_share: ArcBytes::from_bytes(&[]),
            sk: sensitive(),
            eek: sensitive(),
            e_sm: sensitive(),
            params_preset: BfvPreset::default(),
            committee_size: CiphernodesCommitteeSize::Micro,
        }
    }

    fn share_encryption_req(
        recipient_party_id: usize,
        row_index: usize,
        esi_index: usize,
    ) -> ShareEncryptionProofRequest {
        ShareEncryptionProofRequest {
            share_row_raw: sensitive(),
            ciphertext_raw: ArcBytes::from_bytes(&[]),
            recipient_pk_raw: ArcBytes::from_bytes(&[]),
            u_rns_raw: sensitive(),
            e0_rns_raw: sensitive(),
            e1_rns_raw: sensitive(),
            dkg_input_type: DkgInputType::SecretKey,
            params_preset: BfvPreset::default(),
            committee_size: CiphernodesCommitteeSize::Micro,
            recipient_party_id,
            row_index,
            esi_index,
        }
    }

    fn dkg_share_decryption_req() -> DkgShareDecryptionProofRequest {
        DkgShareDecryptionProofRequest {
            sk_bfv: sensitive(),
            honest_ciphertexts_raw: vec![],
            num_honest_parties: 0,
            num_moduli: 0,
            own_plaintext_idx: 0,
            own_share_raw: sensitive(),
            dkg_input_type: DkgInputType::SecretKey,
            params_preset: BfvPreset::default(),
            committee_size: CiphernodesCommitteeSize::Micro,
        }
    }

    fn proof(seed: u8) -> Proof {
        Proof::new(
            CircuitName::PkAggregation,
            ArcBytes::from_bytes(&[seed]),
            ArcBytes::from_bytes(&[seed.wrapping_add(1)]),
        )
    }

    fn pending(sk: usize, esm: usize) -> PendingThresholdProofs {
        PendingThresholdProofs::new(
            E3id::new("1", 1),
            full_share(),
            ec(),
            sk,
            esm,
            vec![1, 2, 3],
        )
    }

    #[test]
    fn threshold_completes_only_when_all_proofs_present() {
        let mut p = pending(1, 1);
        assert!(!p.is_complete());
        assert_eq!(p.total_expected(), 3 + 1 + 1);
        assert_eq!(p.total_received(), 0);

        p.store_proof(&ThresholdProofKind::PkGeneration, proof(1));
        p.store_proof(&ThresholdProofKind::SkShareComputation, proof(2));
        p.store_proof(&ThresholdProofKind::ESmShareComputation, proof(3));
        assert!(!p.is_complete());
        assert_eq!(p.total_received(), 3);

        p.store_proof(
            &ThresholdProofKind::SkShareEncryption {
                recipient_party_id: 2,
                row_index: 0,
            },
            proof(4),
        );
        assert!(!p.is_complete());
        p.store_proof(
            &ThresholdProofKind::ESmShareEncryption {
                esi_index: 0,
                recipient_party_id: 2,
                row_index: 0,
            },
            proof(5),
        );
        assert!(p.is_complete());
        assert_eq!(p.total_received(), 5);
    }

    #[test]
    fn store_proof_dedupes_by_key() {
        let mut p = pending(2, 0);
        let key = ThresholdProofKind::SkShareEncryption {
            recipient_party_id: 2,
            row_index: 0,
        };
        p.store_proof(&key, proof(4));
        p.store_proof(&key, proof(9)); // same (recipient,row) overwrites
        assert_eq!(p.sk_share_encryption_proofs.len(), 1);
        assert!(!p.is_complete()); // still expecting 2 distinct sk enc proofs
    }

    #[test]
    fn decryption_completes_when_sk_and_all_esm_present() {
        let mut d = PendingDecryptionProofs {
            party_id: 7,
            node: "n".into(),
            ec: ec(),
            sk_proof: None,
            esm_proofs: HashMap::new(),
            expected_esm_count: 2,
        };
        assert!(!d.is_complete());
        d.sk_proof = Some(proof(1));
        d.esm_proofs.insert(0, proof(2));
        assert!(!d.is_complete());
        d.esm_proofs.insert(1, proof(3));
        assert!(d.is_complete());
    }

    #[test]
    fn decryption_requires_contiguous_esm_indices() {
        let mut d = PendingDecryptionProofs {
            party_id: 7,
            node: "n".into(),
            ec: ec(),
            sk_proof: Some(proof(1)),
            esm_proofs: HashMap::new(),
            expected_esm_count: 2,
        };
        // Two entries but indices {0,2} — count matches but index 1 missing.
        d.esm_proofs.insert(0, proof(2));
        d.esm_proofs.insert(2, proof(3));
        assert!(!d.is_complete());
    }

    #[test]
    fn node_agg_meta_seq_helpers() {
        assert_eq!(NodeAggregationMeta::total_expected_for(2, 1), 4 + 2 + 1 + 2);
        let meta = NodeAggregationMeta {
            party_id: 0,
            total_expected: NodeAggregationMeta::total_expected_for(2, 1),
            pending_c0: None,
            proof_aggregation_enabled: true,
        };
        // c4_base_seq sits just after C0..C3 = total_expected - 2.
        assert_eq!(meta.c4_base_seq(), 4 + 2 + 1);
    }

    #[test]
    fn threshold_plan_assigns_canonical_seqs() {
        let enc =
            |recipient: usize, row: usize, esi: usize| share_encryption_req(recipient, row, esi);
        let plan = plan_threshold_dispatch(
            pk_generation_req(),
            share_computation_req(),
            share_computation_req(),
            vec![enc(2, 0, 0), enc(3, 0, 0)],
            vec![enc(2, 0, 0)],
        );
        let seqs: Vec<usize> = plan.iter().map(|i| i.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6]);
        assert!(matches!(plan[0].kind, ThresholdProofKind::PkGeneration));
        assert!(matches!(
            plan[3].kind,
            ThresholdProofKind::SkShareEncryption { .. }
        ));
        assert!(matches!(
            plan[5].kind,
            ThresholdProofKind::ESmShareEncryption { .. }
        ));
    }

    #[test]
    fn decryption_plan_assigns_offset_seqs() {
        let plan = plan_decryption_dispatch(
            dkg_share_decryption_req(),
            vec![dkg_share_decryption_req(), dkg_share_decryption_req()],
            7,
        );
        let seqs: Vec<usize> = plan.iter().map(|i| i.seq).collect();
        assert_eq!(seqs, vec![7, 8, 9]);
        assert!(matches!(plan[0].kind, DecryptionProofKind::SecretKey));
        assert!(matches!(
            plan[1].kind,
            DecryptionProofKind::SmudgingNoise { esi_idx: 0 }
        ));
    }
}
