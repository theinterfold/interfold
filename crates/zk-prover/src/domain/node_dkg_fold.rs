// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, synchronous domain logic for node-level DKG proof aggregation.
//!
//! [`DkgProofCollectionState`] buffers all inner proofs (C0–C4) keyed by `seq`
//! and, once the full set is present, assembles a [`NodeDkgFoldRequest`]. This
//! module contains NO actix / bus / signing concerns — the actor owns all I/O
//! and merely drives this state machine.

use std::collections::BTreeMap;

use e3_zk_helpers::CiphernodesCommitteeSize;

use e3_events::{
    CorrelationId, EventContext, NodeDkgFoldRequest, Proof, Sequenced, ShareEncryptionProofRequest,
};

/// Metadata from `ThresholdSharePending` for slot indices and sizing.
pub(crate) struct NodeDkgFoldMeta {
    pub(crate) party_id: u64,
    pub(crate) total_expected: usize,
    pub(crate) sk_enc_count: usize,
    pub(crate) e_sm_enc_count: usize,
    pub(crate) sk_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
    pub(crate) e_sm_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
    pub(crate) committee_n: usize,
    pub(crate) committee_h: usize,
    pub(crate) n_moduli: usize,
    pub(crate) params_preset: e3_fhe_params::BfvPreset,
    pub(crate) committee_size: CiphernodesCommitteeSize,
}

impl NodeDkgFoldMeta {
    /// Total number of inner proofs (C0..C4) expected before the fold can run:
    /// C0, C1, C2a, C2b (4) + C3a (sk) + C3b (esm) + C4a, C4b (2).
    pub(crate) fn total_expected_for(sk_enc_count: usize, e_sm_enc_count: usize) -> usize {
        4 + sk_enc_count + e_sm_enc_count + 2
    }
}

/// Per-E3 collection state: buffer proofs by `seq` until the monolithic fold can run.
pub(crate) struct DkgProofCollectionState {
    pub(crate) meta: NodeDkgFoldMeta,
    pub(crate) buffer: BTreeMap<usize, Proof>,
    pub(crate) fold_correlation: Option<CorrelationId>,
    pub(crate) last_ec: EventContext<Sequenced>,
}

impl DkgProofCollectionState {
    pub(crate) fn new(
        meta: NodeDkgFoldMeta,
        buffer: BTreeMap<usize, Proof>,
        last_ec: EventContext<Sequenced>,
    ) -> Self {
        Self {
            meta,
            buffer,
            fold_correlation: None,
            last_ec,
        }
    }

    /// True once every `seq` in `0..total_expected` has been buffered.
    pub(crate) fn is_ready(&self) -> bool {
        let n = self.meta.total_expected;
        self.buffer.len() == n && (0..n).all(|i| self.buffer.contains_key(&i))
    }

    /// Assemble the [`NodeDkgFoldRequest`] from the buffered inner proofs.
    ///
    /// Callers must ensure [`is_ready`](Self::is_ready) is `true` first; this
    /// method panics if any expected `seq` is missing.
    pub(crate) fn build_fold_request(&self) -> NodeDkgFoldRequest {
        let meta = &self.meta;
        let c3_total_slots = meta.committee_n * meta.n_moduli;
        let slots_a: Vec<u32> = meta
            .sk_share_encryption_requests
            .iter()
            .map(|r| r.c3_slot_index(meta.n_moduli))
            .collect();
        let slots_b: Vec<u32> = meta
            .e_sm_share_encryption_requests
            .iter()
            .map(|r| r.c3_slot_index(meta.n_moduli))
            .collect();

        let sk = meta.sk_enc_count;
        let esm = meta.e_sm_enc_count;
        let buf = &self.buffer;
        let get = |seq: usize| {
            buf.get(&seq)
                .cloned()
                .expect("buffer contains all seq indices")
        };

        let c0_proof = get(0);
        let c1_proof = get(1);
        let c2a_proof = get(2);
        let c2b_proof = get(3);
        let mut c3a_inner_proofs = Vec::with_capacity(sk);
        for s in 0..sk {
            c3a_inner_proofs.push(get(4 + s));
        }
        let mut c3b_inner_proofs = Vec::with_capacity(esm);
        for s in 0..esm {
            c3b_inner_proofs.push(get(4 + sk + s));
        }
        let c4a_seq = 4 + sk + esm;
        let c4a_proof = get(c4a_seq);
        let c4b_proof = get(c4a_seq + 1);

        NodeDkgFoldRequest {
            c0_proof,
            c1_proof,
            c2a_proof,
            c2b_proof,
            c3a_inner_proofs,
            c3b_inner_proofs,
            c4a_proof,
            c4b_proof,
            c3_slot_indices_a: slots_a,
            c3_slot_indices_b: slots_b,
            c3_total_slots,
            party_id: meta.party_id,
            params_preset: meta.params_preset,
            committee_size: meta.committee_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::CircuitName;
    use e3_utils::ArcBytes;

    fn meta(sk: usize, esm: usize) -> NodeDkgFoldMeta {
        NodeDkgFoldMeta {
            party_id: 7,
            total_expected: NodeDkgFoldMeta::total_expected_for(sk, esm),
            sk_enc_count: sk,
            e_sm_enc_count: esm,
            sk_share_encryption_requests: Vec::new(),
            e_sm_share_encryption_requests: Vec::new(),
            committee_n: 3,
            committee_h: 2,
            n_moduli: 2,
            params_preset: e3_fhe_params::BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Minimum,
        }
    }

    fn dummy_proof(seed: u8) -> Proof {
        Proof::new(
            CircuitName::PkAggregation,
            ArcBytes::from_bytes(&[seed]),
            ArcBytes::from_bytes(&[seed.wrapping_add(1)]),
        )
    }

    fn ec() -> EventContext<Sequenced> {
        use e3_events::{InterfoldEventData, TestEvent, Unsequenced};
        EventContext::<Unsequenced>::from(InterfoldEventData::from(TestEvent::new("x", 0)))
            .sequence(0)
    }

    #[test]
    fn total_expected_counts_fixed_plus_encryption_proofs() {
        assert_eq!(NodeDkgFoldMeta::total_expected_for(0, 0), 6);
        assert_eq!(NodeDkgFoldMeta::total_expected_for(2, 3), 11);
    }

    #[test]
    fn is_ready_only_when_all_seqs_present() {
        let mut state = DkgProofCollectionState::new(meta(0, 0), BTreeMap::new(), ec());
        assert!(!state.is_ready());
        for seq in 0..6 {
            state.buffer.insert(seq, dummy_proof(seq as u8));
        }
        assert!(state.is_ready());
        // Remove a middle seq -> not ready even though len could match later.
        state.buffer.remove(&3);
        assert!(!state.is_ready());
    }

    #[test]
    fn build_fold_request_places_proofs_in_canonical_slots() {
        let mut state = DkgProofCollectionState::new(meta(1, 1), BTreeMap::new(), ec());
        // total_expected = 4 + 1 + 1 + 2 = 8 -> seqs 0..8
        for seq in 0..8 {
            state.buffer.insert(seq, dummy_proof(seq as u8));
        }
        assert!(state.is_ready());
        let req = state.build_fold_request();
        assert_eq!(req.c0_proof, dummy_proof(0));
        assert_eq!(req.c1_proof, dummy_proof(1));
        assert_eq!(req.c2a_proof, dummy_proof(2));
        assert_eq!(req.c2b_proof, dummy_proof(3));
        assert_eq!(req.c3a_inner_proofs, vec![dummy_proof(4)]);
        assert_eq!(req.c3b_inner_proofs, vec![dummy_proof(5)]);
        // c4a_seq = 4 + 1 + 1 = 6
        assert_eq!(req.c4a_proof, dummy_proof(6));
        assert_eq!(req.c4b_proof, dummy_proof(7));
        assert_eq!(req.party_id, 7);
        assert_eq!(req.c3_total_slots, 3 * 2);
    }
}
