// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_crypto::SensitiveBytes;
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_trbfv::shares::BfvEncryptedShares;
use e3_zk_helpers::{computation::DkgInputType, CiphernodesCommitteeSize};

fn ec() -> EventContext<Sequenced> {
    use e3_events::{InterfoldEventData, TestEvent, Unsequenced};
    EventContext::<Unsequenced>::from(InterfoldEventData::from(TestEvent::new("x", 0))).sequence(0)
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
        recipient_party_id: 0,
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
    };
    // c4_base_seq sits just after C0..C3 = total_expected - 2.
    assert_eq!(meta.c4_base_seq(), 4 + 2 + 1);
}

#[test]
fn threshold_plan_assigns_canonical_seqs() {
    let enc = |recipient: usize, row: usize, esi: usize| share_encryption_req(recipient, row, esi);
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
