// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

fn field(value: u32) -> [u8; e3_zk_helpers::FIELD_BYTE_LEN] {
    let mut field = [0u8; e3_zk_helpers::FIELD_BYTE_LEN];
    field[28..].copy_from_slice(&value.to_be_bytes());
    field
}

fn field_u128(value: u128) -> [u8; e3_zk_helpers::FIELD_BYTE_LEN] {
    let mut field = [0u8; e3_zk_helpers::FIELD_BYTE_LEN];
    field[16..].copy_from_slice(&value.to_be_bytes());
    field
}

fn commitment(value: u32) -> B256 {
    B256::from(field(value))
}

fn lbfv_aggregation_context(e3_id: &E3id) -> LbfvVerificationContext {
    let accepted_parties = [0, 1]
        .into_iter()
        .map(|party_id| LbfvAcceptedPartyCommitments {
            party_id,
            pk_generation_commitments: [commitment(30 + party_id); 5],
            rlk_d0_commitments: [commitment(50 + party_id); 5],
            rlk_d2_commitments: [commitment(60 + party_id); 5],
        })
        .collect();
    LbfvVerificationContext::V1(LbfvVerificationContextV1 {
        proof_domain: lbfv_proof_domain(e3_id),
        aggregation: Some(LbfvAggregationVerificationContext { accepted_parties }),
    })
}

fn signed_fields(
    signer: &alloy::signers::local::PrivateKeySigner,
    e3_id: &E3id,
    proof_type: ProofType,
    fields: Vec<[u8; e3_zk_helpers::FIELD_BYTE_LEN]>,
) -> SignedProofPayload {
    let public_signals = fields.into_iter().flatten().collect::<Vec<_>>();
    SignedProofPayload::sign(
        e3_events::ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof: e3_events::Proof::new(
                proof_type.circuit_names()[0],
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&public_signals),
            ),
        },
        signer,
    )
    .unwrap()
}

fn lbfv_generation_bundle(
    signer: &alloy::signers::local::PrivateKeySigner,
    e3_id: &E3id,
    party_id: u32,
) -> Vec<SignedProofPayload> {
    let session = split_hash_to_field_limbs(hash_lbfv_proof_session(lbfv_proof_domain(e3_id)));
    let mut proofs = vec![signed_fields(
        signer,
        e3_id,
        ProofType::C1PkGeneration,
        vec![field(21), field(90), field(91)],
    )];
    for row in 0..ProofType::LBFV_ROW_INSTANCES {
        proofs.push(signed_fields(
            signer,
            e3_id,
            ProofType::LbfvPkGeneration,
            vec![
                field_u128(session.hi),
                field_u128(session.lo),
                field(party_id),
                field(row),
                field(21),
                field(30 + row),
            ],
        ));
    }
    for row in 0..ProofType::LBFV_ROW_INSTANCES {
        proofs.push(signed_fields(
            signer,
            e3_id,
            ProofType::RlkGeneration,
            vec![
                field_u128(session.hi),
                field_u128(session.lo),
                field(party_id),
                field(row),
                field(21),
                field(22),
                field(40 + row),
                field(50 + row),
                field(60),
            ],
        ));
    }
    proofs
}

fn lbfv_aggregation_bundle(
    signer: &alloy::signers::local::PrivateKeySigner,
    e3_id: &E3id,
    aggregator_party_id: u32,
) -> Vec<SignedProofPayload> {
    let session = split_hash_to_field_limbs(hash_lbfv_proof_session(lbfv_proof_domain(e3_id)));
    let accepted = split_hash_to_field_limbs(
        hash_lbfv_accepted_party_set(&[0, 1], 3, 2).expect("canonical accepted set"),
    );
    let mut proofs = Vec::new();
    for row in 0..ProofType::LBFV_ROW_INSTANCES {
        proofs.push(signed_fields(
            signer,
            e3_id,
            ProofType::LbfvPkAggregation,
            vec![
                field_u128(session.hi),
                field_u128(session.lo),
                field(aggregator_party_id),
                field_u128(accepted.hi),
                field_u128(accepted.lo),
                field(row),
                field(30),
                field(31),
                field(40 + row),
            ],
        ));
    }
    for row in 0..ProofType::LBFV_ROW_INSTANCES {
        proofs.push(signed_fields(
            signer,
            e3_id,
            ProofType::RlkAggregation,
            vec![
                field_u128(session.hi),
                field_u128(session.lo),
                field(aggregator_party_id),
                field_u128(accepted.hi),
                field_u128(accepted.lo),
                field(row),
                field(50),
                field(51),
                field(60),
                field(61),
                field(70 + row),
                field(80 + row),
            ],
        ));
    }
    proofs
}

#[test]
fn canonical_shape_rejects_cross_phase_and_singleton_multiplicity() {
    let s = signer();
    let e3 = e3();

    let c1 = signed_proof(&s, &e3, ProofType::C1PkGeneration, 1);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::PkGenerationProofs,
        std::slice::from_ref(&c1),
        BfvPreset::InsecureDkg512,
    ));
    assert!(ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::PkGenerationProofs,
        std::slice::from_ref(&c1),
        0,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        None,
    ));
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::PkGenerationProofs,
        std::slice::from_ref(&c1),
        0,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&lbfv_generation_context(&e3)),
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::PkGenerationProofs,
        &[c1.clone(), c1.clone()],
        BfvPreset::InsecureDkg512,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ThresholdDecryptionProofs,
        std::slice::from_ref(&c1),
        BfvPreset::InsecureDkg512,
    ));
    let c6 = signed_proof(&s, &e3, ProofType::C6ThresholdShareDecryption, 9);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ThresholdDecryptionProofs,
        std::slice::from_ref(&c6),
        BfvPreset::InsecureDkg512,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ThresholdDecryptionProofs,
        &[],
        BfvPreset::InsecureDkg512,
    ));

    let share_bundle = signed_share_bundle(&s, &e3, 2);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &share_bundle,
        BfvPreset::InsecureDkg512,
    ));
    let mut duplicate_c2a = share_bundle.clone();
    duplicate_c2a.insert(1, duplicate_c2a[0].clone());
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &duplicate_c2a,
        BfvPreset::InsecureDkg512,
    ));

    let secure_share_bundle = signed_share_bundle(&s, &e3, 3);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &secure_share_bundle,
        BfvPreset::SecureThreshold8192,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &share_bundle,
        BfvPreset::SecureThreshold8192,
    ));

    let c4_bundle = vec![
        signed_proof(&s, &e3, ProofType::C4aSkShareDecryption, 6),
        signed_proof(&s, &e3, ProofType::C4bESmShareDecryption, 7),
    ];
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::DecryptionProofs,
        &c4_bundle,
        BfvPreset::InsecureDkg512,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::DecryptionProofs,
        &c4_bundle[1..],
        BfvPreset::InsecureDkg512,
    ));
    let mut extra_c4b = c4_bundle.clone();
    extra_c4b.push(c4_bundle[1].clone());
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::DecryptionProofs,
        &extra_c4b,
        BfvPreset::InsecureDkg512,
    ));
    let mut wrong_c4_tail = c4_bundle.clone();
    wrong_c4_tail.push(c6);
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::DecryptionProofs,
        &wrong_c4_tail,
        BfvPreset::InsecureDkg512,
    ));
}

#[test]
fn share_shape_uses_threshold_secret_rows_when_dispatch_carries_dkg_preset() {
    let s = signer();
    let e3 = e3();

    // Production dispatch carries the share-encryption (DKG) preset, but C3 requests are
    // generated from rows of the paired threshold-parameter Shamir secret.
    let insecure_production_bundle = signed_share_bundle(&s, &e3, 2);
    assert_eq!(BfvPreset::InsecureDkg512.metadata().num_moduli, 1);
    assert_eq!(BfvPreset::InsecureThreshold512.metadata().num_moduli, 2);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &insecure_production_bundle,
        BfvPreset::InsecureDkg512,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &signed_share_bundle(&s, &e3, 1),
        BfvPreset::InsecureDkg512,
    ));

    let secure_production_bundle = signed_share_bundle(&s, &e3, 3);
    assert_eq!(BfvPreset::SecureDkg8192.metadata().num_moduli, 2);
    assert_eq!(BfvPreset::SecureThreshold8192.metadata().num_moduli, 3);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &secure_production_bundle,
        BfvPreset::SecureDkg8192,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &signed_share_bundle(&s, &e3, 2),
        BfvPreset::SecureDkg8192,
    ));
}

#[test]
fn lbfv_generation_requires_both_canonical_linked_row_families() {
    let signer = signer();
    let e3 = e3();
    let bundle = lbfv_generation_bundle(&signer, &e3, 1);
    let context = lbfv_generation_context(&e3);

    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::LbfvGenerationProofs,
        &bundle,
        BfvPreset::SecureThreshold16384,
    ));
    assert!(ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvGenerationProofs,
        &bundle,
        1,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));

    let mut wrong_context = context.clone();
    let LbfvVerificationContext::V1(wrong_context) = &mut wrong_context;
    wrong_context.proof_domain.crypto_config_id = B256::repeat_byte(0x99);
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvGenerationProofs,
        &bundle,
        1,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&LbfvVerificationContext::V1(wrong_context.clone())),
    ));

    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvGenerationProofs,
        &bundle,
        1,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        None,
    ));

    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::LbfvGenerationProofs,
        &bundle[1..],
        BfvPreset::SecureThreshold16384,
    ));

    let mut reordered = bundle.clone();
    reordered.swap(0, 1);
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::LbfvGenerationProofs,
        &reordered,
        BfvPreset::SecureThreshold16384,
    ));

    let mut duplicate_c1 = bundle.clone();
    duplicate_c1.insert(1, bundle[0].clone());
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::LbfvGenerationProofs,
        &duplicate_c1,
        BfvPreset::SecureThreshold16384,
    ));

    let mut malformed_c1 = bundle.clone();
    let mut signals = malformed_c1[0].payload.proof.public_signals.extract_bytes();
    signals.extend_from_slice(&field(92));
    malformed_c1[0].payload.proof.public_signals = ArcBytes::from_bytes(&signals);
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::LbfvGenerationProofs,
        &malformed_c1,
        BfvPreset::SecureThreshold16384,
    ));
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvGenerationProofs,
        &malformed_c1,
        1,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));

    let mut mismatched_sk = bundle.clone();
    let mut signals = mismatched_sk[0]
        .payload
        .proof
        .public_signals
        .extract_bytes();
    signals[31] ^= 1;
    mismatched_sk[0].payload.proof.public_signals = ArcBytes::from_bytes(&signals);
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvGenerationProofs,
        &mismatched_sk,
        1,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));

    let mut mismatched_r = bundle;
    let rlk = 1 + ProofType::LBFV_ROW_INSTANCES as usize + 4;
    let mut signals = mismatched_r[rlk]
        .payload
        .proof
        .public_signals
        .extract_bytes();
    signals[5 * e3_zk_helpers::FIELD_BYTE_LEN + 31] ^= 1;
    mismatched_r[rlk].payload.proof.public_signals = ArcBytes::from_bytes(&signals);
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvGenerationProofs,
        &mismatched_r,
        1,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));
}

#[test]
fn lbfv_generation_prepares_c1_and_rows_for_one_consistency_decision() {
    use crate::domain::commitment_links::{
        c1_to_lbfv::C1ToLbfvPkGenerationSkCommitmentLink, CommitmentLink,
    };

    let signer = signer();
    let e3 = e3();
    let party = PartyProofsToVerify {
        sender_party_id: 1,
        signed_proofs: lbfv_generation_bundle(&signer, &e3, 1),
    };
    let committee = minimum_committee(vec![PrivateKeySigner::random().address(), signer.address()]);
    let outcome = ShareVerifier::validate_and_prepare(
        &[party],
        &e3,
        &VerificationKind::LbfvGenerationProofs,
        "l-BFV generation",
        Some(&committee),
        BfvPreset::SecureThreshold16384,
        CiphernodesCommitteeSize::Minimum,
        Some(&lbfv_generation_context(&e3)),
    );

    assert_eq!(outcome.consistency_party_data.len(), 1);
    let prepared = &outcome.consistency_party_data[0].proofs;
    assert_eq!(prepared.len(), 11);
    assert_eq!(prepared[0].0.proof_type, ProofType::C1PkGeneration);

    let link = C1ToLbfvPkGenerationSkCommitmentLink;
    let c1_signals = &prepared[0].1;
    for (identity, public_signals, _, _) in &prepared[1..=ProofType::LBFV_ROW_INSTANCES as usize] {
        assert_eq!(identity.proof_type, ProofType::LbfvPkGeneration);
        assert!(link.check_signals(&link.extract_source_values(public_signals), c1_signals,));
    }
}

#[test]
fn lbfv_aggregation_requires_one_aggregator_and_accepted_set() {
    let signer = signer();
    let e3 = e3();
    let bundle = lbfv_aggregation_bundle(&signer, &e3, 2);
    let context = lbfv_aggregation_context(&e3);

    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::LbfvAggregationProofs,
        &bundle,
        BfvPreset::SecureThreshold16384,
    ));
    assert!(ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvAggregationProofs,
        &bundle,
        2,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvAggregationProofs,
        &bundle,
        1,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));

    let mut false_set_hash = bundle.clone();
    let mut signals = false_set_hash[0]
        .payload
        .proof
        .public_signals
        .extract_bytes();
    signals[3 * e3_zk_helpers::FIELD_BYTE_LEN + 31] ^= 1;
    false_set_hash[0].payload.proof.public_signals = ArcBytes::from_bytes(&signals);
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvAggregationProofs,
        &false_set_hash,
        2,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));

    let mut reordered_context = context.clone();
    let LbfvVerificationContext::V1(reordered) = &mut reordered_context;
    reordered
        .aggregation
        .as_mut()
        .unwrap()
        .accepted_parties
        .swap(0, 1);
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvAggregationProofs,
        &bundle,
        2,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&reordered_context),
    ));

    let mut duplicate_context = context.clone();
    let LbfvVerificationContext::V1(duplicate) = &mut duplicate_context;
    duplicate.aggregation.as_mut().unwrap().accepted_parties[1].party_id = 0;
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvAggregationProofs,
        &bundle,
        2,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&duplicate_context),
    ));

    let mut mismatched_source = bundle.clone();
    let mut signals = mismatched_source[3]
        .payload
        .proof
        .public_signals
        .extract_bytes();
    signals[6 * e3_zk_helpers::FIELD_BYTE_LEN + 31] ^= 1;
    mismatched_source[3].payload.proof.public_signals = ArcBytes::from_bytes(&signals);
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvAggregationProofs,
        &mismatched_source,
        2,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));

    let mixed_set = split_hash_to_field_limbs(
        hash_lbfv_accepted_party_set(&[0, 2], 3, 2).expect("alternate accepted set"),
    );
    let mut mixed_pk_rlk_sets = bundle.clone();
    for signed in &mut mixed_pk_rlk_sets[ProofType::LBFV_ROW_INSTANCES as usize..] {
        let mut signals = signed.payload.proof.public_signals.extract_bytes();
        signals[3 * e3_zk_helpers::FIELD_BYTE_LEN..4 * e3_zk_helpers::FIELD_BYTE_LEN]
            .copy_from_slice(&field_u128(mixed_set.hi));
        signals[4 * e3_zk_helpers::FIELD_BYTE_LEN..5 * e3_zk_helpers::FIELD_BYTE_LEN]
            .copy_from_slice(&field_u128(mixed_set.lo));
        signed.payload.proof.public_signals = ArcBytes::from_bytes(&signals);
    }
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvAggregationProofs,
        &mixed_pk_rlk_sets,
        2,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));

    let mut truncated = bundle;
    let mut signals = truncated[0].payload.proof.public_signals.extract_bytes();
    signals.truncate(signals.len() - e3_zk_helpers::FIELD_BYTE_LEN);
    truncated[0].payload.proof.public_signals = ArcBytes::from_bytes(&signals);
    assert!(!ShareVerifier::has_valid_lbfv_statements(
        &VerificationKind::LbfvAggregationProofs,
        &truncated,
        2,
        &e3,
        CiphernodesCommitteeSize::Minimum,
        Some(&context),
    ));
}

#[test]
fn prepare_excludes_wrong_phase_without_creating_slash_evidence() {
    let s = signer();
    let e3 = e3();
    let parties = [PartyProofsToVerify {
        sender_party_id: 0,
        signed_proofs: vec![signed_proof(
            &s,
            &e3,
            ProofType::C6ThresholdShareDecryption,
            9,
        )],
    }];
    let committee = minimum_committee(vec![s.address()]);

    let outcome = ShareVerifier::validate_and_prepare(
        &parties,
        &e3,
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&committee),
        BfvPreset::InsecureDkg512,
        CiphernodesCommitteeSize::Minimum,
        None,
    );

    assert!(outcome.ecdsa_passed_parties.is_empty());
    assert_eq!(outcome.ecdsa_dishonest, HashSet::from([0]));
    assert!(outcome.failures.is_empty());
}

#[test]
fn prepare_collapses_identical_party_replay_and_rejects_conflict() {
    let s = signer();
    let e3 = e3();
    let committee = minimum_committee(vec![s.address()]);
    let party = PartyProofsToVerify {
        sender_party_id: 0,
        signed_proofs: vec![signed_proof(&s, &e3, ProofType::C1PkGeneration, 1)],
    };

    let replayed = ShareVerifier::validate_and_prepare(
        &[party.clone(), party.clone()],
        &e3,
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&committee),
        BfvPreset::InsecureDkg512,
        CiphernodesCommitteeSize::Minimum,
        None,
    );
    assert_eq!(replayed.ecdsa_passed_parties, vec![party.clone()]);
    assert!(replayed.ecdsa_dishonest.is_empty());
    assert_eq!(replayed.consistency_party_data.len(), 1);

    let conflicting = PartyProofsToVerify {
        sender_party_id: 0,
        signed_proofs: vec![signed_proof(&s, &e3, ProofType::C1PkGeneration, 2)],
    };
    let conflict = ShareVerifier::validate_and_prepare(
        &[party, conflicting],
        &e3,
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&committee),
        BfvPreset::InsecureDkg512,
        CiphernodesCommitteeSize::Minimum,
        None,
    );
    assert!(conflict.ecdsa_passed_parties.is_empty());
    assert_eq!(conflict.ecdsa_dishonest, HashSet::from([0]));
    assert!(conflict.failures.is_empty());
}
