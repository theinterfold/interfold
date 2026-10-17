// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[test]
fn canonical_shape_rejects_cross_phase_and_singleton_multiplicity() {
    let s = signer();
    let e3 = e3();

    let c1 = signed_proof(&s, &e3, ProofType::C1PkGeneration, 1);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::PkGenerationProofs,
        std::slice::from_ref(&c1),
        BfvPreset::InsecureDkg64,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::PkGenerationProofs,
        &[c1.clone(), c1.clone()],
        BfvPreset::InsecureDkg64,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ThresholdDecryptionProofs,
        std::slice::from_ref(&c1),
        BfvPreset::InsecureDkg64,
    ));
    let c6 = signed_proof(&s, &e3, ProofType::C6ThresholdShareDecryption, 9);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ThresholdDecryptionProofs,
        std::slice::from_ref(&c6),
        BfvPreset::InsecureDkg64,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ThresholdDecryptionProofs,
        &[],
        BfvPreset::InsecureDkg64,
    ));

    let share_bundle = signed_share_bundle(&s, &e3, 3);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &share_bundle,
        BfvPreset::InsecureDkg64,
    ));
    let mut duplicate_c2a = share_bundle.clone();
    duplicate_c2a.insert(1, duplicate_c2a[0].clone());
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &duplicate_c2a,
        BfvPreset::InsecureDkg64,
    ));

    let secure_share_bundle = signed_share_bundle(&s, &e3, 3);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &secure_share_bundle,
        BfvPreset::SecureThreshold8192,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &signed_share_bundle(&s, &e3, 2),
        BfvPreset::SecureThreshold8192,
    ));

    let c4_bundle = vec![
        signed_proof(&s, &e3, ProofType::C4aSkShareDecryption, 6),
        signed_proof(&s, &e3, ProofType::C4bESmShareDecryption, 7),
    ];
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::DecryptionProofs,
        &c4_bundle,
        BfvPreset::InsecureDkg64,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::DecryptionProofs,
        &c4_bundle[1..],
        BfvPreset::InsecureDkg64,
    ));
    let mut extra_c4b = c4_bundle.clone();
    extra_c4b.push(c4_bundle[1].clone());
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::DecryptionProofs,
        &extra_c4b,
        BfvPreset::InsecureDkg64,
    ));
    let mut wrong_c4_tail = c4_bundle.clone();
    wrong_c4_tail.push(c6);
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::DecryptionProofs,
        &wrong_c4_tail,
        BfvPreset::InsecureDkg64,
    ));
}

#[test]
fn share_shape_uses_threshold_secret_rows_when_dispatch_carries_dkg_preset() {
    let s = signer();
    let e3 = e3();

    // Production dispatch carries the share-encryption (DKG) preset, but C3 requests are
    // generated from rows of the paired threshold-parameter Shamir secret.
    let insecure_production_bundle = signed_share_bundle(&s, &e3, 3);
    assert_eq!(BfvPreset::InsecureDkg64.metadata().num_moduli, 2);
    assert_eq!(BfvPreset::InsecureThreshold64.metadata().num_moduli, 3);
    assert!(ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &insecure_production_bundle,
        BfvPreset::InsecureDkg64,
    ));
    assert!(!ShareVerifier::has_canonical_proof_shape(
        &VerificationKind::ShareProofs,
        &signed_share_bundle(&s, &e3, 2),
        BfvPreset::InsecureDkg64,
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
        &e3.to_string(),
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&committee),
        BfvPreset::InsecureDkg64,
        CiphernodesCommitteeSize::Minimum,
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
        &e3.to_string(),
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&committee),
        BfvPreset::InsecureDkg64,
        CiphernodesCommitteeSize::Minimum,
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
        &e3.to_string(),
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&committee),
        BfvPreset::InsecureDkg64,
        CiphernodesCommitteeSize::Minimum,
    );
    assert!(conflict.ecdsa_passed_parties.is_empty());
    assert_eq!(conflict.ecdsa_dishonest, HashSet::from([0]));
    assert!(conflict.failures.is_empty());
}
