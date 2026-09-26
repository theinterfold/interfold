// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[test]
fn ecdsa_passes_for_well_formed_proof() {
    let s = signer();
    let e3 = e3();
    let p = signed_pk(&s, &e3, false);
    let res = ShareVerifier::ecdsa_validate_signed_proofs(
        7,
        &[p],
        &e3.to_string(),
        "C1",
        Some(s.address()),
    );
    assert!(res.passed);
    assert!(res.failed_payload.is_none());
}

#[test]
fn ecdsa_fails_on_wrong_e3_id() {
    let s = signer();
    let p = signed_pk(&s, &e3(), false);
    let res =
        ShareVerifier::ecdsa_validate_signed_proofs(7, &[p], "999/0", "C1", Some(s.address()));
    assert!(!res.passed);
    assert!(res.failed_payload.is_some());
}

#[test]
fn ecdsa_fails_on_circuit_mismatch() {
    let s = signer();
    let e3 = e3();
    let p = signed_pk(&s, &e3, true);
    let res = ShareVerifier::ecdsa_validate_signed_proofs(
        7,
        &[p],
        &e3.to_string(),
        "C1",
        Some(s.address()),
    );
    assert!(!res.passed);
}

#[test]
fn ecdsa_fails_on_inconsistent_signer() {
    let s1 = signer();
    let s2 = signer();
    let e3 = e3();
    let p1 = signed_pk(&s1, &e3, false);
    let p2 = signed_pk(&s2, &e3, false);
    let res = ShareVerifier::ecdsa_validate_signed_proofs(
        7,
        &[p1, p2],
        &e3.to_string(),
        "C1",
        Some(s1.address()),
    );
    assert!(!res.passed);
}

#[test]
fn ecdsa_fails_when_signer_does_not_own_party_slot() {
    let proof_signer = signer();
    let slot_owner = signer();
    let e3 = e3();
    let proof = signed_pk(&proof_signer, &e3, false);

    let result = ShareVerifier::ecdsa_validate_signed_proofs(
        1,
        &[proof],
        &e3.to_string(),
        "C1",
        Some(slot_owner.address()),
    );

    assert!(!result.passed);
    let (_, recovered) = result.failed_payload.expect("attributable mismatch");
    assert_eq!(recovered, Some(proof_signer.address()));
}

#[test]
fn ecdsa_fails_for_empty_bundle_or_missing_party_slot() {
    let e3 = e3();
    let owner = signer();
    let empty = ShareVerifier::ecdsa_validate_signed_proofs(
        0,
        &[],
        &e3.to_string(),
        "C1",
        Some(owner.address()),
    );
    assert!(!empty.passed);
    assert!(empty.failed_payload.is_none());

    let proof = signed_pk(&owner, &e3, false);
    let missing =
        ShareVerifier::ecdsa_validate_signed_proofs(3, &[proof], &e3.to_string(), "C1", None);
    assert!(!missing.passed);
}

#[test]
fn prepare_rejects_one_signer_relabelled_across_other_party_slots() {
    let first = signer();
    let second = signer();
    let third = signer();
    let e3 = e3();
    let parties = vec![
        PartyProofsToVerify {
            sender_party_id: 0,
            signed_proofs: vec![signed_pk(&first, &e3, false)],
        },
        PartyProofsToVerify {
            sender_party_id: 1,
            // A valid proof from party 0 cannot fill party 1's slot.
            signed_proofs: vec![signed_pk(&first, &e3, false)],
        },
        PartyProofsToVerify {
            sender_party_id: 2,
            // Nor can the same signer fill any other canonical slot.
            signed_proofs: vec![signed_pk(&first, &e3, false)],
        },
    ];
    let committee = [first.address(), second.address(), third.address()];

    let outcome = ShareVerifier::validate_and_prepare(
        &parties,
        &e3,
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&committee),
        BfvPreset::InsecureDkg,
        CiphernodesCommitteeSize::Minimum,
        None,
    );

    assert_eq!(outcome.ecdsa_passed_parties.len(), 1);
    assert_eq!(outcome.ecdsa_passed_parties[0].sender_party_id, 0);
    assert_eq!(outcome.ecdsa_dishonest, HashSet::from([1, 2]));
}
