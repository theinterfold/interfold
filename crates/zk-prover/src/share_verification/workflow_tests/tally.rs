// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[test]
fn prepare_rejects_ambiguous_committee_where_one_signer_owns_multiple_slots() {
    let s = signer();
    let e3 = e3();
    let parties = vec![
        PartyProofsToVerify {
            sender_party_id: 0,
            signed_proofs: vec![signed_proof(&s, &e3, ProofType::C1PkGeneration, 1)],
        },
        PartyProofsToVerify {
            sender_party_id: 1,
            signed_proofs: vec![signed_proof(&s, &e3, ProofType::C1PkGeneration, 2)],
        },
    ];
    let ambiguous_committee = [s.address(), s.address(), signer().address()];

    let outcome = ShareVerifier::validate_and_prepare(
        &parties,
        &e3,
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&ambiguous_committee),
        BfvPreset::InsecureDkg512,
        CiphernodesCommitteeSize::Minimum,
        None,
    );

    assert!(outcome.ecdsa_passed_parties.is_empty());
    assert_eq!(outcome.ecdsa_dishonest, HashSet::from([0, 1]));
    assert!(outcome.failures.is_empty());
}

#[test]
fn prepare_rejects_committee_with_wrong_circuit_dimension() {
    let s = signer();
    let e3 = e3();
    let parties = [PartyProofsToVerify {
        sender_party_id: 0,
        signed_proofs: vec![signed_proof(&s, &e3, ProofType::C1PkGeneration, 1)],
    }];
    let undersized_committee = [s.address()];

    let outcome = ShareVerifier::validate_and_prepare(
        &parties,
        &e3,
        &VerificationKind::PkGenerationProofs,
        "C1",
        Some(&undersized_committee),
        BfvPreset::InsecureDkg512,
        CiphernodesCommitteeSize::Minimum,
        None,
    );

    assert!(outcome.ecdsa_passed_parties.is_empty());
    assert_eq!(outcome.ecdsa_dishonest, HashSet::from([0]));
    assert!(outcome.failures.is_empty());
}

#[test]
fn filter_consistent_drops_inconsistent_and_returns_ids() {
    let proofs = vec![1u64, 2, 3];
    let inconsistent: BTreeSet<u64> = [2].into_iter().collect();
    let (passed, ids) = filter_consistent(proofs, &inconsistent, |p| *p).expect("some");
    assert_eq!(passed, vec![1, 3]);
    assert!(ids.contains(&1) && ids.contains(&3) && !ids.contains(&2));
}

#[test]
fn filter_consistent_returns_none_when_all_filtered() {
    let proofs = vec![1u64, 2];
    let inconsistent: BTreeSet<u64> = [1, 2].into_iter().collect();
    assert!(filter_consistent(proofs, &inconsistent, |p| *p).is_none());
}

#[test]
fn tally_marks_missing_dispatched_party_dishonest() {
    let dispatched: HashSet<u64> = [1, 2].into_iter().collect();
    let ecdsa: HashSet<u64> = HashSet::new();
    // No ZK results at all → both dispatched parties are missing → dishonest.
    let out = ShareVerifier::tally_zk_results(BTreeSet::new(), &ecdsa, &dispatched, &[]);
    assert!(out.dishonest.contains(&1));
    assert!(out.dishonest.contains(&2));
    assert!(out.emissions.is_empty());
}

#[test]
fn tally_collapses_identical_result_replay() {
    let dispatched = HashSet::from([1]);
    let result = PartyVerificationResult {
        sender_party_id: 1,
        all_verified: true,
        failed_signed_payload: None,
        recovered_address: None,
    };

    let out = ShareVerifier::tally_zk_results(
        BTreeSet::new(),
        &HashSet::new(),
        &dispatched,
        &[result.clone(), result],
    );

    assert!(out.dishonest.is_empty());
    assert_eq!(out.emissions.len(), 1);
    assert!(matches!(
        out.emissions[0],
        ZkPartyEmission::Passed { party_id: 1 }
    ));
}

#[test]
fn tally_rejects_conflicting_results_for_one_party() {
    let dispatched = HashSet::from([1]);
    let passed = PartyVerificationResult {
        sender_party_id: 1,
        all_verified: true,
        failed_signed_payload: None,
        recovered_address: None,
    };
    let failed = PartyVerificationResult {
        all_verified: false,
        ..passed.clone()
    };

    let out = ShareVerifier::tally_zk_results(
        BTreeSet::new(),
        &HashSet::new(),
        &dispatched,
        &[passed, failed],
    );

    assert_eq!(out.dishonest, BTreeSet::from([1]));
    assert!(out.emissions.is_empty());
}
