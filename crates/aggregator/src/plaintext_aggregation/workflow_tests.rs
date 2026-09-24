// SPDX-License-Identifier: LGPL-3.0-only

use super::*;

fn ab(b: u8) -> ArcBytes {
    ArcBytes::from_bytes(&[b])
}

fn c6_proof(marker: u8) -> SignedProofPayload {
    SignedProofPayload {
        payload: e3_events::ProofPayload {
            e3_id: e3_events::E3id::new("1", 1),
            proof_type: e3_events::ProofType::C6ThresholdShareDecryption,
            proof: Proof::new(
                CircuitName::ThresholdShareDecryption,
                ab(marker),
                ab(marker),
            ),
        },
        signature: ab(marker),
    }
}

fn collecting(t: u64, n: u64) -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregatorState::init(t, n, Seed([0u8; 32]), vec![ab(1)], ab(2))
}

fn add(state: ThresholdPlaintextAggregatorState, party: u64) -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregation::add_share(
        state,
        party,
        vec![ab(party as u8)],
        vec![c6_proof(party as u8)],
    )
    .unwrap()
}

#[test]
fn small_starts_verification_with_up_to_four_missing_roster_members() {
    for missing in 0..=5 {
        let mut state = collecting(9, 19);
        // The roster is not a prefix of the selected committee.
        for party in 5..19 - missing {
            state = add(state, party);
        }
        if missing <= 4 {
            let ThresholdPlaintextAggregatorState::VerifyingC6(batch) = state else {
                panic!("Small must progress with {missing} missing roster members");
            };
            assert_eq!(batch.shares.len(), 10);
            assert_eq!(batch.queued_shares.len(), (4 - missing) as usize);
        } else {
            assert!(matches!(
                state,
                ThresholdPlaintextAggregatorState::Collecting(_)
            ));
        }
    }
}

#[test]
fn duplicate_shares_do_not_count_or_replace_an_in_flight_batch() {
    let state = add(add(collecting(1, 3), 0), 0);
    let ThresholdPlaintextAggregatorState::Collecting(ref c) = state else {
        panic!()
    };
    assert_eq!(c.shares.len(), 1);
    let state = add(add(add(state, 1), 2), 2);
    let ThresholdPlaintextAggregatorState::VerifyingC6(batch) = state else {
        panic!()
    };
    assert_eq!(batch.shares.keys().copied().collect::<Vec<_>>(), [0, 1]);
    assert_eq!(batch.queued_shares.keys().copied().collect::<Vec<_>>(), [2]);
}

#[test]
fn rejected_share_uses_queued_replacement_after_restart() {
    let state = add(add(add(collecting(1, 5), 0), 2), 4);
    let restored = bincode::deserialize(&bincode::serialize(&state).unwrap()).unwrap();
    let ThresholdPlaintextAggregatorState::VerifyingC6(batch) = restored else {
        panic!()
    };
    let next = ThresholdPlaintextAggregation::retry_collection(batch, BTreeSet::from([0]));
    let ThresholdPlaintextAggregatorState::VerifyingC6(batch) = next else {
        panic!()
    };
    assert_eq!(batch.shares.keys().copied().collect::<Vec<_>>(), [2, 4]);
    assert_eq!(batch.c6_proofs.keys().copied().collect::<Vec<_>>(), [2, 4]);
    assert!(batch.rejected_parties.contains(&0));
}

#[test]
fn rejected_party_cannot_reenter_while_waiting_for_replacement() {
    let state = add(add(collecting(1, 5), 0), 2);
    let ThresholdPlaintextAggregatorState::VerifyingC6(batch) = state else {
        panic!()
    };
    let state = ThresholdPlaintextAggregation::retry_collection(batch, BTreeSet::from([0]));
    let state = add(state, 0);
    let ThresholdPlaintextAggregatorState::Collecting(ref c) = state else {
        panic!()
    };
    assert_eq!(c.shares.keys().copied().collect::<Vec<_>>(), [2]);
    let state = add(state, 4);
    assert!(matches!(
        state,
        ThresholdPlaintextAggregatorState::VerifyingC6(_)
    ));
}

#[test]
fn expulsion_does_not_change_in_flight_batch_identity() {
    let state = add(add(add(collecting(1, 5), 0), 1), 2);
    let state = ThresholdPlaintextAggregation::handle_member_expelled(state, 0).unwrap();
    let state = ThresholdPlaintextAggregation::handle_member_expelled(state, 2).unwrap();
    let state = add(state, 2);
    let ThresholdPlaintextAggregatorState::VerifyingC6(batch) = state else {
        panic!()
    };
    assert_eq!(batch.shares.keys().copied().collect::<Vec<_>>(), [0, 1]);
    assert_eq!(batch.c6_proofs.keys().copied().collect::<Vec<_>>(), [0, 1]);
    assert!(batch.queued_shares.is_empty());
    let next = ThresholdPlaintextAggregation::retry_collection(batch, BTreeSet::new());
    let ThresholdPlaintextAggregatorState::Collecting(c) = next else {
        panic!()
    };
    assert_eq!(c.shares.keys().copied().collect::<Vec<_>>(), [1]);
    assert_eq!(c.rejected_parties, BTreeSet::from([0, 2]));
}

#[test]
fn expulsion_while_collecting_removes_share_without_lowering_threshold() {
    let state = add(add(collecting(2, 5), 0), 1);
    let state = ThresholdPlaintextAggregation::handle_member_expelled(state, 0).unwrap();
    let ThresholdPlaintextAggregatorState::Collecting(c) = state else {
        panic!()
    };
    assert_eq!(c.shares.len(), 1);
    assert_eq!(c.threshold_m, 2);
    assert!(!c.c6_proofs.contains_key(&0));
}

#[test]
fn closed_collection_ignores_late_shares_and_expulsions() {
    let state = ThresholdPlaintextAggregatorState::Complete(Complete {
        decrypted: vec![ab(1)],
        shares: vec![],
    });
    let state = add(state, 0);
    let state = ThresholdPlaintextAggregation::handle_member_expelled(state, 0).unwrap();
    assert!(matches!(
        state,
        ThresholdPlaintextAggregatorState::Complete(_)
    ));
}

#[test]
fn add_share_rejects_c6_share_or_proof_count_mismatch() {
    let missing_share =
        ThresholdPlaintextAggregation::add_share(collecting(1, 3), 0, vec![], vec![c6_proof(1)])
            .expect_err("one decryption share is required for one ciphertext");
    assert!(missing_share.to_string().contains("decryption shares"));
    let missing_proof =
        ThresholdPlaintextAggregation::add_share(collecting(1, 3), 0, vec![ab(1)], vec![])
            .expect_err("one C6 proof is required for one ciphertext");
    assert!(missing_proof.to_string().contains("C6 proofs"));
}

#[test]
fn plan_c6_dispatch_emits_party_proofs_in_party_order() {
    let plan = ThresholdPlaintextAggregation::plan_c6_dispatch(BTreeMap::from([
        (2, vec![]),
        (0, vec![]),
        (1, vec![]),
    ]));
    assert_eq!(
        plan.iter().map(|p| p.sender_party_id).collect::<Vec<_>>(),
        [0, 1, 2]
    );
}
