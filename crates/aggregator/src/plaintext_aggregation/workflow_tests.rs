// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_events::{E3Failed, E3Stage, EventContext, FailureReason, InterfoldEventData, Unsequenced};

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

fn timeout_context() -> EventContext<Sequenced> {
    EventContext::<Unsequenced>::from(InterfoldEventData::E3Failed(E3Failed {
        e3_id: e3_events::E3id::new("1", 1),
        failed_at_stage: E3Stage::CiphertextReady,
        reason: FailureReason::None,
    }))
    .sequence(0)
}

fn collecting(threshold_m: u64, threshold_n: u64) -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregatorState::init(
        threshold_m,
        threshold_n,
        Seed([0u8; 32]),
        vec![ab(1)],
        ab(2),
        u64::MAX,
        timeout_context(),
    )
}

#[test]
fn add_share_below_required_stays_collecting() {
    let state = collecting(1, 3);
    let next =
        ThresholdPlaintextAggregation::add_share(state, 0, vec![ab(10)], vec![c6_proof(10)], 3)
            .unwrap();
    match next {
        ThresholdPlaintextAggregatorState::Collecting(c) => {
            assert_eq!(c.shares.len(), 1);
            assert!(c.shares.contains_key(&0));
        }
        _ => panic!("expected Collecting"),
    }
}

#[test]
fn add_share_reaching_required_transitions_to_verifying_c6() {
    let mut state = collecting(1, 3);
    for pid in 0..3u64 {
        state = ThresholdPlaintextAggregation::add_share(
            state,
            pid,
            vec![ab(pid as u8)],
            vec![c6_proof(pid as u8)],
            3,
        )
        .unwrap();
    }
    match state {
        ThresholdPlaintextAggregatorState::VerifyingC6(v) => {
            assert_eq!(v.shares.len(), 3);
        }
        _ => panic!("expected VerifyingC6"),
    }
}

#[test]
fn add_share_wrong_state_errors() {
    let state = ThresholdPlaintextAggregatorState::VerifyingC6(VerifyingC6 {
        threshold_m: 1,
        threshold_n: 3,
        shares: BTreeMap::new(),
        c6_proofs: BTreeMap::new(),
        ciphertext_output: vec![ab(1)],
        params: ab(2),
    });
    let res = ThresholdPlaintextAggregation::add_share(state, 0, vec![ab(0)], vec![], 3);
    assert!(res.is_err());
}

#[test]
fn handle_member_expelled_removes_share_and_stays_collecting() {
    let mut state = collecting(1, 3);
    for pid in 0..2u64 {
        state = ThresholdPlaintextAggregation::add_share(
            state,
            pid,
            vec![ab(pid as u8)],
            vec![c6_proof(pid as u8)],
            3,
        )
        .unwrap();
    }
    // required_shares stays 3; remove party 0 -> 1 share left -> Collecting
    let next = ThresholdPlaintextAggregation::handle_member_expelled(state, 0, 3).unwrap();
    match next {
        ThresholdPlaintextAggregatorState::Collecting(c) => {
            assert_eq!(c.shares.len(), 1);
            assert!(!c.shares.contains_key(&0));
        }
        _ => panic!("expected Collecting"),
    }
}

#[test]
fn handle_member_expelled_transitions_when_enough_remain() {
    let mut state = collecting(1, 3);
    for pid in 0..3u64 {
        state = ThresholdPlaintextAggregation::add_share(
            state,
            pid,
            vec![ab(pid as u8)],
            vec![c6_proof(pid as u8)],
            3,
        )
        .unwrap();
    }
    // After 3 shares it's already VerifyingC6; rebuild a Collecting with 3 shares to
    // exercise the expulsion->VerifyingC6 path with required_shares lowered to 2.
    let state = ThresholdPlaintextAggregatorState::Collecting(Collecting {
        threshold_m: 1,
        threshold_n: 3,
        shares: BTreeMap::from([(0, vec![ab(0)]), (1, vec![ab(1)]), (2, vec![ab(2)])]),
        c6_proofs: BTreeMap::new(),
        seed: Seed([0u8; 32]),
        ciphertext_output: vec![ab(1)],
        params: ab(2),
        deadline_unix_ms: u64::MAX,
        timeout_context: timeout_context(),
    });
    let _ = state;
    let state = ThresholdPlaintextAggregatorState::Collecting(Collecting {
        threshold_m: 1,
        threshold_n: 3,
        shares: BTreeMap::from([(0, vec![ab(0)]), (1, vec![ab(1)]), (2, vec![ab(2)])]),
        c6_proofs: BTreeMap::new(),
        seed: Seed([0u8; 32]),
        ciphertext_output: vec![ab(1)],
        params: ab(2),
        deadline_unix_ms: u64::MAX,
        timeout_context: timeout_context(),
    });
    // remove party 0 -> 2 shares remain, required_shares=2 -> VerifyingC6
    let next = ThresholdPlaintextAggregation::handle_member_expelled(state, 0, 2).unwrap();
    match next {
        ThresholdPlaintextAggregatorState::VerifyingC6(v) => {
            assert_eq!(v.shares.len(), 2);
        }
        _ => panic!("expected VerifyingC6"),
    }
}

#[test]
fn handle_member_expelled_wrong_state_is_noop() {
    let state = ThresholdPlaintextAggregatorState::Complete(Complete {
        decrypted: vec![ab(1)],
        shares: vec![],
    });
    let next = ThresholdPlaintextAggregation::handle_member_expelled(state, 0, 3).unwrap();
    assert!(matches!(
        next,
        ThresholdPlaintextAggregatorState::Complete(_)
    ));
}

#[test]
fn add_share_rejects_c6_share_or_proof_count_mismatch() {
    let missing_share =
        ThresholdPlaintextAggregation::add_share(collecting(1, 3), 0, vec![], vec![c6_proof(1)], 3)
            .expect_err("one decryption share is required for one ciphertext");
    assert!(missing_share.to_string().contains("decryption shares"));

    let missing_proof =
        ThresholdPlaintextAggregation::add_share(collecting(1, 3), 0, vec![ab(1)], vec![], 3)
            .expect_err("one C6 proof is required for one ciphertext");
    assert!(missing_proof.to_string().contains("C6 proofs"));
}

#[test]
fn plan_c6_dispatch_emits_party_proofs_in_party_order() {
    let mut c6: BTreeMap<u64, Vec<SignedProofPayload>> = BTreeMap::new();
    c6.insert(2, vec![]);
    c6.insert(0, vec![]);
    c6.insert(1, vec![]);
    let plan = ThresholdPlaintextAggregation::plan_c6_dispatch(c6);
    let ids: Vec<u64> = plan.iter().map(|p| p.sender_party_id).collect();
    assert_eq!(ids, vec![0, 1, 2]);
}
