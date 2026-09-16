// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

fn ks(byte: u8) -> ArcBytes {
    ArcBytes::from_bytes(&[byte])
}

fn collecting(threshold_n: usize, threshold_m: usize) -> PublicKeyAggregatorState {
    let canonical_party_nodes = (0..threshold_n as u64)
        .map(|party_id| (party_id, format!("node-{party_id}")))
        .collect();
    PublicKeyAggregatorState::init(
        threshold_n,
        threshold_m,
        Seed([0u8; 32]),
        canonical_party_nodes,
    )
}

#[test]
fn add_keyshare_below_threshold_stays_collecting() {
    // minimum committee maps (m=1, n=3) -> needs 3 parties.
    let state = collecting(3, 1);
    let next = PublicKeyAggregation::add_keyshare(state, ks(1), "node-0".into(), 0, None, None)
        .expect("add ok");
    match next {
        PublicKeyAggregatorState::Collecting {
            submission_order, ..
        } => assert_eq!(submission_order.len(), 1),
        _ => panic!("expected Collecting"),
    }
}

#[test]
fn add_keyshare_duplicate_party_is_idempotent() {
    let state = collecting(3, 1);
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(1), "node-0".into(), 0, None, None).unwrap();
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(9), "node-0".into(), 0, None, None).unwrap();
    match state {
        PublicKeyAggregatorState::Collecting {
            submission_order,
            keyshares,
            ..
        } => {
            assert_eq!(submission_order.len(), 1, "duplicate party ignored");
            assert_eq!(keyshares.len(), 1);
        }
        _ => panic!("expected Collecting"),
    }
}

#[test]
fn add_keyshare_waits_for_the_accepted_roster() {
    let mut state = collecting(3, 1);
    for pid in 0..3u64 {
        state = PublicKeyAggregation::add_keyshare(
            state,
            ks(pid as u8),
            format!("node-{pid}"),
            pid,
            None,
            None,
        )
        .unwrap();
    }
    assert!(matches!(state, PublicKeyAggregatorState::Collecting { .. }));
    let state =
        PublicKeyAggregation::begin_selected_c1(state, Some(&BTreeSet::from([0, 2]))).unwrap();
    match state {
        PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            circuit_committee_n,
            circuit_committee_h,
            threshold_m,
            canonical_party_nodes,
            ..
        } => {
            assert_eq!(
                submission_order
                    .iter()
                    .map(|entry| entry.0)
                    .collect::<Vec<_>>(),
                vec![0, 2]
            );
            assert_eq!(circuit_committee_n, 3);
            assert_eq!(circuit_committee_h, 2);
            assert_eq!(threshold_m, 1);
            assert_eq!(canonical_party_nodes.len(), 3);
        }
        _ => panic!("expected VerifyingC1"),
    }
}

#[test]
fn an_unselected_keyshare_does_not_complete_c1_collection() {
    let roster = BTreeSet::from([1, 2]);
    let mut state = collecting(3, 1);
    for pid in [0, 1] {
        state = PublicKeyAggregation::add_keyshare(
            state,
            ks(pid as u8),
            format!("node-{pid}"),
            pid,
            None,
            Some(&roster),
        )
        .unwrap();
    }
    assert!(matches!(state, PublicKeyAggregatorState::Collecting { .. }));
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(2), "node-2".into(), 2, None, Some(&roster))
            .unwrap();
    match state {
        PublicKeyAggregatorState::VerifyingC1 {
            submission_order, ..
        } => {
            assert_eq!(
                submission_order
                    .iter()
                    .map(|entry| entry.0)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
        }
        _ => panic!("expected selected C1 proofs"),
    }
}

#[test]
fn late_keyshare_does_not_change_selected_c1_collection() {
    let state = PublicKeyAggregatorState::VerifyingC1 {
        submission_order: vec![(0, "node-0".into(), ks(1)), (2, "node-2".into(), ks(2))],
        threshold_m: 1,
        circuit_committee_n: 3,
        circuit_committee_h: 2,
        c1_proofs: vec![None, None],
        no_proof_parties: vec![],
        canonical_party_nodes: HashMap::new(),
    };
    let next = PublicKeyAggregation::add_keyshare(state, ks(3), "node-1".into(), 1, None, None)
        .expect("late keyshare is harmless");
    match next {
        PublicKeyAggregatorState::VerifyingC1 {
            submission_order, ..
        } => assert_eq!(
            submission_order
                .iter()
                .map(|entry| entry.0)
                .collect::<Vec<_>>(),
            vec![0, 2]
        ),
        _ => panic!("late keyshare changed the aggregation phase"),
    }
}

#[test]
fn plan_c1_dispatch_splits_proofs_and_missing() {
    let submission_order = vec![
        (0u64, "node-0".to_string(), ks(1)),
        (1u64, "node-1".to_string(), ks(2)),
    ];
    // party 0 has no proof, party 1 has one
    let c1_proofs: Vec<Option<SignedProofPayload>> = vec![None, None];
    let plan = PublicKeyAggregation::plan_c1_dispatch(&submission_order, &c1_proofs);
    // both None -> both treated as no-proof
    assert_eq!(plan.no_proof_parties, vec![0, 1]);
    assert!(plan.party_proofs.is_empty());
}

#[test]
fn select_honest_set_fails_below_circuit_h() {
    let e3_id = E3id::new("1", 1);
    let honest = vec![(0u64, "n0".to_string(), ks(1), None)];
    let sel = PublicKeyAggregation::select_honest_set(&e3_id, honest, &BTreeSet::new(), 3, 1, 1);
    assert!(matches!(sel, HonestSelection::Fail));
}

#[test]
fn select_honest_set_caps_to_circuit_h_and_sorts() {
    let e3_id = E3id::new("1", 1);
    // 4 honest, circuit_h = 3 -> cap to lowest-3 party_ids {0,1,2}, sorted ascending.
    let honest = vec![
        (3u64, "n3".to_string(), ks(4), None),
        (1u64, "n1".to_string(), ks(2), None),
        (0u64, "n0".to_string(), ks(1), None),
        (2u64, "n2".to_string(), ks(3), None),
    ];
    let sel = PublicKeyAggregation::select_honest_set(&e3_id, honest, &BTreeSet::new(), 3, 1, 4);
    match sel {
        HonestSelection::Proceed {
            honest_entries,
            honest_party_ids,
        } => {
            let ids: Vec<u64> = honest_entries.iter().map(|(p, _, _, _)| *p).collect();
            assert_eq!(ids, vec![0, 1, 2]);
            assert_eq!(honest_party_ids, BTreeSet::from([0, 1, 2]));
        }
        HonestSelection::Fail => panic!("expected Proceed"),
    }
}

#[test]
fn select_honest_set_fails_when_at_or_below_threshold_m() {
    let e3_id = E3id::new("1", 1);
    // 3 honest, circuit_h = 3 but threshold_m = 3 -> len <= m -> Fail.
    let honest = vec![
        (0u64, "n0".to_string(), ks(1), None),
        (1u64, "n1".to_string(), ks(2), None),
        (2u64, "n2".to_string(), ks(3), None),
    ];
    let sel = PublicKeyAggregation::select_honest_set(&e3_id, honest, &BTreeSet::new(), 3, 3, 3);
    assert!(matches!(sel, HonestSelection::Fail));
}

#[test]
fn handle_member_expelled_removes_and_reduces_threshold() {
    let mut state = collecting(3, 1);
    let nodes = [
        "0xabcdef0000000000000000000000000000000000",
        "0x2222222222222222222222222222222222222222",
    ];
    for (pid, node) in nodes.into_iter().enumerate() {
        state = PublicKeyAggregation::add_keyshare(
            state,
            ks(pid as u8),
            node.to_owned(),
            pid as u64,
            None,
            None,
        )
        .unwrap();
    }
    // expel node-0; threshold_n 3 -> 2, keyshares now 1 (< 2) -> stays Collecting
    let state = PublicKeyAggregation::handle_member_expelled(
        state,
        "0xAbCdEf0000000000000000000000000000000000"
            .parse()
            .unwrap(),
    )
    .unwrap();
    match state {
        PublicKeyAggregatorState::Collecting {
            threshold_n,
            submission_order,
            nodes,
            ..
        } => {
            assert_eq!(threshold_n, 2);
            assert_eq!(submission_order.len(), 1);
            assert!(!nodes.contains(&"0xabcdef0000000000000000000000000000000000".to_string()));
        }
        _ => panic!("expected Collecting"),
    }
}

#[test]
fn handle_member_expelled_does_not_start_c1_without_a_roster() {
    let state = PublicKeyAggregatorState::Collecting {
        threshold_n: 2,
        threshold_m: 1,
        circuit_committee_n: 3,
        circuit_committee_h: 2,
        keyshares: OrderedSet::from(vec![ks(10), ks(11)]),
        c1_proofs: vec![None, None],
        seed: Seed([0u8; 32]),
        nodes: OrderedSet::from(vec![
            "0xabcdef0000000000000000000000000000000000".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ]),
        submission_order: vec![
            (
                0,
                "0xabcdef0000000000000000000000000000000000".to_string(),
                ks(10),
            ),
            (
                1,
                "0x2222222222222222222222222222222222222222".to_string(),
                ks(11),
            ),
        ],
        canonical_party_nodes: HashMap::from([
            (0, "0xabcdef0000000000000000000000000000000000".to_string()),
            (1, "0x2222222222222222222222222222222222222222".to_string()),
            (2, "0x3333333333333333333333333333333333333333".to_string()),
        ]),
    };
    let next = PublicKeyAggregation::handle_member_expelled(
        state,
        "0xAbCdEf0000000000000000000000000000000000"
            .parse()
            .unwrap(),
    )
    .unwrap();
    match next {
        PublicKeyAggregatorState::Collecting {
            circuit_committee_n,
            circuit_committee_h,
            submission_order,
            canonical_party_nodes,
            ..
        } => {
            assert_eq!(circuit_committee_n, 3);
            assert_eq!(circuit_committee_h, 2);
            assert_eq!(submission_order.len(), 1);
            assert_eq!(canonical_party_nodes.len(), 3);
        }
        _ => panic!("expected VerifyingC1"),
    }
}
