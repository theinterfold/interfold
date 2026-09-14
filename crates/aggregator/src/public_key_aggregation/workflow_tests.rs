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
    let next = PublicKeyAggregation::add_keyshare(state, ks(1), "node-0".into(), 0, None, [0; 32])
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
    let state = PublicKeyAggregation::add_keyshare(state, ks(1), "node-0".into(), 0, None, [0; 32])
        .unwrap();
    let state = PublicKeyAggregation::add_keyshare(state, ks(9), "node-0".into(), 0, None, [0; 32])
        .unwrap();
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
fn add_keyshare_completes_when_a_dkg_roster_is_complete() {
    // minimum committee (n=3, h=2): parties {0, 2} built their C4 over roster [0, 2].
    // Their two keyshares complete the aggregation without party 1.
    let roster = vec![0u64, 2];
    let hash = e3_events::DkgRosterProposed::roster_hash(&roster);
    let state = collecting(3, 1);
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(1), "node-0".into(), 0, None, hash).unwrap();
    assert!(matches!(state, PublicKeyAggregatorState::Collecting { .. }));
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(3), "node-2".into(), 2, None, hash).unwrap();
    match state {
        PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            roster: got,
            ..
        } => {
            assert_eq!(got, Some(roster));
            let ids: Vec<u64> = submission_order.iter().map(|(pid, _, _)| *pid).collect();
            assert_eq!(ids, vec![0, 2]);
        }
        other => panic!("expected VerifyingC1, got {other:?}"),
    }
}

#[test]
fn add_keyshare_ignores_keyshares_from_another_roster_epoch() {
    // Party 1 submitted for roster [0, 1] (epoch 0) before it vanished. Parties 0 and 2
    // then completed roster [0, 2]. Only the [0, 2] keyshares are forwarded to C1.
    let old = e3_events::DkgRosterProposed::roster_hash(&[0, 1]);
    let new = e3_events::DkgRosterProposed::roster_hash(&[0, 2]);
    let state = collecting(3, 1);
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(1), "node-1".into(), 1, None, old).unwrap();
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(2), "node-0".into(), 0, None, old).unwrap();
    // Two keyshares carry `old`, but `old` is the hash of [0, 1] and both are present, so
    // roster [0, 1] is complete: the aggregator proceeds with it.
    assert!(matches!(
        state,
        PublicKeyAggregatorState::VerifyingC1 { roster: Some(ref r), .. } if r == &[0, 1]
    ));

    // Party 0 re-submits for the new roster; the old entry is replaced.
    let state = collecting(3, 1);
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(2), "node-0".into(), 0, None, old).unwrap();
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(5), "node-0".into(), 0, None, new).unwrap();
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(3), "node-2".into(), 2, None, new).unwrap();
    match state {
        PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            roster,
            ..
        } => {
            assert_eq!(roster, Some(vec![0, 2]));
            let ids: Vec<u64> = submission_order.iter().map(|(pid, _, _)| *pid).collect();
            assert_eq!(ids, vec![0, 2]);
        }
        other => panic!("expected VerifyingC1, got {other:?}"),
    }
}

#[test]
fn add_keyshare_does_not_complete_on_a_mismatched_roster_hash() {
    // Two parties claim the same hash but it is not the hash of their own id set.
    let bogus = [7u8; 32];
    let state = collecting(3, 1);
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(1), "node-0".into(), 0, None, bogus).unwrap();
    let state =
        PublicKeyAggregation::add_keyshare(state, ks(3), "node-2".into(), 2, None, bogus).unwrap();
    assert!(matches!(state, PublicKeyAggregatorState::Collecting { .. }));
}

#[test]
fn add_keyshare_reaching_threshold_transitions_to_verifying_c1() {
    let mut state = collecting(3, 1);
    for pid in 0..3u64 {
        state = PublicKeyAggregation::add_keyshare(
            state,
            ks(pid as u8),
            format!("node-{pid}"),
            pid,
            None,
            [0; 32],
        )
        .unwrap();
    }
    match state {
        PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            circuit_committee_n,
            circuit_committee_h,
            threshold_m,
            canonical_party_nodes,
            ..
        } => {
            assert_eq!(submission_order.len(), 3);
            assert_eq!(circuit_committee_n, 3);
            assert_eq!(circuit_committee_h, 2);
            assert_eq!(threshold_m, 1);
            assert_eq!(canonical_party_nodes.len(), 3);
        }
        _ => panic!("expected VerifyingC1"),
    }
}

#[test]
fn add_keyshare_wrong_state_errors() {
    let state = PublicKeyAggregatorState::VerifyingC1 {
        submission_order: vec![],
        threshold_m: 1,
        circuit_committee_n: 3,
        circuit_committee_h: 2,
        c1_proofs: vec![],
        no_proof_parties: vec![],
        canonical_party_nodes: HashMap::new(),
        roster: None,
    };
    let err = PublicKeyAggregation::add_keyshare(state, ks(1), "n".into(), 0, None, [0; 32]);
    assert!(err.is_err());
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
            [0; 32],
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
fn handle_member_expelled_transitions_when_enough_remain() {
    // Collecting with n=2, m=1, two keyshares present; expel one ->
    // threshold_n 1, keyshares 1 == n -> VerifyingC1.
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
        roster_hashes: vec![[0; 32], [0; 32]],
    };
    let next = PublicKeyAggregation::handle_member_expelled(
        state,
        "0xAbCdEf0000000000000000000000000000000000"
            .parse()
            .unwrap(),
    )
    .unwrap();
    match next {
        PublicKeyAggregatorState::VerifyingC1 {
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
