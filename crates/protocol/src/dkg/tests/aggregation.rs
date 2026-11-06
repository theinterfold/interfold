// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{
    dkg::{DkgWork, FoldAttestation, KeyPublication},
    node::{Job, Submission, Transaction, Work},
    proof::ProofType,
};
use alloy_primitives::B256;

const KEY_BUDGET: u64 = 40 * 60;

fn jobs(effects: &[Effect]) -> Vec<&DkgWork> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Run(Job {
                work: Work::Dkg(work),
                ..
            }) => Some(work),
            _ => None,
        })
        .collect()
}

fn keyshare_checks(effects: &[Effect]) -> Vec<Address> {
    let checks = jobs(effects).into_iter().filter_map(|work| match work {
        DkgWork::CheckKeyshare { member, .. } => Some(*member),
        _ => None,
    });
    checks.collect()
}

fn aggregations(effects: &[Effect]) -> usize {
    let aggregations = jobs(effects)
        .into_iter()
        .filter(|work| matches!(work, DkgWork::AggregateKey { .. }));
    aggregations.count()
}

fn publications(effects: &[Effect]) -> Vec<&KeyPublication> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Submit(Submission {
                transaction: Transaction::PublishCommittee(publication),
                ..
            }) => Some(publication),
            _ => None,
        })
        .collect()
}

/// The first member, the key aggregator, after it sent its keyshare: the second member's C4
/// passed.
fn first_with_keyshare() -> (Node, Vec<Effect>) {
    let [_, second, _] = ordered();
    let mut node = first_with_decryption_key();
    node.step(NOW, decryption_key(e3(1), second, second));
    let effects = node.step(NOW, decryption_key_checked(e3(1), second, true));
    (node, effects)
}

/// The first member with every roster keyshare checked and its own fold sent.
fn first_with_checked_keyshares() -> Node {
    let [first, second, _] = ordered();
    let (mut node, _) = first_with_keyshare();
    node.step(NOW, keyshare(e3(1), second, second));
    node.step(NOW, keyshare_checked(e3(1), first, true));
    node.step(NOW, keyshare_checked(e3(1), second, true));
    let effects = node.step(NOW, proofs_folded(e3(1), node_fold(0xf0)));
    node.step(NOW, sign(first, signing(&effects)));
    node
}

#[test]
fn a_roster_member_folds_all_its_dkg_proofs_and_attests_the_fold_for_its_slot() {
    let [first, ..] = ordered();
    let (mut node, _) = first_with_roster();
    let effects = node.step(NOW, decryption_key_made(e3(1), own_decryption_key(0xd4)));
    let effects = node.step(NOW, sign(first, signing(&effects)));
    let folds: Vec<Vec<ProofType>> = jobs(&effects)
        .into_iter()
        .filter_map(|work| match work {
            DkgWork::FoldProofs { proofs } => Some(proofs.iter().map(|(t, _)| *t).collect()),
            _ => None,
        })
        .collect();
    let [types] = folds.as_slice() else {
        panic!("one fold job, got {effects:?}");
    };
    use ProofType::*;
    let c3_for_two_members = 2 * (3 + 3);
    assert_eq!(types.len(), 4 + c3_for_two_members + 2);
    assert_eq!(
        types[..4],
        [
            C0PkBfv,
            C1PkGeneration,
            C2aSkShareComputation,
            C2bESmShareComputation
        ]
    );
    assert_eq!(
        types[types.len() - 2..],
        [C4aSkShareDecryption, C4bESmShareDecryption]
    );

    let effects = node.step(NOW, proofs_folded(e3(1), node_fold(0xf0)));
    let attestation = FoldAttestation {
        e3: e3(1),
        verifier: ATTESTATION.verifier,
        registry: ATTESTATION.registry,
        party_id: 0,
        sk_agg_commit: node_fold(0xf0).sk_agg_commit,
        esm_agg_commit: node_fold(0xf0).esm_agg_commit,
    };
    assert_eq!(signing(&effects).hashes, vec![attestation.signing_hash()]);
}

#[test]
fn the_aggregator_checks_every_roster_keyshare_once_all_are_in() {
    let [first, second, _] = ordered();
    let (mut node, effects) = first_with_keyshare();
    assert!(keyshare_checks(&effects).is_empty());
    assert!(node.step(NOW, keyshare(e3(1), second, first)).is_empty());
    let effects = node.step(NOW, keyshare(e3(1), second, second));
    assert_eq!(keyshare_checks(&effects), members(&[first, second]));
}

#[test]
fn the_aggregator_aggregates_once_every_c1_passed_and_every_fold_is_in() {
    let [_, second, _] = ordered();
    let mut node = first_with_checked_keyshares();
    let effects = node.step(NOW, fold(e3(1), second, 1, second));
    assert_eq!(aggregations(&effects), 1);
}

#[test]
fn a_fold_attested_for_another_slot_does_not_count() {
    let [_, second, _] = ordered();
    let mut node = first_with_checked_keyshares();
    assert_eq!(
        aggregations(&node.step(NOW, fold(e3(1), second, 2, second))),
        0
    );
}

#[test]
fn a_failed_c1_stops_the_aggregation() {
    let [first, second, _] = ordered();
    let (mut node, _) = first_with_keyshare();
    node.step(NOW, keyshare(e3(1), second, second));
    node.step(NOW, keyshare_checked(e3(1), first, true));
    node.step(NOW, keyshare_checked(e3(1), second, false));
    let effects = node.step(NOW, proofs_folded(e3(1), node_fold(0xf0)));
    node.step(NOW, sign(first, signing(&effects)));
    assert_eq!(
        aggregations(&node.step(NOW, fold(e3(1), second, 1, second))),
        0
    );
}

#[test]
fn the_aggregator_asks_the_chain_writer_to_publish_the_key_with_every_attestation() {
    let [_, second, _] = ordered();
    let mut node = first_with_checked_keyshares();
    node.step(NOW, fold(e3(1), second, 1, second));
    let effects = node.step(NOW, key_aggregated(e3(1), 0x5e));
    let [publication] = publications(&effects)[..] else {
        panic!("one publication, got {effects:?}");
    };
    assert_eq!(publication.commitment, B256::repeat_byte(!0x5e));
    let slots: Vec<u64> = publication
        .attestations
        .iter()
        .map(|a| a.party_id)
        .collect();
    assert_eq!(slots, vec![0, 1]);
}

#[test]
fn the_next_member_aggregates_when_the_aggregator_s_budget_runs_out() {
    let [first, second, third] = ordered();
    let mut node = verified_all(second);
    node.step(NOW, ready(first, &[first, second, third], second));
    node.step(NOW, roster(first, &[first, second], second));
    let effects = node.step(NOW, decryption_key_made(e3(1), own_decryption_key(0xd4)));
    node.step(NOW, sign(second, signing(&effects)));
    node.step(NOW, decryption_key(e3(1), first, first));
    node.step(NOW, decryption_key_checked(e3(1), first, true));
    let effects = node.step(NOW, keyshare(e3(1), first, first));
    assert!(keyshare_checks(&effects).is_empty());
    assert!(keyshare_checks(&node.step(NOW + KEY_BUDGET - 1, Input::Tick)).is_empty());
    let effects = node.step(NOW + KEY_BUDGET, Input::Tick);
    assert_eq!(keyshare_checks(&effects), members(&[first, second]));
}

#[test]
fn a_published_key_ends_the_dkg() {
    let [first, second, _] = ordered();
    let (mut node, _) = first_with_keyshare();
    node.step(
        NOW,
        key_published(12, e3(1), committee(), members(&[first, second])),
    );
    assert!(dkg(&node).published());
    assert_eq!(node.next_deadline(), None);
    node.step(TIMING.deadline, Input::Tick);
    assert_eq!(dkg(&node).failure(), None);
}

#[test]
fn decryption_gets_this_node_s_key_only_for_the_roster_it_summed() {
    let [first, second, third] = ordered();
    let (mut summed, _) = first_with_keyshare();
    let (mut other, _) = first_with_keyshare();
    summed.step(
        NOW,
        key_published(12, e3(1), committee(), members(&[first, second])),
    );
    other.step(
        NOW,
        key_published(12, e3(1), committee(), members(&[first, third])),
    );
    let decryption_work = |node: &mut Node| {
        let effects = node.step(NOW, ciphertext_ready(13, e3(1)));
        effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect,
                    Effect::Run(Job {
                        work: Work::Decryption(_),
                        ..
                    })
                )
            })
            .count()
    };
    assert_eq!(decryption_work(&mut summed), 1);
    assert_eq!(decryption_work(&mut other), 0);
}
