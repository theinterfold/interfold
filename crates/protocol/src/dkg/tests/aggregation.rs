// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{
    decryption::DecryptionWork,
    dkg::{DkgProofs, DkgWork, FoldAttestation, KeyPublication, OwnShares, RecipientShares},
    node::{Job, Submission, Transaction, Work},
    proof::ZkProof,
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

/// The steps of the roster's fold in `effects`: each slot, the fold going into it, and the
/// accumulator it extends.
fn fold_steps(effects: &[Effect]) -> Vec<(u32, &ZkProof, Option<&ZkProof>)> {
    let steps = jobs(effects).into_iter().filter_map(|work| match work {
        DkgWork::FoldRoster {
            slot,
            fold,
            accumulator,
            ..
        } => Some((*slot, fold, accumulator.as_ref())),
        _ => None,
    });
    steps.collect()
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

/// The first member after it dealt `made`, verified every other member's shares, and sent its
/// C4 proofs for the full roster, with the effects of that last step.
fn first_dealing(made: OwnShares) -> (Node, Vec<Effect>) {
    let [first, second, third] = ordered();
    let mut node = with_its_key(first);
    for n in others(first) {
        add_valid_key(&mut node, n);
    }
    let effects = node.step(NOW, shares_made(e3(1), made));
    node.step(NOW, sign(first, signing(&effects)));
    for n in others(first) {
        node.step(NOW, shares_from(e3(1), n, first));
        node.step(NOW, shares_checked(e3(1), n, true));
    }
    node.step(NOW, ready(second, &[first, second, third], first));
    let effects = node.step(NOW, decryption_key_made(e3(1), own_decryption_key(0xd4)));
    let effects = node.step(NOW, sign(first, signing(&effects)));
    (node, effects)
}

fn folds(effects: &[Effect]) -> Vec<(Address, &[Address], &DkgProofs)> {
    let folds = jobs(effects).into_iter().filter_map(|work| match work {
        DkgWork::FoldProofs {
            member,
            committee,
            proofs,
        } => Some((*member, committee.as_slice(), &**proofs)),
        _ => None,
    });
    folds.collect()
}

#[test]
fn a_roster_member_folds_every_dkg_proof_it_made_and_attests_the_fold_for_its_slot() {
    let [first, ..] = ordered();
    let mut made = own_shares(&others(first));
    // A withheld slot is never sent, but its C3 proofs still go into the fold.
    let withheld = address(others(first)[0]);
    made.recipients
        .get_mut(&withheld)
        .expect("a recipient")
        .shares = None;
    let (mut node, effects) = first_dealing(made.clone());
    let c3 = |proofs: fn(&RecipientShares) -> &Vec<ZkProof>| {
        made.recipients
            .iter()
            .map(|(member, recipient)| (*member, proofs(recipient).clone()))
            .collect()
    };
    let expected = DkgProofs {
        c0: own_key(0xee).proof,
        c1: made.c1.clone(),
        c2a: made.c2a.clone(),
        c2b: made.c2b.clone(),
        c3a: c3(|recipient| &recipient.c3a),
        c3b: c3(|recipient| &recipient.c3b),
        c4a: own_decryption_key(0xd4).c4a,
        c4b: own_decryption_key(0xd4).c4b,
    };
    assert_eq!(
        folds(&effects),
        [(address(first), members(&ordered()).as_slice(), &expected)]
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
fn the_aggregator_aggregates_once_every_c1_passed_and_every_slot_is_folded() {
    let [_, second, _] = ordered();
    let mut node = first_with_checked_keyshares();
    assert_eq!(
        aggregations(&node.step(NOW, fold(e3(1), second, 1, second))),
        0
    );
    assert_eq!(
        aggregations(&node.step(NOW, roster_folded(e3(1), 0, 0xa0))),
        0
    );
    let effects = node.step(NOW, roster_folded(e3(1), 1, 0xa1));
    assert_eq!(aggregations(&effects), 1);
    let accumulator = jobs(&effects).into_iter().find_map(|work| match work {
        DkgWork::AggregateKey { accumulator, .. } => Some(accumulator),
        _ => None,
    });
    assert_eq!(accumulator, Some(&proof(0xa1)));
}

/// Folding starts as soon as the first slot's fold is here, and a step extends the one before it.
#[test]
fn the_roster_is_folded_a_step_at_a_time_as_its_folds_arrive() {
    let [first, second, _] = ordered();
    let (mut node, _) = first_with_keyshare();
    node.step(NOW, keyshare(e3(1), second, second));
    let effects = node.step(NOW, proofs_folded(e3(1), node_fold(0xf0)));
    let effects = node.step(NOW, sign(first, signing(&effects)));
    assert_eq!(fold_steps(&effects), [(0, &node_fold(0xf0).proof, None)]);
    let effects = node.step(NOW, fold(e3(1), second, 1, second));
    assert!(fold_steps(&effects).is_empty(), "one step at a time");
    let effects = node.step(NOW, roster_folded(e3(1), 0, 0xa0));
    let [(1, _, Some(accumulator))] = fold_steps(&effects)[..] else {
        panic!("the next slot, got {effects:?}");
    };
    assert_eq!(accumulator, &proof(0xa0));
}

/// The circuit fixes the slots' order, so a later member's fold waits for the earlier ones.
#[test]
fn a_fold_that_arrives_early_waits_for_its_slot() {
    let [first, second, _] = ordered();
    let (mut node, _) = first_with_keyshare();
    node.step(NOW, keyshare(e3(1), second, second));
    let effects = node.step(NOW, fold(e3(1), second, 1, second));
    assert!(fold_steps(&effects).is_empty());
    let effects = node.step(NOW, proofs_folded(e3(1), node_fold(0xf0)));
    let effects = node.step(NOW, sign(first, signing(&effects)));
    assert_eq!(fold_steps(&effects), [(0, &node_fold(0xf0).proof, None)]);
}

#[test]
fn a_fold_attested_for_another_slot_does_not_count() {
    let [_, second, _] = ordered();
    let mut node = first_with_checked_keyshares();
    node.step(NOW, fold(e3(1), second, 2, second));
    let effects = node.step(NOW, roster_folded(e3(1), 0, 0xa0));
    assert!(fold_steps(&effects).is_empty());
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
    node.step(NOW, fold(e3(1), second, 1, second));
    node.step(NOW, roster_folded(e3(1), 0, 0xa0));
    assert_eq!(
        aggregations(&node.step(NOW, roster_folded(e3(1), 1, 0xa1))),
        0
    );
}

#[test]
fn the_aggregator_asks_the_chain_writer_to_publish_the_key_with_every_attestation() {
    let [_, second, _] = ordered();
    let mut node = first_with_checked_keyshares();
    node.step(NOW, fold(e3(1), second, 1, second));
    node.step(NOW, roster_folded(e3(1), 0, 0xa0));
    node.step(NOW, roster_folded(e3(1), 1, 0xa1));
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
    assert_eq!(dkg(&node).next_deadline(), None);
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
        node.step(NOW, ciphertext_ready(13, e3(1)));
        let effects = node.step(NOW, ciphertext_fetched(e3(1)));
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

/// The DKG deadline can pass before the node reads the key's publication: it restarted, or its
/// chain node is behind. Its local failure keeps the key it made for the chain's key over its
/// roster.
#[test]
fn a_key_read_after_the_local_deadline_still_gets_this_node_s_key() {
    let [first, second, _] = ordered();
    let (mut node, _) = first_with_keyshare();
    let late = TIMING.deadline + 1;
    node.step(late, Input::Tick);
    node.step(
        late,
        key_published(12, e3(1), committee(), members(&[first, second])),
    );
    node.step(late, ciphertext_ready(13, e3(1)));
    let effects = node.step(late, ciphertext_fetched(e3(1)));
    let makes_shares = effects.iter().any(|effect| {
        matches!(
            effect,
            Effect::Run(Job {
                work: Work::Decryption(DecryptionWork::MakeShares { .. }),
                ..
            })
        )
    });
    assert!(makes_shares);
}
