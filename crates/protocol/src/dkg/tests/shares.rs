// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{
    dkg::{Dealer, DkgFailure, DkgMessage, DkgWork},
    node::{Body, ChainFact, Input, Job, PeerMessage, Work},
    proof::ProofType,
};
use alloy_primitives::B256;

fn add_valid_shares(node: &mut Node, dealer: u64) -> Vec<Effect> {
    node.step(NOW, shares_from(e3(1), dealer, ME));
    node.step(NOW, shares_checked(e3(1), dealer, true))
}

#[test]
fn a_dealer_signs_every_proof_and_sends_each_member_shares_it_accepts() {
    let mut node = with_its_key(ME);
    add_valid_key(&mut node, 1);
    let effects = add_valid_key(&mut node, 2);
    let [Effect::Run(Job {
        work: Work::Dkg(DkgWork::MakeShares { keys, .. }),
        ..
    })] = effects.as_slice()
    else {
        panic!("a share job, got {effects:?}");
    };
    assert_eq!(keys.keys().copied().collect::<Vec<_>>(), members(&[1, 2]));

    let made = own_shares(&[1, 2]);
    let effects = node.step(NOW, shares_made(e3(1), made.clone()));
    let c3_per_recipient = 3 + 3;
    assert_eq!(signing(&effects).hashes.len(), 3 + 2 * c3_per_recipient);
    assert_eq!(
        signing(&effects).hashes[0],
        made.c1
            .payload_signing_hash(e3(1), ProofType::C1PkGeneration)
    );

    let effects = node.step(NOW, sign(ME, signing(&effects)));
    for recipient in [1, 2] {
        let sent = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::Gossip(
                    message @ PeerMessage {
                        body: Body::Dkg(DkgMessage::Shares(shares)),
                        ..
                    },
                ) if shares.recipient == address(recipient) => Some(message.clone()),
                _ => None,
            })
            .expect("shares for every member with a key");
        let mut peer = with_its_key(recipient);
        let checks = peer.step(NOW, Input::Peer(sent));
        assert!(matches!(
            checks.as_slice(),
            [Effect::Run(Job {
                work: Work::Dkg(DkgWork::CheckShares { .. }),
                ..
            })]
        ));
    }
}

#[test]
fn a_dealer_never_signs_or_sends_a_slot_it_withholds() {
    let mut node = with_its_key(ME);
    add_valid_key(&mut node, 1);
    add_valid_key(&mut node, 2);
    let mut made = own_shares(&[1, 2]);
    made.recipients
        .get_mut(&address(2))
        .expect("a recipient")
        .shares = None;
    let effects = node.step(NOW, shares_made(e3(1), made));
    let c3_per_recipient = 3 + 3;
    assert_eq!(signing(&effects).hashes.len(), 3 + c3_per_recipient);

    let effects = node.step(NOW, sign(ME, signing(&effects)));
    let recipients: Vec<Address> = effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Gossip(PeerMessage {
                body: Body::Dkg(DkgMessage::Shares(shares)),
                ..
            }) => Some(shares.recipient),
            _ => None,
        })
        .collect();
    assert_eq!(recipients, [address(1)]);
}

#[test]
fn a_member_without_a_valid_key_gets_no_shares() {
    let mut node = with_its_key(ME);
    add_valid_key(&mut node, 1);
    node.step(NOW, key_from(e3(1), 2));
    node.step(NOW, key_checked(e3(1), 2, false));
    let effects = node.step(KEY_CUTOFF, Input::Tick);
    let keys = effects.iter().find_map(|effect| match effect {
        Effect::Run(Job {
            work: Work::Dkg(DkgWork::MakeShares { keys, .. }),
            ..
        }) => Some(keys.keys().copied().collect::<Vec<_>>()),
        _ => None,
    });
    assert_eq!(keys, Some(members(&[1])));
}

#[test]
fn shares_count_only_after_their_signatures_and_their_check_pass() {
    let mut node = dealt(ME);
    assert!(node.step(NOW, shares(e3(1), 1, ME, 2)).is_empty());
    assert!(node.step(NOW, shares_from(e3(1), 1, 2)).is_empty());

    let effects = node.step(NOW, shares_from(e3(1), 1, ME));
    assert_eq!(effects.len(), 1, "a check of the shares");
    node.step(NOW, shares_checked(e3(1), 1, false));
    let effects = add_valid_shares(&mut node, 2);
    assert_eq!(ready_sent(&effects), vec![members(&[2, ME])]);
}

#[test]
fn ready_names_this_node_and_every_dealer_whose_shares_passed() {
    let mut node = dealt(ME);
    assert!(ready_sent(&add_valid_shares(&mut node, 1)).is_empty());
    let effects = add_valid_shares(&mut node, 2);
    assert_eq!(ready_sent(&effects), vec![members(&[1, 2, ME])]);
}

#[test]
fn ready_waits_for_a_missing_dealer_until_the_share_checkpoint() {
    let mut node = dealt(ME);
    assert!(ready_sent(&add_valid_shares(&mut node, 1)).is_empty());
    assert!(ready_sent(&node.step(SHARE_CHECKPOINT - 1, Input::Tick)).is_empty());
    let effects = node.step(SHARE_CHECKPOINT, Input::Tick);
    assert_eq!(ready_sent(&effects), vec![members(&[1, ME])]);
}

#[test]
fn ready_does_not_wait_for_a_dealer_this_node_had_no_valid_key_from() {
    let mut node = with_its_key(ME);
    add_valid_key(&mut node, 1);
    node.step(KEY_CUTOFF, Input::Tick);
    let effects = node.step(KEY_CUTOFF, shares_made(e3(1), own_shares(&[1])));
    node.step(KEY_CUTOFF, sign(ME, signing(&effects)));
    node.step(KEY_CUTOFF, shares_from(e3(1), 1, ME));
    let effects = node.step(KEY_CUTOFF, shares_checked(e3(1), 1, true));
    assert_eq!(ready_sent(&effects), vec![members(&[1, ME])]);
}

#[test]
fn a_later_verdict_grows_the_ready_report() {
    let mut node = dealt(ME);
    add_valid_shares(&mut node, 1);
    node.step(SHARE_CHECKPOINT, Input::Tick);
    node.step(SHARE_CHECKPOINT, shares_from(e3(1), 2, ME));
    let effects = node.step(SHARE_CHECKPOINT, shares_checked(e3(1), 2, true));
    assert_eq!(ready_sent(&effects), vec![members(&[1, 2, ME])]);
}

#[test]
fn ready_needs_h_dealers() {
    let mut node = dealt(ME);
    node.step(NOW, shares_from(e3(1), 1, ME));
    node.step(NOW, shares_checked(e3(1), 1, false));
    assert!(ready_sent(&node.step(SHARE_CHECKPOINT, Input::Tick)).is_empty());
}

#[test]
fn a_member_s_ready_report_counts_only_while_it_grows() {
    let mut node = dealt(ME);
    let report = |dealers: &[u64]| {
        let mut dealers: Vec<Dealer> = dealers
            .iter()
            .map(|n| Dealer {
                member: address(*n),
                contribution: B256::repeat_byte(*n as u8),
            })
            .collect();
        dealers.sort_by_key(|dealer| dealer.member);
        Input::Peer(PeerMessage {
            e3: e3(1),
            sender: address(1),
            body: Body::Dkg(DkgMessage::Ready(dealers)),
        })
    };
    node.step(NOW, report(&[1, 2]));
    node.step(NOW, report(&[1, ME]));
    let named = |node: &Node| -> Vec<Address> {
        let dealers = dkg(node).ready(&address(1)).expect("a report from 1");
        dealers.iter().map(|dealer| dealer.member).collect()
    };
    assert_eq!(named(&node), members(&[1, 2]));
    node.step(NOW, report(&[1, 2, ME]));
    assert_eq!(named(&node), members(&[1, 2, ME]));
}

#[test]
fn ready_does_not_wait_for_an_expelled_dealer() {
    let mut node = dealt(ME);
    add_valid_shares(&mut node, 1);
    let expelled = ChainFact::MemberExpelled {
        e3: e3(1),
        member: address(2),
    };
    let effects = node.step(NOW, chain(12, expelled));
    assert_eq!(ready_sent(&effects), vec![members(&[1, ME])]);
}

#[test]
fn a_repeated_share_job_never_replaces_the_first_shares() {
    let mut node = with_its_key(ME);
    add_valid_key(&mut node, 1);
    add_valid_key(&mut node, 2);
    node.step(NOW, shares_made(e3(1), own_shares(&[1, 2])));
    assert!(node
        .step(NOW, shares_made(e3(1), own_shares(&[1])))
        .is_empty());
}

#[test]
fn the_dkg_ends_at_its_deadline() {
    let mut node = dealt(ME);
    node.step(TIMING.deadline, Input::Tick);
    assert_eq!(dkg(&node).failure(), Some(DkgFailure::DeadlinePassed));
    assert_eq!(dkg(&node).next_deadline(), None);
}
