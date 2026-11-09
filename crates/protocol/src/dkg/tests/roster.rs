// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{
    accusation::{accusation_id, AccusationMessage, AccusationWorkResult, SignedVote, Vote},
    node::{ChainFact, JobDone, WorkResult},
    proof::{ProofType, SignedProof},
};
use alloy_primitives::B256;

const ROSTER_BUDGET: u64 = 600;

fn rosters_sent(effects: &[Effect]) -> Vec<Vec<Address>> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Gossip(PeerMessage {
                body: Body::Dkg(DkgMessage::Roster(dealers)),
                ..
            }) => Some(dealers.iter().map(|dealer| dealer.member).collect()),
            _ => None,
        })
        .collect()
}

#[test]
fn the_aggregator_proposes_and_accepts_the_first_h_mutually_ready_dealers() {
    let [first, second, third] = ordered();
    let mut node = verified_all(first);
    let effects = node.step(NOW, ready(second, &[first, second, third], first));
    assert_eq!(rosters_sent(&effects), vec![members(&[first, second])]);
    assert_eq!(accepted(&node), Some(members(&[first, second])));
}

#[test]
fn a_member_accepts_the_aggregator_s_roster_once_the_aggregator_reported_ready() {
    let [first, second, third] = ordered();
    let mut node = verified_all(second);
    node.step(NOW, roster(first, &[first, second], second));
    assert_eq!(accepted(&node), None);
    let effects = node.step(NOW, ready(first, &[first, second, third], second));
    assert!(rosters_sent(&effects).is_empty());
    assert_eq!(accepted(&node), Some(members(&[first, second])));
}

#[test]
fn a_roster_needs_this_node_s_ready_report_to_contain_it() {
    let [first, second, third] = ordered();
    let mut node = dealt(second);
    node.step(NOW, shares_from(e3(1), first, second));
    node.step(NOW, shares_checked(e3(1), first, true));
    node.step(NOW, shares_from(e3(1), third, second));
    node.step(NOW, shares_checked(e3(1), third, false));
    node.step(NOW, ready(first, &[first, third], second));
    node.step(NOW, roster(first, &[first, third], second));
    assert_eq!(accepted(&node), None);
}

#[test]
fn a_later_member_s_roster_waits_until_the_aggregator_s_budget_runs_out() {
    let [first, second, third] = ordered();
    let mut node = verified_all(third);
    node.step(NOW, ready(second, &[first, second, third], third));
    node.step(NOW, roster(second, &[second, third], third));
    assert_eq!(accepted(&node), None);
    node.step(NOW + ROSTER_BUDGET - 1, Input::Tick);
    assert_eq!(accepted(&node), None);
    node.step(NOW + ROSTER_BUDGET, Input::Tick);
    assert_eq!(accepted(&node), Some(members(&[second, third])));
}

#[test]
fn an_accepted_roster_is_fixed() {
    let [first, second, third] = ordered();
    let mut node = verified_all(third);
    node.step(NOW, ready(second, &[first, second, third], third));
    node.step(NOW, roster(second, &[second, third], third));
    node.step(NOW + ROSTER_BUDGET, Input::Tick);
    node.step(
        NOW + ROSTER_BUDGET,
        ready(first, &[first, second, third], third),
    );
    node.step(NOW + ROSTER_BUDGET, roster(first, &[first, third], third));
    assert_eq!(accepted(&node), Some(members(&[second, third])));
}

#[test]
fn an_expelled_aggregator_hands_over_at_once() {
    let [first, second, third] = ordered();
    let mut node = verified_all(third);
    node.step(NOW, ready(second, &[first, second, third], third));
    node.step(NOW, roster(second, &[second, third], third));
    let expelled = ChainFact::MemberExpelled {
        e3: e3(1),
        member: address(first),
    };
    node.step(NOW, chain(12, expelled));
    assert_eq!(accepted(&node), Some(members(&[second, third])));
}

/// Operator `me` after it dealt and verified every other member's shares, on a chain that takes
/// accusations.
fn accusing(me: u64) -> Node {
    let mut node = Node::new(address(me));
    node.step(0, chain(2, ChainFact::SlashingManager { manager: MANAGER }));
    node.step(0, chain(3, ChainFact::VoteValidity { secs: 600 }));
    node.step(0, requested(10, e3(1)));
    node.step(NOW, finalized(11, e3(1), committee()));
    let effects = node.step(NOW, key_made(e3(1), own_key(0xee)));
    node.step(NOW, sign(me, signing(&effects)));
    for n in others(me) {
        add_valid_key(&mut node, n);
    }
    let effects = node.step(NOW, shares_made(e3(1), own_shares(&others(me))));
    node.step(NOW, sign(me, signing(&effects)));
    for n in others(me) {
        node.step(NOW, shares_from(e3(1), n, me));
        node.step(NOW, shares_checked(e3(1), n, true));
    }
    node
}

const MANAGER: Address = Address::repeat_byte(0x5a);

/// `accuser` accuses `accused` of a failing proof, and this node, `me`, finds it failing too: H
/// members have found it, so it is convicted.
fn convict(node: &mut Node, me: u64, accused: u64, accuser: u64) {
    let proof = proof(0x51);
    let signed = SignedProof {
        signature: signature(
            accused,
            proof.payload_signing_hash(e3(1), ProofType::C0PkBfv),
        ),
        proof: proof.clone(),
    };
    let data_hash = B256::repeat_byte(0xd1);
    let vote = Vote {
        e3: e3(1),
        accusation_id: accusation_id(e3(1), address(accused), ProofType::C0PkBfv),
        voter: address(accuser),
        data_hash,
        issued_at: NOW,
        deadline: NOW + 600,
    };
    let vote = SignedVote {
        signature: signature(accuser, vote.signing_hash(MANAGER)),
        vote,
    };
    let accuse = AccusationMessage::Accuse {
        accused: address(accused),
        proof_type: ProofType::C0PkBfv,
        proof: signed,
        vote,
    };
    node.step(
        NOW,
        Input::Peer(PeerMessage {
            e3: e3(1),
            sender: address(accuser),
            body: Body::Accusation(accuse),
        }),
    );
    let verified = WorkResult::Accusation(AccusationWorkResult::Verified {
        proof_type: ProofType::C0PkBfv,
        proof,
        fails: true,
        data_hash,
    });
    let effects = node.step(
        NOW,
        Input::Job(JobDone {
            e3: e3(1),
            result: verified,
        }),
    );
    node.step(NOW, sign(me, signing(&effects)));
}

/// An aggregator that H members found sending a failing proof hands over at once, as an expelled
/// one does, without waiting for its slash to land.
#[test]
fn a_convicted_aggregator_hands_over_at_once() {
    let [first, second, third] = ordered();
    let mut node = accusing(third);
    node.step(NOW, ready(second, &[first, second, third], third));
    node.step(NOW, roster(second, &[second, third], third));
    assert_eq!(accepted(&node), None);
    convict(&mut node, third, first, second);
    assert_eq!(accepted(&node), Some(members(&[second, third])));
}

/// A member H members found sending a failing proof takes no place in a roster this node chooses.
#[test]
fn the_roster_this_node_proposes_leaves_out_a_convicted_member() {
    let [first, second, third] = ordered();
    let mut node = accusing(first);
    convict(&mut node, first, second, third);
    let effects = node.step(NOW, ready(third, &[first, second, third], first));
    assert_eq!(rosters_sent(&effects), vec![members(&[first, third])]);
    assert_eq!(accepted(&node), Some(members(&[first, third])));
}

/// Nodes count votes at different times, so a roster is judged only by chain facts: this node
/// does not refuse one that names a member it has found convicted.
#[test]
fn a_received_roster_that_names_a_convicted_member_is_accepted() {
    let [first, second, third] = ordered();
    let mut node = accusing(second);
    convict(&mut node, second, third, first);
    node.step(NOW, roster(first, &[second, third], second));
    node.step(NOW, ready(first, &[first, second, third], second));
    assert_eq!(accepted(&node), Some(members(&[second, third])));
}

#[test]
fn a_roster_with_an_expelled_member_is_never_accepted() {
    let [first, second, third] = ordered();
    let mut node = verified_all(second);
    node.step(NOW, ready(first, &[first, second, third], second));
    let expelled = ChainFact::MemberExpelled {
        e3: e3(1),
        member: address(third),
    };
    node.step(NOW, chain(12, expelled));
    node.step(NOW, roster(first, &[first, third], second));
    assert_eq!(accepted(&node), None);
}

#[test]
fn a_roster_needs_every_pair_of_its_dealers_to_name_each_other() {
    let [first, second, third] = ordered();
    let mut node = verified_all(first);
    let effects = node.step(NOW, ready(second, &[second, third], first));
    assert!(rosters_sent(&effects).is_empty());
    let effects = node.step(NOW, ready(third, &[first, second, third], first));
    assert_eq!(rosters_sent(&effects), vec![members(&[first, third])]);
}
