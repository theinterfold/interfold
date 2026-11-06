// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::node::ChainFact;

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
