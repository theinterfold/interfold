// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The DKG at the node boundary: inputs in, effects and DKG state out. The committee is
//! Minimum: operators 1, 2, and ME, with H = 2.

mod aggregation;
mod decryption_key;
mod keys;
mod roster;
mod shares;

use super::{Dealer, Dkg, DkgMessage};
use crate::{
    node::{Body, Effect, Input, Node, PeerMessage},
    testing::*,
    Machine,
};
use alloy_primitives::Address;

const NOW: u64 = 90_000;
const KEY_CUTOFF: u64 = 91_000;
const SHARE_CHECKPOINT: u64 = 97_500;

fn committee() -> Vec<Address> {
    [1, 2, ME].map(address).to_vec()
}

fn others(me: u64) -> Vec<u64> {
    [1, 2, ME].into_iter().filter(|n| *n != me).collect()
}

/// Operator `me`, a member whose committee was just finalized.
fn member(me: u64) -> Node {
    let mut node = Node::new(address(me));
    node.step(0, requested(10, e3(1)));
    node.step(NOW, finalized(11, e3(1), committee()));
    node
}

/// Operator `me`, a member that has made, signed, and sent its key.
fn with_its_key(me: u64) -> Node {
    let mut node = member(me);
    let effects = node.step(NOW, key_made(e3(1), own_key(0xee)));
    node.step(NOW, sign(me, signing(&effects)));
    node
}

fn add_valid_key(node: &mut Node, n: u64) -> Vec<Effect> {
    node.step(NOW, key_from(e3(1), n));
    node.step(NOW, key_checked(e3(1), n, true))
}

fn dkg(node: &Node) -> &Dkg {
    node.e3(&e3(1))
        .and_then(|state| state.dkg.as_ref())
        .expect("the DKG started")
}

/// Operator `me` with every member's key valid, after it dealt its shares to the others.
fn dealt(me: u64) -> Node {
    let mut node = with_its_key(me);
    for n in others(me) {
        add_valid_key(&mut node, n);
    }
    let effects = node.step(NOW, shares_made(e3(1), own_shares(&others(me))));
    node.step(NOW, sign(me, signing(&effects)));
    node
}

/// Operator `me` after it dealt and verified every other member's shares.
fn verified_all(me: u64) -> Node {
    let mut node = dealt(me);
    for n in others(me) {
        node.step(NOW, shares_from(e3(1), n, me));
        node.step(NOW, shares_checked(e3(1), n, true));
    }
    node
}

/// The committee's operators in party order, ascending by address.
fn ordered() -> [u64; 3] {
    let mut operators = [1, 2, ME];
    operators.sort_by_key(|n| address(*n));
    operators
}

fn members(operators: &[u64]) -> Vec<Address> {
    let mut members: Vec<Address> = operators.iter().map(|n| address(*n)).collect();
    members.sort();
    members
}

/// Dealer `n`'s contribution, as node `node` names it: its own from `own_shares`, a peer's from
/// what `shares_from` sends.
fn contribution(n: u64, node: u64) -> Dealer {
    if n == node {
        let own = own_shares(&[]);
        return Dealer::new(address(n), own.pk_share, &own.c2a, &own.c2b);
    }
    let Input::Peer(PeerMessage {
        body: Body::Dkg(DkgMessage::Shares(message)),
        ..
    }) = shares_from(e3(1), n, node)
    else {
        unreachable!("shares_from builds shares");
    };
    Dealer::new(
        address(n),
        message.pk_share,
        &message.c2a.proof,
        &message.c2b.proof,
    )
}

/// A Ready report or roster that names `dealers` with the contributions node `node` knows.
fn named(dealers: &[u64], node: u64) -> Vec<Dealer> {
    let mut named: Vec<Dealer> = dealers.iter().map(|n| contribution(*n, node)).collect();
    named.sort_by_key(|dealer| dealer.member);
    named
}

fn from(sender: u64, message: DkgMessage) -> Input {
    Input::Peer(PeerMessage {
        e3: e3(1),
        sender: address(sender),
        body: Body::Dkg(message),
    })
}

fn ready(sender: u64, dealers: &[u64], node: u64) -> Input {
    from(sender, DkgMessage::Ready(named(dealers, node)))
}

fn roster(proposer: u64, dealers: &[u64], node: u64) -> Input {
    from(proposer, DkgMessage::Roster(named(dealers, node)))
}

fn accepted(node: &Node) -> Option<Vec<Address>> {
    let roster = dkg(node).roster()?;
    Some(roster.iter().map(|dealer| dealer.member).collect())
}

/// The first member in party order, after it proposed and accepted the roster of itself and
/// the second member. Returns the step's effects.
fn first_with_roster() -> (Node, Vec<Effect>) {
    let [first, second, third] = ordered();
    let mut node = verified_all(first);
    let effects = node.step(NOW, ready(second, &[first, second, third], first));
    (node, effects)
}

/// The first member after it made, signed, and sent its C4 proofs.
fn first_with_decryption_key() -> Node {
    let [first, ..] = ordered();
    let (mut node, _) = first_with_roster();
    let effects = node.step(NOW, decryption_key_made(e3(1), own_decryption_key(0xd4)));
    node.step(NOW, sign(first, signing(&effects)));
    node
}
