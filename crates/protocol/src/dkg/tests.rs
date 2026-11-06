// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{Dkg, DkgFailure, DkgMessage, DkgWork};
use crate::{
    node::{Body, Effect, Input, Job, Node, Work},
    proof::ProofType,
    testing::*,
    Machine,
};
use alloy_primitives::Address;

const NOW: u64 = 9_000;
const KEY_CUTOFF: u64 = 9_100;

/// A Minimum committee: three members, H = 2.
fn committee() -> Vec<Address> {
    [1, 2, ME].map(address).to_vec()
}

/// Operator `me`, a member whose committee was just finalized.
fn member(me: u64) -> Node {
    let mut node = Node::new(address(me));
    node.step(0, requested(10, e3(1)));
    node.step(NOW, finalized(11, e3(1), committee()));
    node
}

fn member_with_its_key() -> Node {
    let mut node = member(ME);
    let effects = node.step(NOW, key_made(e3(1), own_key(0xee)));
    node.step(NOW, sign(ME, signing(&effects)));
    node
}

fn dkg(node: &Node) -> &Dkg {
    node.e3(&e3(1))
        .and_then(|state| state.dkg.as_ref())
        .expect("the DKG started")
}

fn add_valid_key(node: &mut Node, n: u64) {
    node.step(NOW, key_from(e3(1), n));
    node.step(NOW, key_checked(e3(1), n, true));
}

#[test]
fn a_member_makes_signs_and_sends_a_key_its_peers_accept() {
    let mut node = Node::new(address(ME));
    node.step(0, requested(10, e3(1)));
    let effects = node.step(NOW, finalized(11, e3(1), committee()));
    let make = Effect::Run(Job {
        e3: e3(1),
        work: Work::Dkg(DkgWork::MakeEncryptionKey),
    });
    assert_eq!(effects, vec![make]);

    let effects = node.step(NOW, key_made(e3(1), own_key(0xee)));
    let signing = signing(&effects).clone();
    let own = own_key(0xee);
    assert_eq!(
        signing.hash,
        own.proof.payload_signing_hash(e3(1), ProofType::C0PkBfv)
    );

    let effects = node.step(NOW, sign(ME, &signing));
    let [Effect::Gossip(sent)] = effects.as_slice() else {
        panic!("one gossip, got {effects:?}");
    };
    let check = Effect::Run(Job {
        e3: e3(1),
        work: Work::Dkg(DkgWork::CheckEncryptionKey {
            sender: address(ME),
            key: own.public,
            proof: own.proof,
        }),
    });
    assert_eq!(member(1).step(NOW, Input::Peer(sent.clone())), vec![check]);
}

#[test]
fn a_key_counts_only_after_its_signature_and_its_check_pass() {
    let mut node = member_with_its_key();
    let signed_by_another = key(e3(1), 1, proof(1), 2);
    assert!(node.step(NOW, signed_by_another).is_empty());

    assert_eq!(
        key_checks(&node.step(NOW, key_from(e3(1), 1))),
        vec![address(1)]
    );
    assert!(!dkg(&node).valid_keys().contains(&address(1)));
    node.step(NOW, key_checked(e3(1), 1, true));
    assert!(dkg(&node).valid_keys().contains(&address(1)));

    node.step(NOW, key_from(e3(1), 2));
    node.step(NOW, key_checked(e3(1), 2, false));
    assert!(!dkg(&node).valid_keys().contains(&address(2)));
}

#[test]
fn only_a_member_s_first_signed_key_is_checked() {
    let mut node = member_with_its_key();
    node.step(NOW, key_from(e3(1), 1));
    assert!(node.step(NOW, key(e3(1), 1, proof(0x77), 1)).is_empty());
}

#[test]
fn key_collection_ends_once_every_member_s_key_is_valid() {
    let mut node = member_with_its_key();
    add_valid_key(&mut node, 1);
    add_valid_key(&mut node, 2);
    assert!(dkg(&node).keys_collected());
    assert_eq!(node.next_deadline(), None);
}

#[test]
fn at_the_key_cutoff_h_valid_keys_suffice() {
    let mut node = member_with_its_key();
    add_valid_key(&mut node, 1);
    assert_eq!(node.next_deadline(), Some(KEY_CUTOFF));
    node.step(KEY_CUTOFF - 1, Input::Tick);
    assert!(!dkg(&node).keys_collected());
    node.step(KEY_CUTOFF, Input::Tick);
    assert!(dkg(&node).keys_collected());
}

#[test]
fn at_the_key_cutoff_fewer_than_h_valid_keys_fail() {
    let mut node = member_with_its_key();
    node.step(KEY_CUTOFF, Input::Tick);
    assert_eq!(dkg(&node).failure(), Some(DkgFailure::TooFewKeys));
}

#[test]
fn the_h_valid_keys_must_include_this_node_s_key() {
    let mut node = member(ME);
    add_valid_key(&mut node, 1);
    add_valid_key(&mut node, 2);
    node.step(KEY_CUTOFF, Input::Tick);
    assert_eq!(dkg(&node).failure(), Some(DkgFailure::TooFewKeys));
}

#[test]
fn a_key_still_being_checked_at_the_cutoff_does_not_count() {
    let mut node = member_with_its_key();
    node.step(NOW, key_from(e3(1), 1));
    node.step(KEY_CUTOFF, key_checked(e3(1), 1, true));
    assert_eq!(dkg(&node).failure(), Some(DkgFailure::TooFewKeys));
}

#[test]
fn a_committee_finalized_after_the_key_cutoff_starts_no_dkg() {
    let mut node = Node::new(address(ME));
    node.step(0, requested(10, e3(1)));
    assert!(node
        .step(KEY_CUTOFF, finalized(11, e3(1), committee()))
        .is_empty());
    assert_eq!(
        dkg(&node).failure(),
        Some(DkgFailure::StartedAfterKeyCutoff)
    );
}

#[test]
fn a_repeated_key_job_never_replaces_the_first_key() {
    let mut node = member(ME);
    let effects = node.step(NOW, key_made(e3(1), own_key(0xee)));
    assert!(node.step(NOW, key_made(e3(1), own_key(0x11))).is_empty());
    let effects = node.step(NOW, sign(ME, signing(&effects)));
    let [Effect::Gossip(sent)] = effects.as_slice() else {
        panic!("one gossip, got {effects:?}");
    };
    let Body::Dkg(DkgMessage::EncryptionKey(message)) = &sent.body;
    assert_eq!(message.key, own_key(0xee).public);
}
