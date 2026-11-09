// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{
    dkg::{DkgFailure, DkgMessage, DkgWork},
    node::{Body, ChainFact, Input, Job, PeerMessage, Work},
    proof::ProofType,
};
use e3_committee::CiphernodesCommitteeSize;

#[test]
fn a_member_makes_signs_and_sends_a_key_its_peers_accept() {
    let mut node = Node::new(address(ME));
    node.step(0, requested(10, e3(1)));
    let effects = node.step(NOW, finalized(11, e3(1), committee()));
    let make = Effect::Run(Job {
        e3: e3(1),
        params: params(CiphernodesCommitteeSize::Minimum),
        work: Work::Dkg(DkgWork::MakeEncryptionKey),
    });
    assert_eq!(effects, vec![make]);

    let effects = node.step(NOW, key_made(e3(1), own_key(0xee)));
    let signing = signing(&effects).clone();
    let own = own_key(0xee);
    assert_eq!(
        signing.hashes,
        vec![own.proof.payload_signing_hash(e3(1), ProofType::C0PkBfv)]
    );

    let effects = node.step(NOW, sign(ME, &signing));
    let [Effect::Gossip(sent)] = effects.as_slice() else {
        panic!("one gossip, got {effects:?}");
    };
    let check = Effect::Run(Job {
        e3: e3(1),
        params: params(CiphernodesCommitteeSize::Minimum),
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
    let mut node = with_its_key(ME);
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
    let mut node = with_its_key(ME);
    node.step(NOW, key_from(e3(1), 1));
    assert!(node.step(NOW, key(e3(1), 1, proof(0x77), 1)).is_empty());
}

#[test]
fn key_collection_ends_once_every_member_s_key_is_valid() {
    let mut node = with_its_key(ME);
    add_valid_key(&mut node, 1);
    let effects = add_valid_key(&mut node, 2);
    assert!(dkg(&node).keys_collected());
    assert!(matches!(
        effects.as_slice(),
        [Effect::Run(Job {
            work: Work::Dkg(DkgWork::MakeShares { .. }),
            ..
        })]
    ));
}

#[test]
fn key_collection_does_not_wait_for_an_expelled_member() {
    let mut node = with_its_key(ME);
    add_valid_key(&mut node, 1);
    let expelled = ChainFact::MemberExpelled {
        e3: e3(1),
        member: address(2),
    };
    node.step(NOW, chain(12, expelled));
    assert!(dkg(&node).keys_collected());
}

#[test]
fn at_the_key_cutoff_h_valid_keys_suffice() {
    let mut node = with_its_key(ME);
    add_valid_key(&mut node, 1);
    node.step(KEY_CUTOFF - 1, Input::Tick);
    assert!(!dkg(&node).keys_collected());
    node.step(KEY_CUTOFF, Input::Tick);
    assert!(dkg(&node).keys_collected());
}

#[test]
fn at_the_key_cutoff_fewer_than_h_valid_keys_fail() {
    let mut node = with_its_key(ME);
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
    let mut node = with_its_key(ME);
    node.step(NOW, key_from(e3(1), 1));
    node.step(KEY_CUTOFF, key_checked(e3(1), 1, true));
    assert_eq!(dkg(&node).failure(), Some(DkgFailure::TooFewKeys));
}

#[test]
fn a_committee_finalized_after_the_key_cutoff_starts_no_dkg() {
    let mut node = Node::new(address(ME));
    node.step(0, requested(10, e3(1)));
    let effects = node.step(KEY_CUTOFF, finalized(11, e3(1), committee()));
    assert!(matches!(effects[..], [Effect::Note(_)]), "{effects:?}");
    assert_eq!(
        dkg(&node).failure(),
        Some(DkgFailure::StartedAfterKeyCutoff)
    );
}

/// An operator whose E3 fails at the key cutoff can read which members it waited for.
#[test]
fn too_few_keys_at_the_cutoff_notes_the_members_it_waited_for() {
    use crate::node::{Note, Noted};
    let mut node = with_its_key(ME);
    let effects = node.step(KEY_CUTOFF, Input::Tick);
    let [Effect::Note(Note {
        event: Noted::DkgFailed { failure, missing },
        ..
    })] = &effects[..]
    else {
        panic!("one note: {effects:?}");
    };
    assert_eq!(*failure, DkgFailure::TooFewKeys);
    assert_eq!(*missing, members(&[1, 2]));
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
    let Body::Dkg(DkgMessage::EncryptionKey(message)) = &sent.body else {
        panic!("a key, got {sent:?}");
    };
    assert_eq!(message.key, own_key(0xee).public);
}

#[test]
fn a_member_sends_its_key_again_until_the_dkg_ends() {
    let mut node = with_its_key(ME);
    let keys_sent = |effects: &[Effect]| {
        let keys = effects.iter().filter(|effect| {
            matches!(
                effect,
                Effect::Gossip(PeerMessage {
                    body: Body::Dkg(DkgMessage::EncryptionKey(_)),
                    ..
                })
            )
        });
        keys.count()
    };
    assert_eq!(keys_sent(&node.step(NOW + 29, Input::Tick)), 0);
    assert_eq!(keys_sent(&node.step(NOW + 30, Input::Tick)), 1);
    assert_eq!(keys_sent(&node.step(NOW + 89, Input::Tick)), 0);
    assert_eq!(keys_sent(&node.step(NOW + 90, Input::Tick)), 1);
    node.step(NOW + 200, key_published(12, e3(1), committee(), Vec::new()));
    assert_eq!(keys_sent(&node.step(NOW + 5_000, Input::Tick)), 0);
}
