// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{
    dkg::{DkgFailure, DkgWork, KeyshareMessage},
    node::{ChainFact, Job, Work},
};

fn decryption_key_jobs(effects: &[Effect]) -> Vec<&DkgWork> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Run(Job {
                work: Work::Dkg(work @ DkgWork::MakeDecryptionKey { .. }),
                ..
            }) => Some(work),
            _ => None,
        })
        .collect()
}

fn checks_of_decryption_keys(effects: &[Effect]) -> Vec<Address> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Run(Job {
                work: Work::Dkg(DkgWork::CheckDecryptionKey { member, .. }),
                ..
            }) => Some(*member),
            _ => None,
        })
        .collect()
}

fn keyshares_sent(effects: &[Effect]) -> Vec<&KeyshareMessage> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Gossip(PeerMessage {
                body: Body::Dkg(DkgMessage::Keyshare(keyshare)),
                ..
            }) => Some(keyshare),
            _ => None,
        })
        .collect()
}

#[test]
fn a_roster_member_sums_the_other_roster_dealers_shares_and_binds_every_roster_c2() {
    let [first, second, _] = ordered();
    let (_, effects) = first_with_roster();
    let [DkgWork::MakeDecryptionKey { shares, c2, .. }] = decryption_key_jobs(&effects)[..] else {
        panic!("one decryption key job, got {effects:?}");
    };
    assert_eq!(
        shares.keys().copied().collect::<Vec<_>>(),
        members(&[second])
    );
    assert_eq!(
        c2.keys().copied().collect::<Vec<_>>(),
        members(&[first, second])
    );
}

#[test]
fn a_member_outside_the_roster_makes_no_decryption_key_but_checks_the_roster_s() {
    let [first, second, third] = ordered();
    let mut node = verified_all(third);
    node.step(NOW, ready(first, &[first, second, third], third));
    node.step(NOW, ready(second, &[first, second, third], third));
    let effects = node.step(NOW, roster(first, &[first, second], third));
    assert_eq!(accepted(&node), Some(members(&[first, second])));
    assert!(decryption_key_jobs(&effects).is_empty());
    let effects = node.step(NOW, decryption_key(e3(1), first, first));
    assert_eq!(checks_of_decryption_keys(&effects), members(&[first]));
}

#[test]
fn the_keyshare_waits_for_every_other_roster_member_s_c4_verdict() {
    let [_, second, _] = ordered();
    let mut node = first_with_decryption_key();
    assert_eq!(
        checks_of_decryption_keys(&node.step(NOW, decryption_key(e3(1), second, second))),
        members(&[second])
    );
    let effects = node.step(NOW, decryption_key_checked(e3(1), second, true));
    let own = own_shares(&[]);
    let [keyshare] = keyshares_sent(&effects)[..] else {
        panic!("one keyshare, got {effects:?}");
    };
    assert_eq!(keyshare.pk_share, own.pk_share);
    assert_eq!(keyshare.c1.proof, own.c1);
}

#[test]
fn c4_proofs_are_checked_only_when_signed_by_their_member() {
    let [first, second, _] = ordered();
    let mut node = first_with_decryption_key();
    assert!(node
        .step(NOW, decryption_key(e3(1), second, first))
        .is_empty());
}

#[test]
fn c4_proofs_sent_before_the_roster_are_checked_once_it_is_accepted() {
    let [first, second, third] = ordered();
    let mut node = verified_all(first);
    assert!(node
        .step(NOW, decryption_key(e3(1), second, second))
        .is_empty());
    let effects = node.step(NOW, ready(second, &[first, second, third], first));
    assert_eq!(checks_of_decryption_keys(&effects), members(&[second]));
}

#[test]
fn t_or_fewer_valid_decryption_keys_fail_the_dkg() {
    let [_, second, _] = ordered();
    let mut node = first_with_decryption_key();
    node.step(NOW, decryption_key(e3(1), second, second));
    let effects = node.step(NOW, decryption_key_checked(e3(1), second, false));
    assert!(keyshares_sent(&effects).is_empty());
    assert_eq!(
        dkg(&node).failure(),
        Some(DkgFailure::TooFewValidDecryptionKeys)
    );
}

#[test]
fn expelling_a_roster_member_fails_the_dkg() {
    let [_, second, _] = ordered();
    let mut node = first_with_decryption_key();
    let expelled = ChainFact::MemberExpelled {
        e3: e3(1),
        member: address(second),
    };
    node.step(NOW, chain(12, expelled));
    assert_eq!(dkg(&node).failure(), Some(DkgFailure::RosterMemberExpelled));
}
