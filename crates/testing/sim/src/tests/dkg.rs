// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::committee;
use crate::{Sim, SimNode};
use alloy_primitives::Address;
use e3_committee::CiphernodesCommitteeSize;
use e3_protocol::{
    dkg::DkgMessage,
    node::{Body, Transaction},
    testing::{e3, TIMING},
};
use std::collections::{BTreeMap, BTreeSet};

/// The run through selection and the DKG, stopped just before the DKG deadline, with the
/// committee the chain finalized.
fn run(size: CiphernodesCommitteeSize, seed: u64) -> (Sim, Vec<Address>) {
    let mut sim = committee(size, seed);
    sim.run_until(TIMING.deadline - 1);
    let members = sim
        .committee(&e3(1))
        .expect("a finalized committee")
        .to_vec();
    assert_eq!(members.len(), size.values().n);
    (sim, members)
}

/// The nodes in the committee.
fn members_of<'a>(sim: &'a Sim, members: &'a [Address]) -> impl Iterator<Item = &'a SimNode> {
    sim.nodes()
        .iter()
        .filter(|node| members.contains(&node.address()))
}

/// Under loss a slow member can miss shares until the others publish the key without it, so its
/// views stay partial; whatever views a member holds must agree.
#[test]
fn every_member_collects_every_key_and_ready_reports_agree_on_contributions() {
    for size in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
    ] {
        for seed in 0..16 {
            let (sim, members) = run(size, seed);
            let case = format!("{size:?} seed {seed}");
            for (index, node) in sim.nodes().iter().enumerate() {
                assert_eq!(node.node(), node.shadow(), "{case} node {index}");
                let state = node.node().e3(&e3(1));
                if !members.contains(&node.address()) {
                    assert!(state.is_none(), "{case}: the outsider ended the E3");
                    continue;
                }
                let dkg = state
                    .and_then(|state| state.dkg.as_ref())
                    .expect("a member runs the DKG");
                assert_eq!(dkg.valid_keys().len(), members.len(), "{case} node {index}");
                for report in members.iter().filter_map(|member| dkg.ready(member)) {
                    for dealer in report {
                        let own = dkg.ready(&dealer.member);
                        let agrees = own.is_none_or(|own| own.contains(dealer));
                        assert!(agrees, "{case} node {index}: {dealer:?}");
                    }
                }
            }
        }
    }
}

#[test]
fn members_that_accept_a_roster_accept_the_same_one() {
    for size in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
    ] {
        for seed in 0..16 {
            let (sim, members) = run(size, seed);
            let case = format!("{size:?} seed {seed}");
            let rosters: Vec<_> = members_of(&sim, &members)
                .filter_map(|node| {
                    let dkg = node.node().e3(&e3(1)).and_then(|state| state.dkg.as_ref());
                    dkg.and_then(|dkg| dkg.roster()).map(<[_]>::to_vec)
                })
                .collect();
            let h = size.values().h;
            assert!(
                rosters.len() >= h,
                "{case}: every roster member accepted it"
            );
            assert!(
                rosters.iter().all(|roster| *roster == rosters[0]),
                "{case}: members accepted different rosters"
            );
            assert_eq!(rosters[0].len(), h, "{case}");
        }
    }
}

#[test]
fn every_roster_member_and_only_they_send_one_keyshare() {
    for size in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
    ] {
        for seed in 0..16 {
            let (sim, members) = run(size, seed);
            let case = format!("{size:?} seed {seed}");
            let roster: BTreeSet<Address> = members_of(&sim, &members)
                .find_map(|node| {
                    let dkg = node.node().e3(&e3(1)).and_then(|state| state.dkg.as_ref());
                    dkg.and_then(|dkg| dkg.roster())
                })
                .expect("a member accepted the roster")
                .iter()
                .map(|dealer| dealer.member)
                .collect();
            let mut keyshares: BTreeMap<Address, BTreeSet<_>> = BTreeMap::new();
            for message in sim.gossip() {
                if let Body::Dkg(DkgMessage::Keyshare(keyshare)) = &message.body {
                    keyshares
                        .entry(message.sender)
                        .or_default()
                        .insert(keyshare.pk_share);
                }
            }
            let senders: BTreeSet<Address> = keyshares.keys().copied().collect();
            assert_eq!(senders, roster, "{case}: keyshare senders");
            assert!(keyshares.values().all(|sent| sent.len() == 1), "{case}");
            assert!(
                roster.iter().all(|member| members.contains(member)),
                "{case}"
            );
        }
    }
}

#[test]
fn the_committee_publishes_one_key_and_every_member_sees_the_dkg_end() {
    for size in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
    ] {
        for seed in 0..16 {
            let (sim, members) = run(size, seed);
            let case = format!("{size:?} seed {seed}");
            let commitments: BTreeSet<_> = sim
                .submissions()
                .iter()
                .filter_map(|submission| match &submission.transaction {
                    Transaction::PublishCommittee(publication) => Some(publication.commitment),
                    _ => None,
                })
                .collect();
            assert_eq!(commitments.len(), 1, "{case}: one key");
            for (index, node) in members_of(&sim, &members).enumerate() {
                let dkg = node.node().e3(&e3(1)).and_then(|state| state.dkg.as_ref());
                let published = dkg.is_some_and(|dkg| dkg.published());
                assert!(published, "{case} node {index}: the DKG ended with the key");
            }
        }
    }
}

#[test]
fn no_member_sends_two_different_keys_or_shares() {
    for size in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
    ] {
        for seed in 0..16 {
            let (sim, members) = run(size, seed);
            let case = format!("{size:?} seed {seed}");
            let mut keys: BTreeMap<Address, BTreeSet<_>> = BTreeMap::new();
            let mut shares: BTreeMap<(Address, Address), BTreeSet<_>> = BTreeMap::new();
            for message in sim.gossip() {
                match &message.body {
                    Body::Dkg(DkgMessage::EncryptionKey(key)) => {
                        keys.entry(message.sender).or_default().insert(key.key);
                    }
                    Body::Dkg(DkgMessage::Shares(dealt)) => {
                        let pair = (message.sender, dealt.recipient);
                        shares.entry(pair).or_default().insert(dealt.shares);
                    }
                    Body::Dkg(
                        DkgMessage::Ready(_)
                        | DkgMessage::Roster(_)
                        | DkgMessage::DecryptionKey(_)
                        | DkgMessage::Keyshare(_)
                        | DkgMessage::NodeFold(_),
                    )
                    | Body::Decryption(_)
                    | Body::Accusation(_) => {}
                }
            }
            assert_eq!(
                keys.len(),
                members.len(),
                "{case}: every member sent its key"
            );
            assert!(
                keys.values().all(|sent| sent.len() == 1),
                "{case}: two keys"
            );
            let pairs = members.len() * (members.len() - 1);
            assert_eq!(
                shares.len(),
                pairs,
                "{case}: every dealer reached every member"
            );
            assert!(
                shares.values().all(|sent| sent.len() == 1),
                "{case}: two shares"
            );
        }
    }
}
