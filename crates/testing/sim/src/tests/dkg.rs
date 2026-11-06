// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Faults, Sim};
use alloy_primitives::Address;
use e3_committee::CiphernodesCommitteeSize;
use e3_protocol::{
    dkg::DkgMessage,
    node::{Body, ChainFact, Transaction},
    testing::{address, e3, ATTESTATION, TIMING},
};
use std::collections::{BTreeMap, BTreeSet};

const FAULTS: Faults = Faults {
    crash: 0.1,
    max_delay: 5,
    duplicate: 0.2,
};

/// A committee, then one operator outside it; the first member reads the chain 30 seconds late.
fn run(size: CiphernodesCommitteeSize, seed: u64) -> (Sim, Vec<Address>) {
    let n = size.values().n;
    let operators: Vec<u64> = (1..=n as u64 + 1).collect();
    let mut members: Vec<Address> = operators[..n].iter().map(|&o| address(o)).collect();
    members.sort();
    let mut sim = Sim::new(seed, &operators, FAULTS);
    sim.set_chain_lag(0, 30);
    sim.chain(
        0,
        ChainFact::E3Requested {
            e3: e3(1),
            committee_size: size,
            attestation: ATTESTATION,
        },
    );
    sim.chain(
        10,
        ChainFact::CommitteeFinalized {
            e3: e3(1),
            members: members.clone(),
            dkg: TIMING,
        },
    );
    sim.run_until(TIMING.deadline - 1);
    (sim, members)
}

#[test]
fn every_member_verifies_every_dealer_despite_crashes_and_a_lagging_chain_reader() {
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
                if index == members.len() {
                    assert!(state.is_none(), "{case}: the outsider ended the E3");
                    continue;
                }
                let dkg = state
                    .and_then(|state| state.dkg.as_ref())
                    .expect("a member runs the DKG");
                assert_eq!(dkg.valid_keys().len(), members.len(), "{case} node {index}");
                for member in &members {
                    let report = dkg.ready(member).unwrap_or_default();
                    let named: Vec<Address> = report.iter().map(|dealer| dealer.member).collect();
                    assert_eq!(named, members, "{case} node {index}: Ready of {member}");
                    // A roster needs every report to name the same contribution for a dealer.
                    for dealer in report {
                        let own = dkg.ready(&dealer.member).unwrap_or_default();
                        assert!(own.contains(dealer), "{case} node {index}: {dealer:?}");
                    }
                }
            }
        }
    }
}

#[test]
fn every_member_accepts_the_same_roster_of_h_dealers() {
    for size in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
    ] {
        for seed in 0..16 {
            let (sim, members) = run(size, seed);
            let case = format!("{size:?} seed {seed}");
            let rosters: Vec<_> = sim.nodes()[..members.len()]
                .iter()
                .map(|node| {
                    let dkg = node.node().e3(&e3(1)).and_then(|state| state.dkg.as_ref());
                    dkg.and_then(|dkg| dkg.roster()).map(<[_]>::to_vec)
                })
                .collect();
            let roster = rosters[0]
                .clone()
                .expect("the first member accepted a roster");
            assert!(
                rosters.iter().all(|other| other.as_ref() == Some(&roster)),
                "{case}: members accepted different rosters"
            );
            assert_eq!(roster.len(), size.values().h, "{case}");
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
            let roster: BTreeSet<Address> = sim.nodes()[0]
                .node()
                .e3(&e3(1))
                .and_then(|state| state.dkg.as_ref())
                .and_then(|dkg| dkg.roster())
                .expect("a roster")
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
                .map(|submission| match &submission.transaction {
                    Transaction::PublishCommittee(publication) => publication.commitment,
                })
                .collect();
            assert_eq!(commitments.len(), 1, "{case}: one key");
            for (index, node) in sim.nodes()[..members.len()].iter().enumerate() {
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
                    ) => {}
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
