// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::Address;
use e3_committee::CiphernodesCommitteeSize;
use e3_protocol::{
    dkg::DkgMessage,
    node::{Body, ChainFact},
    testing::{address, e3, TIMING},
};
use e3_sim::{Faults, Sim};
use std::collections::{BTreeMap, BTreeSet};

const FAULTS: Faults = Faults {
    crash: 0.1,
    max_delay: 5,
    duplicate: 0.2,
};

#[test]
fn every_member_collects_every_key_despite_crashes_and_a_lagging_chain_reader() {
    for size in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
    ] {
        let n = size.values().n;
        // The committee, then one operator outside it.
        let operators: Vec<u64> = (1..=n as u64 + 1).collect();
        let members: Vec<Address> = operators[..n].iter().map(|&o| address(o)).collect();
        for seed in 0..16 {
            let mut sim = Sim::new(seed, &operators, FAULTS);
            sim.set_chain_lag(0, 30);
            sim.chain(
                0,
                ChainFact::E3Requested {
                    e3: e3(1),
                    committee_size: size,
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
            sim.run_until(TIMING.deadline);

            for (index, node) in sim.nodes().iter().enumerate() {
                assert_eq!(
                    node.node(),
                    node.shadow(),
                    "{size:?} seed {seed} node {index}"
                );
                let state = node.node().e3(&e3(1));
                if index == n {
                    assert!(
                        state.is_none(),
                        "{size:?} seed {seed}: the outsider ended the E3"
                    );
                    continue;
                }
                let dkg = state
                    .and_then(|state| state.dkg.as_ref())
                    .expect("a member runs the DKG");
                assert!(dkg.keys_collected(), "{size:?} seed {seed} node {index}");
                assert_eq!(
                    dkg.valid_keys().len(),
                    n,
                    "{size:?} seed {seed} node {index}"
                );
            }

            let mut keys: BTreeMap<Address, BTreeSet<_>> = BTreeMap::new();
            for message in sim.gossip() {
                let Body::Dkg(DkgMessage::EncryptionKey(key)) = &message.body;
                keys.entry(message.sender).or_default().insert(key.key);
            }
            assert_eq!(
                keys.len(),
                n,
                "{size:?} seed {seed}: every member sent its key"
            );
            assert!(
                keys.values().all(|sent| sent.len() == 1),
                "{size:?} seed {seed}: a member sent two different keys"
            );
        }
    }
}
