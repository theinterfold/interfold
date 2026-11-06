// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{committee, committee_with};
use crate::RealJobs;
use e3_committee::CiphernodesCommitteeSize;
use e3_protocol::{
    node::Transaction,
    testing::{e3, DECRYPTION_DEADLINE},
};
use std::collections::BTreeSet;

#[test]
fn the_committee_decrypts_one_plaintext_and_every_node_sees_the_e3_complete() {
    for size in [
        CiphernodesCommitteeSize::Minimum,
        CiphernodesCommitteeSize::Micro,
    ] {
        for seed in 0..16 {
            let mut sim = committee(size, seed);
            sim.run_until(DECRYPTION_DEADLINE);
            let case = format!("{size:?} seed {seed}");
            let plaintexts: BTreeSet<_> = sim
                .submissions()
                .iter()
                .filter_map(|submission| match &submission.transaction {
                    Transaction::PublishPlaintext(publication) => Some(publication.plaintext),
                    _ => None,
                })
                .collect();
            assert_eq!(plaintexts.len(), 1, "{case}: one plaintext");
            for (index, node) in sim.nodes().iter().enumerate() {
                assert_eq!(node.node(), node.shadow(), "{case} node {index}");
                assert!(
                    node.node().e3(&e3(1)).is_none(),
                    "{case} node {index}: ended"
                );
            }
        }
    }
}

/// The same run with the real job runners: the committee's key, shares, and decryption are real
/// threshold BFV, so the published plaintext must be the requester's message.
#[test]
fn with_real_threshold_bfv_the_committee_decrypts_the_requester_s_message() {
    let size = CiphernodesCommitteeSize::Minimum;
    let message = vec![3, 1, 4, 1, 5];
    for seed in 0..2 {
        let jobs = RealJobs::new(size.values().n + 1, message.clone());
        let mut sim = committee_with(size, seed, jobs);
        sim.run_until(DECRYPTION_DEADLINE);
        let plaintexts: Vec<_> = sim
            .submissions()
            .iter()
            .filter_map(|submission| match &submission.transaction {
                Transaction::PublishPlaintext(publication) => Some(publication.plaintext),
                _ => None,
            })
            .collect();
        let first = plaintexts.first().expect("a published plaintext");
        let values = sim.jobs().values(first);
        assert_eq!(values[..message.len()], message[..], "seed {seed}");
    }
}
