// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::committee;
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
            let (mut sim, _) = committee(size, seed);
            sim.run_until(DECRYPTION_DEADLINE);
            let case = format!("{size:?} seed {seed}");
            let plaintexts: BTreeSet<_> = sim
                .submissions()
                .iter()
                .filter_map(|submission| match &submission.transaction {
                    Transaction::PublishPlaintext(publication) => Some(publication.plaintext),
                    Transaction::PublishCommittee(_) => None,
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
