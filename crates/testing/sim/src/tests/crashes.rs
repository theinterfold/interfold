// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::SimNode;
use e3_protocol::{
    dkg::DkgSignature,
    node::{ChainFact, FailureReason, Input, Purpose, Signing, Stage},
    proof::ProofType,
    testing::{
        address, chain, e3, finalized, key_checked, key_from, key_made, own_key, requested, sign,
        ME,
    },
    UnixSecs,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Held, repeated, non-member, and late keys; a DKG through its key cutoff; finalization without
/// this node; completion; and a slashable failure through the end of its grace.
fn lifecycle() -> Vec<(UnixSecs, Input)> {
    let own = own_key(0xee);
    let own_key_signed = sign(
        ME,
        &Signing {
            e3: e3(1),
            purpose: Purpose::Dkg(DkgSignature::EncryptionKeyProof),
            hashes: vec![own.proof.payload_signing_hash(e3(1), ProofType::C0PkBfv)],
        },
    );
    vec![
        (0, chain(1, ChainFact::VoteValidity { secs: 600 })),
        (5, key_from(e3(1), 1)),
        (6, key_from(e3(2), 2)),
        (10, requested(2, e3(1))),
        (11, requested(3, e3(2))),
        (12, requested(4, e3(3))),
        (13, key_from(e3(1), 1)),
        (14, key_from(e3(1), 3)),
        (20, finalized(5, e3(1), [ME, 1, 2].map(address).to_vec())),
        (21, finalized(6, e3(3), [1, 2, 3].map(address).to_vec())),
        (22, key_made(e3(1), own)),
        (23, own_key_signed),
        (24, key_checked(e3(1), 1, true)),
        (
            31,
            chain(
                7,
                ChainFact::StageChanged {
                    e3: e3(2),
                    stage: Stage::Complete,
                },
            ),
        ),
        (32, key_from(e3(2), 4)),
        (33, key_from(e3(4), 5)),
        (91_000, Input::Tick),
        (
            91_100,
            chain(
                8,
                ChainFact::Failed {
                    e3: e3(1),
                    reason: FailureReason::DkgInvalidShares,
                },
            ),
        ),
        (300_000, Input::Tick),
    ]
}

#[test]
fn a_node_that_crashes_at_random_steps_ends_where_an_uncrashed_node_ends() {
    for seed in 0..64 {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut node = SimNode::new(ME, rng.random_range(1..=4));
        for (now, input) in lifecycle() {
            if rng.random_bool(0.3) {
                node.crash_and_restart();
            }
            node.apply(now, input);
        }
        node.crash_and_restart();
        assert_eq!(node.node(), node.shadow(), "seed {seed}");
    }
}
