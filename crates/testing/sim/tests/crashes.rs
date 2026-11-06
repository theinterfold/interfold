// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::{Address, B256, U256};
use e3_protocol::{
    dkg::DkgMessage,
    node::{Body, ChainEvent, ChainFact, FailureReason, Input, LogPosition, PeerMessage, Stage},
    BlobRef, E3Id, UnixSecs,
};
use e3_sim::SimNode;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

const ME: Address = Address::repeat_byte(0xaa);

fn e3(number: u64) -> E3Id {
    E3Id {
        chain_id: 1,
        number: U256::from(number),
    }
}

fn chain(block: u64, fact: ChainFact) -> Input {
    Input::Chain(ChainEvent {
        at: LogPosition {
            chain_id: 1,
            block,
            log_index: 0,
        },
        fact,
    })
}

fn key(e3: E3Id, sender: u8) -> Input {
    Input::Peer(PeerMessage {
        e3,
        sender: Address::repeat_byte(sender),
        body: Body::Dkg(DkgMessage::EncryptionKey(BlobRef {
            hash: B256::repeat_byte(sender),
            len: 1_000,
        })),
    })
}

/// Admissions, early and late keys, finalization with and without this node, both kinds of
/// failure, completion, and the end of an accusation grace.
fn lifecycle() -> Vec<(UnixSecs, Input)> {
    vec![
        (0, chain(1, ChainFact::VoteValidity { secs: 600 })),
        (5, key(e3(1), 1)),
        (6, key(e3(2), 2)),
        (10, chain(2, ChainFact::E3Requested { e3: e3(1) })),
        (11, chain(3, ChainFact::E3Requested { e3: e3(2) })),
        (12, chain(4, ChainFact::E3Requested { e3: e3(3) })),
        (13, key(e3(1), 1)),
        (14, key(e3(1), 3)),
        (
            20,
            chain(
                5,
                ChainFact::CommitteeFinalized {
                    e3: e3(1),
                    members: vec![ME, Address::repeat_byte(1)],
                },
            ),
        ),
        (
            21,
            chain(
                6,
                ChainFact::CommitteeFinalized {
                    e3: e3(3),
                    members: vec![Address::repeat_byte(1)],
                },
            ),
        ),
        (
            30,
            chain(
                7,
                ChainFact::Failed {
                    e3: e3(1),
                    reason: FailureReason::DkgInvalidShares,
                },
            ),
        ),
        (
            31,
            chain(
                8,
                ChainFact::StageChanged {
                    e3: e3(2),
                    stage: Stage::Complete,
                },
            ),
        ),
        (32, key(e3(2), 4)),
        (33, key(e3(4), 5)),
        (90_000, Input::Tick),
        (200_000, Input::Tick),
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
