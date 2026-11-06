// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Properties of v2 nodes under crashes, lag, and network faults. They live in the library so that
//! the repository's `--lib` test runs include them.

mod crashes;
mod decryption;
mod dkg;

use crate::{Faults, Sim};
use alloy_primitives::U256;
use e3_committee::CiphernodesCommitteeSize;
use e3_protocol::{
    node::ChainFact,
    testing::{
        address, e3, params, ATTESTATION, CIPHERTEXT, DECRYPTION_DEADLINE, INTERFOLD, REQUEST,
        TIMING,
    },
};

const FAULTS: Faults = Faults {
    crash: 0.1,
    max_delay: 5,
    duplicate: 0.2,
    drop: 0.1,
};

/// One operator more than the committee needs, each active with ten tickets and its own bond
/// owner; the first reads the chain 30 seconds late. The chain requests the E3, readies its seed,
/// and publishes the ciphertext once the DKG window has passed; the operators select and finalize
/// the committee themselves.
fn committee(size: CiphernodesCommitteeSize, seed: u64) -> Sim {
    let operators: Vec<u64> = (1..=size.values().n as u64 + 1).collect();
    let mut sim = Sim::new(seed, &operators, FAULTS);
    sim.set_chain_lag(0, 30);
    for operator in operators.iter().map(|operator| address(*operator)) {
        sim.chain(
            0,
            ChainFact::OperatorActive {
                operator,
                active: true,
            },
        );
        let balance = U256::from(10);
        sim.chain(0, ChainFact::TicketBalance { operator, balance });
        sim.chain(
            0,
            ChainFact::BondOwner {
                operator,
                owner: operator,
            },
        );
    }
    sim.chain(
        1,
        ChainFact::E3Requested {
            e3: e3(1),
            params: params(size),
            interfold: INTERFOLD,
            attestation: ATTESTATION,
            request: REQUEST,
        },
    );
    sim.chain(
        5,
        ChainFact::SeedReady {
            e3: e3(1),
            seed: U256::from(seed),
            committee_deadline: 100,
        },
    );
    sim.chain(
        TIMING.deadline + 500,
        ChainFact::CiphertextReady {
            e3: e3(1),
            ciphertext: CIPHERTEXT,
            deadline: DECRYPTION_DEADLINE,
        },
    );
    sim
}
