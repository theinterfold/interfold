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
use alloy_primitives::Address;
use e3_committee::CiphernodesCommitteeSize;
use e3_protocol::{
    node::ChainFact,
    testing::{address, e3, ATTESTATION, CIPHERTEXT, DECRYPTION_DEADLINE, INTERFOLD, TIMING},
};

const FAULTS: Faults = Faults {
    crash: 0.1,
    max_delay: 5,
    duplicate: 0.2,
};

/// A committee, then one operator outside it; the first member reads the chain 30 seconds late.
/// The chain requests the E3, finalizes the committee, and publishes the ciphertext once the DKG
/// window has passed.
fn committee(size: CiphernodesCommitteeSize, seed: u64) -> (Sim, Vec<Address>) {
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
            interfold: INTERFOLD,
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
    sim.chain(
        TIMING.deadline + 500,
        ChainFact::CiphertextReady {
            e3: e3(1),
            ciphertext: CIPHERTEXT,
            deadline: DECRYPTION_DEADLINE,
        },
    );
    (sim, members)
}
