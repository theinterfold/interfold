// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_protocol::testing::TIMING;

/// A dealer that signs a C2a proof that fails is left out of the roster, accused by the members
/// that check it, and slashed out of the committee, which publishes its key without it.
#[test]
fn a_dealer_whose_signed_proof_fails_is_slashed_and_the_others_publish_the_key() {
    let size = CiphernodesCommitteeSize::Minimum;
    for seed in 0..8 {
        let mut honest = committee(size, seed);
        honest.run_until(TIMING.deadline - 1);
        let faulty = honest.committee(&e3(1)).expect("a finalized committee")[0];

        let mut sim = committee_with(size, seed, MockJobs::with_faulty(seed, faulty));
        sim.run_until(TIMING.deadline - 1);
        let case = format!("seed {seed}");
        let expelled = sim.expelled(&e3(1)).expect("the request");
        assert_eq!(expelled.iter().collect::<Vec<_>>(), [&faulty], "{case}");
        assert!(sim.key_published(&e3(1)), "{case}");
    }
}
