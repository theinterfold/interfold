// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The claim proof of the private round.
//!
//! A bidder opens the commitment of the bid that counted, and shows how the step `b` of that bid
//! compares with the step `k` of the clearing, without showing `b`. The contract stores
//! `bid_commitment` for each version of each bidder, and it takes `k` from the clearing.
//!
//! `cmp` is 0 if `b < k`, 1 if `b == k` and 2 if `b > k`. Only the bidder knows `b` and `salt`.
//! `bidder` and `e3_id` are in the commitment, so a proof is useful for one bidder in one round.
//!
//! Public inputs, in order: `bid_commitment`, `bidder`, `e3_id`, `k`, then the returned `cmp`.
//! See `circuits/PUBLIC_INPUTS.md`.

use poseidon::poseidon2::Poseidon2;

/// The domain of the bid commitment: the ASCII bytes of `prnd-bid-v1`. The bid circuit uses the
/// same value.
pub global BID_DOMAIN: Field = 0x70726e642d6269642d7631;

/// A step is below `STEP_BITS` bits. A round has at most 16 steps, so 4 bits are enough.
pub global STEP_BITS: u32 = 4;

/// The commitment of a bid: it opens to `b` and `salt` for one bidder in one round.
pub fn compute_bid_commitment(b: Field, salt: Field, bidder: Field, e3_id: Field) -> Field {
    Poseidon2::hash([BID_DOMAIN, b, salt, bidder, e3_id], 5)
}

/// 0 if `b < k`, 1 if `b == k`, 2 if `b > k`. Both are below `2^STEP_BITS`.
pub fn compare(b: Field, k: Field) -> Field {
    b.assert_max_bit_size::<STEP_BITS>();
    k.assert_max_bit_size::<STEP_BITS>();
    let (b, k) = (b as u32, k as u32);
    if b < k {
        0
    } else if b == k {
        1
    } else {
        2
    }
}

fn main(
    bid_commitment: pub Field,
    bidder: pub Field,
    e3_id: pub Field,
    k: pub Field,
    b: Field,
    salt: Field,
) -> pub Field {
    // The circuit constrains `bidder`, so no compiler pass can treat it as unused.
    assert(bidder != 0);
    assert(
        compute_bid_commitment(b, salt, bidder, e3_id) == bid_commitment,
        "the bid commitment does not open to the bid",
    );
    compare(b, k)
}

#[test]
fn compares_the_bid_with_the_step() {
    assert(compare(2, 5) == 0);
    assert(compare(5, 5) == 1);
    assert(compare(9, 5) == 2);
    assert(compare(0, 0) == 1);
    assert(compare(15, 0) == 2);
    assert(compare(0, 15) == 0);
    assert(compare(15, 15) == 1);
}

#[test(should_fail)]
fn rejects_a_bid_beyond_the_steps() {
    // `16` is a valid `u32`, but not a step.
    let _ = compare(16, 3);
}

#[test(should_fail)]
fn rejects_a_step_beyond_the_steps() {
    let _ = compare(3, 16);
}

#[test(should_fail)]
fn rejects_a_wrapped_bid() {
    // A negative step in the field is a huge value, not a small one.
    let _ = compare(-1, 3);
}

#[test]
fn the_commitment_opens_for_the_bid() {
    let commitment = compute_bid_commitment(7, 12345, 0xabc, 4);
    assert(commitment == compute_bid_commitment(7, 12345, 0xabc, 4));
    assert(commitment != compute_bid_commitment(8, 12345, 0xabc, 4));
    assert(commitment != compute_bid_commitment(7, 12346, 0xabc, 4));
    assert(commitment != compute_bid_commitment(7, 12345, 0xabd, 4));
    assert(commitment != compute_bid_commitment(7, 12345, 0xabc, 5));
}

#[test]
fn the_circuit_accepts_an_opening() {
    let commitment = compute_bid_commitment(7, 12345, 0xabc, 4);
    assert(main(commitment, 0xabc, 4, 5, 7, 12345) == 2);
    assert(main(commitment, 0xabc, 4, 7, 7, 12345) == 1);
    assert(main(commitment, 0xabc, 4, 9, 7, 12345) == 0);
}

#[test(should_fail_with = "the bid commitment does not open to the bid")]
fn the_circuit_rejects_another_step_than_committed() {
    let commitment = compute_bid_commitment(7, 12345, 0xabc, 4);
    let _ = main(commitment, 0xabc, 4, 5, 3, 12345);
}

#[test(should_fail_with = "the bid commitment does not open to the bid")]
fn the_circuit_rejects_another_bidder() {
    let commitment = compute_bid_commitment(7, 12345, 0xabc, 4);
    let _ = main(commitment, 0xabd, 4, 5, 7, 12345);
}

#[test(should_fail_with = "the bid commitment does not open to the bid")]
fn the_circuit_rejects_another_round() {
    let commitment = compute_bid_commitment(7, 12345, 0xabc, 4);
    let _ = main(commitment, 0xabc, 5, 5, 7, 12345);
}
