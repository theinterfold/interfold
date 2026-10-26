// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The claim proof of the token launch.
//!
//! A bidder claims tokens and a refund at a FRESH address, without showing which bid is theirs. The
//! proof shows that the claimant knows the opening of a bid commitment that is a leaf of the claim
//! tree (`root`), that the bid was counted (`counted_mask`), how its step `b` compares with the
//! step `k` of the clearing, and the nullifier that stops a second claim. `bidder` and the leaf
//! index stay private, so a claim does not link to the `BidSubmitted` event of the bid.
//!
//! - `commitment = Poseidon2([BID_DOMAIN, b, B, X, salt, bidder, sale_id])`: the commitment of the
//!   bid circuit, with `X = escrow_units`.
//! - The tree is the contract's `InternalLazyIMT`: depth `CLAIM_TREE_DEPTH`, the node hash is
//!   circomlib `Poseidon(2)` (`poseidon::poseidon::bn254::hash_2`), and bit `k` of the leaf index
//!   is 1 if the node is the right child at level `k`.
//! - `counted_mask` is an 85-bit value: bit `i` is 1 if the bid with the leaf index `i` counted in
//!   both rounds of the sale.
//! - `nullifier = Poseidon2([NULLIFIER_DOMAIN, salt, sale_id])`.
//! - `cmp` is 0 if `b < k`, 1 if `b == k` and 2 if `b > k`. `budget_units` is `B` if `cmp != 0` and 0
//!   otherwise: a loser (`cmp == 0`) does not show its budget, and the contract needs it only to
//!   compute the payment of a winner.
//! - `recipient` is a public input only so that the proof binds it: a relayer cannot swap it.
//! - `reveal_index` is 1 only while the contract registers marginal claims (a capped sale before its
//!   marginal deadline). Then a claim with `cmp == 1` also returns `index_plus_one = index + 1`: a
//!   marginal bid is filled in bid order, so it must show its position. Every other claim returns 0
//!   and stays unlinkable.
//!
//! Public inputs, in order: `root`, `counted_mask`, `sale_id`, `k`, `nullifier`, `recipient`,
//! `escrow_units`, `budget_units`, `reveal_index`, then the returned `cmp` and `index_plus_one`.
//! See `circuits/PUBLIC_INPUTS.md`.

use poseidon::poseidon::bn254::hash_2;
use poseidon::poseidon2::Poseidon2;

/// The depth of the claim tree: 128 leaves, at least `MAX_BIDDERS`.
pub global CLAIM_TREE_DEPTH: u32 = 7;

/// The leaves of the claim tree.
pub global LEAVES: u32 = 128;

/// The most bidders of a sale: the bits of `counted_mask`.
pub global MAX_BIDDERS: u32 = 85;

/// The domain of the bid commitment: the ASCII bytes of `tlaunch-bid-v1`. The bid circuit uses the
/// same value.
pub global BID_DOMAIN: Field = 0x746c61756e63682d6269642d7631;

/// The domain of the nullifier: the ASCII bytes of `tlaunch-null-v1`.
pub global NULLIFIER_DOMAIN: Field = 0x746c61756e63682d6e756c6c2d7631;

/// A step is below `STEP_BITS` bits. A sale has at most 16 steps, so 4 bits are enough.
pub global STEP_BITS: u32 = 4;

/// The commitment of a bid: it opens to the step, the budget and the escrow, with a salt, for one
/// bidder in one sale.
pub fn compute_bid_commitment(
    b: Field,
    budget: Field,
    escrow_units: Field,
    salt: Field,
    bidder: Field,
    sale_id: Field,
) -> Field {
    Poseidon2::hash(
        [BID_DOMAIN, b, budget, escrow_units, salt, bidder, sale_id],
        7,
    )
}

pub fn compute_nullifier(salt: Field, sale_id: Field) -> Field {
    Poseidon2::hash([NULLIFIER_DOMAIN, salt, sale_id], 3)
}

/// The root of the claim tree that has `leaf` at the index with the bits `index_bits` and the
/// siblings `path` (bottom up).
pub fn merkle_root(
    leaf: Field,
    index_bits: [bool; CLAIM_TREE_DEPTH],
    path: [Field; CLAIM_TREE_DEPTH],
) -> Field {
    let mut node = leaf;
    for k in 0..CLAIM_TREE_DEPTH {
        node = if index_bits[k] {
            hash_2([path[k], node])
        } else {
            hash_2([node, path[k]])
        };
    }
    node
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

/// Whether the bit `index` of `counted_mask` is 1. `index` is below `LEAVES` (the caller
/// decomposes it into `CLAIM_TREE_DEPTH` bits), `counted_mask` is below `2^MAX_BIDDERS` (the
/// decomposition fails otherwise), so a bit beyond the bidders is 0.
fn counted(counted_mask: Field, index: Field) -> bool {
    let mask_bits: [bool; MAX_BIDDERS] = counted_mask.to_le_bits();
    let mut padded = [false; LEAVES];
    for i in 0..MAX_BIDDERS {
        padded[i] = mask_bits[i];
    }
    padded[index as u32]
}

fn main(
    root: pub Field,
    counted_mask: pub Field,
    sale_id: pub Field,
    k: pub Field,
    nullifier: pub Field,
    recipient: pub Field,
    escrow_units: pub Field,
    budget_units: pub Field,
    reveal_index: pub Field,
    b: Field,
    budget: Field,
    salt: Field,
    bidder: Field,
    index: Field,
    path: [Field; CLAIM_TREE_DEPTH],
) -> pub (Field, Field) {
    // A public input is part of the proof transcript, so the proof verifies only for that
    // `recipient`. The circuit also constrains it, so no compiler pass can treat it as unused.
    assert(recipient != 0);
    assert(reveal_index * (reveal_index - 1) == 0, "reveal_index is not a bit");

    let commitment = compute_bid_commitment(b, budget, escrow_units, salt, bidder, sale_id);
    // Fails if `index` is not below `2^CLAIM_TREE_DEPTH`.
    let index_bits: [bool; CLAIM_TREE_DEPTH] = index.to_le_bits();
    assert(
        merkle_root(commitment, index_bits, path) == root,
        "the commitment is not in the claim tree",
    );
    assert(counted(counted_mask, index), "the bid was not counted");
    assert(
        compute_nullifier(salt, sale_id) == nullifier,
        "the nullifier is not the one of the bid",
    );

    let cmp = compare(b, k);
    let shown = if cmp == 0 { 0 } else { budget };
    assert(budget_units == shown, "the budget shown is not the budget of the bid");
    let index_plus_one = if (cmp == 1) & (reveal_index == 1) {
        index + 1
    } else {
        0
    };
    (cmp, index_plus_one)
}

/// A claim tree with the leaves `leaves` (the others 0) and the path of `index`.
fn tree_of(leaves: [Field; 4]) -> (Field, [Field; CLAIM_TREE_DEPTH]) {
    // The zero values of the empty subtrees: `Z0 = 0`, `Z(k + 1) = hash_2(Z(k), Z(k))`.
    let mut zero = [0; CLAIM_TREE_DEPTH];
    for k in 1..CLAIM_TREE_DEPTH {
        zero[k] = hash_2([zero[k - 1], zero[k - 1]]);
    }
    // The leaves 0..4 hold `leaves`; the leaf 2 is the one of the path.
    let l01 = hash_2([leaves[0], leaves[1]]);
    let l23 = hash_2([leaves[2], leaves[3]]);
    let level2 = hash_2([l01, l23]);
    let mut node = level2;
    for k in 2..CLAIM_TREE_DEPTH {
        node = hash_2([node, zero[k]]);
    }
    // The path of the leaf 2: the sibling 3 at level 0, the node `l01` at level 1, then zeros.
    let mut path = [0; CLAIM_TREE_DEPTH];
    path[0] = leaves[3];
    path[1] = l01;
    for k in 2..CLAIM_TREE_DEPTH {
        path[k] = zero[k];
    }
    (node, path)
}

global SALE: Field = 4;
global BIDDER: Field = 0xabc;
global RECIPIENT: Field = 0xdef;
global SALT: Field = 12345;
/// The leaf index of the claimant in the tests.
global INDEX: Field = 2;
/// The counted bitmap with the bits 0, 2 and 3 set.
global MASK: Field = 13;
global BUDGET: Field = 1500;
global ESCROW: Field = 2000;

/// The inputs of `main` of the claimant of the tests: a bid with the step 7, counted, in a tree of
/// four leaves at the index 2.
struct Case {
    root: Field,
    counted_mask: Field,
    k: Field,
    nullifier: Field,
    recipient: Field,
    escrow_units: Field,
    budget_units: Field,
    reveal_index: Field,
    b: Field,
    budget: Field,
    salt: Field,
    bidder: Field,
    index: Field,
    path: [Field; CLAIM_TREE_DEPTH],
}

/// An honest claim of the bid `b = 7` against the step `k`.
fn honest(k: Field, reveal_index: Field) -> Case {
    let commitment = compute_bid_commitment(7, BUDGET, ESCROW, SALT, BIDDER, SALE);
    let (root, path) = tree_of([111, 222, commitment, 333]);
    Case {
        root,
        counted_mask: MASK,
        k,
        nullifier: compute_nullifier(SALT, SALE),
        recipient: RECIPIENT,
        escrow_units: ESCROW,
        budget_units: if (k as u32) <= 7 { BUDGET } else { 0 },
        reveal_index,
        b: 7,
        budget: BUDGET,
        salt: SALT,
        bidder: BIDDER,
        index: INDEX,
        path,
    }
}

fn run(c: Case) -> (Field, Field) {
    main(
        c.root,
        c.counted_mask,
        SALE,
        c.k,
        c.nullifier,
        c.recipient,
        c.escrow_units,
        c.budget_units,
        c.reveal_index,
        c.b,
        c.budget,
        c.salt,
        c.bidder,
        c.index,
        c.path,
    )
}

#[test]
fn the_zero_values_chain_as_the_contract_computes_them() {
    // The first zero values of `InternalLazyIMT`: Z1 = Poseidon(0, 0).
    let z1 = hash_2([0, 0]);
    assert(z1 == 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864);
}

/// The value `sdk/src/commitments.ts` (Barretenberg Poseidon2) computes for the same inputs:
/// `sdk/src/prover.test.ts` pins it as well.
#[test]
fn the_commitment_equals_the_sdk_value() {
    let bidder = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    assert(
        compute_bid_commitment(7, 1500, 2000, 12345, bidder, 4)
            == 0x2324c51ea4ffd7d2c8e6f0f4f2a34c869e5781e72ebd51021d6b19e7f0771a61,
    );
}

#[test]
fn the_nullifier_and_the_tree_hash_equal_the_sdk_values() {
    assert(
        compute_nullifier(12345, 4)
            == 0x21a2afcf84a2f86125299d906c6c755645eb5b1e47773a190dbaf95872ecd2b6,
    );
    // circomlib Poseidon(1, 2), as `poseidon-lite` and the contract's PoseidonT3 compute it.
    assert(hash_2([1, 2]) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a);
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
    let commitment = compute_bid_commitment(7, 1500, 2000, SALT, BIDDER, SALE);
    assert(commitment != compute_bid_commitment(8, 1500, 2000, SALT, BIDDER, SALE));
    assert(commitment != compute_bid_commitment(7, 1501, 2000, SALT, BIDDER, SALE));
    assert(commitment != compute_bid_commitment(7, 1500, 2001, SALT, BIDDER, SALE));
    assert(commitment != compute_bid_commitment(7, 1500, 2000, SALT + 1, BIDDER, SALE));
    assert(commitment != compute_bid_commitment(7, 1500, 2000, SALT, BIDDER + 1, SALE));
    assert(commitment != compute_bid_commitment(7, 1500, 2000, SALT, BIDDER, SALE + 1));
}

#[test]
fn the_nullifier_depends_on_the_salt_and_the_sale() {
    let nullifier = compute_nullifier(SALT, SALE);
    assert(nullifier != compute_nullifier(SALT + 1, SALE));
    assert(nullifier != compute_nullifier(SALT, SALE + 1));
}

#[test]
fn accepts_a_winner_a_marginal_bid_and_a_loser() {
    // b = 7 against k = 5, 7, 9; the loser shows no budget; nobody shows an index.
    assert(run(honest(5, 0)) == (2, 0));
    assert(run(honest(7, 0)) == (1, 0));
    assert(run(honest(9, 0)) == (0, 0));
}

#[test]
fn a_marginal_claim_shows_its_index_only_when_the_contract_asks() {
    // INDEX = 2: the registration shows `index + 1 = 3`.
    assert(run(honest(7, 1)) == (1, 3));
    // A winner or a loser never shows it, even when the contract asks.
    assert(run(honest(5, 1)) == (2, 0));
    assert(run(honest(9, 1)) == (0, 0));
}

#[test(should_fail_with = "reveal_index is not a bit")]
fn rejects_a_reveal_flag_that_is_not_a_bit() {
    let _ = run(honest(7, 2));
}

#[test(should_fail_with = "the budget shown is not the budget of the bid")]
fn rejects_a_loser_that_shows_its_budget() {
    let mut c = honest(9, 0);
    c.budget_units = BUDGET;
    let _ = run(c);
}

#[test(should_fail_with = "the budget shown is not the budget of the bid")]
fn rejects_a_winner_that_hides_its_budget() {
    let mut c = honest(5, 0);
    c.budget_units = 0;
    let _ = run(c);
}

#[test(should_fail_with = "the budget shown is not the budget of the bid")]
fn rejects_a_winner_that_shows_another_budget() {
    let mut c = honest(5, 0);
    c.budget_units = BUDGET - 1;
    let _ = run(c);
}

#[test(should_fail_with = "the commitment is not in the claim tree")]
fn rejects_a_step_that_is_not_committed() {
    let mut c = honest(5, 0);
    c.b = 6;
    let _ = run(c);
}

#[test(should_fail_with = "the commitment is not in the claim tree")]
fn rejects_another_budget_than_committed() {
    let mut c = honest(5, 0);
    c.budget = BUDGET - 1;
    c.budget_units = BUDGET - 1;
    let _ = run(c);
}

#[test(should_fail_with = "the commitment is not in the claim tree")]
fn rejects_another_root() {
    let mut c = honest(5, 0);
    c.root += 1;
    let _ = run(c);
}

#[test(should_fail_with = "the commitment is not in the claim tree")]
fn rejects_another_leaf_index() {
    // The path of the leaf 2 does not open at the leaf 3.
    let mut c = honest(5, 0);
    c.index = 3;
    let _ = run(c);
}

#[test(should_fail_with = "the commitment is not in the claim tree")]
fn rejects_another_escrow() {
    let mut c = honest(5, 0);
    c.escrow_units = ESCROW + 1;
    let _ = run(c);
}

#[test(should_fail_with = "the commitment is not in the claim tree")]
fn rejects_another_bidder() {
    let mut c = honest(5, 0);
    c.bidder = BIDDER + 1;
    let _ = run(c);
}

#[test(should_fail_with = "the bid was not counted")]
fn rejects_a_bid_that_was_not_counted() {
    // The mask has the bits 0 and 3, not the bit 2 of the claimant.
    let mut c = honest(5, 0);
    c.counted_mask = 9;
    let _ = run(c);
}

#[test(should_fail_with = "the nullifier is not the one of the bid")]
fn rejects_another_nullifier() {
    let mut c = honest(5, 0);
    c.nullifier = compute_nullifier(SALT + 1, SALE);
    let _ = run(c);
}

#[test(should_fail)]
fn rejects_a_counted_mask_beyond_the_bidders() {
    // Bit 85 is not a bidder.
    let mut c = honest(5, 0);
    c.counted_mask = MASK + 0x2000000000000000000000;
    let _ = run(c);
}

#[test(should_fail)]
fn rejects_an_index_beyond_the_tree() {
    // 128 + 2 would select the bit 2 of the mask if only the low bits were taken.
    let mut c = honest(5, 0);
    c.index = INDEX + 128;
    let _ = run(c);
}

#[test(should_fail)]
fn rejects_a_zero_recipient() {
    let mut c = honest(5, 0);
    c.recipient = 0;
    let _ = run(c);
}
