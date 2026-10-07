// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! # The slot update every CRISP input proves
//!
//! Voting, updating, and masking all prove one relation between three BFV ciphertexts:
//!
//! ```text
//!   published slot ciphertext = addend + ballot ciphertext   (mod q_i, coefficient by coefficient)
//! ```
//!
//! The addend is the ciphertext already in the slot for a mask, and the zero ciphertext for a
//! vote, an update, and any input to an empty slot. [`verify_slot_update`] is the one place both
//! ballot circuits (`crisp` and `crisp_onchain`) prove it.
//!
//! ## Why the relation is checked at every coefficient
//!
//! The three ciphertexts reach the rest of the protocol only through their SAFE commitments: the
//! ballot's through the `user_data_encryption` fold, the parent's through the commitment
//! `CRISPProgram` stored for it, and the result's through the bytes the Secure Process opens. Those
//! commitments pack coefficients into shared carriers with `pack`, which is not injective: a
//! coefficient can overflow its slot and cancel against the next one, so a prover can open a
//! commitment to coefficients other than the committed ones.
//!
//! A check at one Fiat-Shamir point cannot survive that. The point depends only on the
//! commitments, so a prover fixes it first and then picks an opening, or quotients, that satisfy
//! the one equation. That is how a mask could publish a ciphertext that drops the vote it names.
//!
//! The relation here is linear and aligned coefficient by coefficient across the three
//! ciphertexts, which all pack with the same `BIT_CT` layout. An opening that keeps the carriers
//! of a commitment differs from the committed coefficients by a vector the packing sends to zero.
//! Summing the per-coefficient equations with the carrier weights therefore gives the same
//! equation for the committed coefficients:
//!
//! ```text
//!   sum_k (published_k - ballot_k - addend_k) * radix^(g-1-k) = q_i * sum_k r_k * radix^(g-1-k)
//! ```
//!
//! The committed coefficients are bounded (the ballot by `user_data_encryption`, the parent and the
//! result by their canonical bytes) and each `r_k` is in `[-1, 1]`, so both sides are far below the
//! field modulus and every base-`radix` digit fits its slot. The equation then holds over the
//! integers digit by digit, which is `published_k = ballot_k + addend_k + q_i * r_k` for the
//! committed coefficients. No choice of opening changes what the relation proves, so the packing
//! does not need the digit asserts of `pack_checked`, which would put the ballot circuit above the
//! browser prover's `2^21` gate ceiling.

use interfold_lib::math::commitments::compute_ciphertext_commitment;
use interfold_lib::math::polynomial::Polynomial;

/// The ciphertext an input adds to, which is either the one already in the slot or nothing.
///
/// A mask keeps what the slot holds, so its addend is that ciphertext. A real vote replaces the
/// slot, and a first input has nothing to replace, so both add to the zero ciphertext instead.
///
/// Selecting here rather than branching keeps the addition constraints live on every path. The
/// alternative — proving the addition only for masks — leaves the published ciphertext of a real
/// vote unconstrained, and makes the two paths different shapes of proof.
///
/// # Arguments
/// * `polynomials` - The ciphertext limbs already in the slot
/// * `keep` - Whether this input adds to them
///
/// # Returns
/// The limbs when `keep` is true, all zeros otherwise.
pub fn select_addend<let N: u32, let L: u32>(
    polynomials: [Polynomial<N>; L],
    keep: bool,
) -> [Polynomial<N>; L] {
    let factor: Field = if keep { 1 } else { 0 };

    let mut selected = polynomials;
    for i in 0..L {
        selected[i] = polynomials[i].mul_scalar(factor);
    }

    selected
}

/// Constrains the slot update of one CRISP input and returns the commitments it links to.
///
/// Proves `sum = addend + ballot` coefficient by coefficient, where the addend is the slot's
/// current ciphertext for a mask and zero otherwise. The selector is derived, not witnessed:
/// `keep_previous = is_mask_vote & !is_first_vote`. A voter therefore cannot add a new ballot on
/// top of an old one and count twice, and a masker cannot discard what the slot holds.
///
/// A mask must open `prev_ct_commitment`, the commitment `CRISPProgram` stored for the entry the
/// input names as its parent. A vote adds to nothing and opens nothing, so it can write to its own
/// slot whatever the parent turns out to be: `CRISPProgram` cannot tell whether a parent's bytes
/// reproduce its commitment, and only the Secure Process can, once the input window closes.
///
/// # Arguments
/// * `qis` - The CRT moduli
/// * `prev_ct0is`, `prev_ct1is` - The ciphertext already in the slot
/// * `prev_ct_commitment` - The commitment `CRISPProgram` stored for the parent entry, or zero
/// * `sum_ct0is`, `sum_ct1is` - The ciphertext this input publishes as the slot
/// * `sum_r0is`, `sum_r1is` - The per-coefficient quotients of the addition, each in `[-1, 1]`
/// * `ct0is`, `ct1is` - The ballot ciphertext, which `user_data_encryption` proves
/// * `is_first_vote` - Whether the input names no parent
/// * `is_mask_vote` - Whether the input keeps what the slot holds
///
/// # Returns
/// `(sum_ct_commitment, ct_commitment)`: the commitment the slot takes, and the ballot commitment
/// the fold links to `user_data_encryption`.
pub fn verify_slot_update<let N: u32, let L: u32, let BIT_CT: u32>(
    qis: [Field; L],
    prev_ct0is: [Polynomial<N>; L],
    prev_ct1is: [Polynomial<N>; L],
    prev_ct_commitment: Field,
    sum_ct0is: [Polynomial<N>; L],
    sum_ct1is: [Polynomial<N>; L],
    sum_r0is: [Polynomial<N>; L],
    sum_r1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    is_first_vote: bool,
    is_mask_vote: bool,
) -> (Field, Field) {
    let ct_commitment = compute_ciphertext_commitment::<N, L, BIT_CT>(ct0is, ct1is);
    let sum_ct_commitment = compute_ciphertext_commitment::<N, L, BIT_CT>(sum_ct0is, sum_ct1is);

    let keep_previous = is_mask_vote & !is_first_vote;
    // Computed on every path, so the three operations prove the same shape of statement.
    let recomputed_prev_ct_commitment =
        compute_ciphertext_commitment::<N, L, BIT_CT>(prev_ct0is, prev_ct1is);
    if keep_previous {
        assert(
            prev_ct_commitment == recomputed_prev_ct_commitment,
            "the addend does not open the parent commitment",
        );
    }

    let addend_ct0is = select_addend(prev_ct0is, keep_previous);
    let addend_ct1is = select_addend(prev_ct1is, keep_previous);

    for i in 0..L {
        // The sum of two coefficients in `(-q_i, q_i)` differs from its centered residue by at
        // most one `q_i`, so `[-1, 1]` covers every honest quotient. The bound is also what lets
        // the per-coefficient equations hold over the integers.
        sum_r0is[i].range_check_2bounds::<1>(1, 1);
        sum_r1is[i].range_check_2bounds::<1>(1, 1);

        for k in 0..N {
            assert(
                sum_ct0is[i].coefficients[k]
                    == ct0is[i].coefficients[k]
                        + addend_ct0is[i].coefficients[k]
                        + qis[i] * sum_r0is[i].coefficients[k],
                "the published ciphertext is not the ballot added to the addend",
            );
            assert(
                sum_ct1is[i].coefficients[k]
                    == ct1is[i].coefficients[k]
                        + addend_ct1is[i].coefficients[k]
                        + qis[i] * sum_r1is[i].coefficients[k],
                "the published ciphertext is not the ballot added to the addend",
            );
        }
    }

    (sum_ct_commitment, ct_commitment)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Reduced dimensions: four coefficients, one small modulus, and a 16-bit packing layout (a radix
// of 2^20, twelve digits per carrier). The relation and the packing are the production functions.

global TEST_N: u32 = 4;
global TEST_L: u32 = 1;
global TEST_BIT_CT: u32 = 16;
global TEST_Q: Field = 40961;
global TEST_QIS: [Field; TEST_L] = [TEST_Q];

fn ciphertext(
    c0: [Field; TEST_N],
    c1: [Field; TEST_N],
) -> ([Polynomial<TEST_N>; TEST_L], [Polynomial<TEST_N>; TEST_L]) {
    ([Polynomial::new(c0)], [Polynomial::new(c1)])
}

fn commit(ct: ([Polynomial<TEST_N>; TEST_L], [Polynomial<TEST_N>; TEST_L])) -> Field {
    compute_ciphertext_commitment::<TEST_N, TEST_L, TEST_BIT_CT>(ct.0, ct.1)
}

fn no_quotients() -> [Polynomial<TEST_N>; TEST_L] {
    [Polynomial::new([0; TEST_N])]
}

/// The ciphertext already in the slot.
fn slot_head() -> ([Polynomial<TEST_N>; TEST_L], [Polynomial<TEST_N>; TEST_L]) {
    ciphertext([1200, -3400, 20000, 17], [-9, 8000, -20000, 5])
}

/// A fresh ballot ciphertext.
fn ballot() -> ([Polynomial<TEST_N>; TEST_L], [Polynomial<TEST_N>; TEST_L]) {
    ciphertext([300, 45, 1000, -2], [7, -600, -1000, 11])
}

#[test]
fn a_vote_publishes_its_ballot_alone() {
    let ballot = ballot();
    let empty = ciphertext([0; TEST_N], [0; TEST_N]);

    let (sum_commitment, ct_commitment) = verify_slot_update::<TEST_N, TEST_L, TEST_BIT_CT>(
        TEST_QIS,
        empty.0,
        empty.1,
        0,
        ballot.0,
        ballot.1,
        no_quotients(),
        no_quotients(),
        ballot.0,
        ballot.1,
        true,
        false,
    );

    assert(sum_commitment == commit(ballot));
    assert(ct_commitment == commit(ballot));
}

/// An update names the slot's head as its parent but replaces it, so it adds to nothing.
#[test]
fn an_update_replaces_the_ballot_in_the_slot() {
    let head = slot_head();
    let ballot = ballot();

    let (sum_commitment, _) = verify_slot_update::<TEST_N, TEST_L, TEST_BIT_CT>(
        TEST_QIS,
        head.0,
        head.1,
        commit(head),
        ballot.0,
        ballot.1,
        no_quotients(),
        no_quotients(),
        ballot.0,
        ballot.1,
        false,
        false,
    );

    assert(sum_commitment == commit(ballot));
}

/// A mask keeps the ballot in the slot. Two coefficients wrap past `q / 2` and need the quotient.
#[test]
fn a_mask_keeps_the_ballot_in_the_slot() {
    let head = slot_head();
    let mask = ballot();
    // 20000 + 1000 = 21000 wraps to 21000 - q, and -20000 - 1000 = -21000 wraps to q - 21000.
    let sum = ciphertext(
        [1500, -3355, 21000 - TEST_Q, 15],
        [-2, 7400, TEST_Q - 21000, 16],
    );
    let r0 = [Polynomial::new([0, 0, -1, 0])];
    let r1 = [Polynomial::new([0, 0, 1, 0])];

    let (sum_commitment, _) = verify_slot_update::<TEST_N, TEST_L, TEST_BIT_CT>(
        TEST_QIS,
        head.0,
        head.1,
        commit(head),
        sum.0,
        sum.1,
        r0,
        r1,
        mask.0,
        mask.1,
        false,
        true,
    );

    assert(sum_commitment == commit(sum));
}

#[test(should_fail_with = "the published ciphertext is not the ballot added to the addend")]
fn a_mask_cannot_publish_its_ballot_without_the_slot() {
    let head = slot_head();
    let mask = ballot();

    let _ = verify_slot_update::<TEST_N, TEST_L, TEST_BIT_CT>(
        TEST_QIS,
        head.0,
        head.1,
        commit(head),
        mask.0,
        mask.1,
        no_quotients(),
        no_quotients(),
        mask.0,
        mask.1,
        false,
        true,
    );
}

/// The demonstrated forgery: a mask that publishes only its own ballot, and so erases the vote in
/// the slot, with a second opening of the parent commitment.
///
/// The parent opening differs from the head only by `delta * v`, where `v = (1, -radix, 0, 0)` is a
/// carry that the packing maps to zero, so it opens the same commitment. A check at one
/// Fiat-Shamir point derived from the three commitments accepted it once `delta` solved that one
/// equation. The attacker computes that point the way such a check derived it.
#[test(should_fail_with = "the published ciphertext is not the ballot added to the addend")]
fn a_second_opening_of_the_parent_cannot_erase_the_slot() {
    let head = slot_head();
    let mask = ballot();
    let parent_commitment = commit(head);
    let published_commitment = commit(mask);

    let domain_separator: [u8; 64] = [
        0x43, 0x4c, 0x47, 0x5f, 0x43, 0x54, 0x5f, 0x41, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let gammas = interfold_lib::math::commitments::compute_challenge::<TEST_L>(
        [published_commitment, parent_commitment, published_commitment].as_vector(),
        domain_separator,
    );
    let gamma = gammas[0];

    // The single-point check was `(published0 - ballot0 - addend0)(gamma) +
    // gammas[1] * (published1 - ballot1 - addend1)(gamma) == 0` with zero quotients. Publishing the
    // mask ballot alone leaves `addend0(gamma) = -gammas[1] * head1(gamma)`.
    let radix: Field = 1048576;
    let carry = Polynomial::new([1, -radix, 0, 0]);
    let delta = (0 - gammas[1] * head.1[0].eval(gamma) - head.0[0].eval(gamma)) / carry.eval(gamma);
    let forged0 = [head.0[0].add(carry.mul_scalar(delta))];

    assert(
        compute_ciphertext_commitment::<TEST_N, TEST_L, TEST_BIT_CT>(forged0, head.1)
            == parent_commitment,
        "the forged opening must open the parent commitment",
    );

    let _ = verify_slot_update::<TEST_N, TEST_L, TEST_BIT_CT>(
        TEST_QIS,
        forged0,
        head.1,
        parent_commitment,
        mask.0,
        mask.1,
        no_quotients(),
        no_quotients(),
        mask.0,
        mask.1,
        false,
        true,
    );
}
