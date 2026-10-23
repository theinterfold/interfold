// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The validity rules of an auction bid, shared by the four bid circuits.
//!
//! A bid is `K` ciphertexts, one for each role: 3 for the auction types 0 to 2 (`ge`, `gt`, `mask`)
//! and 4 for type 3 (`ge`, `gt`, `mask`, `pair_mask`). All of them are SIMD-encoded. Slot `i` has
//! level `i % LEVELS`, and a bid `b` is in `0..levels`, where the auction creator chose `levels` in
//! `2..=LEVELS` (a public input, which the contract supplies from the auction). The steps
//! `levels..LEVELS` stay empty: every thermometer is 0 there.
//!
//! ```text
//!   role 0 (ge)         slot i  [b >= i % LEVELS]
//!   role 1 (gt)         slot i  [b >  i % LEVELS]
//!   role 2 (mask)       slot i  uniform in 0..t         (no constraint)
//!   role 3 (pair mask)  slot (2c) * LEVELS + l  ==  slot (2c + 1) * LEVELS + l
//! ```
//!
//! One proof must cover all `K` Interfold `user_data_encryption` proofs (each ciphertext is a
//! well-formed encryption of its `k1` under the committee key). In one circuit that is more than
//! 2^22 gates, and the browser can prove at most 2^21 (the WASM heap is 4 GiB). So the bid is a tree
//! of circuits, each below 2^21 gates:
//!
//! ```text
//!   auction_bid_pair    roles 0 and 1: both wrapper proofs, the one private `b`, levels
//!   auction_bid_masks   roles 2 and 3: both wrapper proofs, the pair-mask check   (K = 4 only)
//!   auction_bid3        the pair proof and the wrapper proof of role 2             (EVM verifier)
//!   auction_bid4        the pair proof and the masks proof                         (EVM verifier)
//! ```
//!
//! Roles 0 and 1 use the same `b` inside `auction_bid_pair`, which is why a bid needs no commitment
//! to `b`. A mask has a free `k1`: the mask is uniform random, and it only hides the output of the
//! program.
//!
//! The inner proofs publish what the outer proof compares: the ciphertext commitments of their
//! roles, the commitment of encryption key row 0 (`pk_row0`), the key hash of the wrapper circuit
//! and its two VK chains. Every wrapper proof in the tree has to agree on the last four. The
//! outer circuit takes the key hash of each inner circuit as a witness, and the VK anchor covers
//! them, so a proof with another circuit in any position of the tree fails verification.
//!
//! The on-chain commitment of an l-BFV committee key covers every public-key row and the
//! relinearization key, while the encryption proof commits only to row 0, the encryption key. The
//! client supplies the other commitments (`openLbfvKeyEnvelope`), and the outer circuit rebuilds the
//! on-chain commitment from them with row 0 taken from the proofs.
//!
//! `k1` is the plaintext as the user-data encryption proof sees it: `reverse([Q_MOD_T * m]_t)` for
//! the plaintext polynomial `m`. The SIMD map is linear, so for a bid `b` that `k1` is one row of a
//! public table, `constants.nr`. The generator `program/examples/bid_table.rs` writes the table
//! from fhe.rs. The circuit selects the row with the one-hot vector of `b`, so it only adds
//! constants times witnesses: no multiplication, and no reduction mod `t`, because every row is
//! already in `[0, t - 1]`.
//!
//! The same map is linear for the pair mask: `k1` is the sum of the `PAIR_UNITS` rows of
//! `TABLE_PAIR_UNIT`, each times its value `v_j`, mod `t`. A row is `k1` of the plaintext that has 1
//! in the two slots of one pair at one level, and 0 elsewhere. The circuit checks the integer
//! equation `sum_j v_j * row_j[i] = k1[i] + t * q[i]` for every coefficient `i`. Range checks keep
//! it from wrapping around the field: `v_j < 2^PAIR_VALUE_BITS` and `q[i] < 2^PAIR_QUOTIENT_BITS`
//! make both sides smaller than `2^24`. As `k1[i] < t`, the quotient `q[i]` is the floor of the sum
//! over `t`, so only the plaintext `sum_j v_j * unit_j mod t` can satisfy the equation. The program
//! multiplies one value of the sum of the pair masks into two lanes (the `y` lane and the `z` lane
//! of one copy), so the two slots of a pair must hold the same value at every level.
//!
//! The commitment of `k1` is the one with the digit asserts, so that the packing is injective and a
//! commitment has one opening. The encryption circuit range-checks `k1` to `[0, t - 1]`, and equal
//! commitments transfer that bound to this `k1`.
mod constants;

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
pub use constants::PAIR_UNITS;
use constants::{
    LEVELS, TABLE_GE, TABLE_GT, TABLE_N, TABLE_PAIR_UNIT, TABLE_PLAINTEXT_MODULUS, TABLE_Q_MOD_T,
};
// The insecure SIMD preset, like the user-data encryption circuits `compile_circuits.sh` bundles.
use interfold_lib::configs::insecure_simd::threshold::{
    GADGET_DIM, N, PLAINTEXT_MODULUS, Q_MOD_T, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
};
use interfold_lib::math::commitments::{
    compute_lbfv_key_envelope_commitment, compute_lbfv_public_key_commitment,
    compute_single_polynomial_commitment_checked, DS_USER_DATA_ENCRYPTION_COMMITMENT,
};
use interfold_lib::math::polynomial::Polynomial;

/// `levels` fits in `LEVELS_BITS` bits. `LEVELS` is 16, so 8 bits are enough.
pub global LEVELS_BITS: u32 = 8;

/// A pair value is below `2^PAIR_VALUE_BITS`. This is more than `t - 1` and it does not matter: a
/// value `v` and `v - t` give the same plaintext mod `t`.
pub global PAIR_VALUE_BITS: u32 = 9;
/// The quotient of the pair equation is below `PAIR_UNITS * 2^PAIR_VALUE_BITS`, so below `2^15`.
pub global PAIR_QUOTIENT_BITS: u32 = 15;

/// Length of the public inputs of a `user_data_encryption_chunked` wrapper proof: `ct0_vk_chain`,
/// `ct1_vk_chain`, `pk_commitment`, `ct_commitment`, `k1_commitment`.
pub global UDE_PUBLIC_LEN: u32 = 5;
/// `ct_commitment[0]`, `ct_commitment[1]`, `levels`, then `pk_row0`, `ude_key_hash`, `ct0_chain`
/// and `ct1_chain`: the public inputs of `auction_bid_pair`.
pub global PAIR_PUBLIC_LEN: u32 = 7;
/// `ct_commitment[2]`, `ct_commitment[3]`, then the four shared values: the public inputs of
/// `auction_bid_masks`.
pub global MASKS_PUBLIC_LEN: u32 = 6;

/// The bid `b` as a one-hot vector. `b` is in `0..LEVELS`, and no other `b` has a witness.
fn one_hot(b: Field) -> [Field; LEVELS] {
    // Safety: `e` is constrained below to be the one-hot vector of `b`.
    let e = unsafe { one_hot_hint(b) };
    let mut count = 0;
    let mut weighted = 0;
    for l in 0..LEVELS {
        assert(e[l] * (e[l] - 1) == 0, "the one-hot vector is boolean");
        count += e[l];
        weighted += (l as Field) * e[l];
    }
    assert(count == 1, "the bid is in 0..LEVELS");
    assert(weighted == b, "the one-hot vector is the bid");
    e
}

unconstrained fn one_hot_hint(b: Field) -> [Field; LEVELS] {
    let mut e = [0; LEVELS];
    for l in 0..LEVELS {
        if b == l as Field {
            e[l] = 1;
        }
    }
    e
}

/// `k1` is the row of `table` for the bid in `e`, in every coefficient.
fn k1_is_row(k1: Polynomial<N>, e: [Field; LEVELS], table: [[Field; TABLE_N]; LEVELS]) {
    for i in 0..N {
        let mut row_i = 0;
        for l in 0..LEVELS {
            row_i += e[l] * table[l][i];
        }
        assert(k1.coefficients[i] == row_i, "k1 is not the plaintext of the claimed bid");
    }
}

/// The integer `sum_j values[j] * TABLE_PAIR_UNIT[j][i]` of every coefficient `i`.
fn pair_sums(values: [Field; PAIR_UNITS]) -> [Field; N] {
    let mut sums = [0; N];
    for i in 0..N {
        for j in 0..PAIR_UNITS {
            sums[i] += values[j] * TABLE_PAIR_UNIT[j][i];
        }
    }
    sums
}

/// The floor of every pair sum over `t`, the quotient of the pair equation for an honest `k1`.
unconstrained fn pair_quotients(values: [Field; PAIR_UNITS]) -> [Field; N] {
    let sums = pair_sums(values);
    let mut quotients = [0; N];
    for i in 0..N {
        quotients[i] = ((sums[i] as u64) / (PLAINTEXT_MODULUS as u64)) as Field;
    }
    quotients
}

/// `k1` is the combination mod `t` of the units of `TABLE_PAIR_UNIT` with the weights `values`.
pub fn k1_is_pair_mask(k1: Polynomial<N>, values: [Field; PAIR_UNITS]) {
    // The ranges of the pair equation hold for a plaintext modulus up to `2^PAIR_VALUE_BITS`, and
    // for the number of units.
    std::static_assert(
        (PLAINTEXT_MODULUS as u64) <= (1 as u64) << (PAIR_VALUE_BITS as u64),
        "the pair-mask ranges are for a smaller plaintext modulus",
    );
    std::static_assert(
        (PAIR_UNITS as u64) <= (1 as u64) << ((PAIR_QUOTIENT_BITS - PAIR_VALUE_BITS) as u64),
        "the pair-mask ranges are for fewer units",
    );
    // Safety: the equation below constrains each quotient, and the range checks keep it exact.
    let quotients = unsafe { pair_quotients(values) };
    for j in 0..PAIR_UNITS {
        values[j].assert_max_bit_size::<PAIR_VALUE_BITS>();
    }
    for i in 0..N {
        quotients[i].assert_max_bit_size::<PAIR_QUOTIENT_BITS>();
    }
    let sums = pair_sums(values);
    for i in 0..N {
        assert(
            sums[i] == k1.coefficients[i] + PLAINTEXT_MODULUS * quotients[i],
            "k1 is not a pair-equal mask",
        );
    }
}

/// `k1` of the roles `ge` and `gt` are the thermometers of the one bid `b`, for an auction of
/// `levels` steps.
pub fn check_thermometers(k1_ge: Polynomial<N>, k1_gt: Polynomial<N>, b: Field, levels: Field) {
    // The table is generated for the parameters of the preset.
    std::static_assert(TABLE_N == N, "the table is for another degree");
    std::static_assert(
        TABLE_PLAINTEXT_MODULUS == PLAINTEXT_MODULUS,
        "the table is for another plaintext modulus",
    );
    std::static_assert(TABLE_Q_MOD_T == Q_MOD_T, "the table is for another modulus chain");

    // `levels` is a small integer first, so the comparisons below cannot wrap around the field.
    levels.assert_max_bit_size::<LEVELS_BITS>();
    assert(
        (levels as u32 >= 2) & (levels as u32 <= LEVELS),
        "levels is not in 2..=LEVELS",
    );
    let e = one_hot(b);
    // `b` is below `LEVELS` here, so the cast keeps its value.
    assert((b as u32) < (levels as u32), "the bid is not below levels");

    k1_is_row(k1_ge, e, TABLE_GE);
    k1_is_row(k1_gt, e, TABLE_GT);
}

/// The commitment of `k1` the user-data encryption proof exposes as its last public input.
pub fn k1_commitment(k1: Polynomial<N>) -> Field {
    compute_single_polynomial_commitment_checked::<N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        k1,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    )
}

/// Verifies the wrapper proof of one role, and that it is about `ct_commitment` and about the key
/// row and VK chains every other wrapper proof of the bid uses.
///
/// `ude_public_inputs` is `ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment,
/// k1_commitment`. The `k1_commitment` is returned for the caller to open, or to ignore for a mask.
pub fn verify_wrapper(
    verification_key: UltraHonkVerificationKey,
    proof: UltraHonkProof,
    ude_public_inputs: [Field; UDE_PUBLIC_LEN],
    ude_key_hash: Field,
    ct_commitment: Field,
    pk_row0: Field,
    ct0_chain: Field,
    ct1_chain: Field,
) -> Field {
    verify_honk_proof_non_zk(verification_key, proof, ude_public_inputs, ude_key_hash);
    assert(ude_public_inputs[0] == ct0_chain, "different ct0 vk chains");
    assert(ude_public_inputs[1] == ct1_chain, "different ct1 vk chains");
    // The wrapper's `pk_commitment` is `pk_aggregation(pk0, pk1)` of the encryption key: row 0.
    assert(ude_public_inputs[2] == pk_row0, "different encryption keys");
    assert(ude_public_inputs[3] == ct_commitment, "the proof is for another ciphertext");
    ude_public_inputs[4]
}

/// The on-chain commitment of the committee key, from row 0 of the proofs and the other
/// commitments the client opens.
pub fn committee_key_commitment(
    public_key_row_commitments: [Field; GADGET_DIM],
    relinearization_key_commitment: Field,
) -> Field {
    compute_lbfv_key_envelope_commitment(
        compute_lbfv_public_key_commitment(public_key_row_commitments),
        relinearization_key_commitment,
    )
}

global NO_PAIR_VALUES: [Field; PAIR_UNITS] = [0; PAIR_UNITS];

fn honest(table: [[Field; TABLE_N]; LEVELS], b: u32) -> Polynomial<N> {
    Polynomial { coefficients: table[b] }
}

/// `k1` of the pair mask with the values `values`: the combination mod `t` of the units.
fn honest_pair_mask(values: [Field; PAIR_UNITS]) -> Polynomial<N> {
    let t = PLAINTEXT_MODULUS as u64;
    let mut k1 = Polynomial { coefficients: [0; N] };
    for i in 0..N {
        let mut sum: u64 = 0;
        for j in 0..PAIR_UNITS {
            sum += (values[j] as u64) * (TABLE_PAIR_UNIT[j][i] as u64);
        }
        k1.coefficients[i] = (sum % t) as Field;
    }
    k1
}

fn pair_values() -> [Field; PAIR_UNITS] {
    let mut values = [0; PAIR_UNITS];
    for j in 0..PAIR_UNITS {
        values[j] = ((j * 37 + 5) % 257) as Field;
    }
    values
}

/// All the slots are in use: the creator chose the full `LEVELS` steps.
global ALL_LEVELS: Field = LEVELS as Field;

/// The honest thermometers of the bid `b`.
fn honest_thermometers(b: u32) {
    check_thermometers(honest(TABLE_GE, b), honest(TABLE_GT, b), b as Field, ALL_LEVELS);
}

#[test]
fn accepts_an_honest_bid() {
    honest_thermometers(5);
}

#[test]
fn accepts_the_extreme_bids() {
    honest_thermometers(0);
    honest_thermometers(LEVELS - 1);
}

#[test]
fn accepts_the_top_step_of_a_shorter_auction() {
    check_thermometers(honest(TABLE_GE, 5), honest(TABLE_GT, 5), 5, 6);
    check_thermometers(honest(TABLE_GE, 0), honest(TABLE_GT, 0), 0, 2);
    check_thermometers(honest(TABLE_GE, 1), honest(TABLE_GT, 1), 1, 2);
}

#[test]
fn accepts_an_honest_pair_mask() {
    let values = pair_values();
    k1_is_pair_mask(honest_pair_mask(values), values);
}

#[test]
fn accepts_the_extreme_pair_masks() {
    let zero = NO_PAIR_VALUES;
    k1_is_pair_mask(honest_pair_mask(zero), zero);
    // The largest sums and quotients: every value is `t - 1`.
    let mut largest = zero;
    for j in 0..PAIR_UNITS {
        largest[j] = PLAINTEXT_MODULUS - 1;
    }
    k1_is_pair_mask(honest_pair_mask(largest), largest);
}

#[test(should_fail_with = "k1 is not a pair-equal mask")]
fn rejects_a_pair_mask_that_breaks_one_pair_equality() {
    let values = pair_values();
    let mut k1 = honest_pair_mask(values);
    k1.coefficients[3] = (((k1.coefficients[3] as u64) + 1) % (PLAINTEXT_MODULUS as u64)) as Field;
    k1_is_pair_mask(k1, values);
}

#[test(should_fail_with = "k1 is not a pair-equal mask")]
fn rejects_a_free_mask_for_the_pair_mask_role() {
    let mut k1 = Polynomial { coefficients: [0; N] };
    for i in 0..N {
        k1.coefficients[i] = ((i * 37 + 11) % 257) as Field;
    }
    k1_is_pair_mask(k1, pair_values());
}

#[test(should_fail_with = "k1 is not a pair-equal mask")]
fn rejects_a_pair_mask_with_other_values_than_its_own() {
    let mut values = pair_values();
    let k1 = honest_pair_mask(values);
    values[10] += 1;
    k1_is_pair_mask(k1, values);
}

#[test(should_fail)]
fn rejects_a_pair_value_beyond_its_range() {
    // A value of `2^PAIR_VALUE_BITS` or more is out of range, although its quotient is honest.
    let mut values = pair_values();
    values[0] += (1 as u64 << (PAIR_VALUE_BITS as u64)) as Field;
    k1_is_pair_mask(honest_pair_mask(values), values);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_ge_and_gt_of_different_bids() {
    // Each thermometer is honest for its own bid, but one bid `b` serves both roles.
    check_thermometers(honest(TABLE_GE, 5), honest(TABLE_GT, 6), 5, ALL_LEVELS);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_ge_and_gt_of_different_bids_for_the_other_bid() {
    check_thermometers(honest(TABLE_GE, 5), honest(TABLE_GT, 6), 6, ALL_LEVELS);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_thermometer_of_a_higher_bid() {
    check_thermometers(honest(TABLE_GE, 6), honest(TABLE_GT, 5), 5, ALL_LEVELS);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_thermometer_of_a_lower_bid() {
    check_thermometers(honest(TABLE_GE, 5), honest(TABLE_GT, 4), 5, ALL_LEVELS);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_non_thermometer() {
    let mut ge = honest(TABLE_GE, 5);
    ge.coefficients[3] += 1;
    check_thermometers(ge, honest(TABLE_GT, 5), 5, ALL_LEVELS);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_gt_thermometer_for_the_ge_role() {
    check_thermometers(honest(TABLE_GT, 5), honest(TABLE_GT, 5), 5, ALL_LEVELS);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_ge_thermometer_for_the_gt_role() {
    check_thermometers(honest(TABLE_GE, 5), honest(TABLE_GE, 5), 5, ALL_LEVELS);
}

#[test(should_fail_with = "the bid is in 0..LEVELS")]
fn rejects_a_bid_beyond_the_slots() {
    check_thermometers(honest(TABLE_GE, 15), honest(TABLE_GT, 15), LEVELS as Field, ALL_LEVELS);
}

#[test(should_fail_with = "the bid is not below levels")]
fn rejects_a_bid_equal_to_the_levels() {
    // The thermometers of step 5 are honest for the bid, but the auction has 5 steps: 0..5.
    check_thermometers(honest(TABLE_GE, 5), honest(TABLE_GT, 5), 5, 5);
}

#[test(should_fail_with = "the bid is not below levels")]
fn rejects_a_bid_above_the_levels() {
    check_thermometers(honest(TABLE_GE, 9), honest(TABLE_GT, 9), 9, 5);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_one_level() {
    check_thermometers(honest(TABLE_GE, 0), honest(TABLE_GT, 0), 0, 1);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_zero_levels() {
    check_thermometers(honest(TABLE_GE, 0), honest(TABLE_GT, 0), 0, 0);
}

#[test(should_fail_with = "levels is not in 2..=LEVELS")]
fn rejects_more_levels_than_slots() {
    check_thermometers(honest(TABLE_GE, 0), honest(TABLE_GT, 0), 0, 17);
}

#[test(should_fail)]
fn rejects_a_levels_value_beyond_the_range_check() {
    // `2^32 + 2` would be 2 after a truncation to `u32`.
    check_thermometers(honest(TABLE_GE, 0), honest(TABLE_GT, 0), 0, 0x100000002);
}
