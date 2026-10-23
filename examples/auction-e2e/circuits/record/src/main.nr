// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Validity of one auction ciphertext before it is encrypted.
//!
//! A bidder sends 3 or 4 ciphertexts per bid, one for each role. All of them are SIMD-encoded.
//! Slot `i` has level `i % LEVELS`, and a bid `b` is in `0..LEVELS`:
//!
//! ```text
//!   role 0 (ge)         slot i  [b >= i % LEVELS]
//!   role 1 (gt)         slot i  [b >  i % LEVELS]
//!   role 2 (mask)       slot i  uniform in 0..t         (no constraint)
//!   role 3 (pair mask)  slot (2c) * LEVELS + l  ==  slot (2c + 1) * LEVELS + l
//! ```
//!
//! For role 0 and 1 the circuit proves that `k1` is the one the honest bid `b` gives, and returns
//! `bid_commitment = Poseidon2(b, salt)`. The contract requires the roles 0 and 1 of one bidder to
//! return the same `bid_commitment`. Thus both thermometers come from one `b`. A mask returns
//! `bid_commitment = 0` and `k1` is free: the mask is uniform random, and it only hides the output
//! of the program.
//!
//! The pair mask (role 3) is uniform random too, but its slots in the groups `2c` and `2c + 1`
//! must be equal at every level. The program multiplies one value of the sum of the pair masks into
//! two lanes (the `y` lane and the `z` lane of one copy). If a bidder could choose the two slots
//! apart, the two lanes would hold different masks and the decoded ratio would be wrong. The
//! circuit proves the shape, and returns `bid_commitment = 0`. The 64 free values are the witness
//! `pair_values`.
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
//! over `t`, so only the plaintext `sum_j v_j * unit_j mod t` can satisfy the equation.
//!
//! The returned `k1_commitment` is the value the fold circuit matches against the encryption
//! proof. It uses the commitment with the digit asserts, so that the packing is injective and a
//! commitment has one opening. The encryption circuit range-checks `k1` to `[0, t - 1]`, and equal
//! commitments transfer that bound to this `k1`.
mod constants;

use constants::{
    LEVELS, PAIR_UNITS, TABLE_GE, TABLE_GT, TABLE_N, TABLE_PAIR_UNIT, TABLE_PLAINTEXT_MODULUS,
    TABLE_Q_MOD_T,
};
use interfold_lib::configs::insecure_simd::threshold::{
    N, PLAINTEXT_MODULUS, Q_MOD_T, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
};
use interfold_lib::math::commitments::{
    compute_single_polynomial_commitment_checked, DS_USER_DATA_ENCRYPTION_COMMITMENT,
};
use interfold_lib::math::polynomial::Polynomial;
use poseidon::poseidon2::Poseidon2;

pub global ROLE_GE: Field = 0;
pub global ROLE_GT: Field = 1;
pub global ROLE_MASK: Field = 2;
pub global ROLE_PAIR_MASK: Field = 3;

/// A pair value is below `2^PAIR_VALUE_BITS`. This is more than `t - 1` and it does not matter: a
/// value `v` and `v - t` give the same plaintext mod `t`.
pub global PAIR_VALUE_BITS: u32 = 9;
/// The quotient of the pair equation is below `PAIR_UNITS * 2^PAIR_VALUE_BITS`, so below `2^15`.
pub global PAIR_QUOTIENT_BITS: u32 = 15;

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

/// The witnesses of the pair equation are in range, so that the equation holds over the integers.
fn pair_witness(values: [Field; PAIR_UNITS]) -> [Field; N] {
    // Safety: for the pair mask role, `k1_is_pair_mask` constrains each quotient. The other roles
    // do not use it.
    let quotients = unsafe { pair_quotients(values) };
    for j in 0..PAIR_UNITS {
        values[j].assert_max_bit_size::<PAIR_VALUE_BITS>();
    }
    for i in 0..N {
        quotients[i].assert_max_bit_size::<PAIR_QUOTIENT_BITS>();
    }
    quotients
}

/// `k1` is the combination mod `t` of the units of `TABLE_PAIR_UNIT` with the weights `values`.
fn k1_is_pair_mask(k1: Polynomial<N>, values: [Field; PAIR_UNITS], quotients: [Field; N]) {
    let sums = pair_sums(values);
    for i in 0..N {
        assert(
            sums[i] == k1.coefficients[i] + PLAINTEXT_MODULUS * quotients[i],
            "k1 is not a pair-equal mask",
        );
    }
}

fn main(
    k1: Polynomial<N>,
    b: Field,
    salt: Field,
    pair_values: [Field; PAIR_UNITS],
    role: pub Field,
) -> pub (Field, Field) {
    // The table is generated for the parameters of the preset.
    std::static_assert(TABLE_N == N, "the table is for another degree");
    std::static_assert(
        TABLE_PLAINTEXT_MODULUS == PLAINTEXT_MODULUS,
        "the table is for another plaintext modulus",
    );
    std::static_assert(TABLE_Q_MOD_T == Q_MOD_T, "the table is for another modulus chain");
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

    assert(
        role * (role - ROLE_GT) * (role - ROLE_MASK) * (role - ROLE_PAIR_MASK) == 0,
        "unknown role",
    );
    let commits_to_bid = ((role == ROLE_GE) as Field) + ((role == ROLE_GT) as Field);
    let e = one_hot(b);
    // Zero for the other roles, whose `pair_values` are zero.
    let quotients = pair_witness(pair_values);

    if role == ROLE_MASK {
        // Unconstrained: a mask is uniform random.
    } else if role == ROLE_PAIR_MASK {
        k1_is_pair_mask(k1, pair_values, quotients);
    } else if role == ROLE_GE {
        k1_is_row(k1, e, TABLE_GE);
    } else {
        k1_is_row(k1, e, TABLE_GT);
    }

    let k1_commitment = compute_single_polynomial_commitment_checked::<N, USER_DATA_ENCRYPTION_CHUNKED_BIT_K>(
        k1,
        DS_USER_DATA_ENCRYPTION_COMMITMENT,
    );
    let bid_commitment = commits_to_bid * Poseidon2::hash([b, salt], 2);

    (k1_commitment, bid_commitment)
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

fn arbitrary_mask() -> Polynomial<N> {
    let mut k1 = Polynomial { coefficients: [0; N] };
    for i in 0..N {
        k1.coefficients[i] = ((i * 37 + 11) % 257) as Field;
    }
    k1
}

#[test]
fn accepts_an_honest_ge_thermometer() {
    let _ = main(honest(TABLE_GE, 5), 5, 77, NO_PAIR_VALUES, ROLE_GE);
}

#[test]
fn accepts_an_honest_gt_thermometer() {
    let _ = main(honest(TABLE_GT, 5), 5, 77, NO_PAIR_VALUES, ROLE_GT);
}

#[test]
fn accepts_the_extreme_bids() {
    let _ = main(honest(TABLE_GE, 0), 0, 1, NO_PAIR_VALUES, ROLE_GE);
    let _ = main(honest(TABLE_GT, 0), 0, 1, NO_PAIR_VALUES, ROLE_GT);
    let _ = main(honest(TABLE_GE, LEVELS - 1), (LEVELS - 1) as Field, 1, NO_PAIR_VALUES, ROLE_GE);
    let _ = main(honest(TABLE_GT, LEVELS - 1), (LEVELS - 1) as Field, 1, NO_PAIR_VALUES, ROLE_GT);
}

#[test]
fn both_thermometers_of_a_bid_have_the_same_bid_commitment() {
    let (_, ge) = main(honest(TABLE_GE, 9), 9, 123, NO_PAIR_VALUES, ROLE_GE);
    let (_, gt) = main(honest(TABLE_GT, 9), 9, 123, NO_PAIR_VALUES, ROLE_GT);
    assert(ge == gt);
    assert(ge != 0);
}

#[test]
fn the_bid_commitment_depends_on_the_bid_and_the_salt() {
    let (_, a) = main(honest(TABLE_GE, 9), 9, 123, NO_PAIR_VALUES, ROLE_GE);
    let (_, other_bid) = main(honest(TABLE_GE, 8), 8, 123, NO_PAIR_VALUES, ROLE_GE);
    let (_, other_salt) = main(honest(TABLE_GE, 9), 9, 124, NO_PAIR_VALUES, ROLE_GE);
    assert(a != other_bid);
    assert(a != other_salt);
}

#[test]
fn accepts_any_mask_and_commits_to_nothing() {
    let (_, bid_commitment) = main(arbitrary_mask(), 0, 0, NO_PAIR_VALUES, ROLE_MASK);
    assert(bid_commitment == 0);
}

#[test]
fn accepts_an_honest_pair_mask_and_commits_to_nothing() {
    let values = pair_values();
    let (_, bid_commitment) = main(honest_pair_mask(values), 0, 0, values, ROLE_PAIR_MASK);
    assert(bid_commitment == 0);
}

#[test]
fn accepts_the_extreme_pair_masks() {
    let zero = NO_PAIR_VALUES;
    let _ = main(honest_pair_mask(zero), 0, 0, zero, ROLE_PAIR_MASK);
    // The largest sums and quotients: every value is `t - 1`.
    let mut largest = zero;
    for j in 0..PAIR_UNITS {
        largest[j] = PLAINTEXT_MODULUS - 1;
    }
    let _ = main(honest_pair_mask(largest), 0, 0, largest, ROLE_PAIR_MASK);
}

#[test(should_fail_with = "k1 is not a pair-equal mask")]
fn rejects_a_pair_mask_that_breaks_one_pair_equality() {
    let values = pair_values();
    let mut k1 = honest_pair_mask(values);
    k1.coefficients[3] = (((k1.coefficients[3] as u64) + 1) % (PLAINTEXT_MODULUS as u64)) as Field;
    let _ = main(k1, 0, 0, values, ROLE_PAIR_MASK);
}

#[test(should_fail_with = "k1 is not a pair-equal mask")]
fn rejects_a_free_mask_for_the_pair_mask_role() {
    let _ = main(arbitrary_mask(), 0, 0, pair_values(), ROLE_PAIR_MASK);
}

#[test(should_fail_with = "k1 is not a pair-equal mask")]
fn rejects_a_pair_mask_with_other_values_than_its_own() {
    let mut values = pair_values();
    let k1 = honest_pair_mask(values);
    values[10] += 1;
    let _ = main(k1, 0, 0, values, ROLE_PAIR_MASK);
}

#[test(should_fail)]
fn rejects_a_pair_value_beyond_its_range() {
    // A value of `2^PAIR_VALUE_BITS` or more is out of range, although its quotient is honest.
    let mut values = pair_values();
    values[0] += (1 as u64 << (PAIR_VALUE_BITS as u64)) as Field;
    let _ = main(honest_pair_mask(values), 0, 0, values, ROLE_PAIR_MASK);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_pair_mask_for_the_ge_role() {
    let values = pair_values();
    let _ = main(honest_pair_mask(values), 5, 77, values, ROLE_GE);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_thermometer_of_a_higher_bid() {
    let _ = main(honest(TABLE_GE, 6), 5, 77, NO_PAIR_VALUES, ROLE_GE);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_thermometer_of_a_lower_bid() {
    let _ = main(honest(TABLE_GT, 4), 5, 77, NO_PAIR_VALUES, ROLE_GT);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_a_non_thermometer() {
    let mut k1 = honest(TABLE_GE, 5);
    k1.coefficients[3] += 1;
    let _ = main(k1, 5, 77, NO_PAIR_VALUES, ROLE_GE);
}

#[test(should_fail_with = "k1 is not the plaintext of the claimed bid")]
fn rejects_the_gt_thermometer_for_the_ge_role() {
    let _ = main(honest(TABLE_GT, 5), 5, 77, NO_PAIR_VALUES, ROLE_GE);
}

#[test(should_fail_with = "the bid is in 0..LEVELS")]
fn rejects_a_bid_beyond_the_levels() {
    let _ = main(honest(TABLE_GE, 15), LEVELS as Field, 77, NO_PAIR_VALUES, ROLE_GE);
}

#[test(should_fail_with = "unknown role")]
fn rejects_an_unknown_role() {
    let _ = main(honest(TABLE_GE, 5), 5, 77, NO_PAIR_VALUES, 4);
}
