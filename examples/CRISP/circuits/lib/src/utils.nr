// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use interfold_lib::configs::default::MAX_MSG_NON_ZERO_COEFFS;
use interfold_lib::configs::default::threshold::{
    PLAINTEXT_MODULUS, Q_INVERSE_MOD_T, Q_MOD_T, USER_DATA_ENCRYPTION_BIT_K,
};
use interfold_lib::math::helpers::assert_in_range;
use interfold_lib::math::modulo::unconstrained_U128::__compute_mod_reduction;
use interfold_lib::math::polynomial::Polynomial;

use crate::constants::MAX_OPTIONS;

/// Checks the option count of a round. Every option must sit inside the first
/// `MAX_MSG_NON_ZERO_COEFFS` message coefficients, which the committee publishes as the tally, and
/// the degree `D` must hold them. The last two assertions are decided when the circuit is built.
fn check_option_count<let D: u32>(num_options: u32) {
    assert(num_options > 1);
    assert(num_options <= MAX_OPTIONS);
    assert(MAX_OPTIONS <= MAX_MSG_NON_ZERO_COEFFS);
    assert(MAX_MSG_NON_ZERO_COEFFS <= D);
}

/// Checks that `weight` is the value the committee decrypts the option coefficient to.
///
/// The witness generator scales each message coefficient `m` to `k1 = (Q_MOD_T * m) mod t`, so
/// `k1 + t * quotient == Q_MOD_T * weight`. With all three values in `[0, t)`, neither side reaches
/// `t * t`, so the equation holds over the integers, and one weight solves it because `Q_MOD_T` is
/// invertible modulo `t`.
///
/// The bound on the coefficient also makes this `k1` the plaintext that `user_data_encryption_ct0`
/// encrypts. That circuit bounds its `k1` to `[0, t)`, the fold only checks that the two
/// `k1_commitment` values are equal, and a packed commitment has one opening only while every
/// coefficient fits its slot.
fn check_weight(coefficient: Field, weight: Field, quotient: Field) {
    assert_in_range::<USER_DATA_ENCRYPTION_BIT_K>(coefficient, PLAINTEXT_MODULUS);
    assert_in_range::<USER_DATA_ENCRYPTION_BIT_K>(weight, PLAINTEXT_MODULUS);
    assert_in_range::<USER_DATA_ENCRYPTION_BIT_K>(quotient, PLAINTEXT_MODULUS);
    assert(coefficient + PLAINTEXT_MODULUS * quotient == Q_MOD_T * weight);
}

/// Computes the weight and the quotient that [`check_weight`] checks.
unconstrained fn decode_weight_hint(coefficient: Field) -> (Field, Field) {
    let (_, weight) = __compute_mod_reduction(coefficient * Q_INVERSE_MOD_T, PLAINTEXT_MODULUS);
    let (quotient, _) = __compute_mod_reduction(Q_MOD_T * weight, PLAINTEXT_MODULUS);
    (weight, quotient)
}

/// Validates a ballot against the voter's balance.
///
/// A ballot holds one coefficient per option, so the decrypted tally holds per-option totals. `k1`
/// is the whole BFV plaintext of degree `D`, reversed, so option `o` is `k1[D - 1 - o]`:
///
/// ```text
///   [ ------------------ zero ------------------ | option n-1 | ... | option 1 | option 0 ]
///   0                                                                                    D
/// ```
///
/// Every other coefficient must be zero, so no payload outside the ballot reaches the tally. The
/// weights must sum to at most `balance`, and with two options at most one weight is non-zero.
///
/// # Arguments
/// * `k1` - The plaintext polynomial encoding the vote
/// * `balance` - The voter's balance/voting power
/// * `num_options` - Number of voting options
pub fn check_coefficient_values_with_balance<let D: u32>(
    k1: Polynomial<D>,
    balance: Field,
    num_options: u32,
) -> bool {
    check_option_count::<D>(num_options);

    let mut valid = true;
    for i in 0..(D - MAX_OPTIONS) {
        valid = valid & (k1.coefficients[i] == 0);
    }

    let mut total: Field = 0;
    let mut non_zero_count: u32 = 0;
    for option in 0..MAX_OPTIONS {
        let coefficient = k1.coefficients[D - 1 - option];
        // Safety: `check_weight` constrains both values.
        let (weight, quotient) = unsafe { decode_weight_hint(coefficient) };
        check_weight(coefficient, weight, quotient);

        if option < num_options {
            total += weight;
            if weight != 0 {
                non_zero_count += 1;
            }
        } else {
            valid = valid & (coefficient == 0);
        }
    }

    if num_options == 2 {
        valid = valid & (non_zero_count <= 1);
    }

    // At most `MAX_OPTIONS` weights below `t` fit in a u64, so this cast is exact. Truncating the
    // balance can only lower the bound.
    valid & ((total as u64) <= (balance as u64))
}

/// Checks that every coefficient of `k1` is zero, not only the option coefficients. A mask needs no
/// signature, so anyone may write one to any eligible slot, and a payload anywhere in it would
/// reach that slot. `num_options` is still checked, so a mask cannot pass for a round that the
/// vote rules refuse.
pub fn check_coefficient_zero<let D: u32>(k1: Polynomial<D>, num_options: u32) -> bool {
    check_option_count::<D>(num_options);

    let mut valid = true;
    for i in 0..D {
        valid = valid & (k1.coefficients[i] == 0);
    }
    valid
}

// Tests build `k1` the way the witness generator does and take `t` and `Q_MOD_T` from the compiled
// preset, so they hold for any plaintext modulus of at least 100.

/// The degree of the `insecure-512` preset, well above `MAX_OPTIONS`, so the layout is read from
/// the real degree.
global TEST_DEGREE: u32 = 512;

/// The `k1` coefficient the witness generator produces for one message coefficient.
fn scale(m: u64) -> Field {
    (((Q_MOD_T as u64) * m) % (PLAINTEXT_MODULUS as u64)) as Field
}

/// Builds `k1` the way `encodeVote` and the witness generator do: the weight of option `o`, scaled,
/// at `k1[D - 1 - o]`, and zero everywhere else.
fn encode_ballot<let N: u32>(weights: [u64; N]) -> Polynomial<TEST_DEGREE> {
    let mut coefficients = [0; TEST_DEGREE];
    for option in 0..N {
        coefficients[TEST_DEGREE - 1 - option] = scale(weights[option]);
    }
    Polynomial { coefficients }
}

/// Each row: the weights of options 0 to 2, the option count, the balance, and whether the vote
/// rules accept the ballot.
#[test]
fn test_vote_rules() {
    let top = (PLAINTEXT_MODULUS as u64) - 1;
    let rows: [([u64; 3], u32, u64, bool); 7] = [
        ([0, 3, 0], 2, 10, true),
        ([1, 1, 0], 2, 10, false),
        // The largest weight decodes exactly, so the balance bound is tight.
        ([top, 0, 0], 2, top, true),
        ([top, 0, 0], 2, top - 1, false),
        ([40, 0, 60], 3, 100, true),
        ([60, 60, 0], 3, 100, false),
        ([0, 0, 0], 3, 100, true),
    ];
    for row in rows {
        let (weights, num_options, balance, accepted) = row;
        let pol = encode_ballot(weights);
        assert(
            check_coefficient_values_with_balance(pol, balance as Field, num_options) == accepted,
        );
    }
}

/// The last option of the largest round sits next to the coefficients that must be zero.
#[test]
fn test_last_option_of_largest_round_counts() {
    let pol = encode_ballot([0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
    assert(check_coefficient_values_with_balance(pol, 7, MAX_OPTIONS));
    assert(!check_coefficient_values_with_balance(pol, 6, MAX_OPTIONS));
}

/// A payload below the options, or in an option the round does not have, is refused.
#[test]
fn test_coefficient_outside_the_round_options_fails() {
    let mut below = encode_ballot([1, 0]);
    below.coefficients[0] = 1;
    assert(!check_coefficient_values_with_balance(below, 10, 2));

    // Option 3 is the first one that a three-option round does not have.
    assert(!check_coefficient_values_with_balance(encode_ballot([1, 0, 0, 1]), 10, 3));
}

/// The pair solves the equation for the coefficient `Q_MOD_T - 2 * t`, which is below zero, so
/// only the coefficient bound refuses it.
#[test(should_fail)]
fn test_coefficient_below_zero_is_refused() {
    check_weight(Q_MOD_T - 2 * PLAINTEXT_MODULUS, 1, 2);
}

/// The weight `t` solves the equation for the coefficient 0 with the quotient `Q_MOD_T`, so only
/// the weight bound refuses it.
#[test(should_fail)]
fn test_weight_outside_range_is_refused() {
    check_weight(0, PLAINTEXT_MODULUS, Q_MOD_T);
}

/// A weight the coefficient does not carry is refused, also with the quotient of that weight.
#[test(should_fail)]
fn test_weight_the_coefficient_does_not_carry_is_refused() {
    let quotient = ((Q_MOD_T as u64) * 6) / (PLAINTEXT_MODULUS as u64);
    check_weight(scale(5), 6, quotient as Field);
}

/// A quotient outside `[0, t)` solves the equation for any weight, so only the quotient bound
/// refuses this weight of zero.
#[test(should_fail)]
fn test_quotient_outside_range_is_refused() {
    check_weight(scale(5), 0, -scale(5) / PLAINTEXT_MODULUS);
}

/// A mask must be zero everywhere: in the option coefficients and below them.
#[test]
fn test_check_coefficient_zero() {
    assert(check_coefficient_zero(encode_ballot([0, 0]), 3));
    assert(!check_coefficient_zero(encode_ballot([1, 0]), 3));

    let mut pol = encode_ballot([0, 0]);
    pol.coefficients[0] = 1;
    assert(!check_coefficient_zero(pol, 3));
}
