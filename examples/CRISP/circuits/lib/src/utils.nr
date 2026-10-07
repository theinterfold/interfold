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

/// Checks the option count of a round, and that the ballot layout fits the compiled degree.
///
/// A ballot holds one coefficient per option: message coefficient `o` is the weight on option `o`,
/// so the decrypted tally holds one total per option. `k1` reaches this circuit as the whole BFV
/// plaintext polynomial, of degree `D`, reversed, so option `o` is `k1[D - 1 - o]`:
///
/// ```text
///   [ ------------------ zero ------------------ | option n-1 | ... | option 1 | option 0 ]
///   0                                                                                    D
/// ```
///
/// The committee publishes the first `MAX_MSG_NON_ZERO_COEFFS` message coefficients as the tally,
/// so every option must sit inside that region. `D` and both bounds are compile-time values, so the
/// last two assertions are decided when the circuit is built.
///
/// # Arguments
/// * `num_options` - Number of voting options
fn check_option_count<let D: u32>(num_options: u32) {
    assert(num_options > 1);
    assert(num_options <= MAX_OPTIONS);
    assert(MAX_OPTIONS <= MAX_MSG_NON_ZERO_COEFFS);
    assert(MAX_MSG_NON_ZERO_COEFFS <= D);
}

/// Reads the weight that one option coefficient of `k1` carries.
///
/// The witness generator scales each message coefficient `m` to the non-centered residue
/// `k1 = (Q_MOD_T * m) mod t`, so the weight is the `v` in `[0, t)` with
/// `k1 + t * r == Q_MOD_T * v` for a quotient `r` in `[0, t)`. The prover supplies `v` and `r`,
/// and [`check_weight`] constrains them.
///
/// # Arguments
/// * `coefficient` - The `k1` coefficient of one option
///
/// # Returns
/// The weight.
fn decode_weight(coefficient: Field) -> Field {
    // Safety: `check_weight` constrains both values.
    let (weight, quotient) = unsafe { decode_weight_hint(coefficient) };
    check_weight(coefficient, weight, quotient);

    weight
}

/// Checks that `weight` is the value the committee decrypts `coefficient` to.
///
/// The coefficient, the weight and the quotient must all be in `[0, t)`.
///
/// The bound on the coefficient makes this `k1` the plaintext that `user_data_encryption_ct0`
/// encrypts. That circuit range-checks its `k1` to `[0, t)`, and the fold only checks that the two
/// `k1_commitment` values are equal. Plain packing gives a commitment one opening only while every
/// coefficient fits its slot. Every other coefficient of this `k1` must be zero, so this bound
/// keeps all of them in their slots.
///
/// With every value below `t`, neither side of the equation reaches `t * t`, so the field
/// equation holds over the integers. `Q_MOD_T` is invertible modulo `t`, so one weight solves it.
///
/// # Arguments
/// * `coefficient` - The `k1` coefficient of one option
/// * `weight` - The weight the coefficient carries
/// * `quotient` - The quotient `r` of `Q_MOD_T * weight` by `t`
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
/// Constrains the whole plaintext, not only the options: every coefficient outside the options of
/// the round must be zero, and every option coefficient is decoded to its weight.
///
/// Rules:
/// - 2 options: Mutually exclusive (at most one weight is non-zero)
/// - 3+ options: Weights can be split between options
/// In both cases the weights must sum to at most the balance.
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

    // Everything below the option coefficients is outside the ballot. A payload there survives
    // homomorphic addition and is decrypted with the tally, so it would both corrupt the slot and
    // give a coercer a channel to read a receipt out of.
    for i in 0..(D - MAX_OPTIONS) {
        valid = valid & (k1.coefficients[i] == 0);
    }

    let mut total: Field = 0;
    let mut non_zero_count: u32 = 0;

    for option in 0..MAX_OPTIONS {
        let coefficient = k1.coefficients[D - 1 - option];
        let weight = decode_weight(coefficient);

        if option < num_options {
            total += weight;
            if weight != 0 {
                non_zero_count += 1;
            }
        } else {
            // An option the round does not have carries nothing.
            valid = valid & (coefficient == 0);
        }
    }

    // With two options the ballot picks one side, so its only non-zero weight is the total.
    if num_options == 2 {
        valid = valid & (non_zero_count <= 1);
    }

    // At most `MAX_OPTIONS` weights below `t` fit in a u64, so this cast is exact. Truncating the
    // balance can only lower the bound.
    valid & ((total as u64) <= (balance as u64))
}

/// Checks that the plaintext carries no ballot at all.
///
/// Every coefficient of `k1` must be zero, not only the option coefficients. A mask needs no
/// signature, so anyone may write one to any eligible slot; a mask that could carry a payload
/// outside the options would let anyone corrupt a slot they cannot vote in, and would give a
/// coercer a channel to mark a ballot with. Checking the whole polynomial closes both.
///
/// `num_options` is still taken, and still range-checked, so a caller cannot reach this function
/// with a round configuration the vote rules would refuse.
///
/// # Arguments
/// * `k1` - The plaintext polynomial encoding the vote
/// * `num_options` - Number of voting options
///
/// # Returns
/// Returns `true` if every coefficient is zero, `false` otherwise.
///
pub fn check_coefficient_zero<let D: u32>(k1: Polynomial<D>, num_options: u32) -> bool {
    check_option_count::<D>(num_options);

    let mut valid = true;

    for i in 0..D {
        valid = valid & (k1.coefficients[i] == 0);
    }

    valid
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Every test builds `k1` the way the witness generator does — SDK message layout, scaled by
// `Q_MOD_T` modulo `t`, reversed over the full BFV degree — and takes `t` and `Q_MOD_T` from the
// compiled preset, so the suite holds for any plaintext modulus of at least 100.

/// The BFV degree of the `insecure-512` preset. The option coefficients sit at the top of the
/// reversed polynomial, so a degree well above `MAX_OPTIONS` checks that the layout is read from
/// the real degree.
global TEST_DEGREE: u32 = 512;

/// The `k1` coefficient the witness generator produces for one message coefficient.
fn scale(m: u64) -> Field {
    (((Q_MOD_T as u64) * m) % (PLAINTEXT_MODULUS as u64)) as Field
}

/// Builds `k1` for a ballot: `encodeVote` from `@crisp-e3/sdk` writes the weight of option `o` to
/// message coefficient `o`, and the witness generator scales every coefficient and reverses the
/// polynomial over the full degree.
///
/// # Arguments
/// * `weights` - One weight per option, in option order; entries past `num_options` are ignored
/// * `num_options` - Number of voting options
fn encode_ballot<let D: u32>(weights: [u64; MAX_OPTIONS], num_options: u32) -> Polynomial<D> {
    let mut coefficients: [Field; D] = [0; D];

    for option in 0..MAX_OPTIONS {
        if option < num_options {
            coefficients[D - 1 - option] = scale(weights[option]);
        }
    }

    Polynomial { coefficients }
}

#[test]
fn test_2_options_vote_first() {
    let pol = encode_ballot::<TEST_DEGREE>([5, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2);
    assert(check_coefficient_values_with_balance(pol, 10, 2));
}

#[test]
fn test_2_options_vote_second() {
    let pol = encode_ballot::<TEST_DEGREE>([0, 3, 0, 0, 0, 0, 0, 0, 0, 0], 2);
    assert(check_coefficient_values_with_balance(pol, 10, 2));
}

#[test]
fn test_2_options_both_voted_fails() {
    let pol = encode_ballot::<TEST_DEGREE>([1, 1, 0, 0, 0, 0, 0, 0, 0, 0], 2);
    assert(!check_coefficient_values_with_balance(pol, 10, 2));
}

#[test]
fn test_2_options_exceeds_balance_fails() {
    let pol = encode_ballot::<TEST_DEGREE>([10, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2);
    assert(!check_coefficient_values_with_balance(pol, 5, 2));
}

#[test]
fn test_2_options_at_balance_passes() {
    let pol = encode_ballot::<TEST_DEGREE>([5, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2);
    assert(check_coefficient_values_with_balance(pol, 5, 2));
}

/// The largest weight a coefficient can carry is `t - 1`. It decodes to exactly that value, so a
/// balance one below it refuses the ballot.
#[test]
fn test_largest_weight_decodes_exactly() {
    let largest = (PLAINTEXT_MODULUS as u64) - 1;
    let pol = encode_ballot::<TEST_DEGREE>([largest, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2);

    assert(check_coefficient_values_with_balance(pol, largest as Field, 2));
    assert(!check_coefficient_values_with_balance(pol, (largest - 1) as Field, 2));
}

/// The prover supplies the weight and the quotient. This pair solves the decode equation for the
/// coefficient `Q_MOD_T - 2 * t`, which is below zero. A coefficient outside `[0, t)` could open
/// `k1_commitment` to a polynomial other than the encrypted plaintext, so it is refused.
#[test(should_fail)]
fn test_coefficient_below_zero_is_refused() {
    check_weight(Q_MOD_T - 2 * PLAINTEXT_MODULUS, 1, 2);
}

/// The prover supplies the weight. A weight the coefficient does not carry is refused, also with
/// the quotient that belongs to that weight.
#[test(should_fail)]
fn test_weight_the_coefficient_does_not_carry_is_refused() {
    let quotient = ((Q_MOD_T as u64) * 6) / (PLAINTEXT_MODULUS as u64);

    check_weight(scale(5), 6, quotient as Field);
}

// --- 3+ Options (Split Voting) ---

#[test]
fn test_3_options_split_vote() {
    let pol = encode_ballot::<TEST_DEGREE>([40, 0, 60, 0, 0, 0, 0, 0, 0, 0], 3);
    assert(check_coefficient_values_with_balance(pol, 100, 3));
}

#[test]
fn test_3_options_vote_all_three() {
    let pol = encode_ballot::<TEST_DEGREE>([30, 30, 30, 0, 0, 0, 0, 0, 0, 0], 3);
    assert(check_coefficient_values_with_balance(pol, 100, 3));
}

#[test]
fn test_3_options_total_exceeds_balance_fails() {
    let pol = encode_ballot::<TEST_DEGREE>([60, 60, 0, 0, 0, 0, 0, 0, 0, 0], 3);
    assert(!check_coefficient_values_with_balance(pol, 100, 3));
}

#[test]
fn test_5_options_single_vote() {
    let pol = encode_ballot::<TEST_DEGREE>([0, 0, 50, 0, 0, 0, 0, 0, 0, 0], 5);
    assert(check_coefficient_values_with_balance(pol, 100, 5));
}

/// The last option of the largest round sits at the bottom of the option region, next to the
/// coefficients that must be zero.
#[test]
fn test_last_option_of_largest_round_counts() {
    let pol = encode_ballot::<TEST_DEGREE>([0, 0, 0, 0, 0, 0, 0, 0, 0, 7], MAX_OPTIONS);

    assert(check_coefficient_values_with_balance(pol, 7, MAX_OPTIONS));
    assert(!check_coefficient_values_with_balance(pol, 6, MAX_OPTIONS));
}

#[test]
fn test_zero_vote_passes() {
    let pol = encode_ballot::<TEST_DEGREE>([0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 3);
    assert(check_coefficient_values_with_balance(pol, 100, 3));
}

/// Coefficients below the option region must be zero, or a submitter could attach a payload the
/// vote rules never look at.
#[test]
fn test_payload_outside_ballot_region_fails() {
    let mut pol: Polynomial<TEST_DEGREE> = encode_ballot([1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2);
    pol.coefficients[0] = 1;

    assert(!check_coefficient_values_with_balance(pol, 10, 2));
}

/// An option the round does not have must carry nothing, although its coefficient sits inside the
/// option region.
#[test]
fn test_unused_option_coefficient_fails() {
    let mut pol: Polynomial<TEST_DEGREE> = encode_ballot([1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 3);
    // Option 3, the first one a three-option round does not have.
    pol.coefficients[TEST_DEGREE - 1 - 3] = scale(1);

    assert(!check_coefficient_values_with_balance(pol, 10, 3));
}

#[test]
fn test_check_coefficient_zero_passes() {
    let pol: Polynomial<TEST_DEGREE> = Polynomial { coefficients: [0; TEST_DEGREE] };
    assert(check_coefficient_zero(pol, 3));
}

#[test]
fn test_check_coefficient_zero_fails() {
    let pol = encode_ballot::<TEST_DEGREE>([1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 3);
    assert(!check_coefficient_zero(pol, 3));
}

/// A mask must be zero everywhere, not only where the vote rules look. This coefficient is outside
/// every option.
#[test]
fn test_check_coefficient_zero_outside_ballot_region_fails() {
    let mut pol: Polynomial<TEST_DEGREE> = Polynomial { coefficients: [0; TEST_DEGREE] };
    pol.coefficients[0] = 1;

    assert(!check_coefficient_zero(pol, 3));
}
