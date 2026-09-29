// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use interfold_lib::configs::default::MAX_MSG_NON_ZERO_COEFFS;
use interfold_lib::math::polynomial::Polynomial;

use crate::constants::{MAX_OPTIONS, MAX_VOTE_BITS};

/// Where the ballot sits inside `k1`, and how wide one option is.
///
/// `k1` reaches this circuit as the whole BFV plaintext polynomial, of degree `D`, reversed:
/// `k1[i]` is coefficient `D - 1 - i` of the message. The SDK writes the ballot into the first
/// `MAX_MSG_NON_ZERO_COEFFS` message coefficients and pads the rest with zeros, so after the
/// reversal the ballot occupies the **last** `MAX_MSG_NON_ZERO_COEFFS` coefficients of `k1` and the
/// options appear back to front.
///
/// The layout inside `k1` is:
///
/// ```text
///   [ ------- zero prefix ------- | pad | option n-1 | ... | option 1 | option 0 ]
///   0                                  base                                     D
/// ```
///
/// `pad` is the tail of the message region that no option uses, because the SDK divides
/// `MAX_MSG_NON_ZERO_COEFFS` between the options and zero-fills the remainder. The reversal moves
/// that tail to the front of the ballot region, which is why it counts towards the zero prefix.
///
/// Each option holds `segment_size` binary coefficients, least significant first.
///
/// # Arguments
/// * `num_options` - Number of voting options
///
/// # Returns
/// The first coefficient of option `num_options - 1`, and the width of one option.
fn ballot_layout<let D: u32>(num_options: u32) -> (u32, u32) {
    assert(num_options > 1);
    assert(num_options as u64 <= MAX_OPTIONS as u64);
    // The ballot cannot be laid out in a polynomial too short to hold the message region. `D` is
    // the compiled BFV degree, so this is decided when the circuit is built.
    assert(D >= MAX_MSG_NON_ZERO_COEFFS);

    let segment_size: u32 = MAX_MSG_NON_ZERO_COEFFS / num_options;
    let pad: u32 = MAX_MSG_NON_ZERO_COEFFS - (segment_size * num_options);

    (D - MAX_MSG_NON_ZERO_COEFFS + pad, segment_size)
}

/// Checks that every coefficient before the ballot region is zero.
///
/// The ballot only occupies the coefficients the options are laid out in. Everything before them
/// must be zero, or a submitter could attach a payload that the vote rules never look at. Such a
/// payload survives homomorphic addition and is decrypted with the tally, so it is both a way to
/// corrupt a slot and a channel a coercer could read a receipt out of.
///
/// # Arguments
/// * `k1` - The plaintext polynomial encoding the vote
/// * `base` - The first coefficient of the ballot region, from [`ballot_layout`]
///
/// # Returns
/// Returns `true` if every coefficient below `base` is zero, `false` otherwise.
fn check_prefix_zero<let D: u32>(k1: Polynomial<D>, base: u32) -> bool {
    let mut valid = true;

    for i in 0..D {
        if i < base {
            valid = valid & (k1.coefficients[i] == 0);
        }
    }

    valid
}

/// Validates vote coefficients for n-choice voting.
///
/// Constrains the whole plaintext, not only the option segments: coefficients outside the ballot
/// region must be zero, and every coefficient inside it must be a binary digit.
///
/// Rules:
/// - 2 options: Mutually exclusive (only one can be non-zero)
/// - 3+ options: Can split votes, but total must not exceed balance
///
/// # Arguments
/// * `k1` - The plaintext polynomial encoding the vote
/// * `q_mod_t` - The non-centered plaintext scale modulo the plaintext modulus
/// * `balance` - The voter's balance/voting power
/// * `num_options` - Number of voting options
pub fn check_coefficient_values_with_balance<let D: u32>(
    k1: Polynomial<D>,
    q_mod_t: Field,
    balance: Field,
    num_options: u32,
) -> bool {
    let (base, segment_size) = ballot_layout::<D>(num_options);

    let mut valid = check_prefix_zero(k1, base);

    let mut sums: [u64; MAX_OPTIONS] = [0; MAX_OPTIONS];
    let mut non_zero_count: u64 = 0;
    let mut total_votes: u64 = 0;

    // Process each option
    for opt_idx in 0..MAX_OPTIONS {
        if (opt_idx as u64) < (num_options as u64) {
            // Because of the reversal, option `opt_idx` sits at segment `num_options - 1 - opt_idx`.
            let circuit_segment: u32 = num_options - 1 - opt_idx;
            let start_idx: u32 = base + (circuit_segment * segment_size);

            let mut sum: u64 = 0;

            // Bits are reversed (LSB first)
            for bit_pos in 0..MAX_VOTE_BITS {
                if (bit_pos as u64) < (segment_size as u64) {
                    let idx: u32 = start_idx + bit_pos;
                    let coeff = k1.coefficients[idx];

                    // Binary constraint: coeff must be 0 or q_mod_t
                    valid = valid & (0 == coeff * (q_mod_t - coeff));

                    let bit: u64 = if coeff == 0 { 0 } else { 1 };
                    sum += bit * (1 << (bit_pos as u64));
                }
            }

            sums[opt_idx] = sum;
            total_votes += sum;

            if sum != 0 {
                non_zero_count += 1;
            }
        }
    }

    // Voting rules based on number of options
    if num_options == 2 {
        valid = valid & (non_zero_count <= 1);

        for opt_idx in 0..MAX_OPTIONS {
            if ((opt_idx as u64) < (num_options as u64)) & (sums[opt_idx] != 0) {
                valid = valid & (sums[opt_idx] <= (balance as u64));
            }
        }
    } else {
        valid = valid & (total_votes <= (balance as u64));
    }

    valid
}

/// Checks that the plaintext carries no ballot at all.
///
/// Every coefficient of `k1` must be zero, not only the option segments. A mask needs no signature,
/// so anyone may write one to any eligible slot; a mask that could carry a payload outside the
/// segments would let anyone corrupt a slot they cannot vote in, and would give a coercer a channel
/// to mark a ballot with. Checking the whole polynomial closes both.
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
    let (_base, _segment_size) = ballot_layout::<D>(num_options);

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
// Every test builds `k1` the way the witness generator does — SDK message layout, reversed over the
// full BFV degree — rather than at the width of the message region. The two only agree when the
// degree equals `MAX_MSG_NON_ZERO_COEFFS`, which no preset uses, so testing at the message width
// hid the layout the circuit actually receives.

/// The BFV degree of the `insecure-512` preset. Large enough that the padding between the top of
/// the message region and the degree is most of the polynomial, which is the region the old index
/// arithmetic read from.
global TEST_DEGREE: u32 = 512;

/// Builds `k1` for a ballot: `encodeVote` from `@crisp-e3/sdk`, followed by the reversal the
/// witness generator applies.
///
/// # Arguments
/// * `values` - One value per option, in option order; entries past `num_options` are ignored
/// * `num_options` - Number of voting options
/// * `one` - The coefficient a set bit encodes to, which is `q_mod_t`
fn encode_ballot<let D: u32>(
    values: [u64; MAX_OPTIONS],
    num_options: u32,
    one: Field,
) -> Polynomial<D> {
    let segment_size: u32 = MAX_MSG_NON_ZERO_COEFFS / num_options;
    let mut coefficients: [Field; D] = [0; D];

    for opt in 0..MAX_OPTIONS {
        if opt < num_options {
            let start: u32 = opt * segment_size;

            for i in 0..MAX_VOTE_BITS {
                if i < segment_size {
                    // The SDK writes each segment most significant bit first.
                    let bit_pos: u32 = segment_size - 1 - i;
                    let bit: u64 = (values[opt] >> (bit_pos as u64)) & 1;

                    coefficients[D - 1 - (start + i)] = if bit == 1 { one } else { 0 };
                }
            }
        }
    }

    Polynomial { coefficients }
}

#[test]
fn test_2_options_vote_first() {
    let pol = encode_ballot::<TEST_DEGREE>([5, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2, 1);
    assert(check_coefficient_values_with_balance(pol, 1, 100, 2));
}

#[test]
fn test_non_centered_plaintext_scale() {
    let pol = encode_ballot::<TEST_DEGREE>([5, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2, 93);
    assert(check_coefficient_values_with_balance(pol, 93, 100, 2));
    assert(!check_coefficient_values_with_balance(pol, -7, 100, 2));
}

#[test]
fn test_2_options_vote_second() {
    let pol = encode_ballot::<TEST_DEGREE>([0, 3, 0, 0, 0, 0, 0, 0, 0, 0], 2, 1);
    assert(check_coefficient_values_with_balance(pol, 1, 100, 2));
}

#[test]
fn test_2_options_both_voted_fails() {
    let pol = encode_ballot::<TEST_DEGREE>([1, 1, 0, 0, 0, 0, 0, 0, 0, 0], 2, 1);
    assert(!check_coefficient_values_with_balance(pol, 1, 100, 2));
}

#[test]
fn test_2_options_exceeds_balance_fails() {
    let pol = encode_ballot::<TEST_DEGREE>([10, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2, 1);
    assert(!check_coefficient_values_with_balance(pol, 1, 5, 2));
}

#[test]
fn test_2_options_at_balance_passes() {
    let pol = encode_ballot::<TEST_DEGREE>([5, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2, 1);
    assert(check_coefficient_values_with_balance(pol, 1, 5, 2));
}

/// The top bit of an option segment. The old index arithmetic read the zero padding instead, so a
/// ballot worth `2**49` passed against any balance.
#[test]
fn test_2_options_top_bit_is_bounded() {
    let pol = encode_ballot::<TEST_DEGREE>([562949953421312, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2, 1);
    assert(!check_coefficient_values_with_balance(pol, 1, 1, 2));
    assert(check_coefficient_values_with_balance(pol, 1, 562949953421312, 2));
}

// --- 3+ Options (Split Voting) ---

#[test]
fn test_3_options_split_vote() {
    let pol = encode_ballot::<TEST_DEGREE>([40, 0, 60, 0, 0, 0, 0, 0, 0, 0], 3, 1);
    assert(check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_3_options_vote_all_three() {
    let pol = encode_ballot::<TEST_DEGREE>([30, 30, 30, 0, 0, 0, 0, 0, 0, 0], 3, 1);
    assert(check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_3_options_total_exceeds_balance_fails() {
    let pol = encode_ballot::<TEST_DEGREE>([60, 60, 0, 0, 0, 0, 0, 0, 0, 0], 3, 1);
    assert(!check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_5_options_single_vote() {
    let pol = encode_ballot::<TEST_DEGREE>([0, 0, 50, 0, 0, 0, 0, 0, 0, 0], 5, 1);
    assert(check_coefficient_values_with_balance(pol, 1, 100, 5));
}

#[test]
fn test_zero_vote_passes() {
    let pol = encode_ballot::<TEST_DEGREE>([0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 3, 1);
    assert(check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_invalid_coefficient_fails() {
    let mut pol: Polynomial<TEST_DEGREE> = encode_ballot([1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2, 1);
    // Option 0 occupies the top segment, so its least significant coefficient is the last one.
    pol.coefficients[TEST_DEGREE - 1] = 2;

    assert(!check_coefficient_values_with_balance(pol, 1, 100, 2));
}

/// Coefficients the ballot layout does not use must be zero. Before the layout was corrected they
/// were never read, which let any submitter attach a payload to a slot.
#[test]
fn test_payload_outside_ballot_region_fails() {
    let mut pol: Polynomial<TEST_DEGREE> = encode_ballot([1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 2, 1);
    pol.coefficients[0] = 1;

    assert(!check_coefficient_values_with_balance(pol, 1, 100, 2));
}

/// With three options the SDK leaves one message coefficient unused, which the reversal puts at the
/// bottom of the ballot region. It belongs to no option, so it must be zero.
#[test]
fn test_unused_message_coefficient_fails() {
    let mut pol: Polynomial<TEST_DEGREE> = encode_ballot([1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 3, 1);
    // MAX_MSG_NON_ZERO_COEFFS is 100 and three segments of 33 leave one coefficient over.
    pol.coefficients[TEST_DEGREE - MAX_MSG_NON_ZERO_COEFFS] = 1;

    assert(!check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_check_coefficient_zero_passes() {
    let pol: Polynomial<TEST_DEGREE> = Polynomial { coefficients: [0; TEST_DEGREE] };
    assert(check_coefficient_zero(pol, 3));
}

#[test]
fn test_check_coefficient_zero_fails() {
    let pol = encode_ballot::<TEST_DEGREE>([1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 3, 1);
    assert(!check_coefficient_zero(pol, 3));
}

/// A mask must be zero everywhere, not only where the vote rules look. This coefficient is outside
/// every option segment, and it used to pass.
#[test]
fn test_check_coefficient_zero_outside_ballot_region_fails() {
    let mut pol: Polynomial<TEST_DEGREE> = Polynomial { coefficients: [0; TEST_DEGREE] };
    pol.coefficients[0] = 1;

    assert(!check_coefficient_zero(pol, 3));
}
