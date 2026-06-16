// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use interfold_lib::math::polynomial::Polynomial;

use crate::constants::{MAX_OPTIONS, MAX_VOTE_BITS};

/// Validates vote coefficients for n-choice voting.
///
/// Rules:
/// - 2 options: Mutually exclusive (only one can be non-zero)
/// - 3+ options: Can split votes, but total must not exceed balance
///
/// # Arguments
/// * `k1` - The plaintext polynomial encoding the vote
/// * `q_mod_t_centered` - The field representation of 1 in centered form
/// * `balance` - The voter's balance/voting power
/// * `num_options` - Number of voting options
pub fn check_coefficient_values_with_balance<let D: u32>(
    k1: Polynomial<D>,
    q_mod_t_centered: Field,
    balance: Field,
    num_options: u32,
) -> bool {
    assert(num_options > 1);
    assert(num_options as u64 <= MAX_OPTIONS as u64);

    let mut valid = true;

    let segment_size: u32 = D / num_options;
    let remainder: u32 = D - (segment_size * num_options);

    let mut sums: [u64; MAX_OPTIONS] = [0; MAX_OPTIONS];
    let mut non_zero_count: u64 = 0;
    let mut total_votes: u64 = 0;

    // Process each option
    for opt_idx in 0..MAX_OPTIONS {
        if (opt_idx as u64) < (num_options as u64) {
            // Due to reversal, TypeScript option opt_idx is at circuit segment (num_options - 1 - opt_idx)
            // Remainder zeros at end of TypeScript layout become start after k1.reverse()
            let circuit_segment: u32 = num_options - 1 - opt_idx;
            let start_idx: u32 = remainder + (circuit_segment * segment_size);

            let mut sum: u64 = 0;

            // Bits are reversed (LSB first)
            for bit_pos in 0..MAX_VOTE_BITS {
                if (bit_pos as u64) < (segment_size as u64) {
                    let idx: u32 = start_idx + bit_pos;
                    let coeff = k1.coefficients[idx];

                    // Binary constraint: coeff must be 0 or q_mod_t
                    valid = valid & (0 == coeff * (q_mod_t_centered - coeff));

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

/// Checks if all vote coefficients are zero.
///
/// This function verifies that all vote regions contain only zeros.
/// Used in masking operations to ensure that invalid or unauthorized votes are properly
/// masked (set to zero) before being added to the tally.
///
/// # Arguments
/// * `k1` - The plaintext polynomial encoding the vote
///
/// # Returns
/// Returns `true` if all vote coefficients are zero, `false` otherwise.
///
pub fn check_coefficient_zero<let D: u32>(k1: Polynomial<D>, num_options: u32) -> bool {
    assert(num_options > 1);
    assert(num_options as u64 <= MAX_OPTIONS as u64);

    let mut valid = true;

    let segment_size: u32 = D / num_options;
    let remainder: u32 = D - (segment_size * num_options);

    for opt_idx in 0..MAX_OPTIONS {
        if (opt_idx as u64) < (num_options as u64) {
            let circuit_segment: u32 = num_options - 1 - opt_idx;
            let start_idx: u32 = remainder + (circuit_segment * segment_size);

            for bit_pos in 0..MAX_VOTE_BITS {
                if (bit_pos as u64) < (segment_size as u64) {
                    let idx: u32 = start_idx + bit_pos;
                    valid = valid & (k1.coefficients[idx] == 0);
                }
            }
        }
    }

    valid
}

#[test]
fn test_2_options_vote_first() {
    let mut coeffs = [0; 100];
    // Option 0, value 5, circuit segment 1 [50..99], LSB first
    coeffs[50] = 1; // 2^0 = 1
    coeffs[52] = 1; // 2^2 = 4

    let pol = Polynomial { coefficients: coeffs };
    assert(check_coefficient_values_with_balance(pol, 1, 100, 2));
}

#[test]
fn test_2_options_vote_second() {
    let mut coeffs = [0; 100];
    // Option 1, value 3, circuit segment 0 [0..49], LSB first
    coeffs[0] = 1; // 2^0 = 1
    coeffs[1] = 1; // 2^1 = 2

    let pol = Polynomial { coefficients: coeffs };
    assert(check_coefficient_values_with_balance(pol, 1, 100, 2));
}

#[test]
fn test_2_options_both_voted_fails() {
    let mut coeffs = [0; 100];
    coeffs[50] = 1; // Option 0
    coeffs[0] = 1; // Option 1

    let pol = Polynomial { coefficients: coeffs };
    assert(!check_coefficient_values_with_balance(pol, 1, 100, 2));
}

#[test]
fn test_2_options_exceeds_balance_fails() {
    let mut coeffs = [0; 100];
    // Option 0, value 10, balance 5
    coeffs[51] = 1; // 2^1 = 2
    coeffs[53] = 1; // 2^3 = 8

    let pol = Polynomial { coefficients: coeffs };
    assert(!check_coefficient_values_with_balance(pol, 1, 5, 2));
}

// --- 3+ Options (Split Voting) ---

#[test]
fn test_3_options_split_vote() {
    // D = 99, segment_size = 33
    // Vote 40 on option 0, 60 on option 2, total = 100, balance = 100
    let mut coeffs = [0; 99];

    // Option 0 at circuit segment 2 [66..98], value 40 = 101000, LSB first
    coeffs[69] = 1; // 2^3 = 8
    coeffs[71] = 1; // 2^5 = 32
    // Total: 40

    // Option 2 at circuit segment 0 [0..32], value 60 = 111100, LSB first
    coeffs[2] = 1; // 2^2 = 4
    coeffs[3] = 1; // 2^3 = 8
    coeffs[4] = 1; // 2^4 = 16
    coeffs[5] = 1; // 2^5 = 32
    // Total: 60

    let pol = Polynomial { coefficients: coeffs };
    assert(check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_3_options_vote_all_three() {
    // Vote 30 on each, total = 90, balance = 100
    let mut coeffs = [0; 99];

    // Option 0 at circuit segment 2 [66..98], value 30 = 11110, LSB first
    coeffs[67] = 1; // 2^1 = 2
    coeffs[68] = 1; // 2^2 = 4
    coeffs[69] = 1; // 2^3 = 8
    coeffs[70] = 1; // 2^4 = 16
    // Total: 30

    // Option 1 at circuit segment 1 [33..65], value 30
    coeffs[34] = 1; // 2^1 = 2
    coeffs[35] = 1; // 2^2 = 4
    coeffs[36] = 1; // 2^3 = 8
    coeffs[37] = 1; // 2^4 = 16
    // Total: 30

    // Option 2 at circuit segment 0 [0..32], value 30
    coeffs[1] = 1; // 2^1 = 2
    coeffs[2] = 1; // 2^2 = 4
    coeffs[3] = 1; // 2^3 = 8
    coeffs[4] = 1; // 2^4 = 16
    // Total: 30

    let pol = Polynomial { coefficients: coeffs };
    assert(check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_3_options_total_exceeds_balance_fails() {
    // Vote 60 + 60 = 120, balance = 100
    let mut coeffs = [0; 99];

    // Option 0, value 60
    coeffs[68] = 1; // 2^2 = 4
    coeffs[69] = 1; // 2^3 = 8
    coeffs[70] = 1; // 2^4 = 16
    coeffs[71] = 1; // 2^5 = 32

    // Option 1, value 60
    coeffs[35] = 1; // 2^2 = 4
    coeffs[36] = 1; // 2^3 = 8
    coeffs[37] = 1; // 2^4 = 16
    coeffs[38] = 1; // 2^5 = 32

    let pol = Polynomial { coefficients: coeffs };
    assert(!check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_5_options_single_vote() {
    // D = 100, segment_size = 20
    // Vote only on option 2 with value 50
    let mut coeffs = [0; 100];

    // Option 2 at circuit segment 2 [40..59], value 50 = 110010, LSB first
    coeffs[41] = 1; // 2^1 = 2
    coeffs[44] = 1; // 2^4 = 16
    coeffs[45] = 1; // 2^5 = 32
    // Total: 50

    let pol = Polynomial { coefficients: coeffs };
    assert(check_coefficient_values_with_balance(pol, 1, 100, 5));
}

#[test]
fn test_zero_vote_passes() {
    let pol = Polynomial { coefficients: [0; 100] };
    assert(check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_non_divisible_d_vote_passes() {
    // D=100, num_options=3 => D % num_options != 0 (remainder=1)
    // segment_size=33, remainder=1; option 0 at circuit_segment 2 [67..99]
    let mut coeffs = [0; 100];
    coeffs[67] = 1; // Option 0, bit 0 (2^0)
    coeffs[69] = 1; // Option 0, bit 2 (2^2) => vote value 5

    let pol = Polynomial { coefficients: coeffs };
    assert(check_coefficient_values_with_balance(pol, 1, 100, 3));
}

#[test]
fn test_invalid_coefficient_fails() {
    let mut coeffs = [0; 100];
    coeffs[50] = 2; // Invalid

    let pol = Polynomial { coefficients: coeffs };
    assert(!check_coefficient_values_with_balance(pol, 1, 100, 2));
}

#[test]
fn test_check_coefficient_zero_passes() {
    let pol = Polynomial { coefficients: [0; 100] };
    assert(check_coefficient_zero(pol, 3));
}

#[test]
fn test_check_coefficient_zero_fails() {
    let mut coeffs = [0; 99];
    coeffs[33] = 1;

    let pol = Polynomial { coefficients: coeffs };
    assert(!check_coefficient_zero(pol, 3));
}

#[test]
fn test_check_coefficient_zero_non_divisible_d_fails() {
    // D=100, num_options=3 => remainder=1; option 2 at circuit_segment 0 [1..33]
    let mut coeffs = [0; 100];
    coeffs[1] = 1; // Option 2 LSB

    let pol = Polynomial { coefficients: coeffs };
    assert(!check_coefficient_zero(pol, 3));
}
