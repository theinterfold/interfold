// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Utility functions for polynomial operations.

use num_bigint::BigInt;
use num_traits::Zero;

/// Centers a value already in [0, modulus) into the symmetric range (-modulus/2, modulus/2].
///
/// Caller must ensure `x` is in [0, modulus). For odd modulus the range is (-(q-1)/2, (q-1)/2];
/// for even modulus, values ≥ q/2 become negative.
///
/// # Arguments
///
/// * `x` - Value in [0, modulus).
/// * `modulus` - The modulus.
pub fn center(x: &BigInt, modulus: &BigInt) -> BigInt {
    let half_modulus = modulus / 2;

    let mut r = x.clone();

    if (modulus % BigInt::from(2)) == BigInt::from(1) {
        if r > half_modulus {
            r -= modulus;
        }
    } else if r >= half_modulus {
        r -= modulus;
    }

    r
}

/// Reduces a number modulo a modulus.
///
/// # Arguments
///
/// * `x` - The number to reduce
/// * `modulus` - The modulus to reduce by
///
/// # Returns
///
/// The reduced number in the range [0, modulus)
pub fn reduce(x: &BigInt, modulus: &BigInt) -> BigInt {
    let mut r = x % modulus;
    if r < BigInt::zero() {
        r += modulus;
    }
    r
}

/// Checks if all coefficients in a vector are within a centered range.
///
/// This function verifies that every coefficient in the input vector falls within
/// the inclusive range [lower_bound, upper_bound]. This is typically used for
/// coefficients that have been centered around zero.
///
/// # Arguments
///
/// * `vec` - A slice of `BigInt` coefficients to check.
/// * `lower_bound` - The minimum allowed value (inclusive).
/// * `upper_bound` - The maximum allowed value (inclusive).
///
/// # Returns
///
/// `true` if all coefficients are within bounds, `false` otherwise.
pub fn range_check_centered(vec: &[BigInt], lower_bound: &BigInt, upper_bound: &BigInt) -> bool {
    vec.iter()
        .all(|coeff| coeff >= lower_bound && coeff <= upper_bound)
}

/// Checks if all coefficients satisfy standard range constraints with separate upper and lower bounds.
///
/// This function verifies that each coefficient falls within one of two ranges:
/// 1. [0, up_bound] (positive range)
/// 2. [modulus + low_bound, modulus) (negative range wrapped around modulus)
///
/// This is commonly used in cryptographic applications where coefficients can be
/// represented in both positive and negative forms modulo a prime.
///
/// # Mathematical Background
///
/// In modular arithmetic, negative values are often represented as their positive
/// equivalents: `-x ≡ modulus - x (mod modulus)`. This function checks both
/// the direct positive representation and the wrapped negative representation.
///
/// # Arguments
///
/// * `vec` - A slice of `BigInt` coefficients to check
/// * `low_bound` - The lower bound for the negative range (typically negative)
/// * `up_bound` - The upper bound for the positive range
/// * `modulus` - The modulus used for wraparound calculations
///
/// # Returns
///
/// `true` if all coefficients satisfy the range constraints, `false` otherwise
pub fn range_check_standard_2bounds(
    vec: &[BigInt],
    low_bound: &BigInt,
    up_bound: &BigInt,
    modulus: &BigInt,
) -> bool {
    vec.iter().all(|coeff| {
        (coeff >= &BigInt::from(0) && coeff <= up_bound)
            || (coeff >= &(modulus + low_bound) && coeff < modulus)
    })
}

/// Checks if all coefficients satisfy symmetric standard range constraints.
///
/// This function verifies that each coefficient falls within one of two symmetric ranges:
/// 1. [0, bound] (positive range)
/// 2. [modulus - bound, modulus) (negative range wrapped around modulus)
///
/// This is a special case of `range_check_standard_2bounds` where the bounds are
/// symmetric around zero. Commonly used for error distributions in cryptography.
///
/// # Mathematical Background
///
/// For a coefficient `c` and bound `b`, this function accepts:
/// - `c ∈ [0, b]` (small positive values).
/// - `c ∈ [modulus - b, modulus)` (small negative values as positive representatives).
///
/// # Arguments
///
/// * `vec` - A slice of `BigInt` coefficients to check
/// * `bound` - The symmetric bound (both positive and negative)
/// * `modulus` - The modulus used for wraparound calculations
///
/// # Returns
///
/// `true` if all coefficients satisfy the symmetric range constraints, `false` otherwise
pub fn range_check_standard(vec: &[BigInt], bound: &BigInt, modulus: &BigInt) -> bool {
    vec.iter().all(|coeff| {
        (coeff >= &BigInt::from(0) && coeff <= bound)
            || (coeff >= &(modulus - bound) && coeff < modulus)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    #[test]
    fn test_reduce_then_center() {
        let modulus = BigInt::from(7);

        assert_eq!(
            center(&reduce(&BigInt::from(10), &modulus), &modulus),
            BigInt::from(3)
        );
        assert_eq!(
            center(&reduce(&BigInt::from(-3), &modulus), &modulus),
            BigInt::from(-3)
        );
        assert_eq!(
            center(&reduce(&BigInt::from(6), &modulus), &modulus),
            BigInt::from(-1)
        );
    }

    #[test]
    fn test_reduce_less_than_neg_modulus() {
        let modulus = BigInt::from(7);

        // Test value < -p (the bug fix case)
        assert_eq!(reduce(&BigInt::from(-10), &modulus), BigInt::from(4)); // -10 % 7 = -3, -3 + 7 = 4
        assert_eq!(reduce(&BigInt::from(-14), &modulus), BigInt::from(0)); // -14 % 7 = 0
        assert_eq!(reduce(&BigInt::from(-15), &modulus), BigInt::from(6)); // -15 % 7 = -1, -1 + 7 = 6
        assert_eq!(reduce(&BigInt::from(-21), &modulus), BigInt::from(0)); // -21 % 7 = 0

        // Test exactly -p
        assert_eq!(reduce(&BigInt::from(-7), &modulus), BigInt::from(0));

        // Test values in [-p, 0)
        assert_eq!(reduce(&BigInt::from(-6), &modulus), BigInt::from(1)); // -6 % 7 = -6, -6 + 7 = 1
        assert_eq!(reduce(&BigInt::from(-1), &modulus), BigInt::from(6)); // -1 % 7 = -1, -1 + 7 = 6

        // Test positive values
        assert_eq!(reduce(&BigInt::from(0), &modulus), BigInt::from(0));
        assert_eq!(reduce(&BigInt::from(3), &modulus), BigInt::from(3));
        assert_eq!(reduce(&BigInt::from(7), &modulus), BigInt::from(0));
        assert_eq!(reduce(&BigInt::from(10), &modulus), BigInt::from(3));

        // Verify all results are in [0, modulus)
        let test_values = vec![
            BigInt::from(-100),
            BigInt::from(-50),
            BigInt::from(-7),
            BigInt::from(-1),
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(7),
            BigInt::from(50),
            BigInt::from(100),
        ];
        for val in test_values {
            let result = reduce(&val, &modulus);
            assert!(
                result >= BigInt::from(0),
                "Result {} should be >= 0",
                result
            );
            assert!(
                result < modulus,
                "Result {} should be < {}",
                result,
                modulus
            );
        }
    }
}
