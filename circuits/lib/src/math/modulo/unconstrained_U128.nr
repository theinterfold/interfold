// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Unconstrained functions for modular u128 arithmetic.
//!
//! This module provides unconstrained functions that perform modular arithmetic
//! computations without generating circuit constraints. These functions are used
//! internally by the constrained operations in `U128` and should not be called
//! directly in circuits without proper verification.

/// Computes quotient and remainder for value modulo q (unconstrained).
///
/// This function performs integer division and modulo operations to compute
/// `value = q * quotient + remainder` where `0 <= remainder < q`.
///
/// # Arguments
/// * `value` - The value to reduce
/// * `q` - The modulus
///
/// # Returns
/// A tuple `(quotient, remainder)` where:
/// - `quotient = value / q`
/// - `remainder = value % q`
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
pub unconstrained fn __compute_mod_reduction(value: Field, q: Field) -> (Field, Field) {
    let value_u128 = value as u128;
    let q_u128 = q as u128;

    let quotient_u128 = value_u128 / q_u128;
    let remainder_u128 = value_u128 % q_u128;

    (quotient_u128 as Field, remainder_u128 as Field)
}

/// Computes the negation of a value modulo m (unconstrained).
///
/// Returns `(m - val) mod m`, with special handling for zero (returns 0).
///
/// # Arguments
/// * `val` - The value to negate
/// * `m` - The modulus
///
/// # Returns
/// The additive inverse `(-val) mod m`
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
pub unconstrained fn __neg(val: Field, m: Field) -> Field {
    if val == 0 {
        0
    } else {
        m - val
    }
}

/// Subtracts two values with underflow handling (unconstrained).
///
/// Computes `(lhs - rhs) mod m`, handling the case where `lhs < rhs` by adding
/// the modulus. Returns both the result and a flag indicating if underflow occurred.
///
/// # Preconditions
/// Inputs must be reduced modulo `m` such that `lhs, rhs in [0, m)`. This ensures
/// that the computed difference is bounded and cannot overflow `u128`.
///
/// # Arguments
/// * `lhs` - Left-hand side value (minuend), must be in `[0, m)`
/// * `rhs` - Right-hand side value (subtrahend), must be in `[0, m)`
/// * `m` - The modulus, must satisfy `m <= u128::MAX`
///
/// # Returns
/// A tuple `(result, underflow)` where:
/// - `result = (lhs - rhs) mod m`
/// - `underflow = true` if `lhs < rhs`, `false` otherwise
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
/// As long as inputs are reduced modulo `m` (and `m <= u128::MAX`), the subtraction-with-underflow
/// logic is safe and will not overflow `u128`. This function is used by the constrained `sub` method
/// in `modulo::U128`, which ensures inputs are properly reduced before calling `__sub_with_underflow`.
/// See the surrounding `modulo/unconstrained_U128` module documentation for details.
pub unconstrained fn __sub_with_underflow(lhs: Field, rhs: Field, m: Field) -> (Field, bool) {
    let lhs_u128 = lhs as u128;
    let rhs_u128 = rhs as u128;
    let m_u128 = m as u128;

    let underflow = lhs_u128 < rhs_u128;
    let result = if underflow {
        // Compute (lhs - rhs + m) mod m safely to avoid u128 overflow
        // Since lhs < rhs, we compute: m - (rhs - lhs)
        // This avoids the potential overflow in lhs + m
        let diff = rhs_u128 - lhs_u128; // This is safe since rhs > lhs
        (m_u128 - diff) as Field
    } else {
        (lhs_u128 - rhs_u128) as Field
    };
    (result, underflow)
}

/// Multiplies two values and returns both quotient and remainder (unconstrained).
///
/// Computes `lhs * rhs = m * quotient + remainder` where `0 <= remainder < m`.
///
/// # Arguments
/// * `lhs` - Left-hand side value
/// * `rhs` - Right-hand side value
/// * `m` - The modulus
///
/// # Returns
/// A tuple `(quotient, remainder)` where `lhs * rhs = m * quotient + remainder`
///
/// # Overflow Warning
/// Field multiplication wraps modulo the field prime (~254 bits). For two u128 values
/// near 2^128, their product (up to 2^256) exceeds the Field modulus, causing silent
/// wraparound before the mod reduction. This can produce incorrect results.
///
/// # Safe Input Range
/// To avoid overflow, ensure `lhs * rhs < Field::MODULUS`. For typical use cases:
/// - Party IDs, polynomial coefficients, and small cryptographic values (< 2^64) are safe
/// - Arbitrary u128 values may overflow and should be validated by callers
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
/// Callers must ensure inputs are within the safe range to prevent silent overflow.
pub unconstrained fn __mul_with_quotient(lhs: Field, rhs: Field, m: Field) -> (Field, Field) {
    // WARNING: Field multiplication can overflow for large inputs.
    // For u128 values near 2^128, the product (up to 2^256) exceeds Field modulus (~2^254),
    // causing wraparound. This is safe for typical use cases (party IDs, small coefficients),
    // but callers must validate input ranges for arbitrary u128 values.
    let product = lhs * rhs;
    __compute_mod_reduction(product, m)
}

/// Multiplies lhs and rhs via u128 arithmetic, returning (quotient, remainder).
///
/// Safe when lhs, rhs < 2^62: product < 2^124, fits in u128 without wrapping.
/// Prefer this over `__mul_with_quotient` when inputs are known to be < 2^62 (i.e. when
/// the modulus is < 2^62), as it avoids silent Field-prime wraparound.
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
pub unconstrained fn __mul_with_quotient_u128(lhs: Field, rhs: Field, m: Field) -> (Field, Field) {
    let product = lhs as u128 * rhs as u128; // safe: inputs < 2^62, product < 2^124
    let q = m as u128;
    ((product / q) as Field, (product % q) as Field)
}

/// Computes the modular multiplicative inverse using Fermat's Little Theorem (unconstrained).
///
/// For a prime modulus `m` and value `val` coprime to `m`, computes `val^(-1) mod m`
/// using the identity: val^(-1) = val^(m-2) (mod m) (from Fermat's Little Theorem).
///
/// # Arguments
/// * `val` - The value to invert (must be coprime with the modulus)
/// * `m` - The modulus (should be prime for this method to work correctly)
///
/// # Returns
/// The modular inverse `val^(-1) mod m` such that `(val * result) mod m = 1`
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
pub unconstrained fn __inv_mod(val: Field, m: Field) -> Field {
    // by Fermat's Little Theorem: val^(m-1)= 1 mod m
    __pow_mod(val, m - 2, m)
}

/// Computes modular division: `lhs * rhs^(-1) mod m` (unconstrained).
///
/// This is equivalent to multiplying `lhs` by the modular inverse of `rhs`.
///
/// # Arguments
/// * `lhs` - The numerator
/// * `rhs` - The denominator (must be coprime with the modulus)
/// * `m` - The modulus
///
/// # Returns
/// The result of `(lhs * rhs^(-1)) mod m`
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
pub unconstrained fn __div_mod(lhs: Field, rhs: Field, m: Field) -> Field {
    let rhs_inv = __inv_mod(rhs, m);
    __mul_mod(lhs, rhs_inv, m)
}

/// Computes modular exponentiation: `base^exp mod m` (unconstrained).
///
/// Uses the binary exponentiation method (also known as square-and-multiply)
/// for efficient computation of large powers.
///
/// # Arguments
/// * `base` - The base value
/// * `exp` - The exponent
/// * `m` - The modulus
///
/// # Returns
/// The result of `base^exp mod m`
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
pub unconstrained fn __pow_mod(base: Field, exp: Field, m: Field) -> Field {
    let mut result = 1 as Field;
    let (_, base_mod) = __compute_mod_reduction(base, m);
    let mut current_base = base_mod;
    let mut e = exp as u128;

    while e > 0 {
        if (e % 2) == 1 {
            result = __mul_mod(result, current_base, m);
        }
        current_base = __mul_mod(current_base, current_base, m);
        e = e / 2;
    }

    result
}

/// Multiplies two values with modular reduction (unconstrained).
///
/// Computes `(lhs * rhs) mod m` and returns only the remainder.
///
/// # Arguments
/// * `lhs` - Left-hand side value
/// * `rhs` - Right-hand side value
/// * `m` - The modulus
///
/// # Returns
/// The result of `(lhs * rhs) mod m`
///
/// # Safety
/// This is an unconstrained function. The result must be verified in constrained code.
pub unconstrained fn __mul_mod(lhs: Field, rhs: Field, m: Field) -> Field {
    let (_, r) = __mul_with_quotient(lhs, rhs, m);
    r
}

// ------------------------------ TESTS ------------------------------
// Note: All unsafe blocks in the following tests are safe because we are testing
// unconstrained functions in a controlled test environment. These functions are
// designed to be called from unsafe blocks or other unconstrained functions.
// Each unsafe block is used to call an unconstrained function for testing purposes.

#[test]
fn test_compute_mod_reduction_simple() {
    // Safety: Test function calling unconstrained helper
    let (q, r) = unsafe { __compute_mod_reduction(42, 10) };
    assert(q == 4); // 42 / 10 = 4
    assert(r == 2); // 42 % 10 = 2
    // Verify: 42 = 10 * 4 + 2
    assert(10 * q + r == 42);
}

#[test]
fn test_compute_mod_reduction_exact_multiple() {
    // Safety: Test function calling unconstrained helper
    let (q, r) = unsafe { __compute_mod_reduction(100, 10) };
    assert(q == 10); // 100 / 10 = 10
    assert(r == 0); // 100 % 10 = 0
    assert(10 * q + r == 100);
}

#[test]
fn test_compute_mod_reduction_large_value() {
    // Safety: Test function calling unconstrained helper
    let (q, r) = unsafe { __compute_mod_reduction(12345, 100) };
    assert(q == 123); // 12345 / 100 = 123
    assert(r == 45); // 12345 % 100 = 45
    assert(100 * q + r == 12345);
}

#[test]
fn test_compute_mod_reduction_smaller_than_modulus() {
    // Safety: Test function calling unconstrained helper
    let (q, r) = unsafe { __compute_mod_reduction(7, 10) };
    assert(q == 0); // 7 / 10 = 0
    assert(r == 7); // 7 % 10 = 7
    assert(10 * q + r == 7);
}

#[test]
fn test_neg_zero() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __neg(0, 100) };
    assert(result == 0); // Negation of zero is zero
}

#[test]
fn test_neg_non_zero() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __neg(30, 100) };
    assert(result == 70); // 100 - 30 = 70
}

#[test]
fn test_neg_large_value() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __neg(12345, 100000) };
    assert(result == 87655); // 100000 - 12345 = 87655
}

#[test]
fn test_neg_verification() {
    let val: Field = 42;
    let m: Field = 97;
    // Safety: Test function calling unconstrained helper
    let neg_val = unsafe { __neg(val, m) };
    // Verify: val + neg_val = 0 (mod m)
    let sum = val + neg_val;
    // Safety: Test function calling unconstrained helper
    let (_, remainder) = unsafe { __compute_mod_reduction(sum, m) };
    assert(remainder == 0);
}

#[test]
fn test_sub_with_underflow_no_underflow() {
    // Safety: Test function calling unconstrained helper
    let (result, underflow) = unsafe { __sub_with_underflow(50, 30, 100) };
    assert(underflow == false);
    assert(result == 20); // 50 - 30 = 20
}

#[test]
fn test_sub_with_underflow_with_underflow() {
    // Safety: Test function calling unconstrained helper
    let (result, underflow) = unsafe { __sub_with_underflow(30, 50, 100) };
    assert(underflow == true);
    assert(result == 80); // (30 - 50 + 100) mod 100 = 80
}

#[test]
fn test_sub_with_underflow_equal_values() {
    // Safety: Test function calling unconstrained helper
    let (result, underflow) = unsafe { __sub_with_underflow(42, 42, 100) };
    assert(underflow == false);
    assert(result == 0);
}

#[test]
fn test_sub_with_underflow_verification() {
    let lhs: Field = 30;
    let rhs: Field = 50;
    let m: Field = 100;
    // Safety: Test function calling unconstrained helper
    let (result, underflow) = unsafe { __sub_with_underflow(lhs, rhs, m) };

    if underflow {
        // Verify: lhs + m = rhs + result
        assert(lhs + m == rhs + result);
    } else {
        // Verify: lhs = rhs + result
        assert(lhs == rhs + result);
    }
}

#[test]
fn test_mul_with_quotient_simple() {
    // Safety: Test function calling unconstrained helper
    let (q, r) = unsafe { __mul_with_quotient(6, 7, 10) };
    assert(q == 4); // (6 * 7) / 10 = 42 / 10 = 4
    assert(r == 2); // (6 * 7) % 10 = 42 % 10 = 2
    // Verify: 6 * 7 = 10 * 4 + 2
    assert(6 * 7 == 10 * q + r);
}

#[test]
fn test_mul_with_quotient_with_reduction() {
    // Safety: Test function calling unconstrained helper
    let (q, r) = unsafe { __mul_with_quotient(12, 15, 100) };
    assert(q == 1); // (12 * 15) / 100 = 180 / 100 = 1
    assert(r == 80); // (12 * 15) % 100 = 180 % 100 = 80
    assert(12 * 15 == 100 * q + r);
}

#[test]
fn test_mul_with_quotient_exact_multiple() {
    // Safety: Test function calling unconstrained helper
    let (q, r) = unsafe { __mul_with_quotient(5, 20, 100) };
    assert(q == 1); // (5 * 20) / 100 = 100 / 100 = 1
    assert(r == 0); // (5 * 20) % 100 = 100 % 100 = 0
    assert(5 * 20 == 100 * q + r);
}

#[test]
fn test_mul_with_quotient_verification() {
    let lhs: Field = 123;
    let rhs: Field = 456;
    let m: Field = 1000;
    // Safety: Test function calling unconstrained helper
    let (q, r) = unsafe { __mul_with_quotient(lhs, rhs, m) };
    // Verify: lhs * rhs = m * q + r
    assert(lhs * rhs == m * q + r);
    // Verify remainder is in range [0, m)
    assert((r as u128) < (m as u128));
}

#[test]
fn test_mul_mod_simple() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __mul_mod(6, 7, 10) };
    assert(result == 2); // (6 * 7) mod 10 = 42 mod 10 = 2
}

#[test]
fn test_mul_mod_with_reduction() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __mul_mod(12, 15, 100) };
    assert(result == 80); // (12 * 15) mod 100 = 180 mod 100 = 80
}

#[test]
fn test_mul_mod_exact_multiple() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __mul_mod(5, 20, 100) };
    assert(result == 0); // (5 * 20) mod 100 = 100 mod 100 = 0
}

#[test]
fn test_mul_mod_with_zero() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __mul_mod(42, 0, 100) };
    assert(result == 0);
}

#[test]
fn test_mul_mod_commutative() {
    let a: Field = 7;
    let b: Field = 9;
    let m: Field = 100;
    // Safety: Test function calling unconstrained helper
    let mul_a_b = unsafe { __mul_mod(a, b, m) };
    // Safety: Test function calling unconstrained helper
    let mul_b_a = unsafe { __mul_mod(b, a, m) };
    // Verify: a * b = b * a
    assert(mul_a_b == mul_b_a);
}

#[test]
fn test_pow_mod_simple() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __pow_mod(2, 3, 10) };
    assert(result == 8); // 2^3 mod 10 = 8 mod 10 = 8
}

#[test]
fn test_pow_mod_with_reduction() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __pow_mod(2, 10, 100) };
    assert(result == 24); // 2^10 = 1024, 1024 mod 100 = 24
}

#[test]
fn test_pow_mod_exponent_one() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __pow_mod(7, 1, 100) };
    assert(result == 7); // 7^1 mod 100 = 7
}

#[test]
fn test_pow_mod_exponent_zero() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __pow_mod(7, 0, 100) };
    assert(result == 1); // 7^0 mod 100 = 1
}

#[test]
fn test_pow_mod_base_zero() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __pow_mod(0, 5, 100) };
    assert(result == 0); // 0^5 mod 100 = 0
}

#[test]
fn test_pow_mod_large_exponent() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __pow_mod(3, 7, 97) };
    // 3^7 = 2187, 2187 mod 97 = 53
    assert(result == 53);
}

#[test]
fn test_pow_mod_fermat_little_theorem() {
    // For prime modulus p and value a, a^(p-1) = 1 (mod p)
    let a: Field = 3;
    let p: Field = 11; // Prime
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __pow_mod(a, p - 1, p) };
    assert(result == 1);
}

#[test]
fn test_inv_mod_simple() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __inv_mod(3, 11) };
    // 3 * 4 = 12 = 1 (mod 11), so 3^(-1) = 4 (mod 11)
    assert(result == 4);
    // Verify: 3 * result = 1 (mod 11)
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(3, result, 11) } == 1);
}

#[test]
fn test_inv_mod_larger_prime() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __inv_mod(7, 13) };
    // Verify: 7 * result = 1 (mod 13)
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(7, result, 13) } == 1);
}

#[test]
fn test_inv_mod_another_prime() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __inv_mod(5, 17) };
    // Verify: 5 * result = 1 (mod 17)
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(5, result, 17) } == 1);
}

#[test]
fn test_inv_mod_inverse_of_inverse() {
    let a: Field = 7;
    let m: Field = 11;
    // Safety: Test function calling unconstrained helper
    let inv_a = unsafe { __inv_mod(a, m) };
    // Safety: Test function calling unconstrained helper
    let inv_inv_a = unsafe { __inv_mod(inv_a, m) };
    // (a^(-1))^(-1) = a
    assert(inv_inv_a == a);
}

#[test]
fn test_div_mod_simple() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __div_mod(6, 2, 11) };
    assert(result == 3); // 6 / 2 = 3
    // Verify: result * 2 = 6 (mod 11)
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(result, 2, 11) } == 6);
}

#[test]
fn test_div_mod_with_inverse() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __div_mod(7, 3, 11) };
    // 3^(-1) mod 11 = 4 (since 3 * 4 = 12 = 1 mod 11)
    // 7 * 4 = 28 = 6 (mod 11)
    assert(result == 6);
    // Verify: result * 3 = 7 (mod 11)
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(result, 3, 11) } == 7);
}

#[test]
fn test_div_mod_verification() {
    let a: Field = 10;
    let b: Field = 3;
    let m: Field = 17;
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __div_mod(a, b, m) };
    // Verify: result * b = a (mod m)
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(result, b, m) } == a);
}

#[test]
fn test_div_mod_larger_values() {
    let a: Field = 250;
    let b: Field = 7;
    let m: Field = 97;
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __div_mod(a, b, m) };
    // Verify: result * b = a (mod m)
    // Safety: Test function calling unconstrained helper
    let (_, a_reduced) = unsafe { __compute_mod_reduction(a, m) }; // 250 mod 97 = 56
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(result, b, m) } == a_reduced);
}

#[test]
fn test_div_mod_by_one() {
    // Safety: Test function calling unconstrained helper
    let result = unsafe { __div_mod(42, 1, 100) };
    assert(result == 42); // 42 / 1 = 42
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(result, 1, 100) } == 42);
}

#[test]
fn test_all_operations_consistency() {
    // Test that all operations work together correctly
    let m: Field = 97; // Prime
    let a: Field = 42;
    let b: Field = 13;

    // Test: (a + b) mod m
    let sum = a + b;
    // Safety: Test function calling unconstrained helper
    let (_, sum_reduced) = unsafe { __compute_mod_reduction(sum, m) };
    assert(sum_reduced == 55);

    // Test: (a - b) mod m using subtraction
    // Safety: Test function calling unconstrained helper
    let (diff, _) = unsafe { __sub_with_underflow(a, b, m) };
    assert(diff == 29);

    // Test: (a * b) mod m
    // Safety: Test function calling unconstrained helper
    let prod = unsafe { __mul_mod(a, b, m) };
    assert(prod == 61); // (42 * 13) mod 97 = 546 mod 97 = 61

    // Test: b^(-1) mod m
    // Safety: Test function calling unconstrained helper
    let inv = unsafe { __inv_mod(b, m) };
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(b, inv, m) } == 1);

    // Test: (a / b) mod m
    // Safety: Test function calling unconstrained helper
    let quot = unsafe { __div_mod(a, b, m) };
    // Safety: Test function calling unconstrained helper
    assert(unsafe { __mul_mod(quot, b, m) } == a);

    // Test: (-a) mod m
    // Safety: Test function calling unconstrained helper
    let neg = unsafe { __neg(a, m) };
    let sum_neg = a + neg;
    // Safety: Test function calling unconstrained helper
    let (_, sum_neg_reduced) = unsafe { __compute_mod_reduction(sum_neg, m) };
    assert(sum_neg_reduced == 0);
}
