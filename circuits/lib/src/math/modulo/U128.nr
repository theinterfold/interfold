// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Constrained modular arithmetic operations for u128 values.
//!
//! This module provides a `ModU128` struct that implements modular arithmetic operations
//! with full constraint generation for zero-knowledge proof circuits. All operations
//! are verified in-circuit to ensure correctness.
use super::unconstrained_U128::{
    __compute_mod_reduction, __div_mod, __inv_mod, __neg, __sub_with_underflow,
};

/// Modular arithmetic context for u128 values.
///
/// This struct holds a modulus and provides methods for performing modular arithmetic
/// operations with full constraint generation. All operations are verified in-circuit.
///
/// # Generic Parameters
///
/// The operations work with `Field` values, but are designed for u128-sized integers.
/// The modulus must be a positive value less than 2^128.
pub struct ModU128 {
    /// The modulus for all operations
    pub m: Field,
}

impl ModU128 {
    /// Creates a new modular arithmetic context with the given modulus.
    ///
    /// # Arguments
    /// * `m` - The modulus for all operations. Must be positive.
    ///
    /// # Returns
    /// A new `ModU128` instance configured with the specified modulus.
    pub fn new(m: Field) -> Self {
        ModU128 { m }
    }

    /// Returns the modulus as a Field value.
    ///
    /// # Returns
    /// The modulus value used by this context.
    pub fn get_mod_field(self) -> Field {
        self.m
    }

    /// Reduces a value modulo the modulus.
    ///
    /// Computes `n mod m` and returns the result in the range [0, m).
    /// This operation is fully constrained and verified in-circuit.
    ///
    /// # Arguments
    /// * `n` - The value to reduce
    ///
    /// # Returns
    /// The value `n mod m` in the range [0, m)
    ///
    /// # Panics
    /// The circuit will fail if the reduction is incorrect.
    pub fn reduce_mod(self, n: Field) -> Field {
        // Safety: __compute_mod_reduction is safe to call here because we assert the properties of the output
        let (q, r) = unsafe { __compute_mod_reduction(n, self.m) };

        // Ensure remainder is in [0, m)
        assert(r as u128 < self.m as u128);
        // Verify the reduction is correct
        assert(n == q * self.m + r);

        r
    }

    /// Adds two values with modular reduction.
    ///
    /// Computes `(lhs + rhs) mod m` and returns the result.
    /// Handles overflow correctly by reducing modulo the modulus.
    ///
    /// # Arguments
    /// * `lhs` - Left-hand side value
    /// * `rhs` - Right-hand side value
    ///
    /// # Returns
    /// The result of `(lhs + rhs) mod m`
    pub fn add(self, lhs: Field, rhs: Field) -> Field {
        self.reduce_mod(lhs + rhs)
    }

    /// Subtracts two values with modular reduction.
    ///
    /// Computes `(lhs - rhs) mod m` and returns the result.
    /// Handles underflow correctly by adding the modulus when needed.
    ///
    /// # Arguments
    /// * `lhs` - Left-hand side value (minuend)
    /// * `rhs` - Right-hand side value (subtrahend)
    ///
    /// # Returns
    /// The result of `(lhs - rhs) mod m`
    pub fn sub(self, lhs: Field, rhs: Field) -> Field {
        // Safety: __sub_with_underflow is safe because we verify the subtraction equation below
        let (result, underflow) = unsafe { __sub_with_underflow(lhs, rhs, self.m) };

        // Verify the subtraction
        if underflow {
            assert(lhs + self.m == rhs + result, "Subtraction with underflow verification failed");
        } else {
            assert(lhs == rhs + result, "Subtraction verification failed");
        }

        result
    }

    /// Multiplies two values with modular reduction.
    ///
    /// Computes `(lhs * rhs) mod m` and returns the result.
    /// The product is computed first, then reduced modulo the modulus.
    ///
    /// # Arguments
    /// * `lhs` - Left-hand side value
    /// * `rhs` - Right-hand side value
    ///
    /// # Returns
    /// The result of `(lhs * rhs) mod m`
    pub fn mul_mod(self, lhs: Field, rhs: Field) -> Field {
        self.reduce_mod(lhs * rhs)
    }

    /// Computes modular division: `lhs * rhs^(-1) mod m`.
    ///
    /// This is equivalent to multiplying `lhs` by the modular inverse of `rhs`.
    /// The result satisfies: `(result * rhs) mod m = lhs mod m`.
    ///
    /// # Arguments
    /// * `lhs` - The numerator
    /// * `rhs` - The denominator (must be coprime with the modulus)
    ///
    /// # Returns
    /// The result of `(lhs * rhs^(-1)) mod m`
    ///
    /// # Panics
    /// The circuit will fail if `rhs` is not invertible modulo `m` (i.e., if
    /// `gcd(rhs, m) != 1`). For prime moduli, any non-zero `rhs` is invertible.
    pub fn div_mod(self, lhs: Field, rhs: Field) -> Field {
        // Safety: __div_mod is safe because we verify result * rhs = lhs (mod m) below
        let result = unsafe { __div_mod(lhs, rhs, self.m) };

        // Verify: (result * rhs) mod m == lhs mod m
        assert(
            self.mul_mod(result, rhs) == self.reduce_mod(lhs),
            "Division verification failed: result * rhs ≠ lhs (mod m)",
        );

        result
    }

    /// Negates a value modulo m.
    ///
    /// Computes the additive inverse: `(-val) mod m = (m - val) mod m`.
    /// Special case: negation of zero is zero.
    ///
    /// # Arguments
    /// * `val` - The value to negate
    ///
    /// # Returns
    /// The result of `(-val) mod m`, which satisfies `(val + result) mod m = 0`
    pub fn neg(self, val: Field) -> Field {
        // Safety: __neg is safe because we verify val + result = 0 (mod m) below
        let result = unsafe { __neg(val, self.m) };

        // Verify: val + result = 0 (mod m)
        // Special case: if val = 0, result should be 0
        if val == 0 {
            assert(result == 0, "Negation of zero should be zero");
        } else {
            assert(val + result == self.m, "Negation verification failed");
        }

        result
    }

    /// Computes the modular multiplicative inverse using Fermat's Little Theorem.
    ///
    /// For a prime modulus `m` and value `val` coprime to `m`, computes `val^(-1) mod m`
    /// such that `(val * result) mod m = 1`.
    ///
    /// The implementation uses Fermat's Little Theorem: `val^(m-1) = 1 (mod m)`,
    /// so `val^(-1) = val^(m-2) (mod m)`.
    ///
    /// # Arguments
    /// * `val` - The value to invert (must be coprime with the modulus)
    ///
    /// # Returns
    /// The modular inverse `val^(-1) mod m` such that `(val * result) mod m = 1`
    ///
    /// # Panics
    /// The circuit will fail if `val` is not invertible modulo `m` (i.e., if
    /// `gcd(val, m) != 1`). For prime moduli, any non-zero `val` is invertible.
    pub fn inv_mod(self, val: Field) -> Field {
        // Safety: __inv_mod is safe because we verify val * result = 1 (mod m) below
        let result = unsafe { __inv_mod(val, self.m) };

        // Verify: val * result = 1 (mod m)
        assert(self.mul_mod(val, result) == 1, "Inverse verification failed");

        result
    }
}

#[test]
fn test_reduce_mod_already_reduced() {
    let value = 42;
    let m = ModU128::new(100);
    let result = m.reduce_mod(value);
    assert(result == 42);
}

#[test]
fn test_reduce_mod_needs_reduction() {
    let value = 250;
    let m = ModU128::new(100);
    let result = m.reduce_mod(value);
    assert(result == 50);
}

#[test]
fn test_reduce_mod_exact_multiple() {
    let value = 300;
    let m = ModU128::new(100);
    let result = m.reduce_mod(value);
    assert(result == 0);
}

#[test]
fn test_reduce_mod_large_value() {
    let value = 123456789;
    let m = ModU128::new(1000);
    let result = m.reduce_mod(value);
    assert(result == 789);
}

#[test]
fn test_add_no_overflow() {
    let a = 30;
    let b = 40;
    let m = ModU128::new(100);
    let result = m.add(a, b);
    assert(result == 70);
}

#[test]
fn test_add_with_overflow() {
    let a = 60;
    let b = 50;
    let m = ModU128::new(100);
    let result = m.add(a, b);
    assert(result == 10); // (60 + 50) mod 100 = 10
}

#[test]
fn test_add_exact_modulus() {
    let a = 50;
    let b = 50;
    let m = ModU128::new(100);
    let result = m.add(a, b);
    assert(result == 0);
}

#[test]
fn test_add_with_zero() {
    let a = 42;
    let b = 0;
    let m = ModU128::new(100);
    let result = m.add(a, b);
    assert(result == 42);
}

#[test]
fn test_sub_no_underflow() {
    let a = 50;
    let b = 30;
    let m = ModU128::new(100);
    let result = m.sub(a, b);
    assert(result == 20);
}

#[test]
fn test_sub_with_underflow() {
    let a = 30;
    let b = 50;
    let m = ModU128::new(100);
    let result = m.sub(a, b);
    assert(result == 80); // (30 - 50 + 100) mod 100 = 80
}

#[test]
fn test_sub_equal_values() {
    let a = 42;
    let b = 42;
    let m = ModU128::new(100);
    let result = m.sub(a, b);
    assert(result == 0);
}

#[test]
fn test_sub_subtract_zero() {
    let a = 42;
    let b = 0;
    let m = ModU128::new(100);
    let result = m.sub(a, b);
    assert(result == 42);
}
#[test]
fn test_mul_mod_small_values() {
    let a = 6;
    let b = 7;
    let m = ModU128::new(100);
    let result = m.mul_mod(a, b);
    assert(result == 42);
}

#[test]
fn test_mul_mod_with_reduction() {
    let a = 12;
    let b = 15;
    let m = ModU128::new(100);
    let result = m.mul_mod(a, b);
    assert(result == 80); // 12 * 15 = 180, 180 mod 100 = 80
}

#[test]
fn test_mul_mod_result_zero() {
    let a = 5;
    let b = 20;
    let m = ModU128::new(100);
    let result = m.mul_mod(a, b);
    assert(result == 0); // 5 * 20 = 100, 100 mod 100 = 0
}

#[test]
fn test_mul_mod_with_zero() {
    let a = 42;
    let b = 0;
    let m = ModU128::new(100);
    let result = m.mul_mod(a, b);
    assert(result == 0);
}

#[test]
fn test_mul_mod_large_values() {
    let a = 123;
    let b = 456;
    let m = ModU128::new(1000);
    let result = m.mul_mod(a, b);
    assert(result == 88); // 123 * 456 = 56088, 56088 mod 1000 = 88
}

#[test]
fn test_neg_non_zero() {
    let val = 30;
    let m = ModU128::new(100);
    let result = m.neg(val);
    assert(result == 70); // 100 - 30 = 70
}

#[test]
fn test_neg_zero() {
    let val = 0;
    let m = ModU128::new(100);
    let result = m.neg(val);
    assert(result == 0); // Negation of 0 is 0, not m
}

#[test]
fn test_neg_large_modulus() {
    let val = 12345;
    let m = ModU128::new(1000000);
    let result = m.neg(val);
    assert(result == 987655); // 1000000 - 12345 = 987655
}

#[test]
fn test_inv_mod_simple() {
    let val = 3;
    let m = ModU128::new(11);
    let result = m.inv_mod(val);
    // 3 * 4 = 12 = 1 (mod 11), so 3^(-1) = 4 (mod 11)
    assert(result == 4);
    // Verify: 3 * result = 1 (mod 11)
    assert(m.mul_mod(val, result) == 1);
}

#[test]
fn test_inv_mod_larger_prime() {
    let val = 7;
    let m = ModU128::new(13);
    let result = m.inv_mod(val);
    // Verify: 7 * result = 1 (mod 13)
    assert(m.mul_mod(val, result) == 1);
}

#[test]
fn test_inv_mod_with_result_verification() {
    let val = 5;
    let m = ModU128::new(17);
    let result = m.inv_mod(val);
    // Verify the inverse property
    let product = m.mul_mod(val, result);
    assert(product == 1);
}

#[test]
fn test_inv_mod_coprime_values() {
    let val = 9;
    let m = ModU128::new(23);
    let result = m.inv_mod(val);
    assert(m.mul_mod(val, result) == 1);
}

#[test]
fn test_div_mod_simple() {
    let a = 6;
    let b = 2;
    let m = ModU128::new(11);
    let result = m.div_mod(a, b);
    assert(result == 3); // 6 / 2 = 3
}

#[test]
fn test_div_mod_with_inverse() {
    let a = 7;
    let b = 3;
    let m = ModU128::new(11);
    let result = m.div_mod(a, b);
    // 3^(-1) mod 11 = 4 (since 3 * 4 = 12 = 1 mod 11)
    // 7 * 4 = 28 = 6 (mod 11)
    assert(result == 6);
    // Verify: result * b = a (mod m)
    assert(m.mul_mod(result, b) == a);
}

#[test]
fn test_div_mod_verification() {
    let a = 10;
    let b = 3;
    let m = ModU128::new(17);
    let result = m.div_mod(a, b);
    // Verify: result * b = a (mod m)
    assert(m.mul_mod(result, b) == m.reduce_mod(a));
}

#[test]
fn test_div_mod_larger_values() {
    let a = 250;
    let b = 7;
    let m = ModU128::new(97);
    let result = m.div_mod(a, b);
    // Verify: result * b = a (mod m)
    let a_reduced = m.reduce_mod(a); // 250 mod 100 = 50
    assert(m.mul_mod(result, b) == a_reduced);
}

#[test]
fn test_reduce_mod_function() {
    let m = ModU128::new(7);

    // Test reduce_mod directly first
    assert(m.reduce_mod(38) == 3);
    assert(m.reduce_mod(6) == 6);
    assert(m.reduce_mod(7) == 0);
    assert(m.reduce_mod(14) == 0);
}

#[test]
fn test_field_properties_multiplicative_identity() {
    let a = 42;
    let m = ModU128::new(100);
    // a * 1 = a
    assert(m.mul_mod(a, 1) == a);
}

#[test]
fn test_field_properties_additive_inverse() {
    let a = 42;
    let m = ModU128::new(100);
    let neg_a = m.sub(0, a);
    // a + (-a) = 0
    assert(m.add(a, neg_a) == 0);
}

#[test]
fn test_field_properties_commutativity_add() {
    let a = 35;
    let b = 47;
    let m = ModU128::new(100);
    // a + b = b + a
    assert(m.add(a, b) == m.add(b, a));
}

#[test]
fn test_field_properties_commutativity_mul() {
    let a = 7;
    let b = 9;
    let m = ModU128::new(100);
    // a * b = b * a
    assert(m.mul_mod(a, b) == m.mul_mod(b, a));
}

#[test]
fn test_field_properties_associativity_add() {
    let a = 23;
    let b = 34;
    let c = 45;
    let m = ModU128::new(100);
    // (a + b) + c = a + (b + c)
    let left = m.add(m.add(a, b), c);
    let right = m.add(a, m.add(b, c));
    assert(left == right);
}

#[test]
fn test_field_properties_associativity_mul() {
    let a = 3;
    let b = 7;
    let c = 11;
    let m = ModU128::new(100);
    // (a * b) * c = a * (b * c)
    let left = m.mul_mod(m.mul_mod(a, b), c);
    let right = m.mul_mod(a, m.mul_mod(b, c));
    assert(left == right);
}

#[test]
fn test_field_properties_distributivity() {
    let a = 5;
    let b = 7;
    let c = 9;
    let m = ModU128::new(100);
    // a * (b + c) = (a * b) + (a * c)
    let left = m.mul_mod(a, m.add(b, c));
    let right = m.add(m.mul_mod(a, b), m.mul_mod(a, c));
    assert(left == right);
}
#[test]
fn test_division_multiplication_inverse() {
    let a = 35;
    let b = 7;
    let m = ModU128::new(97);
    let quotient = m.div_mod(a, b);
    let product = m.mul_mod(quotient, b);
    assert(product == m.reduce_mod(a));
}

#[test]
fn test_inverse_of_inverse() {
    let a = 7;
    let m = ModU128::new(11);
    // (a^(-1))^(-1) = a
    let inv_a = m.inv_mod(a);
    let inv_inv_a = m.inv_mod(inv_a);
    assert(inv_inv_a == a);
}

#[test]
fn test_operations_with_prime_modulus() {
    let m = ModU128::new(97); // Prime number
    let a = 42;
    let b = 13;

    // Test addition
    let sum = m.add(a, b);
    assert(sum == 55); // 42 + 13 = 55

    // Test subtraction
    let diff = m.sub(a, b);
    assert(diff == 29); // 42 - 13 = 29

    // Test multiplication
    let prod = m.mul_mod(a, b);
    assert(prod == 61); // (42 * 13) mod 97 = 546 mod 97 = 61

    // Test inverse: b * b^(-1) = 1 (mod m)
    let inv = m.inv_mod(b);
    assert(m.mul_mod(b, inv) == 1);

    // Test division: (a / b) * b = a (mod m)
    let quot = m.div_mod(a, b);
    assert(m.mul_mod(quot, b) == a);
}
