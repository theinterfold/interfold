// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Constrained modular arithmetic for moduli that fit in 62 bits.
//!
//! `ModU64` stores the modulus as `u64` and uses `u64` casts for all range checks.
//! A `u64` cast costs ~11 lookup gates; a `u128` cast costs ~22.
//! Each `mul_mod` therefore saves ~22 gates over `ModU128` (two range checks per call).

use super::unconstrained_U64::{
    __inv_mod_u64, __mul_mod_witness_u64, __neg_u64, __reduce_witness_u64, __sub_with_underflow_u64,
};

/// Modular arithmetic context for prime moduli < 2^62.
///
/// Use this instead of `ModU128` when the modulus is known to be at most 62 bits.
/// The gate savings come from narrower range checks: u64 vs u128.
pub struct ModU64 {
    pub m: u64, // must be prime, < 2^62
}

impl ModU64 {
    pub fn new(m: u64) -> Self {
        ModU64 { m }
    }

    pub fn get_mod_field(self) -> Field {
        self.m as Field
    }

    /// Reduces n modulo m. n may be a large Field (e.g. after encoding plaintext).
    pub fn reduce_mod(self, n: Field) -> Field {
        // Safety: __reduce_witness_u64 divides via u128; result verified below.
        let quotient = unsafe { __reduce_witness_u64(n, self.m) };
        let remainder = n - (quotient as Field) * (self.m as Field);
        // u64 casts: ~11 lookup gates each (vs ~22 for u128)
        let rem_u64 = remainder as u64;
        let quo_u64 = quotient as u64; // no-op: quotient already u64; present for clarity
        assert((quo_u64 as Field) * (self.m as Field) + (rem_u64 as Field) == n);
        assert(rem_u64 < self.m);
        rem_u64 as Field
    }

    /// Asserts that n == 0 mod m without computing the remainder.
    ///
    /// Cheaper than reduce_mod + assert == 0: skips the remainder range check and bounds assert.
    /// Gate cost: ~11 (quotient u64 range check) + 1 (arithmetic assert) = ~12 gates
    /// vs reduce_mod's ~24 gates.
    ///
    /// Soundness: quo*m == n holds in integers (not just Field) because both sides are
    /// bounded well below the field prime, so Field equality implies integer equality.
    pub fn assert_zero_mod(self, n: Field) {
        // Safety: __reduce_witness_u64 computes floor(n/m); verified by arithmetic assert below.
        let quotient = unsafe { __reduce_witness_u64(n, self.m) };
        let quo_u64 = quotient as u64; // ~11 lookup gates
        assert((quo_u64 as Field) * (self.m as Field) == n, "Divisibility check failed");
    }

    /// (lhs + rhs) mod m. Inputs must already be reduced (< m).
    pub fn add(self, lhs: Field, rhs: Field) -> Field {
        // lhs + rhs < 2m < 2^63; no Field overflow before reduce_mod.
        self.reduce_mod(lhs + rhs)
    }

    /// (lhs - rhs) mod m. Inputs must already be reduced (< m).
    pub fn sub(self, lhs: Field, rhs: Field) -> Field {
        // Safety: __sub_with_underflow_u64 verified by the equation below.
        let (res_u64, underflow) = unsafe { __sub_with_underflow_u64(lhs, rhs, self.m) };
        if underflow {
            assert(
                lhs + (self.m as Field) == rhs + (res_u64 as Field),
                "Subtraction with underflow verification failed",
            );
        } else {
            assert(lhs == rhs + (res_u64 as Field), "Subtraction verification failed");
        }
        res_u64 as Field
    }

    /// (a * b) mod m. Inputs must already be reduced (< m < 2^62).
    ///
    /// Gate breakdown:
    ///   ~11 gates: quotient u64 range check (implicit in return type of unconstrained)
    ///   ~11 gates: rem_u64 cast
    ///     1 gate:  arithmetic assert
    ///     1 gate:  bounds assert
    pub fn mul_mod(self, a: Field, b: Field) -> Field {
        // Safety: __mul_mod_witness_u64 uses u128 for the 124-bit product; result verified below.
        let quotient = unsafe { __mul_mod_witness_u64(a, b, self.m) };
        let remainder = a * b - (quotient as Field) * (self.m as Field);
        let rem_u64 = remainder as u64; // ~11 lookup gates
        let quo_u64 = quotient as u64; // no-op: quotient already u64
        assert((quo_u64 as Field) * (self.m as Field) + (rem_u64 as Field) == a * b);
        assert(rem_u64 < self.m);
        rem_u64 as Field
    }

    /// (a / b) mod m: multiplies a by b^(-1) mod m.
    pub fn div_mod(self, a: Field, b: Field) -> Field {
        // Safety: __inv_mod_u64 uses Fermat's Little Theorem; verified via mul_mod below.
        let b_inv = unsafe { __inv_mod_u64(b, self.m) };
        self.mul_mod(a, b_inv as Field)
    }

    /// (-val) mod m.
    pub fn neg(self, val: Field) -> Field {
        // Safety: __neg_u64 returns m - val; verified by addition equation below.
        let result = unsafe { __neg_u64(val, self.m) };
        let res_u64 = result as u64;
        if val == 0 {
            assert(res_u64 == 0, "Negation of zero should be zero");
        } else {
            assert(val + (res_u64 as Field) == (self.m as Field), "Negation verification failed");
        }
        res_u64 as Field
    }

    /// val^(-1) mod m. m must be prime; val must be non-zero.
    pub fn inv_mod(self, val: Field) -> Field {
        // Safety: __inv_mod_u64 uses Fermat's Little Theorem; verified by mul_mod below.
        let result = unsafe { __inv_mod_u64(val, self.m) };
        assert(self.mul_mod(val, result as Field) == 1, "Inverse verification failed");
        result as Field
    }
}

// ------------------------------ TESTS ------------------------------

#[test]
fn test_u64_reduce_mod_already_reduced() {
    let m = ModU64::new(100);
    assert(m.reduce_mod(42) == 42);
}

#[test]
fn test_u64_reduce_mod_needs_reduction() {
    let m = ModU64::new(100);
    assert(m.reduce_mod(250) == 50);
}

#[test]
fn test_u64_reduce_mod_exact_multiple() {
    let m = ModU64::new(100);
    assert(m.reduce_mod(300) == 0);
}

#[test]
fn test_u64_add_no_overflow() {
    let m = ModU64::new(100);
    assert(m.add(30, 40) == 70);
}

#[test]
fn test_u64_add_with_overflow() {
    let m = ModU64::new(100);
    assert(m.add(60, 50) == 10);
}

#[test]
fn test_u64_add_exact_modulus() {
    let m = ModU64::new(100);
    assert(m.add(50, 50) == 0);
}

#[test]
fn test_u64_add_with_zero() {
    let m = ModU64::new(100);
    assert(m.add(42, 0) == 42);
}

#[test]
fn test_u64_sub_no_underflow() {
    let m = ModU64::new(100);
    assert(m.sub(50, 30) == 20);
}

#[test]
fn test_u64_sub_with_underflow() {
    let m = ModU64::new(100);
    assert(m.sub(30, 50) == 80); // (30 - 50 + 100) mod 100 = 80
}

#[test]
fn test_u64_sub_equal_values() {
    let m = ModU64::new(100);
    assert(m.sub(42, 42) == 0);
}

#[test]
fn test_u64_sub_zero() {
    let m = ModU64::new(100);
    assert(m.sub(42, 0) == 42);
}

#[test]
fn test_u64_mul_mod_small_values() {
    let m = ModU64::new(100);
    assert(m.mul_mod(6, 7) == 42);
}

#[test]
fn test_u64_mul_mod_with_reduction() {
    let m = ModU64::new(100);
    assert(m.mul_mod(12, 15) == 80); // 180 mod 100
}

#[test]
fn test_u64_mul_mod_result_zero() {
    let m = ModU64::new(100);
    assert(m.mul_mod(5, 20) == 0); // 100 mod 100
}

#[test]
fn test_u64_mul_mod_with_zero() {
    let m = ModU64::new(100);
    assert(m.mul_mod(42, 0) == 0);
}

#[test]
fn test_u64_mul_mod_prime_modulus() {
    let m = ModU64::new(97);
    assert(m.mul_mod(42, 13) == 61); // 546 mod 97
}

#[test]
fn test_u64_neg_nonzero() {
    let m = ModU64::new(100);
    assert(m.neg(30) == 70);
}

#[test]
fn test_u64_neg_zero() {
    let m = ModU64::new(100);
    assert(m.neg(0) == 0);
}

#[test]
fn test_u64_neg_large_modulus() {
    let m = ModU64::new(1000000);
    assert(m.neg(12345) == 987655);
}

#[test]
fn test_u64_inv_mod_simple() {
    let m = ModU64::new(11);
    let result = m.inv_mod(3);
    assert(result == 4); // 3*4 = 12 = 1 mod 11
    assert(m.mul_mod(3, result) == 1);
}

#[test]
fn test_u64_inv_mod_prime() {
    let m = ModU64::new(13);
    let result = m.inv_mod(7);
    assert(m.mul_mod(7, result) == 1);
}

#[test]
fn test_u64_inv_mod_coprime() {
    let m = ModU64::new(23);
    let result = m.inv_mod(9);
    assert(m.mul_mod(9, result) == 1);
}

#[test]
fn test_u64_div_mod_simple() {
    let m = ModU64::new(11);
    assert(m.div_mod(6, 2) == 3);
}

#[test]
fn test_u64_div_mod_with_inverse() {
    let m = ModU64::new(11);
    let result = m.div_mod(7, 3);
    // 3^(-1) mod 11 = 4; 7*4 = 28 = 6 mod 11
    assert(result == 6);
    assert(m.mul_mod(result, 3) == 7);
}

#[test]
fn test_u64_div_mod_larger() {
    let m = ModU64::new(97);
    let result = m.div_mod(35, 7);
    assert(m.mul_mod(result, 7) == m.reduce_mod(35));
}

#[test]
fn test_u64_field_properties_prime_modulus() {
    let m = ModU64::new(97);
    let a = 42;
    let b = 13;

    assert(m.add(a, b) == 55);
    assert(m.sub(a, b) == 29);
    assert(m.mul_mod(a, b) == 61);

    let inv = m.inv_mod(b);
    assert(m.mul_mod(b, inv) == 1);

    let quot = m.div_mod(a, b);
    assert(m.mul_mod(quot, b) == a);
}

#[test]
fn test_u64_additive_inverse() {
    let m = ModU64::new(97);
    let a = 42;
    let neg_a = m.neg(a);
    assert(m.add(a, neg_a) == 0);
}

#[test]
fn test_u64_additive_identity() {
    let m = ModU64::new(100);
    assert(m.add(42, 0) == 42);
}

#[test]
fn test_u64_multiplicative_identity() {
    let m = ModU64::new(100);
    assert(m.mul_mod(42, 1) == 42);
}

#[test]
fn test_u64_commutativity_add() {
    let m = ModU64::new(100);
    assert(m.add(35, 47) == m.add(47, 35));
}

#[test]
fn test_u64_commutativity_mul() {
    let m = ModU64::new(100);
    assert(m.mul_mod(7, 9) == m.mul_mod(9, 7));
}

#[test]
fn test_u64_inverse_of_inverse() {
    let m = ModU64::new(11);
    let a = 7;
    assert(m.inv_mod(m.inv_mod(a)) == a);
}

#[test]
fn test_u64_division_multiplication_inverse() {
    let m = ModU64::new(97);
    let a = 35;
    let b = 7;
    let quotient = m.div_mod(a, b);
    assert(m.mul_mod(quotient, b) == m.reduce_mod(a));
}
