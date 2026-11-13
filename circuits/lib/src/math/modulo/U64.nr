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
    __inv_mod_u64, __mul_mod_witness_u64, __neg_u64, __reduce_field_witness_u64,
    __reduce_witness_u64, __sub_with_underflow_u64,
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

    /// Reduce the full canonical BN254 integer, not its low u128 bits.
    pub fn reduce_field(self, n: Field) -> Field {
        self.reduce_fields([n])[0]
    }

    /// Share modulus-only bounds across a PRF row. Width cutoffs affect cost, not the remainder.
    pub fn reduce_fields<let N: u32>(self, values: [Field; N]) -> [Field; N] {
        assert(self.m >= 2);
        assert(self.m < (1u64 << 62));
        // p < 2^254: m >= 2^k leaves at most 254-k quotient bits.
        if self.m >= (1u64 << 50) {
            self.reduce_fields_bounded::<N, 204, 62>(values)
        } else if self.m >= (1u64 << 26) {
            // A 32-bit remainder is cheaper than the exact 27-bit width with bb's range tables.
            if self.m < (1u64 << 32) {
                self.reduce_fields_bounded::<N, 228, 32>(values)
            } else {
                self.reduce_fields_bounded::<N, 228, 62>(values)
            }
        } else {
            let mut reduced = [0; N];
            for i in 0..N {
                reduced[i] = self.reduce_field_bytes(values[i]);
            }
            reduced
        }
    }

    fn reduce_fields_bounded<let N: u32, let QUOTIENT_BITS: u32, let REMAINDER_BITS: u32>(
        self,
        values: [Field; N],
    ) -> [Field; N] {
        let (bound, max_remainder) = self.field_reduction_bounds();
        let mut reduced = [0; N];
        for i in 0..N {
            // Safety: both hint outputs are bounded below, including the scalar-wrap boundary.
            let (quotient, remainder) = unsafe { __reduce_field_witness_u64(values[i], self.m) };
            reduced[i] = self.verify_field_reduction::<QUOTIENT_BITS, REMAINDER_BITS>(
                values[i],
                quotient,
                remainder,
                bound,
                max_remainder,
            );
        }
        reduced
    }

    fn field_reduction_bounds(self) -> (Field, Field) {
        // Checked integer reduction of p-1 fixes these bounds; production moduli are constants.
        let max_remainder = self.reduce_field_bytes(-1);
        (((-1) - max_remainder) / self.get_mod_field(), max_remainder)
    }

    fn verify_field_reduction<let QUOTIENT_BITS: u32, let REMAINDER_BITS: u32>(
        self,
        n: Field,
        quotient: Field,
        remainder: Field,
        bound: Field,
        max_remainder: Field,
    ) -> Field {
        // Each caller derives both budgets from its modulus interval. These maxima keep
        // the differences far below p, so the checks imply integer rather than field ordering.
        assert(QUOTIENT_BITS <= 228);
        assert(REMAINDER_BITS <= 62);
        quotient.assert_max_bit_size::<QUOTIENT_BITS>();
        (bound - quotient).assert_max_bit_size::<QUOTIENT_BITS>();
        remainder.assert_max_bit_size::<REMAINDER_BITS>();
        (self.get_mod_field() - 1 - remainder).assert_max_bit_size::<REMAINDER_BITS>();
        // At the maximal quotient only r <= (p-1)%m excludes the integer alias n+p.
        let at_bound = (quotient == bound) as Field;
        (at_bound * (max_remainder - remainder)).assert_max_bit_size::<REMAINDER_BITS>();
        assert(quotient * self.get_mod_field() + remainder == n);
        remainder
    }

    /// Canonical byte decomposition keeps all intermediate integers below 2^125 and quotients
    /// within u64. This checks the bounds above once per row and handles tiny test moduli.
    fn reduce_field_bytes(self, n: Field) -> Field {
        let bytes = n.to_le_bytes::<32>();
        let next = self.reduce_mod(2.pow_32(64) - 1) + 1;
        let base = if next == self.get_mod_field() {
            0
        } else {
            next
        };
        let mut acc: Field = 0;
        for limb in 0..4 {
            let mut digit: Field = 0;
            for byte in 0..8 {
                digit = digit * 256 + bytes[(3 - limb) * 8 + 7 - byte] as Field;
            }
            acc = self.reduce_mod(acc * base + digit);
        }
        acc
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

    /// Asserts that n == 0 mod m, with the quotient bounded to `BIT_K` bits.
    ///
    /// Same check as [`Self::assert_zero_mod`], for callers that know how small the quotient is.
    /// The `u64` cast there bounds a quotient that is often a few bits wide; an 8-bit range check
    /// measures 2 gates cheaper per call (C5 on secure-8192: 49,152 gates over 24,576 calls).
    ///
    /// Soundness does not depend on `BIT_K` being tight. `quotient * m < 2^(BIT_K + 62)` is far
    /// below the field prime, so as long as the caller keeps `|n|` far below it too, the field
    /// equation implies the integer one and `m` divides `n`. A negative `n` wraps to a value near
    /// the prime and matches no bounded quotient.
    ///
    /// The caller must keep `n < 2^BIT_K * m`. If that is missed the honest quotient overflows
    /// `BIT_K` and the circuit is unsatisfiable: a completeness failure, not a soundness one.
    pub fn assert_zero_mod_bounded<let BIT_K: u32>(self, n: Field) {
        // Safety: __reduce_witness_u64 computes floor(n/m); the range check and the arithmetic
        // assert below verify it.
        let quotient = unsafe { __reduce_witness_u64(n, self.m) } as Field;
        quotient.assert_max_bit_size::<BIT_K>();
        assert(quotient * (self.m as Field) == n, "Divisibility check failed");
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
        // Safety: __inv_mod_u64 uses Fermat's Little Theorem; verified below by result*b == a mod m.
        let b_inv = unsafe { __inv_mod_u64(b, self.m) };
        let result = self.mul_mod(a, b_inv as Field);
        assert(
            self.mul_mod(result, b) == self.reduce_mod(a),
            "Division verification failed: result * b != a (mod m)",
        );
        result
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
fn full_field_reduction_matches_independent_integer_boundaries() {
    // Python integers: n % q for n = 0, 1, 2^128-1, 2^128, p-1 (BN254 scalar p).
    let inputs = [0, 1, 2.pow_32(128) - 1, 2.pow_32(128), -1];
    let moduli: [u64; 7] = [2, 17, 97, 65537, 134217089, 576460752317792257, 4611686018427387903];
    let expected: [[Field; 5]; 7] = [
        [0, 1, 1, 0, 0],
        [0, 1, 0, 1, 13],
        [0, 1, 34, 35, 87],
        [0, 1, 0, 1, 47592],
        [0, 1, 48527706, 48527707, 106971341],
        [0, 1, 211416599117169663, 211416599117169664, 291189715534697300],
        [0, 1, 15, 16, 200848709165208246],
    ];
    for row in 0..7 {
        for column in 0..5 {
            assert(ModU64::new(moduli[row]).reduce_field(inputs[column]) == expected[row][column]);
        }
    }
}

#[test]
fn batched_field_reduction_matches_integer_vectors_at_each_cutoff() {
    let values = [0, 1, 2.pow_32(128) - 1, 2.pow_32(128), -1];
    let moduli: [u64; 9] = [
        67108863,
        67108864,
        67108865,
        4294967295,
        4294967296,
        4294967297,
        1125899906842623,
        1125899906842624,
        1125899906842625,
    ];
    // Python big-integer n % q, immediately below/at/above each optimization cutoff.
    let expected: [[Field; 5]; 9] = [
        [0, 1, 16777215, 16777216, 3466926],
        [0, 1, 67108863, 0, 0],
        [0, 1, 16777215, 16777216, 52175571],
        [0, 1, 0, 1, 557243166],
        [0, 1, 4294967295, 0, 4026531840],
        [0, 1, 0, 1, 2007103251],
        [0, 1, 268435455, 268435456, 339439094045487],
        [0, 1, 1125899906842623, 0, 551490712240128],
        [0, 1, 268435455, 268435456, 1031447538910491],
    ];
    for row in 0..9 {
        assert(ModU64::new(moduli[row]).reduce_fields(values) == expected[row]);
    }
}

#[test]
fn hinted_field_reduction_accepts_the_scalar_boundary() {
    let narrow = ModU64::new(134217089);
    let (bound, remainder) = narrow.field_reduction_bounds();
    assert(
        narrow.verify_field_reduction::<228, 32>(-1, bound, remainder, bound, remainder)
            == 106971341,
    );
    let wide = ModU64::new(576460752317792257);
    let (bound, remainder) = wide.field_reduction_bounds();
    assert(
        wide.verify_field_reduction::<204, 62>(-1, bound, remainder, bound, remainder)
            == 291189715534697300,
    );
}

#[test(should_fail)]
fn narrow_field_reduction_rejects_a_scalar_modulus_alias() {
    let q = ModU64::new(134217089);
    let (bound, remainder) = q.field_reduction_bounds();
    // The forged integer sum is p, hence zero in the scalar field.
    let _ = q.verify_field_reduction::<228, 32>(0, bound, remainder + 1, bound, remainder);
}

#[test(should_fail)]
fn wide_field_reduction_rejects_a_scalar_modulus_alias() {
    let q = ModU64::new(576460752317792257);
    let (bound, remainder) = q.field_reduction_bounds();
    let _ = q.verify_field_reduction::<204, 62>(0, bound, remainder + 1, bound, remainder);
}

#[test(should_fail)]
fn narrow_field_reduction_rejects_an_oversized_quotient() {
    let q = ModU64::new(134217089);
    let (bound, remainder) = q.field_reduction_bounds();
    let alias = q.get_mod_field() - remainder - 1;
    let _ = q.verify_field_reduction::<228, 32>(alias, bound + 1, 0, bound, remainder);
}

#[test(should_fail)]
fn wide_field_reduction_rejects_an_oversized_quotient() {
    let q = ModU64::new(576460752317792257);
    let (bound, remainder) = q.field_reduction_bounds();
    let alias = q.get_mod_field() - remainder - 1;
    let _ = q.verify_field_reduction::<204, 62>(alias, bound + 1, 0, bound, remainder);
}

#[test(should_fail)]
fn hinted_field_reduction_rejects_a_noncanonical_remainder() {
    let q = ModU64::new(576460752317792257);
    let (bound, remainder) = q.field_reduction_bounds();
    let _ = q.verify_field_reduction::<204, 62>(
        q.get_mod_field(),
        0,
        q.get_mod_field(),
        bound,
        remainder,
    );
}

#[test(should_fail)]
fn hinted_field_reduction_rejects_a_negative_quotient() {
    let q = ModU64::new(576460752317792257);
    let (bound, remainder) = q.field_reduction_bounds();
    let _ = q.verify_field_reduction::<204, 62>(0, -1, 0, bound, remainder);
}

#[test(should_fail)]
fn full_field_reduction_rejects_zero_modulus() {
    let _ = ModU64::new(0).reduce_field(1);
}

#[test(should_fail)]
fn full_field_reduction_rejects_unit_modulus() {
    let _ = ModU64::new(1).reduce_field(1);
}

#[test(should_fail)]
fn full_field_reduction_rejects_oversized_modulus() {
    let _ = ModU64::new(1u64 << 62).reduce_field(1);
}

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

#[test(should_fail_with = "Division verification failed: result * b != a (mod m)")]
fn test_u64_div_mod_rejects_non_invertible_divisor() {
    // m = 100 is composite and b = 10 shares a factor with it, so b has no true
    // modular inverse. The Fermat's-Little-Theorem-based unconstrained hint
    // (`__inv_mod_u64`, which assumes a prime modulus) silently returns 0 here,
    // which previously let `div_mod` return an unconstrained/bogus result. This
    // regression-tests IF-001: the verification assert must now catch it.
    let m = ModU64::new(100);
    let _ = m.div_mod(7, 10);
}

#[test]
fn test_assert_zero_mod_bounded_accepts_multiples() {
    let m = ModU64::new(101);
    m.assert_zero_mod_bounded::<8>(0);
    m.assert_zero_mod_bounded::<8>(101);
    // Largest quotient that fits 8 bits.
    m.assert_zero_mod_bounded::<8>(255 * 101);
}

#[test(should_fail_with = "Divisibility check failed")]
fn test_assert_zero_mod_bounded_rejects_non_multiple() {
    ModU64::new(101).assert_zero_mod_bounded::<8>(102);
}

#[test(should_fail)]
fn test_assert_zero_mod_bounded_rejects_quotient_over_bound() {
    // 256 * 101 is a multiple, but its quotient needs 9 bits.
    ModU64::new(101).assert_zero_mod_bounded::<8>(256 * 101);
}

#[test(should_fail)]
fn test_assert_zero_mod_bounded_rejects_negative() {
    // -101 wraps to a value near the field prime; no 8-bit quotient reaches it.
    ModU64::new(101).assert_zero_mod_bounded::<8>(0 - 101);
}
