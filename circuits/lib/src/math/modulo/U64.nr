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

    /// Reduce a canonical BN254 field element, with an integer quotient and no scalar wrap.
    pub fn reduce_field(self, n: Field) -> Field {
        self.reduce_fields([n])[0]
    }

    /// Integer quotient and remainder of one canonical field element.
    ///
    /// For a modulus of at least 2^50 the witness reduction already
    /// range-checks that quotient, so this returns it. The cutoff is 2^50
    /// because the secure parameter sets are expected to use moduli above
    /// that size, so they take this path. Smaller moduli still divide
    /// `(n - remainder) / m`. In both cases
    /// `quotient * m + remainder = n` holds as an integer, with no scalar wrap.
    pub fn quot_rem(self, n: Field) -> (Field, Field) {
        assert(self.m > 0);
        assert(self.m < (1u64 << 62));
        if self.m >= (1u64 << 50) {
            let (bound, max_remainder) = self.field_reduction_bounds();
            // Safety: verification bounds both outputs and excludes quotient*m+remainder >= p.
            let (quotient, remainder) = unsafe { __reduce_field_witness_u64(n, self.m) };
            let remainder =
                self.verify_field_reduction(n, quotient, remainder, bound, max_remainder);
            (quotient, remainder)
        } else {
            let remainder = self.reduce_field_bytes(n);
            let quotient = (n - remainder) / self.get_mod_field();
            assert(quotient * self.get_mod_field() + remainder == n);
            (quotient, remainder)
        }
    }

    /// Reuse modulus-only bounds across a row instead of rebuilding their SSA for every output.
    pub fn reduce_fields<let N: u32>(self, values: [Field; N]) -> [Field; N] {
        assert(self.m > 0);
        assert(self.m < (1u64 << 62));
        let mut reduced = [0; N];
        if self.m >= (1u64 << 50) {
            let (bound, max_remainder) = self.field_reduction_bounds();
            for i in 0..N {
                // Safety: verification bounds both outputs and excludes quotient*m+remainder >= p.
                let (quotient, remainder) =
                    unsafe { __reduce_field_witness_u64(values[i], self.m) };
                reduced[i] = self.verify_field_reduction(
                    values[i],
                    quotient,
                    remainder,
                    bound,
                    max_remainder,
                );
            }
        } else {
            for i in 0..N {
                reduced[i] = self.reduce_field_bytes(values[i]);
            }
        }
        reduced
    }

    fn field_reduction_bounds(self) -> (Field, Field) {
        // -1 is the canonical integer p-1. This checked, constant-input reduction
        // fixes (p-1)%m; field division then equals the integer floor((p-1)/m).
        // Production moduli are constants, so this does not decompose each PRF output.
        let max_remainder = self.reduce_field_bytes(-1);
        (((-1) - max_remainder) / self.get_mod_field(), max_remainder)
    }

    fn verify_field_reduction(
        self,
        n: Field,
        quotient: Field,
        remainder: Field,
        bound: Field,
        max_remainder: Field,
    ) -> Field {
        // m>=2^50 implies bound<2^204. Both range checks are far below p,
        // so they enforce the integer interval 0<=quotient<=bound.
        quotient.assert_max_bit_size::<204>();
        (bound - quotient).assert_max_bit_size::<204>();
        remainder.assert_max_bit_size::<62>();
        (self.get_mod_field() - 1 - remainder).assert_max_bit_size::<62>();
        // If quotient<bound the largest possible sum is already <p. At the
        // boundary, this extra remainder limit excludes the alias n+p.
        let at_bound = (quotient == bound) as Field;
        (at_bound * (max_remainder - remainder)).assert_max_bit_size::<62>();
        assert(quotient * self.get_mod_field() + remainder == n);
        remainder
    }

    /// Checked byte/limb reduction also handles tiny test moduli with wider quotients.
    fn reduce_field_bytes(self, n: Field) -> Field {
        let bytes = n.to_le_bytes::<32>();
        if self.m >= (1u64 << 58) {
            // With m >= 2^58, each 120-bit digit contributes a <2^62 quotient.
            // acc, base < m < 2^62, so acc*base + digit < 2^125 and its
            // quotient is <2^63. Both fit reduce_mod's u128/u64 witness contract.
            let base = self.reduce_mod(2.pow_32(120));
            let mut acc = byte_limb::<30, 2>(bytes);
            acc = self.reduce_mod(acc * base + byte_limb::<15, 15>(bytes));
            self.reduce_mod(acc * base + byte_limb::<0, 15>(bytes))
        } else {
            // Compute 2^64 mod m without asking the hint for a 65-bit quotient
            // when m=1. For m>=2 each fused quotient is <m+2^63<2^64;
            // for m=1 the product is zero and the digit itself fits u64.
            let next = self.reduce_mod(2.pow_32(64) - 1) + 1;
            let base = if next == self.get_mod_field() {
                0
            } else {
                next
            };
            let mut acc = self.reduce_mod(byte_limb::<24, 8>(bytes));
            acc = self.reduce_mod(acc * base + byte_limb::<16, 8>(bytes));
            acc = self.reduce_mod(acc * base + byte_limb::<8, 8>(bytes));
            self.reduce_mod(acc * base + byte_limb::<0, 8>(bytes))
        }
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
        assert(
            lhs + (underflow as Field) * self.get_mod_field() == rhs + (res_u64 as Field),
            "Subtraction verification failed",
        );
        assert(res_u64 < self.m, "Subtraction result is not canonical");
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

fn byte_limb<let START: u32, let LEN: u32>(bytes: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    let mut place: Field = 1;
    for i in 0..LEN {
        acc = acc + (bytes[START + i] as Field) * place;
        place = place * 256;
    }
    acc
}

// ------------------------------ TESTS ------------------------------

#[test]
fn test_u64_reduce_field() {
    let m = ModU64::new(100);
    assert(m.reduce_field(42) == 42);
    assert(m.reduce_field(250) == 50);
    assert(m.reduce_field(2.pow_32(200) * 100 + 7) == 7);
    assert(m.reduce_field(2.pow_32(60) * 13 + 7) == 95);
}

#[test]
fn full_field_reduction_matches_integer_reference_vectors() {
    let values: [Field; 10] = [
        0,
        1,
        -1,
        -2,
        2.pow_32(64) - 1,
        2.pow_32(64),
        2.pow_32(120) - 1,
        2.pow_32(120),
        2.pow_32(240),
        2.pow_32(253) + 2.pow_32(128) + 12345,
    ];
    let moduli: [u64; 8] =
        [1, 2, 100, 134217089, (1u64 << 58) - 1, 1u64 << 58, 576460752317792257, (1u64 << 62) - 1];
    // Python big-integer remainders, including p-1/p-2 and both limb-width paths.
    let expected: [[Field; 10]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 1, 1, 0, 1, 0, 0, 1],
        [0, 1, 16, 15, 15, 16, 75, 76, 76, 93],
        [0, 1, 106971341, 106971340, 15469436, 15469437, 19588124, 19588125, 61448896, 123812334],
        [0, 1, 217004635485453411, 217004635485453410, 63, 64, 15, 16, 256, 2113593],
        [
            0,
            1,
            279774667609210880,
            279774667609210879,
            288230376151711743,
            0,
            288230376151711743,
            0,
            0,
            12345,
        ],
        [
            0,
            1,
            291189715534697300,
            291189715534697299,
            576460751857991648,
            576460751857991649,
            825846090301443,
            825846090301444,
            4335869519754109,
            566753813557515260,
        ],
        [
            0,
            1,
            200848709165208246,
            200848709165208245,
            3,
            4,
            288230376151711743,
            288230376151711744,
            18014398509481984,
            12393,
        ],
    ];
    for q in 0..8 {
        let m = ModU64::new(moduli[q]);
        assert(m.reduce_fields(values) == expected[q]);
        for i in 0..10 {
            assert(m.reduce_field(values[i]) == expected[q][i]);
        }
    }
}

#[test]
fn full_field_reduction_accepts_the_scalar_boundary() {
    let m = ModU64::new(576460752317792257);
    let (bound, max_remainder) = m.field_reduction_bounds();
    assert(
        m.verify_field_reduction(-1, bound, max_remainder, bound, max_remainder) == max_remainder,
    );
}

#[test(should_fail)]
fn full_field_reduction_rejects_a_scalar_modulus_alias() {
    let m = ModU64::new(576460752317792257);
    let (bound, max_remainder) = m.field_reduction_bounds();
    // This forged integer sum is exactly p, hence equals zero in the scalar field.
    let _ = m.verify_field_reduction(0, bound, max_remainder + 1, bound, max_remainder);
}

#[test(should_fail)]
fn full_field_reduction_rejects_an_oversized_quotient() {
    let m = ModU64::new(576460752317792257);
    let (bound, max_remainder) = m.field_reduction_bounds();
    let alias = m.get_mod_field() - max_remainder - 1;
    let _ = m.verify_field_reduction(alias, bound + 1, 0, bound, max_remainder);
}

#[test(should_fail)]
fn full_field_reduction_rejects_a_noncanonical_remainder() {
    let m = ModU64::new(576460752317792257);
    let (bound, max_remainder) = m.field_reduction_bounds();
    let _ = m.verify_field_reduction(m.get_mod_field(), 0, m.get_mod_field(), bound, max_remainder);
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
