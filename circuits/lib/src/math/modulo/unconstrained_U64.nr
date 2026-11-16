// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Unconstrained witnesses for 62-bit modular arithmetic.
//!
//! Moduli must be < 2^62; inputs are assumed already reduced (< m).
//! Intermediate products of two 62-bit values are at most 124 bits, safe in u128.

/// Returns floor(n / m).
///
/// n may be a large Field (e.g. lhs*rhs before reduction); cast to u128 for safe division.
pub unconstrained fn __reduce_witness_u64(n: Field, m: u64) -> u64 {
    (n as u128 / m as u128) as u64
}

/// Returns floor(a*b / m) for use in `mul_mod`.
///
/// Safe because a, b < m < 2^62, so a*b < 2^124 fits in u128 without wrapping.
pub unconstrained fn __mul_mod_witness_u64(a: Field, b: Field, m: u64) -> u64 {
    ((a as u128 * b as u128) / m as u128) as u64
}

/// Returns (result, underflow) for (lhs - rhs) mod m.
///
/// Inputs must be in [0, m).
pub unconstrained fn __sub_with_underflow_u64(lhs: Field, rhs: Field, m: u64) -> (u64, bool) {
    let l = lhs as u64;
    let r = rhs as u64;
    let underflow = l < r;
    let result = if underflow { m - (r - l) } else { l - r };
    (result, underflow)
}

/// Returns (-val) mod m.
pub unconstrained fn __neg_u64(val: Field, m: u64) -> u64 {
    if val == 0 {
        0
    } else {
        m - val as u64
    }
}

/// Square-and-multiply modular exponentiation using u128 arithmetic.
pub unconstrained fn __pow_mod_u64(base: u64, exp: u64, m: u64) -> u64 {
    let mut result: u128 = 1;
    let mut b: u128 = base as u128 % m as u128;
    let mut e: u128 = exp as u128;
    let q = m as u128;
    while e > 0 {
        if (e % 2) == 1 {
            result = result * b % q;
        }
        b = b * b % q;
        e /= 2;
    }
    result as u64
}

/// Returns val^(-1) mod m via Fermat's Little Theorem (m must be prime).
pub unconstrained fn __inv_mod_u64(val: Field, m: u64) -> u64 {
    __pow_mod_u64(val as u64, m - 2, m)
}

// ------------------------------ TESTS ------------------------------

#[test]
fn test_reduce_witness_u64_basic() {
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let result = unsafe { __reduce_witness_u64(250, 100) };
    assert(result == 2);
}

#[test]
fn test_reduce_witness_u64_exact() {
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let result = unsafe { __reduce_witness_u64(300, 100) };
    assert(result == 3);
}

#[test]
fn test_mul_mod_witness_u64() {
    // 12 * 15 = 180; floor(180 / 100) = 1
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let result = unsafe { __mul_mod_witness_u64(12, 15, 100) };
    assert(result == 1);
}

#[test]
fn test_sub_with_underflow_u64_no_underflow() {
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let (res, underflow) = unsafe { __sub_with_underflow_u64(50, 30, 100) };
    assert(res == 20);
    assert(!underflow);
}

#[test]
fn test_sub_with_underflow_u64_underflow() {
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let (res, underflow) = unsafe { __sub_with_underflow_u64(30, 50, 100) };
    assert(res == 80); // 30 - 50 + 100
    assert(underflow);
}

#[test]
fn test_neg_u64_nonzero() {
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let result = unsafe { __neg_u64(30, 100) };
    assert(result == 70);
}

#[test]
fn test_neg_u64_zero() {
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let result = unsafe { __neg_u64(0, 100) };
    assert(result == 0);
}

#[test]
fn test_inv_mod_u64_simple() {
    // 3^(-1) mod 11 = 4 (since 3*4 = 12 = 1 mod 11)
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let result = unsafe { __inv_mod_u64(3, 11) };
    assert(result == 4);
}

#[test]
fn test_pow_mod_u64() {
    // 2^10 mod 97 = 1024 mod 97 = 927 % 97 = 927 - 9*97 = 927 - 873 = 54
    // Safety: test-only call to unconstrained witness helper; no circuit constraints apply.
    let result = unsafe { __pow_mod_u64(2, 10, 97) };
    assert(result == 54);
}
