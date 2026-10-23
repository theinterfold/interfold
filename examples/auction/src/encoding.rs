// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Plaintext encodings shared by the designs.

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use std::ops::Range;
use std::sync::Arc;

pub fn simd(params: &Arc<BfvParameters>, slots: &[u64]) -> Plaintext {
    Plaintext::try_encode(slots, Encoding::simd(), params).expect("slots fit the degree")
}

pub fn poly(params: &Arc<BfvParameters>, coefficients: &[u64]) -> Plaintext {
    Plaintext::try_encode(coefficients, Encoding::poly(), params)
        .expect("coefficients fit the degree")
}

pub fn coefficients(plaintext: &Plaintext) -> Vec<u64> {
    Vec::<u64>::try_decode(plaintext, Encoding::poly()).expect("a decrypted plaintext decodes")
}

/// SIMD plaintext with every slot equal to `value`.
pub fn constant_slots(params: &Arc<BfvParameters>, value: u64) -> Plaintext {
    simd(params, &vec![value; params.degree()])
}

/// SIMD plaintext with 1 in the slots of `ranges` and 0 elsewhere.
pub fn ones_in(
    params: &Arc<BfvParameters>,
    ranges: impl IntoIterator<Item = Range<usize>>,
) -> Plaintext {
    let mut slots = vec![0u64; params.degree()];
    for range in ranges {
        slots[range].fill(1);
    }
    simd(params, &slots)
}

/// The SIMD slot values of a decrypted plaintext, which carries no encoding.
pub fn slot_values(plaintext: &Plaintext) -> Vec<u64> {
    Vec::<u64>::try_decode(plaintext, Encoding::simd()).expect("a decrypted plaintext decodes")
}

/// The points `α_k` with `slot k = P(α_k) mod t`, where `P` is the plaintext polynomial.
///
/// These are the SIMD slots of the polynomial `X`. fhe.rs reads SIMD slots only from a plaintext
/// without an encoding, which only decryption gives, so this encrypts and decrypts `X` under a
/// throwaway key. The points depend on the parameters only.
pub fn slot_points(params: &Arc<BfvParameters>) -> Vec<u64> {
    let mut x = vec![0u64; params.degree()];
    x[1] = 1;
    let mut rng = rand::rng();
    let key = SecretKey::random(params, &mut rng);
    let ciphertext: Ciphertext = key
        .try_encrypt(&poly(params, &x), &mut rng)
        .expect("encryption under a fresh key");
    slot_values(
        &key.try_decrypt(&ciphertext)
            .expect("decryption under the same key"),
    )
}

/// `P(point) mod t` by Horner's rule: N multiplications mod t. This is the work that a contract
/// does to check one slot of the published plaintext.
pub fn evaluate(coefficients: &[u64], point: u64, t: u64) -> u64 {
    coefficients.iter().rev().fold(0u128, |acc, &c| {
        (acc * u128::from(point) + u128::from(c)) % u128::from(t)
    }) as u64
}

/// The sum of all SIMD slots mod t.
///
/// Coefficient 0 of a SIMD plaintext is `N⁻¹ · Σ slots mod t`, so this needs only coefficient 0.
/// The designs place their result there and mask every other coefficient or make it a function
/// of the result.
pub fn slot_sum(params: &BfvParameters, coefficient_zero: u64) -> u64 {
    let t = params.plaintext();
    (u128::from(coefficient_zero) * params.degree() as u128 % u128::from(t)) as u64
}

/// Coefficients of `X^exponent` in Z_t[X]/(X^N + 1), for `-N < exponent < N`.
pub fn monomial(degree: usize, t: u64, exponent: i64) -> Vec<u64> {
    let mut coefficients = vec![0u64; degree];
    if exponent >= 0 {
        coefficients[exponent as usize] = 1;
    } else {
        // X^-k = -X^(N-k) because X^N = -1.
        coefficients[(degree as i64 + exponent) as usize] = t - 1;
    }
    coefficients
}

/// Inverse of a non-zero `value` mod the prime `t`.
pub fn inverse(value: u64, t: u64) -> u64 {
    let (mut result, mut base, mut exponent) = (1u128, u128::from(value % t), t - 2);
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % u128::from(t);
        }
        base = base * base % u128::from(t);
        exponent >>= 1;
    }
    result as u64
}
