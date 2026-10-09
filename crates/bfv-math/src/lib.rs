// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV scaling, plaintext decoding, and coefficient widths.

use e3_polynomial::center;
use fhe::bfv::{BfvParameters, Encoding, Plaintext};
use fhe_math::zq::Modulus;
use fhe_traits::FheDecoder;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::ToPrimitive;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BfvMathError {
    #[error("BFV error: {0}")]
    Fhe(#[from] fhe::Error),
    #[error("Sample error: {0}")]
    Sample(String),
    #[error("Unexpected error: {0}")]
    Other(String),
}

/// Decode plaintext coefficients in polynomial encoding.
pub fn plaintext_poly_u64(pt: &Plaintext) -> Result<Vec<u64>, BfvMathError> {
    Vec::<u64>::try_decode(pt, Encoding::poly()).map_err(BfvMathError::Fhe)
}

/// Return the product Q = q_0 * q_1 * ... * q_{L-1} of CRT moduli.
pub fn compute_q_product(moduli: &[u64]) -> BigUint {
    let mut q = BigUint::from(1u64);
    for &m in moduli {
        q *= BigUint::from(m);
    }
    q
}

/// Return delta = floor(Q / t) for plaintext modulus t.
pub fn compute_delta(q: &BigUint, t: u64) -> BigUint {
    q / BigUint::from(t)
}

/// Return floor(delta / 2).
pub fn compute_delta_half(delta: &BigUint) -> BigUint {
    delta / BigUint::from(2u64)
}

/// Return Q^{-1} mod t for BFV decoding. Fail if gcd(Q, t) != 1.
pub fn compute_q_inverse_mod_t(q: &BigUint, t: u64) -> Result<u64, BfvMathError> {
    let q_bigint = BigInt::from(q.clone());
    let t_bigint = BigInt::from(t);
    let gcd_result = q_bigint.extended_gcd(&t_bigint);
    if gcd_result.gcd != BigInt::from(1) {
        return Err(BfvMathError::Other(format!(
            "Q and t are not coprime, gcd = {}",
            gcd_result.gcd
        )));
    }
    let inv = gcd_result.x % &t_bigint;
    let inv_positive = if inv < BigInt::from(0) {
        inv + &t_bigint
    } else {
        inv
    };
    inv_positive.to_u64().ok_or_else(|| {
        BfvMathError::Other(format!(
            "q_inverse_mod_t too large to fit in u64: {}",
            inv_positive
        ))
    })
}

/// Return Q mod t.
pub fn compute_q_mod_t(q: &BigUint, t: u64) -> BigUint {
    q % BigUint::from(t)
}

/// Return Q mod t in centered form for the given CRT and plaintext moduli.
pub fn compute_q_mod_t_centered(moduli: &[u64], t: u64) -> BigInt {
    let q = compute_q_product(moduli);
    let q_mod_t_uint = compute_q_mod_t(&q, t);
    let t_bn = BigInt::from(t);
    center(&BigInt::from(q_mod_t_uint), &t_bn)
}

/// Return k0_i = (-t)^{-1} mod q_i for each CRT modulus.
pub fn compute_k0is(moduli: &[u64], plaintext_modulus: u64) -> Result<Vec<u64>, BfvMathError> {
    let mut k0is = Vec::with_capacity(moduli.len());
    for &qi in moduli {
        let m = Modulus::new(qi).map_err(|e| {
            BfvMathError::Sample(format!("Failed to create modulus for k0is: {:?}", e))
        })?;
        if plaintext_modulus >= qi {
            return Err(BfvMathError::Other(format!(
                "plaintext modulus {plaintext_modulus} must be smaller than CRT modulus {qi}"
            )));
        }
        let neg_t = m.neg(plaintext_modulus);
        let k0qi = m.inv(neg_t).ok_or(BfvMathError::Fhe(fhe::Error::MathError(
            fhe_math::Error::NonInvertible {
                value: neg_t,
                modulus: qi,
            },
        )))?;
        k0is.push(k0qi);
    }
    Ok(k0is)
}

/// Return the bit width of a bound, with a minimum of one bit.
pub fn calculate_bit_width(bound: BigInt) -> u32 {
    if bound <= BigInt::from(0) {
        return 1;
    }

    bound.bits() as u32
}

/// Return the bit width of centered ring coefficients.
pub fn compute_modulus_bit(params: &BfvParameters) -> u32 {
    let moduli = params.moduli();
    let modulus = BigInt::from(compute_max_modulus(moduli));
    let bound = (modulus - BigInt::from(1)) / BigInt::from(2);

    calculate_bit_width(bound)
}

/// Return the maximum CRT modulus. The slice must not be empty.
pub fn compute_max_modulus(moduli: &[u64]) -> u64 {
    moduli.iter().copied().max().unwrap()
}

/// Return max_l bits(q_l - 1) for native CRT coefficients in [0, q_l).
pub fn compute_native_crt_coeff_bit(moduli: &[u64]) -> u32 {
    moduli
        .iter()
        .map(|&q| calculate_bit_width(BigInt::from(q) - 1))
        .max()
        .unwrap_or(1)
}

/// Return the bit width of plaintext coefficients in [0, t).
pub fn compute_msg_bit(params: &BfvParameters) -> u32 {
    let t = BigInt::from(params.plaintext());
    let bound = t.clone() - BigInt::from(1);
    calculate_bit_width(bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_q_product() {
        let moduli = [3u64, 5, 7];
        let q = compute_q_product(&moduli);
        assert_eq!(q, BigUint::from(105u64));
    }

    #[test]
    fn compute_k0is_requires_plaintext_modulus_below_each_crt_modulus() {
        assert_eq!(compute_k0is(&[17], 5).unwrap(), vec![10]);
        assert!(compute_k0is(&[17], 17).is_err());
        assert!(compute_k0is(&[17], 18).is_err());
    }

    #[test]
    fn calculate_bit_width_handles_zero_and_positive_bounds() {
        assert_eq!(calculate_bit_width(BigInt::from(0)), 1);
        assert_eq!(calculate_bit_width(BigInt::from(1)), 1);
        assert_eq!(calculate_bit_width(BigInt::from(2)), 2);
        assert_eq!(calculate_bit_width(BigInt::from(3)), 2);
        assert_eq!(calculate_bit_width(BigInt::from(4)), 3);
        assert_eq!(calculate_bit_width(BigInt::from(7)), 3);
        assert_eq!(calculate_bit_width(BigInt::from(8)), 4);
    }

    #[test]
    fn calculate_bit_width_handles_negative_bounds() {
        assert_eq!(calculate_bit_width(BigInt::from(-1)), 1);
    }
}
