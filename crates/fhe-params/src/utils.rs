// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Centered residues, batch inverses, and coefficient widths for BFV parameters.

use fhe::bfv::BfvParameters;
use fhe_math::zq::Modulus;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::ToPrimitive;
use thiserror::Error;

/// Errors from computing the k0_i batch of modular inverses.
#[derive(Error, Debug)]
pub enum K0Error {
    #[error("BFV error: {0}")]
    Fhe(#[from] fhe::Error),
    #[error("Sample error: {0}")]
    Sample(String),
    #[error("Unexpected error: {0}")]
    Other(String),
}

/// Center an already-computed Q residue in [0, t) for a positive u64 plaintext modulus.
pub fn compute_q_mod_t_centered(q_mod_t: &BigUint, t: u64) -> BigInt {
    let t_bn = BigInt::from(t);
    // Preserve the raw helper's full u64 domain; zq::Modulus is limited to 62 bits.
    let half = &t_bn / 2u32;
    (BigInt::from(q_mod_t.clone()) + &half).mod_floor(&t_bn) - half
}

/// Return k0_i = (-t)^{-1} mod q_i for each CRT modulus.
pub fn compute_k0is(moduli: &[u64], plaintext_modulus: u64) -> Result<Vec<u64>, K0Error> {
    let mut k0is = Vec::with_capacity(moduli.len());
    for &qi in moduli {
        let m = Modulus::new(qi)
            .map_err(|e| K0Error::Sample(format!("Failed to create modulus for k0is: {:?}", e)))?;
        if plaintext_modulus >= qi {
            return Err(K0Error::Other(format!(
                "plaintext modulus {plaintext_modulus} must be smaller than CRT modulus {qi}"
            )));
        }
        let neg_t = m.neg(plaintext_modulus);
        let k0qi = m.inv(neg_t).ok_or(K0Error::Fhe(fhe::Error::MathError(
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
pub fn calculate_bit_width(bound: &BigUint) -> u32 {
    bound.bits().max(1) as u32
}

/// Return the bit width of centered ring coefficients.
pub fn compute_modulus_bit(params: &BfvParameters) -> u32 {
    let moduli = params.moduli();
    let bound = moduli.iter().copied().max().unwrap().saturating_sub(1) / 2;
    (u64::BITS - bound.leading_zeros()).max(1)
}

/// Return max_l bits(q_l - 1) for native CRT coefficients in [0, q_l).
pub fn compute_native_crt_coeff_bit(moduli: &[u64]) -> u32 {
    moduli
        .iter()
        .map(|&q| (u64::BITS - q.saturating_sub(1).leading_zeros()).max(1))
        .max()
        .unwrap_or(1)
}

/// Return the bit width of plaintext coefficients in [0, t).
pub fn compute_msg_bit(params: &BfvParameters) -> u32 {
    let bound = params.plaintext().saturating_sub(1);
    (u64::BITS - bound.leading_zeros()).max(1)
}

/// Return the absolute coefficient bound of the BFV error sampler for `variance`.
///
/// Variances up to 16 use the centered binomial sampler with bound `2 * variance`. Larger
/// variances use the uniform sampler, whose bound `b` is the smallest with `b * (b + 1) >= 3 * variance`.
pub fn error_sampler_bound(variance: &BigUint) -> BigUint {
    if let Some(value) = variance.to_u64().filter(|value| *value <= 16) {
        return BigUint::from(2 * value);
    }

    let target = BigUint::from(3u32) * variance;
    let mut bound = target.sqrt();
    while &bound * (&bound + 1u32) < target {
        bound += 1u32;
    }
    while bound > 0u32.into() && (&bound - 1u32) * &bound >= target {
        bound -= 1u32;
    }
    bound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centered_q_residues_preserve_small_and_full_width_moduli() {
        for (residue, t, expected) in [
            (3, 5, BigInt::from(-2)),
            (2, 5, BigInt::from(2)),
            (3, 6, BigInt::from(-3)),
            (0, 1, BigInt::from(0)),
            (1 << 61, 1 << 62, -BigInt::from(1u64 << 61)),
            (u64::MAX / 2, u64::MAX, BigInt::from(u64::MAX / 2)),
            (u64::MAX / 2 + 1, u64::MAX, -BigInt::from(u64::MAX / 2)),
            (
                (u64::MAX - 1) / 2,
                u64::MAX - 1,
                -BigInt::from((u64::MAX - 1) / 2),
            ),
            (u64::MAX - 1, u64::MAX, BigInt::from(-1)),
        ] {
            assert_eq!(
                compute_q_mod_t_centered(&BigUint::from(residue), t),
                expected
            );
        }
        for t in [100, 0xffffee001, 17000000, 576460752317792257] {
            let modulus = Modulus::new(t).unwrap();
            for residue in [0, (t - 1) / 2, t / 2 + 1, t - 1] {
                assert_eq!(
                    compute_q_mod_t_centered(&BigUint::from(residue), t),
                    BigInt::from(modulus.center(residue)),
                );
            }
        }
    }

    #[test]
    fn compute_k0is_rejects_invalid_moduli_and_plaintext() {
        assert_eq!(compute_k0is(&[17], 5).unwrap(), vec![10]);
        for (moduli, t, expected) in [
            (
                [17],
                17,
                "Unexpected error: plaintext modulus 17 must be smaller than CRT modulus 17",
            ),
            (
                [17],
                18,
                "Unexpected error: plaintext modulus 18 must be smaller than CRT modulus 17",
            ),
            (
                [1],
                0,
                "Sample error: Failed to create modulus for k0is: InvalidModulus(1)",
            ),
            (
                [15],
                5,
                "BFV error: Math library error: Value 10 is not invertible modulo 15.",
            ),
        ] {
            assert_eq!(compute_k0is(&moduli, t).unwrap_err().to_string(), expected);
        }
    }

    #[test]
    fn calculate_bit_width_handles_zero_and_positive_bounds() {
        for (bound, expected) in [(0u32, 1), (1, 1), (2, 2), (3, 2), (4, 3), (7, 3), (8, 4)] {
            assert_eq!(calculate_bit_width(&BigUint::from(bound)), expected);
        }
        assert_eq!(calculate_bit_width(&(BigUint::from(1u32) << 128usize)), 129);
    }

    #[test]
    fn coefficient_widths_preserve_power_of_two_and_raw_slice_boundaries() {
        for (t, expected_msg_width) in [(2, 1), (8, 3), (9, 4)] {
            let params = crate::build_bfv_params(8, t, &[17, 97], None);
            assert_eq!(compute_modulus_bit(&params), 6);
            assert_eq!(compute_native_crt_coeff_bit(params.moduli()), 7);
            assert_eq!(compute_msg_bit(&params), expected_msg_width);
        }
        for (moduli, expected) in [
            (vec![], 1),
            (vec![0], 1),
            (vec![1], 1),
            (vec![2], 1),
            (vec![17, 5], 5),
            (vec![u64::MAX], 64),
        ] {
            assert_eq!(compute_native_crt_coeff_bit(&moduli), expected);
        }
    }

    #[test]
    fn error_sampler_bound_matches_cbd_and_uniform_variance_rules() {
        assert_eq!(
            error_sampler_bound(&BigUint::from(16u32)),
            BigUint::from(32u32)
        );
        assert_eq!(
            error_sampler_bound(&BigUint::from(13_334u32)),
            BigUint::from(200u32)
        );
    }
}
