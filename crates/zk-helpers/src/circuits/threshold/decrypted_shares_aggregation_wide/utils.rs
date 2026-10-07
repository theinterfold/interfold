// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Utilities for Decryption Share Aggregation TRBFV circuit.
//!
//! **Generic BFV math** lives in [`crate::math`] and is re-exported here for convenience.
//! **This module** adds only Shamir + scalar CRT helpers: [`lagrange_recover_at_zero`] and
//! [`crt_reconstruct`]. Coefficient reduction uses [`e3_polynomial::reduce`] in
//! [`Inputs::compute`](super::computation::Inputs).

use crate::math;
use crate::CircuitsErrors;
use num_bigint::{BigInt, BigUint};
use num_traits::{ToPrimitive, Zero};

// Re-export so callers can use decrypted_shares_aggregation::utils for one-stop.
pub use math::{
    compute_delta, compute_delta_half, compute_q_inverse_mod_t, compute_q_mod_t, compute_q_product,
    compute_t_inv_mod_q, mod_inverse_bigint,
};

/// Lagrange interpolation at 0: given shares (party_id, value) mod modulus, returns the recovered secret.
/// Party IDs are 1-based (1, 2, ..., T+1). Formula: f(0) = sum_i y_i * L_i(0) with
/// L_i(0) = prod_{j != i} (0 - x_j) / (x_i - x_j) mod modulus. Used only by this circuit (Shamir recovery).
pub fn lagrange_recover_at_zero(
    party_ids: &[usize],
    shares: &[BigInt],
    modulus: u64,
) -> Result<u64, CircuitsErrors> {
    if party_ids.len() != shares.len() {
        return Err(CircuitsErrors::Other(format!(
            "lagrange_recover_at_zero: party_ids.len() {} != shares.len() {}",
            party_ids.len(),
            shares.len()
        )));
    }
    let m = BigInt::from(modulus);
    let mut secret = BigInt::zero();
    for (i, &x_i) in party_ids.iter().enumerate() {
        let y_i = &shares[i] % &m;
        let y_i_pos = if y_i < BigInt::zero() {
            &y_i + &m
        } else {
            y_i.clone()
        };
        let mut lambda_i = BigInt::from(1);
        for (j, &x_j) in party_ids.iter().enumerate() {
            if i != j {
                let x_i_b = BigInt::from(x_i);
                let x_j_b = BigInt::from(x_j);
                let num = BigInt::from(0) - &x_j_b;
                let den = &x_i_b - &x_j_b;
                let den_inv = crate::math::mod_inverse_bigint(&den, &m)
                    .ok_or_else(|| CircuitsErrors::Other("lagrange: den not invertible".into()))?;
                lambda_i = (&lambda_i * &num % &m * &den_inv % &m + &m) % &m;
            }
        }
        secret = (&secret + &y_i_pos * &lambda_i % &m + &m) % &m;
    }
    let secret_pos = if secret < BigInt::zero() {
        &secret + &m
    } else {
        secret
    };
    secret_pos
        .to_u64()
        .ok_or_else(|| CircuitsErrors::Other("lagrange_recover: result too large for u64".into()))
}

/// CRT reconstruction: given residues[i] in [0, moduli[i]), returns the unique value in [0, Q).
/// Used here for per-coefficient u_global from u_per_modulus; reusable for any scalar CRT.
pub fn crt_reconstruct(residues: &[u64], moduli: &[u64]) -> Result<BigUint, CircuitsErrors> {
    if residues.len() != moduli.len() {
        return Err(CircuitsErrors::Other(format!(
            "crt_reconstruct: residues.len() {} != moduli.len() {}",
            residues.len(),
            moduli.len()
        )));
    }
    let q: BigUint = crate::math::compute_q_product(moduli);
    let mut result = BigUint::zero();
    for (i, &r_i) in residues.iter().enumerate() {
        let m_i = BigUint::from(moduli[i]);
        let m_i_bigint = BigInt::from(m_i.clone());
        let q_i = &q / &m_i;
        let q_i_bigint = BigInt::from(q_i.clone());
        let inv = crate::math::mod_inverse_bigint(&q_i_bigint, &m_i_bigint).ok_or_else(|| {
            CircuitsErrors::Other("crt_reconstruct: q_i not invertible mod m_i".into())
        })?;
        let c_i = (BigInt::from(r_i) * &inv) % &m_i_bigint;
        let c_i_pos = if c_i < BigInt::zero() {
            &c_i + &m_i_bigint
        } else {
            c_i
        };
        let c_i_u = c_i_pos
            .to_biguint()
            .ok_or_else(|| CircuitsErrors::Other("crt_reconstruct: c_i_pos negative".into()))?;
        result = (result + c_i_u * q_i) % &q;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crt_reconstruct_small() {
        let moduli = [3u64, 5, 7];
        let residues = [2u64, 4, 3]; // x ≡ 2 mod 3, ≡ 4 mod 5, ≡ 3 mod 7
        let x = crt_reconstruct(&residues, &moduli).unwrap();
        assert_eq!(x, BigUint::from(59u64)); // 59 mod 3=2, mod 5=4, mod 7=3
    }

    #[test]
    fn test_lagrange_recover_at_zero_two_points() {
        let party_ids = [1usize, 2];
        let shares = [BigInt::from(10i64), BigInt::from(20i64)];
        let modulus = 7u64;
        let secret = lagrange_recover_at_zero(&party_ids, &shares, modulus).unwrap();
        // f(0) = f(1)*L_1(0) + f(2)*L_2(0); L_1(0) = (0-2)/(1-2) = 2, L_2(0) = (0-1)/(2-1) = -1 mod 7 = 6
        // f(0) = 10*2 + 20*6 = 20 + 120 = 140 ≡ 0 mod 7 (for linear f(x)=10x: f(1)=10, f(2)=20 -> f(0)=0)
        assert_eq!(secret, 0);
    }
}
