// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Unified math helpers for ZK circuit computations: BFV/TRBFV parameters (Q, delta, inverses),
//! CRT operations (k0is, FHE poly to CRT), and polynomial ring (cyclotomic, residue decomposition).

use crate::CircuitsErrors;
use e3_polynomial::center;
use e3_polynomial::{CrtPolynomial, CrtPolynomialError, Polynomial, ToPowerBasisPoly};
use fhe::bfv::{Encoding, Plaintext};
use fhe_math::zq::Modulus;
use fhe_traits::FheDecoder;
use ndarray::Array2;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};

/// Encoded plaintext coefficients in poly encoding (u64 limb values).
pub fn plaintext_poly_u64(pt: &Plaintext) -> Result<Vec<u64>, CircuitsErrors> {
    Vec::<u64>::try_decode(pt, Encoding::poly()).map_err(CircuitsErrors::Fhe)
}

/// Copy an `Array2<u64>` into workspace `ndarray` with `BigInt` coefficients.
pub fn array2_u64_to_bigint(arr: &Array2<u64>) -> Array2<BigInt> {
    let (rows, cols) = arr.dim();
    let mut out = Array2::<BigInt>::zeros((rows, cols));
    for i in 0..rows {
        for j in 0..cols {
            out[[i, j]] = BigInt::from(arr[[i, j]]);
        }
    }
    out
}

/// Product Q = q_0 * q_1 * ... * q_{L-1} of CRT moduli.
pub fn compute_q_product(moduli: &[u64]) -> BigUint {
    let mut q = BigUint::from(1u64);
    for &m in moduli {
        q *= BigUint::from(m);
    }
    q
}

/// Delta = floor(Q / t) for plaintext modulus t.
pub fn compute_delta(q: &BigUint, t: u64) -> BigUint {
    q / BigUint::from(t)
}

/// Delta_half = floor(delta / 2).
pub fn compute_delta_half(delta: &BigUint) -> BigUint {
    delta / BigUint::from(2u64)
}

/// Q^{-1} mod t (for BFV decoding). Fails if gcd(Q, t) != 1.
pub fn compute_q_inverse_mod_t(q: &BigUint, t: u64) -> Result<u64, CircuitsErrors> {
    let q_bigint = BigInt::from(q.clone());
    let t_bigint = BigInt::from(t);
    let gcd_result = q_bigint.extended_gcd(&t_bigint);
    if gcd_result.gcd != BigInt::from(1) {
        return Err(CircuitsErrors::Other(format!(
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
        CircuitsErrors::Other(format!(
            "q_inverse_mod_t too large to fit in u64: {}",
            inv_positive
        ))
    })
}

/// Q mod t.
pub fn compute_q_mod_t(q: &BigUint, t: u64) -> BigUint {
    q % BigUint::from(t)
}

/// Q mod t in centered form [-t/2, t/2], given CRT moduli and plaintext modulus t.
/// Use with threshold or DKG params via `params.moduli()` and `params.plaintext()`.
pub fn compute_q_mod_t_centered(moduli: &[u64], t: u64) -> BigInt {
    let q = compute_q_product(moduli);
    let q_mod_t_uint = compute_q_mod_t(&q, t);
    let t_bn = BigInt::from(t);
    center(&BigInt::from(q_mod_t_uint), &t_bn)
}

/// t^{-1} mod Q (for CRT / scaling). Fails if gcd(Q, t) != 1.
pub fn compute_t_inv_mod_q(q: &BigUint, t: u64) -> Result<BigUint, CircuitsErrors> {
    let q_bigint = BigInt::from(q.clone());
    let t_bigint = BigInt::from(t);
    let gcd_result = q_bigint.extended_gcd(&t_bigint);
    if gcd_result.gcd != BigInt::from(1) {
        return Err(CircuitsErrors::Other(format!(
            "Q and t are not coprime (t_inv_mod_q), gcd = {}",
            gcd_result.gcd
        )));
    }
    let y = gcd_result.y;
    let t_inv_bigint = if y < BigInt::from(0) {
        y + &q_bigint
    } else {
        y
    };
    t_inv_bigint
        .to_biguint()
        .ok_or_else(|| CircuitsErrors::Other("Failed to convert t_inv_mod_q to BigUint".into()))
}

/// Modular inverse a^{-1} mod m; None if gcd(a, m) != 1.
pub fn mod_inverse_bigint(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let g = a.extended_gcd(m);
    if g.gcd != BigInt::from(1) {
        return None;
    }
    let inv = g.x % m;
    Some(if inv < BigInt::zero() { inv + m } else { inv })
}

// ---------- CRT (k0is, FHE poly to CRT) ----------

/// Computes k0_i = (-t)^{-1} mod q_i for each modulus (used in Configs and bounds).
pub fn compute_k0is(moduli: &[u64], plaintext_modulus: u64) -> Result<Vec<u64>, CircuitsErrors> {
    let mut k0is = Vec::with_capacity(moduli.len());
    for &qi in moduli {
        let m = Modulus::new(qi).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to create modulus for k0is: {:?}", e))
        })?;
        let k0qi = m.inv(m.neg(plaintext_modulus)).ok_or_else(|| {
            CircuitsErrors::Fhe(fhe::Error::MathError(fhe_math::Error::Default(
                "Failed to calculate modulus inverse for k0qi".into(),
            )))
        })?;
        k0is.push(k0qi);
    }
    Ok(k0is)
}

/// Converts an FHE polynomial to CRT form with reverse + center (no ZKP reduce).
pub fn fhe_poly_to_crt_centered(
    poly: &impl ToPowerBasisPoly,
    moduli: &[u64],
) -> Result<CrtPolynomial, CrtPolynomialError> {
    let mut crt = CrtPolynomial::from_fhe_polynomial(poly);
    crt.reverse();
    crt.center(moduli)?;
    Ok(crt)
}

// ---------- Polynomial ring (cyclotomic, residue decomposition) ----------

/// Returns the coefficient vector for the cyclotomic polynomial x^N + 1 (degree N).
#[must_use]
pub fn cyclotomic_polynomial(n: u64) -> Vec<BigInt> {
    let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];
    cyclo[0] = BigInt::from(1u64);
    cyclo[n as usize] = BigInt::from(1u64);
    cyclo
}

/// Decomposes the residue `xi - xi_hat` into `r1 * qi + r2 * cyclo` mod R_qi.
pub fn decompose_residue(
    xi: &Polynomial,
    xi_hat: &Polynomial,
    qi_bigint: &BigInt,
    cyclo: &[BigInt],
    n: u64,
) -> (Polynomial, Polynomial) {
    let cyclo_poly = Polynomial::new(cyclo.to_vec());
    let qi_poly = Polynomial::new(vec![qi_bigint.clone()]);

    let mut xi_hat_mod_rqi = xi_hat.clone();
    xi_hat_mod_rqi = xi_hat_mod_rqi.reduce_by_cyclotomic(cyclo).unwrap();
    xi_hat_mod_rqi.reduce(qi_bigint);
    xi_hat_mod_rqi.center(qi_bigint);
    assert_eq!(xi, &xi_hat_mod_rqi);

    let num_coeffs = xi.sub(xi_hat).coefficients().to_vec();
    assert_eq!((num_coeffs.len() as u64) - 1, 2 * (n - 1));

    let mut num_mod_zqi = Polynomial::new(num_coeffs.clone());
    num_mod_zqi.reduce(qi_bigint);
    num_mod_zqi.center(qi_bigint);

    let (r2_poly, r2_rem_poly) = num_mod_zqi.clone().div(&cyclo_poly).unwrap();
    assert!(r2_rem_poly.coefficients().iter().all(|c| c.is_zero()));
    assert_eq!((r2_poly.coefficients().len() as u64) - 1, n - 2);

    let r2_times_cyclo = r2_poly.mul(&cyclo_poly);
    let mut r2_times_cyclo_mod = r2_times_cyclo.clone();
    r2_times_cyclo_mod.reduce(qi_bigint);
    r2_times_cyclo_mod.center(qi_bigint);
    assert_eq!(&num_mod_zqi, &r2_times_cyclo_mod);
    assert_eq!(
        (r2_times_cyclo.coefficients().len() as u64) - 1,
        2 * (n - 1)
    );

    let num_poly = Polynomial::new(num_coeffs);
    let r1_num = num_poly.sub(&r2_times_cyclo);
    assert_eq!((r1_num.coefficients().len() as u64) - 1, 2 * (n - 1));

    let (r1_poly, r1_rem_poly) = r1_num.div(&qi_poly).unwrap();
    assert!(r1_rem_poly.coefficients().iter().all(|c| c.is_zero()));
    assert_eq!((r1_poly.coefficients().len() as u64) - 1, 2 * (n - 1));
    assert_eq!(&r1_num, &r1_poly.mul(&qi_poly));

    let r1_times_qi = r1_poly.clone().scalar_mul(qi_bigint);
    let xi_calculated = xi_hat
        .clone()
        .add(&r1_times_qi)
        .add(&r2_times_cyclo)
        .trim_leading_zeros();
    assert_eq!(xi, &xi_calculated);

    (r1_poly, r2_poly)
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
}
