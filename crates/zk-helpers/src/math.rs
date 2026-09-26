// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Unified math helpers for ZK circuit computations: BFV/TRBFV parameters (Q, delta, inverses),
//! CRT operations (k0is, FHE poly to CRT), and polynomial ring (cyclotomic, residue decomposition).

use crate::utils::validate_crt_shape;
use crate::CircuitsErrors;
use e3_polynomial::{center, reduce};
use e3_polynomial::{CrtPolynomial, CrtPolynomialError, Polynomial, ToPowerBasisPoly};
use fhe::bfv::{Encoding, Plaintext, SecretKey};
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, PowerBasis, RepresentationTag};
use fhe_math::zq::Modulus;
use fhe_traits::FheDecoder;
use ndarray::Array2;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use std::sync::Arc;

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
            CircuitsErrors::Fhe(fhe::Error::MathError(fhe_math::Error::NonInvertible {
                value: m.neg(plaintext_modulus),
                modulus: qi,
            }))
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

/// Convert an FHE polynomial to centered CRT form and validate its circuit shape.
pub fn fhe_poly_to_crt_centered_checked(
    poly: &impl ToPowerBasisPoly,
    moduli: &[u64],
    degree: usize,
) -> Result<CrtPolynomial, CircuitsErrors> {
    let crt = fhe_poly_to_crt_centered(poly, moduli)?;
    validate_crt_shape(&crt, moduli.len(), degree)
        .map_err(|error| CircuitsErrors::Other(format!("invalid FHE polynomial shape: {error}")))?;
    Ok(crt)
}

/// Convert an FHE secret key to centered CRT form for circuit witnesses.
pub fn fhe_secret_key_to_crt_centered(
    secret_key: &SecretKey,
    context: &Arc<Context>,
    moduli: &[u64],
    degree: usize,
) -> Result<CrtPolynomial, CircuitsErrors> {
    if secret_key.coeffs.len() != degree {
        return Err(CircuitsErrors::Other(format!(
            "secret key has {} coefficients; expected {degree}",
            secret_key.coeffs.len()
        )));
    }
    let poly = Poly::<PowerBasis>::try_convert_from(secret_key.coeffs.as_ref(), context, false)
        .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
    fhe_poly_to_crt_centered_checked(&poly, moduli, degree)
}

/// Verify that an FHE polynomial uses the expected ring context.
pub fn validate_fhe_poly_context<R: RepresentationTag>(
    poly: &Poly<R>,
    context: &Context,
    name: &str,
) -> Result<(), CircuitsErrors> {
    if poly.ctx().degree != context.degree || poly.ctx().moduli() != context.moduli() {
        return Err(CircuitsErrors::Other(format!(
            "{name} context does not match the adapter"
        )));
    }
    Ok(())
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
///
/// `cyclo` must be `x^N + 1`, which gives every division a closed form and makes the
/// decomposition O(N):
///
/// - Division by `x^N + 1`: write `A = A_hi * x^N + A_lo`. Because `x^N = -1` in the ring,
///   `A = A_hi * (x^N + 1) + (A_lo - A_hi)`. The quotient is `A_hi` (the first `N-1`
///   coefficients in descending order) and the remainder is `A_lo - A_hi`.
/// - `r2 * cyclo` is `r2` shifted by `N` plus `r2`, which is `[r2 | 0 | r2]`.
/// - `r1` is an exact per-coefficient division by `qi`.
///
/// # Panics
///
/// Panics when `xi` is not `xi_hat` reduced into `R_qi`, when the centered residue is not a
/// multiple of `cyclo`, or when the remaining numerator is not a multiple of `qi`. Each panic
/// means the caller built an inconsistent witness.
pub fn decompose_residue(
    xi: &Polynomial,
    xi_hat: &Polynomial,
    qi_bigint: &BigInt,
    cyclo: &[BigInt],
    n: u64,
) -> (Polynomial, Polynomial) {
    let n = n as usize;
    assert_eq!(cyclo.len(), n + 1, "cyclo must have degree N");
    assert!(
        cyclo[0].is_one() && cyclo[n].is_one() && cyclo[1..n].iter().all(|c| c.is_zero()),
        "decompose_residue requires the cyclotomic polynomial x^N + 1"
    );

    let xi = xi.coefficients();
    let hat = xi_hat.coefficients();
    assert_eq!(xi.len(), n, "xi must have degree N-1");
    assert_eq!(hat.len(), 2 * n - 1, "xi_hat must have degree 2(N-1)");

    // xi_hat mod (cyclo, qi), centered. Coefficients are descending, so the coefficient of
    // x^(N-1-j) is at index j: the low half is `hat[N-1+j]`, the wrapped high half `hat[j-1]`.
    for j in 0..n {
        let mut reduced = hat[n - 1 + j].clone();
        if j > 0 {
            reduced -= &hat[j - 1];
        }
        reduced = center(&reduce(&reduced, qi_bigint), qi_bigint);
        assert_eq!(
            xi[j], reduced,
            "xi must equal xi_hat reduced into R_qi (coefficient {j})"
        );
    }

    // num = xi - xi_hat, right-aligned to degree 2(N-1).
    let num: Vec<BigInt> = (0..2 * n - 1)
        .map(|k| {
            if k >= n - 1 {
                &xi[k - (n - 1)] - &hat[k]
            } else {
                -&hat[k]
            }
        })
        .collect();

    // r2 is the quotient of the centered residue by cyclo, which is its wrapped high half.
    let num_mod_zqi: Vec<BigInt> = num
        .iter()
        .map(|c| center(&reduce(c, qi_bigint), qi_bigint))
        .collect();
    let r2: Vec<BigInt> = num_mod_zqi[..n - 1].to_vec();

    // The division must be exact: remainder = low half - high half = 0.
    for j in 0..n {
        let high = if j > 0 {
            num_mod_zqi[j - 1].clone()
        } else {
            BigInt::zero()
        };
        assert_eq!(
            num_mod_zqi[n - 1 + j],
            high,
            "centered residue must be divisible by cyclo (coefficient {j})"
        );
    }

    // r1 = (num - r2 * cyclo) / qi, with r2 * cyclo = [r2 | 0 | r2].
    let r1: Vec<BigInt> = (0..2 * n - 1)
        .map(|k| {
            let mut coeff = num[k].clone();
            if k < n - 1 {
                coeff -= &r2[k];
            } else if k > n - 1 {
                coeff -= &r2[k - n];
            }
            let (quotient, remainder) = coeff.div_rem(qi_bigint);
            assert!(
                remainder.is_zero(),
                "r1 numerator must be divisible by qi (coefficient {k})"
            );
            quotient
        })
        .collect();

    (Polynomial::new(r1), Polynomial::new(r2))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference implementation kept to prove that the optimized `decompose_residue`
    /// stays bit-identical. Schoolbook long division, O(N^2).
    fn decompose_residue_reference(
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

        let num_poly = Polynomial::new(num_coeffs);
        let r1_num = num_poly.sub(&r2_times_cyclo);
        let (r1_poly, r1_rem_poly) = r1_num.div(&qi_poly).unwrap();
        assert!(r1_rem_poly.coefficients().iter().all(|c| c.is_zero()));

        (r1_poly, r2_poly)
    }

    /// Deterministic xorshift64* stream; keeps the fixtures reproducible without `rand`.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// Centered value in (-qi/2, qi/2], the shape every circuit limb has.
        fn centered(&mut self, qi: u64) -> BigInt {
            BigInt::from((self.next() % qi) as i128 - (qi / 2) as i128)
        }

        /// Ternary value, the shape of `u` and `sk`.
        fn ternary(&mut self) -> BigInt {
            BigInt::from(self.next() % 3) - BigInt::from(1)
        }
    }

    /// Builds `(xi, xi_hat)` the way every circuit does: `xi_hat = a * b + e` at full
    /// degree `2N-2`, `xi` the same value reduced into `R_qi` and centered.
    fn sample_case(n: u64, qi: u64, seed: u64) -> (Polynomial, Polynomial, BigInt, Vec<BigInt>) {
        let mut rng = Rng(seed);
        let qi_bigint = BigInt::from(qi);
        let cyclo = cyclotomic_polynomial(n);

        let a = Polynomial::new((0..n).map(|_| rng.centered(qi)).collect());
        let b = Polynomial::new((0..n).map(|_| rng.ternary()).collect());
        let e = Polynomial::new((0..n).map(|_| BigInt::from(rng.next() % 19) - 9).collect());

        let xi_hat = a.mul(&b).add(&e);
        assert_eq!((xi_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

        let mut xi = xi_hat.reduce_by_cyclotomic(&cyclo).unwrap();
        xi.reduce(&qi_bigint);
        xi.center(&qi_bigint);

        (xi, xi_hat, qi_bigint, cyclo)
    }

    #[test]
    fn test_compute_q_product() {
        let moduli = [3u64, 5, 7];
        let q = compute_q_product(&moduli);
        assert_eq!(q, BigUint::from(105u64));
    }

    #[test]
    fn decompose_residue_preserves_zero_quotient_shapes() {
        let n = 4;
        let cyclo = cyclotomic_polynomial(n);
        let xi = Polynomial::zero((n - 1) as usize);
        let xi_hat = Polynomial::zero((2 * (n - 1)) as usize);

        let (r1, r2) = decompose_residue(&xi, &xi_hat, &BigInt::from(17), &cyclo, n);

        assert!(r1.is_zero());
        assert!(r2.is_zero());
        assert_eq!(r1.degree(), (2 * (n - 1)) as usize);
        assert_eq!(r2.degree(), (n - 2) as usize);
    }

    #[test]
    fn decompose_residue_matches_long_division() {
        // Production modulus (secure-8192 limb 0) plus a small one to vary the wrap.
        for (n, qi, seed) in [
            (8u64, 65537u64, 1),
            (64, 0x02000000015a0001, 2),
            (512, 0x02000000015a0001, 3),
        ] {
            let (xi, xi_hat, qi_bigint, cyclo) = sample_case(n, qi, seed);

            let (r1_ref, r2_ref) = decompose_residue_reference(&xi, &xi_hat, &qi_bigint, &cyclo, n);
            let (r1, r2) = decompose_residue(&xi, &xi_hat, &qi_bigint, &cyclo, n);

            assert_eq!(
                r1.coefficients(),
                r1_ref.coefficients(),
                "r1 mismatch at n={n}"
            );
            assert_eq!(
                r2.coefficients(),
                r2_ref.coefficients(),
                "r2 mismatch at n={n}"
            );
        }
    }
}
