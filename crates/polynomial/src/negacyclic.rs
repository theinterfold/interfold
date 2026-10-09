// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Negacyclic folding with descending coefficients.

use crate::Polynomial;
#[cfg(test)]
use crate::{center, reduce};
#[cfg(test)]
use num_bigint::BigInt;
#[cfg(test)]
use num_traits::Zero;

/// Reduces a polynomial of degree `2N-2` modulo `x^N + 1`, in O(N).
///
/// `x^N = -1` in the ring, so a coefficient at degree `e + N` folds onto degree `e` with its sign
/// flipped. Coefficients are stored **descending**, so the coefficient of `x^(N-1-j)` sits at index
/// `j`: its low part is `poly[N-1+j]` and the high part that wraps onto it is `poly[j-1]`. Index
/// `j = 0` is degree `N-1`, whose partner would be degree `2N-1` and so does not exist.
///
/// Callers that only need the reduced value do not pay for [`Polynomial::reduce_by_cyclotomic`].
/// That routine goes through
/// generic long division, whose inner loop runs over all `N+1` divisor coefficients including the
/// `N-1` zeros of `x^N + 1` — about `N^2` BigInt multiply-subtracts, 67 million at `N = 8192`, for a
/// result this computes in `N` subtractions. `fold_matches_generic_reduction` pins the two together.
///
/// # Panics
///
/// Panics when `poly` does not have exactly `2N-1` coefficients.
pub fn fold_negacyclic(poly: &Polynomial, n: usize) -> Polynomial {
    let c = poly.coefficients();
    assert_eq!(c.len(), 2 * n - 1, "fold_negacyclic expects degree 2(N-1)");

    let mut out = Vec::with_capacity(n);
    out.push(c[n - 1].clone());
    for j in 1..n {
        out.push(&c[n - 1 + j] - &c[j - 1]);
    }
    Polynomial::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cyclotomic_polynomial(n: u64) -> Vec<BigInt> {
        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];
        cyclo[0] = BigInt::from(1u64);
        cyclo[n as usize] = BigInt::from(1u64);
        cyclo
    }

    /// The folded quotient must match independent residue decomposition by long division.
    #[test]
    fn folded_quotient_matches_decompose_then_reduce() {
        let qi = BigInt::from(97u32);
        for n in [2usize, 4, 8, 17] {
            let cyclo = cyclotomic_polynomial(n as u64);
            let hat = Polynomial::new(
                (0..2 * n - 1)
                    .map(|k| {
                        let magnitude = BigInt::from((k * 131 + 7) as i64);
                        if k % 2 == 0 {
                            -magnitude
                        } else {
                            magnitude
                        }
                    })
                    .collect::<Vec<BigInt>>(),
            );

            // `pk0` is `hat` reduced into R_qi.
            let folded = fold_negacyclic(&hat, n);
            let pk0 = Polynomial::new(
                folded
                    .coefficients()
                    .iter()
                    .map(|c| center(&reduce(c, &qi), &qi))
                    .collect::<Vec<BigInt>>(),
            );

            // Independent long division.
            let (r1, _r2) = decompose_residue_reference(&pk0, &hat, &qi, &cyclo, n as u64);
            let old = r1.reduce_by_cyclotomic(&cyclo).unwrap();

            // Production route: fold once, then an exact scalar division.
            let (new, remainder) = pk0
                .sub(&folded)
                .div(&Polynomial::constant(qi.clone()))
                .unwrap();
            assert!(remainder.is_zero(), "division must be exact at N = {n}");

            assert_eq!(
                old.coefficients(),
                new.coefficients(),
                "linear derivation disagrees with decompose+reduce at N = {n}"
            );
        }
    }

    /// The O(N) fold must agree with generic long division, coefficient for coefficient.
    ///
    /// This is the whole licence for skipping `reduce_by_cyclotomic`: the fast path is only safe
    /// while it produces the same polynomial. Sizes are odd and even, and the inputs include
    /// negative coefficients and a high half that wraps onto every position.
    #[test]
    fn fold_matches_generic_reduction() {
        for n in [2usize, 3, 4, 8, 17] {
            let cyclo = cyclotomic_polynomial(n as u64);
            // Deterministic but sign-varying coefficients across the whole degree-2(N-1) range.
            let coefficients: Vec<BigInt> = (0..2 * n - 1)
                .map(|k| {
                    let magnitude = BigInt::from((k * 37 + 11) as i64);
                    if k % 3 == 0 {
                        -magnitude
                    } else {
                        magnitude
                    }
                })
                .collect();
            let poly = Polynomial::new(coefficients);

            let fast = fold_negacyclic(&poly, n);
            let generic = poly.reduce_by_cyclotomic(&cyclo).unwrap();
            assert_eq!(
                fast.coefficients(),
                generic.coefficients(),
                "fold disagrees with long division at N = {n}"
            );
        }
    }

    /// A zero high half leaves the low half untouched, which fixes the index alignment.
    ///
    /// If the fold were off by one, or read the halves in the wrong order, this would shift.
    #[test]
    fn fold_of_low_half_only_is_the_identity() {
        let n = 4;
        // Degree 2(N-1) = 6, with everything above degree N-1 = 3 set to zero. Descending order
        // puts the low half last, so the leading N-1 entries are the high half.
        let poly = Polynomial::new(vec![
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(7),
            BigInt::from(-5),
            BigInt::from(3),
            BigInt::from(-1),
        ]);
        let folded = fold_negacyclic(&poly, n);
        assert_eq!(
            folded.coefficients(),
            &[
                BigInt::from(7),
                BigInt::from(-5),
                BigInt::from(3),
                BigInt::from(-1)
            ]
        );
    }

    /// Independent residue decomposition by generic long division.
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
}
