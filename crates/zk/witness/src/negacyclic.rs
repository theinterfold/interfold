// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Negacyclic folding, exact negacyclic products and exact quotients, with descending
//! coefficients.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::WitnessError;

use e3_polynomial::{Polynomial, PolynomialError};
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Context, Poly, PowerBasis};
use fhe_math::zq::primes::generate_prime;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;

use num_traits::Zero;
use num_traits::{Signed, ToPrimitive};

/// Bits of each auxiliary NTT prime. Two of them give an exact window of about `2^123`.
const AUX_PRIME_BITS: usize = 62;

/// Computes `a * b mod (x^N + 1)` exactly over the integers, in O(N log N).
///
/// Both inputs hold `N` descending coefficients, as [`fold_negacyclic`] reads them, and the result
/// equals `fold_negacyclic(&a.mul(b), n)`. The product is taken in `Z_P[x]/(x^N + 1)` for `P` the
/// product of two NTT-friendly primes, then lifted to the centred window `(-P/2, P/2)`. That lift
/// is the integer product because every result coefficient is a sum of `N` terms `a_i * b_j`, so
/// `|c| <= N * max|a| * max|b|`, which is checked to be below `P/2` before the NTT path is taken.
/// Inputs that do not fit `i64`, have another length, or could exceed the window use the quadratic
/// product and fold instead, so the result is exact either way.
pub(crate) fn negacyclic_mul_exact(a: &Polynomial, b: &Polynomial, n: usize) -> Polynomial {
    match ntt_negacyclic_mul(a, b, n) {
        Some(product) => product,
        None => fold_negacyclic(&a.mul(b), n),
    }
}

fn ntt_negacyclic_mul(a: &Polynomial, b: &Polynomial, n: usize) -> Option<Polynomial> {
    let (ac, bc) = (a.coefficients(), b.coefficients());
    if ac.len() != n || bc.len() != n || !n.is_power_of_two() || n < 8 {
        return None;
    }
    let ctx = aux_context(n)?;
    let modulus: BigUint = ctx.moduli().iter().map(|&p| BigUint::from(p)).product();
    let half = &modulus >> 1u32;

    let max_abs = |c: &[BigInt]| c.iter().map(|v| v.abs()).max().unwrap_or_default();
    let worst = max_abs(ac) * max_abs(bc) * BigInt::from(n);
    if worst >= BigInt::from(half.clone()) {
        return None;
    }

    // fhe-math stores ascending coefficients; ours are descending.
    let ascending = |c: &[BigInt]| {
        c.iter()
            .rev()
            .map(|v| v.to_i64())
            .collect::<Option<Vec<i64>>>()
    };
    let (a_asc, b_asc) = (ascending(ac)?, ascending(bc)?);
    let pa = Poly::<PowerBasis>::try_convert_from(a_asc.as_slice(), &ctx, false).ok()?;
    let pb = Poly::<PowerBasis>::try_convert_from(b_asc.as_slice(), &ctx, false).ok()?;
    let product = (&pa.into_ntt() * &pb.into_ntt()).into_power_basis();

    let lifted: Vec<BigUint> = (&product).into();
    let modulus = BigInt::from(modulus);
    let half = BigInt::from(half);
    let mut out: Vec<BigInt> = lifted
        .into_iter()
        .map(|c| {
            let c = BigInt::from(c);
            if c > half {
                c - &modulus
            } else {
                c
            }
        })
        .collect();
    out.reverse();
    Some(Polynomial::new(out))
}

/// The two-prime NTT context for degree `n`, built once per degree.
fn aux_context(n: usize) -> Option<Arc<Context>> {
    static CONTEXTS: OnceLock<Mutex<HashMap<usize, Arc<Context>>>> = OnceLock::new();
    let contexts = CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut contexts = contexts.lock().ok()?;
    if let Some(ctx) = contexts.get(&n) {
        return Some(ctx.clone());
    }
    let step = 2 * n as u64;
    let p1 = generate_prime(AUX_PRIME_BITS, step, 1u64 << AUX_PRIME_BITS)?;
    let p2 = generate_prime(AUX_PRIME_BITS, step, p1)?;
    let ctx = Context::new_arc(&[p1, p2], n).ok()?;
    contexts.insert(n, ctx.clone());
    Some(ctx)
}

/// Keep the circuit's descending product shape when an operand is zero.
/// Polynomial::mul retains its canonical single-coefficient zero result.
pub(crate) fn product_for_fold(lhs: &Polynomial, rhs: &Polynomial, n: usize) -> Polynomial {
    assert_eq!(
        lhs.coefficients().len(),
        n,
        "product operand must have N coefficients"
    );
    assert_eq!(
        rhs.coefficients().len(),
        n,
        "product operand must have N coefficients"
    );
    let product = lhs.mul(rhs);
    let width = 2 * n - 1;
    assert!(
        product.coefficients().len() <= width,
        "product exceeds degree 2(N-1)"
    );
    if product.coefficients().len() == width {
        return product;
    }
    let mut coefficients = vec![BigInt::zero(); width - product.coefficients().len()];
    coefficients.extend_from_slice(product.coefficients());
    Polynomial::new(coefficients)
}

/// Reduces a polynomial of degree `2N-2` modulo `x^N + 1`, in O(N).
///
/// `x^N = -1` in the ring, so a coefficient at degree `e + N` folds onto degree `e` with its sign
/// flipped. Coefficients are stored **descending**, so the coefficient of `x^(N-1-j)` sits at index
/// `j`: its low part is `poly[N-1+j]` and the high part that wraps onto it is `poly[j-1]`. Index
/// `j = 0` is degree `N-1`, whose partner would be degree `2N-1` and so does not exist.
///
/// The tests compare this linear fold with independent polynomial long division.
///
/// # Panics
///
/// Panics when `poly` does not have exactly `2N-1` coefficients.
pub(crate) fn fold_negacyclic(poly: &Polynomial, n: usize) -> Polynomial {
    let c = poly.coefficients();
    assert_eq!(c.len(), 2 * n - 1, "fold_negacyclic expects degree 2(N-1)");

    let mut out = Vec::with_capacity(n);
    out.push(c[n - 1].clone());
    for j in 1..n {
        out.push(&c[n - 1 + j] - &c[j - 1]);
    }
    Polynomial::new(out)
}

/// Returns `a * b mod X^N + 1` over the integers, with exactly `N` coefficients.
///
/// # Errors
///
/// Returns an error when an operand has more than `N` coefficients.
pub(crate) fn negacyclic_mul(
    a: &Polynomial,
    b: &Polynomial,
    n: usize,
) -> Result<Polynomial, WitnessError> {
    if a.coefficients().len() > n || b.coefficients().len() > n {
        return Err(WitnessError::Other(format!(
            "negacyclic product operands must have at most {n} coefficients"
        )));
    }
    // `mul` collapses a zero factor to one coefficient; the fold needs all `2N - 1`.
    let product = Polynomial::new(vec![BigInt::zero(); 2 * n - 1]).add(&a.mul(b));
    Ok(fold_negacyclic(&product, n))
}

/// Divides every coefficient of `numerator` by `modulus` exactly.
///
/// A reduced identity `x == x_hat + modulus * k` holds over the integers exactly when
/// `x - x_hat` divides coefficient-wise, so a remainder means the caller built an inconsistent
/// witness.
///
/// # Errors
///
/// Returns an error naming `what` when a coefficient is not a multiple of `modulus`.
pub(crate) fn exact_quotient(
    numerator: &Polynomial,
    modulus: &BigInt,
    what: &str,
) -> Result<Polynomial, WitnessError> {
    numerator
        .coefficients()
        .iter()
        .map(|coefficient| {
            let (quotient, remainder) = coefficient.div_rem(modulus);
            if remainder.is_zero() {
                Ok(quotient)
            } else {
                Err(WitnessError::Other(format!(
                    "{what} is not divisible by its CRT modulus"
                )))
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Polynomial::new)
}

#[cfg(test)]
/// Independent long division by the monic polynomial X^N + 1.
pub(crate) fn reduce_reference(poly: &Polynomial, n: usize) -> Polynomial {
    let mut divisor = vec![BigInt::zero(); n + 1];
    divisor[0] = BigInt::from(1);
    divisor[n] = BigInt::from(1);
    let mut remainder = poly.coefficients().to_vec();
    for i in 0..remainder.len().saturating_sub(n) {
        let leading = remainder[i].clone();
        for (j, coefficient) in divisor.iter().enumerate() {
            remainder[i + j] -= &leading * coefficient;
        }
    }
    let mut coefficients = vec![BigInt::zero(); n];
    let tail_len = remainder.len().min(n);
    coefficients[n - tail_len..].clone_from_slice(&remainder[remainder.len() - tail_len..]);
    Polynomial::new(coefficients)
}

/// Fold the integer expression and solve `actual = reduced + qi * quotient` exactly.
pub(crate) fn exact_reduction_quotient(
    actual: &Polynomial,
    expression: &Polynomial,
    n: usize,
    qi: &BigInt,
) -> Result<(Polynomial, Polynomial), PolynomialError> {
    let reduced = fold_negacyclic(expression, n);
    let quotient = actual.sub(&reduced).div_exact(qi)?;
    Ok((reduced, quotient))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "fold_negacyclic expects degree 2(N-1)")]
    fn fold_rejects_extra_coefficients() {
        fold_negacyclic(&Polynomial::new(vec![BigInt::zero(); 8]), 4);
    }

    /// Verify odd/even sizes and signed high coefficients against long division.
    #[test]
    fn fold_matches_generic_reduction() {
        for n in [2usize, 3, 4, 8, 17] {
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
            let generic = reduce_reference(&poly, n);
            assert_eq!(
                fast.coefficients(),
                generic.coefficients(),
                "fold disagrees with long division at N = {n}"
            );
        }

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
        assert_eq!(folded, reduce_reference(&poly, n));
    }

    /// The NTT product matches the quadratic product plus fold, for the shapes the user-data
    /// encryption witness takes (a ~2^57 key limb times a ternary `u`) and for mixed signs.
    #[test]
    fn exact_product_matches_quadratic_fold() {
        use rand::Rng;
        let mut rng = rand::rng();
        for n in [8usize, 16, 512, 8192] {
            let key: Vec<BigInt> = (0..n)
                .map(|_| BigInt::from(rng.random_range(-(1i64 << 57)..(1i64 << 57))))
                .collect();
            let ternary: Vec<BigInt> = (0..n)
                .map(|_| BigInt::from(rng.random_range(-1i64..=1)))
                .collect();
            let (a, b) = (Polynomial::new(key), Polynomial::new(ternary));

            assert!(
                ntt_negacyclic_mul(&a, &b, n).is_some(),
                "N = {n} must take the NTT path"
            );
            assert_eq!(
                negacyclic_mul_exact(&a, &b, n),
                fold_negacyclic(&a.mul(&b), n),
                "NTT product disagrees with the quadratic fold at N = {n}"
            );
        }
    }

    /// Products that could leave the exact window fall back to the quadratic path.
    #[test]
    fn exact_product_falls_back_outside_the_window() {
        let n = 8;
        let big = Polynomial::new(vec![BigInt::from(i64::MAX); n]);
        assert!(ntt_negacyclic_mul(&big, &big, n).is_none());
        assert_eq!(
            negacyclic_mul_exact(&big, &big, n),
            fold_negacyclic(&big.mul(&big), n)
        );

        let short = Polynomial::new(vec![BigInt::from(3); n - 1]);
        let full = Polynomial::new(vec![BigInt::from(5); n]);
        assert!(ntt_negacyclic_mul(&short, &full, n).is_none());
    }
}
