// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compact arithmetic for the circuit paths that work in `Z[X]/(X^N+1)`.
//!
//! The routines here let a circuit prove a BFV relation in `Z[X]/(X^N+1)` instead of `Z[X]`.
//! Reduction modulo `q_l` becomes an additive `q_l * short` term rather than an operation, and the
//! coefficients travel as small signed integers embedded in the native field.
//!
//! Every value that must be read back as an integer needs a range check. The field has no ordering,
//! so a checked equation only proves a congruence modulo the native prime; the bounds are what turn
//! that congruence into an equality over the integers. `q_l` is invertible modulo the native prime,
//! so an unbounded quotient makes the equation satisfiable for any left-hand side.

use crate::math::helpers::compute_safe;
use crate::math::polynomial::Polynomial;
// INTERFOLD_MAX_SUITE_V1. The circuit identifier is also absorbed into each transcript.
pub global DS: [u8; 64] = [
    73, 78, 84, 69, 82, 70, 79, 76, 68, 95, 77, 65, 88, 95, 83, 85, 73, 84, 69, 95, 86, 49, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
];

/// Constrains every coefficient to the canonical centered interval `[-(q-1)/2, (q-1)/2]`.
///
/// This fixes one representative per residue class, so a commitment over the result binds to a
/// value rather than to whichever lift the prover preferred.
///
/// `K` is the configured bit width of `(q-1)/2`, which every parameter set already publishes as its
/// public-key bit width. The interval is compared against the modulus itself rather than against a
/// bit width, so this holds for any modulus, whatever its distance from a power of two.
pub fn centered<let N: u32, let K: u32>(a: Polynomial<N>, q: Field) {
    let half = (q - 1) / 2;
    a.range_check_2bounds::<K>(half, half);
}

/// Packs range-checked coefficients into field carriers for a challenge transcript.
///
/// Every digit must already lie in `[0, 2^W)`, otherwise the base-`2^W` concatenation is not
/// injective. Public commitment packing is deliberately not routed through here.
pub fn append<let N: u32, let W: u32>(
    mut inputs: [Field],
    p: Polynomial<N>,
    offset: Field,
) -> [Field] {
    assert(W > 0);
    assert(W <= 192);
    let group = 253 / W;
    let radix = 2.pow_32(W as Field);
    let chunks = (N + group - 1) / group;
    for c in 0..chunks {
        let remaining = N - c * group;
        let take = if remaining < group { remaining } else { group };
        let mut acc: Field = 0;
        for j in 0..take {
            acc = acc * radix + p.coefficients[c * group + j] + offset;
        }
        for _ in 0..(group - take) {
            acc = acc * radix + offset;
        }
        inputs = inputs.push_back(acc);
    }
    inputs
}

/// Derives a checking point from a transcript that already binds every independent operand.
pub fn challenge(inputs: [Field]) -> Field {
    compute_safe(DS, inputs, [0x80000000 | inputs.len(), 1])[0]
}

/// Evaluates `X^(N-1-j) * u mod (X^N+1)` at `x`, for every `j`, by constrained recurrence.
///
/// Multiplying an already-reduced polynomial by `X` can overflow exactly one coefficient, which
/// wraps to the constant term negated; the correction term is therefore a single coefficient of `u`
/// read directly from the input. No product hint is accepted, so nothing here needs bounding.
pub fn kernel<let N: u32>(u: Polynomial<N>, x: Field) -> [Field; N] {
    assert(N > 0);
    let phi = x.pow_32(N as Field) + 1;
    let mut out = [0; N];
    out[N - 1] = u.eval(x);
    for j in 1..N {
        out[N - 1 - j] = x * out[N - j] - phi * u.coefficients[j - 1];
    }
    out
}

/// Combines a kernel with the coefficients of a second polynomial, giving the evaluation of their
/// reduced product.
pub fn dot<let N: u32>(a: Polynomial<N>, k: [Field; N]) -> Field {
    let mut out: Field = 0;
    for j in 0..N {
        out += a.coefficients[j] * k[j];
    }
    out
}

/// Reduces descending-order coefficients modulo `X^N + 1`.
///
/// Degree `d + N` folds onto degree `d` with a sign flip, which in descending order makes each
/// output a difference of two inputs. This is a witness derivation, not a trusted computation: the
/// inputs are unconstrained and may wrap the native field. **Every caller must range-check every
/// returned coefficient before it enters an equation or a transcript.**
pub fn fold_negacyclic<let N: u32>(poly: Polynomial<2 * N - 1>) -> Polynomial<N> {
    assert(N >= 2);
    let mut reduced = [0; N];
    reduced[0] = poly.coefficients[N - 1];
    for j in 1..N {
        reduced[j] = poly.coefficients[N - 1 + j] - poly.coefficients[j - 1];
    }
    Polynomial::new(reduced)
}

#[test]
fn centered_accepts_both_interval_ends() {
    // One modulus from each parameter set, including the insecure one, whose distance from a power
    // of two differs in every case.
    let q8192 = 288230376164294657;
    let q16384 = 1125899917262849;
    let q512 = 68719403009;
    centered::<5, 58>(Polynomial::new([-(q8192 - 1) / 2, -1, 0, 1, (q8192 - 1) / 2]), q8192);
    centered::<5, 50>(Polynomial::new([-(q16384 - 1) / 2, -1, 0, 1, (q16384 - 1) / 2]), q16384);
    centered::<5, 35>(Polynomial::new([-(q512 - 1) / 2, -1, 0, 1, (q512 - 1) / 2]), q512);
}

#[test(should_fail)]
fn centered_rejects_non_canonical() {
    let q = 288230376164294657;
    // One coefficient lifted by a whole modulus: congruent, but not the canonical representative.
    centered::<5, 58>(Polynomial::new([0, 0, q, 0, 0]), q);
}

#[test(should_fail)]
fn centered_rejects_just_past_the_interval() {
    let q = 288230376164294657;
    centered::<5, 58>(Polynomial::new([0, 0, (q - 1) / 2 + 1, 0, 0]), q);
}

#[test]
fn fold_matches_independent_reduction() {
    // A degree-6 product folded to length 4, against the reduction written out by hand.
    let product = Polynomial::new([7, -3, 2, 9, -4, 5, 1]);
    let folded = fold_negacyclic::<4>(product);
    // Descending order: X^6 X^5 X^4 X^3 X^2 X^1 X^0 -> fold X^(d+4) onto X^d negated.
    assert(folded.coefficients == [9, -4 - 7, 5 + 3, 1 - 2]);
    // The reduction must agree with the original polynomial at every point modulo X^4 + 1.
    let points: [Field; 4] = [0, 1, -2, 31];
    for i in 0..4 {
        let x = points[i];
        let phi = x.pow_32(4) + 1;
        // product(x) - folded(x) is a multiple of x^4 + 1, witnessed by the top three coefficients.
        let quotient = Polynomial::new([7, -3, 2]).eval(x);
        assert(product.eval(x) - folded.eval(x) == quotient * phi);
    }
}

#[test]
fn kernel_identity() {
    let a = Polynomial::new([4, 3, 2, 1]);
    let u = Polynomial::new([-1, 0, 1, -1]);
    let mut prod = [0; 7];
    for i in 0..4 {
        for j in 0..4 {
            prod[i + j] += a.coefficients[i] * u.coefficients[j];
        }
    }
    let p = fold_negacyclic::<4>(Polynomial::new(prod));
    let points: [Field; 4] = [0, 1, 2, 17];
    for j in 0..4 {
        let x = points[j];
        assert(dot(a, kernel(u, x)) == p.eval(x));
    }
}
