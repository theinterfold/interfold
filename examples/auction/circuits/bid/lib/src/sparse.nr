// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Strategy 3: `k1` has non-zero coefficients only at `S` public positions.
//!
//! When `N` is a multiple of `bidders · B`, every slot with the same level holds the same value,
//! so the slots have the period `B`. Then `m(X)` is a polynomial in `X^(N / 2B)`, and `k1` has at
//! most `2B - 1` non-zero coefficients. The generator finds the positions from the real fhe.rs
//! slot map: they are the positions where one of the level polynomials `D[l]` of
//! [`crate::table`] is non-zero. Every honest `k1` is a combination of the `D[l]`. Conversely, a
//! polynomial is determined by its slots, so a `k1` with the right slots has no coefficient
//! elsewhere. Thus restricting `k1` to the positions changes nothing about the statement.
//!
//! The circuit takes only the `S` coefficients as inputs. It builds `k1` with the constant 0 at
//! all other positions, and computes the commitment on the whole polynomial. The NTT is not
//! needed: slots with equal rows `alpha^(N - 1 - position)` on the support have equal values, so
//! one weighted sum per class of slots checks all of them. There are about `2B` classes.
//!
//! # Bound
//!
//! `x = sum_j k1[position_j] · weights[j]` has `S` terms below `t^2`, so `x < S · t^2` and the
//! quotient of `x - target` is below `S · t`. `QBITS = bit_length(S · t)` covers it.

use crate::bid::{assert_congruent, commit_k1, residue_targets, thermometer};
use interfold_lib::math::polynomial::Polynomial;

/// The constants that the generator writes.
pub struct SparseConstants<let N: u32, let S: u32, let K: u32, let C: u32> {
    /// The plaintext modulus.
    pub t: Field,
    /// The positions in `k1` of the non-zero coefficients, in ascending order.
    pub positions: [u32; S],
    /// The level of each class of slots; `B` for slots beyond the last copy.
    pub class_level: [u32; K],
    /// `weights[k][j] = alpha_k^(N - 1 - positions[j])` mod `t`.
    pub weights: [[Field; S]; K],
    /// See `ntt::NttConstants`.
    pub target_at: [Field; C],
    pub target_next: [Field; C],
}

/// Checks that `k1s[c]` encodes the SIMD plaintext of the bid `b` for every ciphertext `c`, and
/// returns the `k1` commitments. `support[c]` holds the coefficients of `k1s[c]` at `positions`.
pub fn prove<let N: u32, let B: u32, let C: u32, let S: u32, let K: u32, let BIT_K: u32, let QBITS: u32>(
    b: Field,
    support: [[Field; S]; C],
    constants: SparseConstants<N, S, K, C>,
) -> [Field; C] {
    let ge = thermometer::<B>(b);
    let t = constants.t;
    let mut k1s = [Polynomial::new([0; N]); C];

    for c in 0..C {
        let targets = residue_targets::<B>(ge, constants.target_at[c], constants.target_next[c]);
        for k in 0..K {
            let mut x = 0;
            for j in 0..S {
                x += support[c][j] * constants.weights[k][j];
            }
            assert_congruent::<QBITS>(x, targets[constants.class_level[k]], t);
        }

        let mut coefficients = [0; N];
        for j in 0..S {
            coefficients[constants.positions[j]] = support[c][j];
        }
        k1s[c] = Polynomial::new(coefficients);
    }

    commit_k1::<N, C, BIT_K>(k1s)
}
