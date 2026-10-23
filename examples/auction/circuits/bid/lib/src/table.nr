// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Strategy 2: a public table. `k1[i] = sum_l expected(l) · D[l][i] mod t`.
//!
//! `D[l] = Q · INTT(indicator of the slots of level l)`, reversed like `k1` and reduced mod `t`.
//! The generator writes `D` (`B` rows of `N` constants). The SIMD map is linear, so the plaintext
//! of a bid is the sum over levels of `expected(l)` times the plaintext of the level indicator.
//! `expected(l) = coef_at[c] · ge[l] + coef_next[c] · ge[l + 1]`: `(1, 0)` and `(0, 1)` for the 2
//! ciphertexts of `vickrey`, and `(2, -1)` for `vickrey-compact`.
//!
//! The cost is about `N · (B + 2) / 3` gates for each ciphertext, plus `N` small range checks.
//!
//! # Bound
//!
//! Each `expected(l)` is in `{0, 1, 2}`, and `D[l][i]` is in `[0, t - 1]`. Thus the sum
//! `x_i` is in `[0, 2B(t - 1)]`, and the quotient of `x_i - k1[i] = t · q` is below `2B`.
//! `QBITS = bit_length(2B)` covers it. There is no reduction chain: each coefficient reduces once.

use crate::bid::{assert_congruent, commit_k1, thermometer};
use interfold_lib::math::polynomial::Polynomial;

/// Checks that `k1s[c]` encodes the SIMD plaintext of the bid `b` for every ciphertext `c`, and
/// returns the `k1` commitments. `table[l]` is in the order of `k1`.
pub fn prove<let N: u32, let B: u32, let C: u32, let BIT_K: u32, let QBITS: u32>(
    b: Field,
    k1s: [Polynomial<N>; C],
    t: Field,
    coef_at: [Field; C],
    coef_next: [Field; C],
    table: [[Field; N]; B],
) -> [Field; C] {
    let ge = thermometer::<B>(b);

    for c in 0..C {
        let mut expected = [0; B];
        for l in 0..B {
            let value = coef_at[c] * ge[l] + coef_next[c] * ge[l + 1];
            std::as_witness(value);
            expected[l] = value;
        }

        for i in 0..N {
            let mut x = 0;
            for l in 0..B {
                x += expected[l] * table[l][i];
            }
            assert_congruent::<QBITS>(x, k1s[c].coefficients[i], t);
        }
    }

    commit_k1::<N, C, BIT_K>(k1s)
}
