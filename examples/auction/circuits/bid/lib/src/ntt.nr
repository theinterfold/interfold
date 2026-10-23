// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Strategy 1: a forward negacyclic NTT of `k1` mod `t` in the circuit.
//!
//! `k1` holds `[Q · m]_t` with `m` reversed. The SIMD slots of `m` are its values at the `N`
//! primitive `2N`-th roots of unity mod `t`, and the NTT computes those values. Output `j` of the
//! NTT is slot `slot_of_output[j]`. The generator maps `j` to the level of that slot (`level_of[j]`),
//! so the circuit does not need the slot order of fhe.rs. The expected output is
//! `Q · expected(level)`, where `expected` depends on the design:
//!
//! | design            | ciphertext | `expected(l)`                |
//! | ----------------- | ---------- | ---------------------------- |
//! | `vickrey`         | 0          | `[b >= l]`                   |
//! | `vickrey`         | 1          | `[b > l] = [b >= l + 1]`     |
//! | `vickrey-compact` | 0          | `2 [b >= l] - [b > l]`       |
//!
//! Slots beyond the last copy hold 0: the generator gives them the level `B`, and `ge[B] = 0`.
//!
//! # Reduction schedule and bound
//!
//! The NTT is the Cooley-Tukey form with twiddles in bit-reversed order (Longa-Naehrig). Each
//! butterfly maps `(x, y)` to `(x + w·y, x + (t - w)·y)`. Both twiddles are in `[1, t - 1]`, so no
//! value is negative. The circuit does NOT reduce mod `t` between layers. A layer is 2 linear
//! gates for each butterfly, and each output is a witness (`as_witness`), so no expression grows.
//!
//! Let `M_l` bound the values after `l` layers. `M_0 = t - 1` (the honest `k1`), and
//! `M_{l+1} <= M_l + (t - 1) · M_l = t · M_l`. After the `L = log2 N` layers every value is below
//! `(t - 1) · t^L < t^(L + 1)`. The generator asserts `t^(L + 1) < 2^253 < p`, so no value
//! wraps mod the field prime `p` ("lazy reduction is safe").
//!
//! Only the last layer reduces. Its 2 outputs `v` are compared with the expected residue
//! `target` (in `[0, t - 1]`) in one gate each: `v - target = t · q`. `q < v / t < t^L`, so
//! `QBITS = bit_length(t^L)` bounds it. The check in `assert_congruent` needs
//! `t · 2^QBITS + t < p`, which the generator asserts too. One reduction of `N` values costs
//! `N` range checks of `QBITS` bits. A reduction between layers would cost the same number of
//! quotient bits in total, so the single final reduction is the cheapest schedule.
//!
//! The honest `k1` must be in `[0, t - 1]` for these bounds. See `commit_k1` for how the
//! commitment link transfers that range check from the encryption proof.

use crate::bid::{assert_congruent, commit_k1, residue_targets, thermometer};
use interfold_lib::math::polynomial::Polynomial;

/// The constants that the generator writes.
pub struct NttConstants<let N: u32, let B: u32, let C: u32> {
    /// The plaintext modulus.
    pub t: Field,
    /// `twiddles[k] = psi^brv(k)` for a primitive `2N`-th root `psi` mod `t`.
    pub twiddles: [Field; N],
    /// The level of the slot at each NTT output; `B` for a slot beyond the last copy.
    pub level_of: [u32; N],
    /// For ciphertext `c`, `[Q · expected(l)]_t = target_at[c] · ge[l] + target_next[c] · ge[l + 1]`.
    /// `(ge[l], ge[l + 1])` is `(0, 0)`, `(1, 0)` or `(1, 1)`, so the target is in `[0, t - 1]`.
    pub target_at: [Field; C],
    pub target_next: [Field; C],
}

/// One layer of butterflies, `m` blocks. Every output is a witness.
fn layer<let N: u32>(a: [Field; N], twiddles: [Field; N], t: Field, m: u32) -> [Field; N] {
    let half = N / (2 * m);
    let mut out = a;
    for i in 0..m {
        let w = twiddles[m + i];
        let neg_w = t - w;
        for j in 0..half {
            let lo = 2 * i * half + j;
            let hi = lo + half;
            let x = a[lo];
            let y = a[hi];
            let sum = x + w * y;
            let diff = x + neg_w * y;
            std::as_witness(sum);
            std::as_witness(diff);
            out[lo] = sum;
            out[hi] = diff;
        }
    }
    out
}

/// Checks that `k1s[c]` encodes the SIMD plaintext of the bid `b` for every ciphertext `c`, and
/// returns the `k1` commitments.
///
/// `LOG_N = log2 N`, `BIT_K` is the bit width of `t - 1` (the width that `user_data_encryption`
/// uses for `k1`), and `QBITS` is the quotient width from the module comment.
pub fn prove<let N: u32, let LOG_N: u32, let B: u32, let C: u32, let BIT_K: u32, let QBITS: u32>(
    b: Field,
    k1s: [Polynomial<N>; C],
    constants: NttConstants<N, B, C>,
) -> [Field; C] {
    let ge = thermometer::<B>(b);
    let t = constants.t;

    for c in 0..C {
        let targets = residue_targets::<B>(ge, constants.target_at[c], constants.target_next[c]);

        // Undo the reversal of `k1`.
        let mut a = k1s[c].coefficients;
        for i in 0..N {
            a[i] = k1s[c].coefficients[N - 1 - i];
        }

        // Layers 0 to L - 2 do not reduce.
        for layer_index in 0..(LOG_N - 1) {
            a = layer(a, constants.twiddles, t, 1 << layer_index);
        }

        // The last layer (`m = N / 2`, `half = 1`) reduces: `v - target = t · q`.
        let m = N / 2;
        for i in 0..m {
            let w = constants.twiddles[m + i];
            let neg_w = t - w;
            let x = a[2 * i];
            let y = a[2 * i + 1];
            assert_congruent::<QBITS>(x + w * y, targets[constants.level_of[2 * i]], t);
            assert_congruent::<QBITS>(x + neg_w * y, targets[constants.level_of[2 * i + 1]], t);
        }
    }

    commit_k1::<N, C, BIT_K>(k1s)
}
