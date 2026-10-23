// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pieces that both strategies share: the bid bits, the quotient check, and the commitments.

use interfold_lib::math::commitments::{
    compute_single_polynomial_commitment_checked, DS_USER_DATA_ENCRYPTION_COMMITMENT,
};
use interfold_lib::math::polynomial::Polynomial;

unconstrained fn one_hot_hint<let B: u32>(b: Field) -> [Field; B] {
    let mut e = [0; B];
    for l in 0..B {
        if b == l as Field {
            e[l] = 1;
        }
    }
    e
}

/// Exact quotient `value / t`. The caller range-checks it, so a wrong hint fails the proof.
unconstrained fn quotient_hint(value: Field, t: Field) -> Field {
    value / t
}

/// The thermometer of the bid: `ge[l] = [b >= l]` for `l` in `0..B`, and `ge[B] = ge[B + 1] = 0`.
///
/// `b` is bound to a one-hot vector `e` of `B` booleans with `sum(e) = 1` and `sum(l · e[l]) = b`.
/// Thus `b` is in `0..B`, and no other `b` has a witness. `ge` is the running sum of `e` from the
/// top level down. Each `ge[l]` is one witness, so later uses add no terms to an expression.
pub fn thermometer<let B: u32>(b: Field) -> [Field; B + 2] {
    // Safety: `e` is constrained below to be the one-hot vector of `b`.
    let e = unsafe { one_hot_hint::<B>(b) };
    let mut ge = [0; B + 2];
    let mut running = 0;
    let mut weighted = 0;
    for k in 0..B {
        let l = B - 1 - k;
        assert(e[l] * (e[l] - 1) == 0);
        running += e[l];
        std::as_witness(running);
        ge[l] = running;
        weighted += (l as Field) * e[l];
    }
    assert(running == 1);
    assert(weighted == b);
    ge
}

/// The expected residues `[Q · expected(l)]_t` of one ciphertext as witnesses, for `l` in `0..B`,
/// and the constant 0 for `l = B` (a slot beyond the last copy).
///
/// `target_at · ge[l] + target_next · ge[l + 1]` is the residue because `(ge[l], ge[l + 1])` is
/// `(0, 0)`, `(1, 0)` or `(1, 1)`: the generator picks the constants for these 3 cases.
pub fn residue_targets<let B: u32>(
    ge: [Field; B + 2],
    target_at: Field,
    target_next: Field,
) -> [Field; B + 1] {
    let mut targets = [0; B + 1];
    for l in 0..B {
        let target = target_at * ge[l] + target_next * ge[l + 1];
        std::as_witness(target);
        targets[l] = target;
    }
    targets
}

/// Asserts `value = target (mod t)`, for an integer `value >= 0` and an integer `target` in
/// `0..t`.
///
/// The prover supplies `q` with `value - target = t · q`. The range check `q < 2^QBITS` makes the
/// equation hold over the integers, and not only mod the field prime `p`, when
/// `t · 2^QBITS + t < p`. Then `value - target` is a multiple of `t`. The caller proves that
/// `value < t · 2^QBITS`, so an honest `q` is never negative: `value >= 0` and `target < t` give
/// `value - target > -t`.
pub fn assert_congruent<let QBITS: u32>(value: Field, target: Field, t: Field) {
    // Safety: `q` is range-checked and used in the equation below.
    let q = unsafe { quotient_hint(value - target, t) };
    q.assert_max_bit_size::<QBITS>();
    assert(value - target == t * q);
}

/// The commitments to the `k1` polynomials: the public outputs of the proof.
///
/// This is the commitment that `user_data_encryption` computes, with the digit asserts of
/// `pack_checked`. The asserts force every `k1[i] + 2^nibble` below `2^(nibble + 4)`, so the packing
/// is injective: a commitment has one opening. An equal commitment in the encryption proof then
/// gives the same `k1` here, and that proof range-checks `k1` to `[0, t - 1]`. This circuit does
/// not repeat that range check: it costs about twice as much as the digit assert. The check is the
/// same one that `compute_single_polynomial_commitment_checked` documents for a circuit that
/// opens a commitment it did not create. The commitment value is the same as the unchecked one.
pub fn commit_k1<let N: u32, let C: u32, let BIT_K: u32>(k1s: [Polynomial<N>; C]) -> [Field; C] {
    let mut commitments = [0; C];
    for c in 0..C {
        commitments[c] = compute_single_polynomial_commitment_checked::<N, BIT_K>(
            k1s[c],
            DS_USER_DATA_ENCRYPTION_COMMITMENT,
        );
    }
    commitments
}
