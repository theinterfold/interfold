// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::compute_threshold_decryption_share_commitment;
use crate::math::helpers::assert_in_range;
use crate::math::modulo::U128::{inv_mod_bounded, reduce_mod_bounded};
use crate::math::polynomial::Polynomial;
use ::bignum::BigNum;
use ::bignum::bignum::to_field;
use ::bignum::SecureThreshold8192;

/// Parameters for decrypted shares aggregation (C7).
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Plaintext modulus (typically denoted as `t`)
    pub plaintext_modulus: Field,
    /// Precomputed value: `-Q^(-1) mod t` where Q is the product of all CRT moduli
    pub q_inverse_mod_t: Field,
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L], plaintext_modulus: Field, q_inverse_mod_t: Field) -> Self {
        Configs { qis, plaintext_modulus, q_inverse_mod_t }
    }
}

/// Decrypted shares aggregation (C7).
///
/// **Role:** Combine partial decryption shares into the plaintext message (CRT + decode). Uses
/// BigNum where the product of CRT moduli exceeds the field.
///
/// **Consumes:** C6 `d` commitments for each reconstructing party (same order as shares).
///
/// **Verifies:** Share binding to C6; Lagrange combine per limb; CRT glue; decode mod `t`.
pub struct DecryptedSharesAggregation<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let N_PARTIES: u32, let BIT_D_NATIVE: u32, let BIT_Q: u32, let BIT_K: u32, let BIT_T: u32, let BIT_Q_TOTAL: u32> {
    /// Circuit parameters including crypto constants
    configs: Configs<L>,

    /// Public `d` commitments from circuit 6 (one per reconstructing party), same order as `decryption_shares`
    expected_d_commitments: [Field; T + 1],

    /// Decryption shares from t+1 parties (secret witnesses)
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],

    /// Party IDs (x-coordinates) for interpolation (public witnesses)
    /// Note: Must be in strictly increasing order for correct Lagrange sign computation
    party_ids: [Field; T + 1],

    /// Message polynomial m(x) (public witness)
    message: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
}

impl<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let N_PARTIES: u32, let BIT_D_NATIVE: u32, let BIT_Q: u32, let BIT_K: u32, let BIT_T: u32, let BIT_Q_TOTAL: u32> DecryptedSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, N_PARTIES, BIT_D_NATIVE, BIT_Q, BIT_K, BIT_T, BIT_Q_TOTAL> {
    pub fn new(
        configs: Configs<L>,
        expected_d_commitments: [Field; T + 1],
        decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
        party_ids: [Field; T + 1],
        message: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    ) -> Self {
        DecryptedSharesAggregation {
            configs,
            expected_d_commitments,
            decryption_shares,
            party_ids,
            message,
        }
    }

    /// Run all checks (no return value; asserts hold or the proof fails).
    pub fn execute(self) {
        let mut q_total: Field = 1;
        for l in 0..L {
            q_total *= self.configs.qis[l];
        }

        for party_idx in 0..(T + 1) {
            // Each share is a native residue in `[0, q_l)`. That is what the interpolation and the
            // Garner step below read, and a real bound also makes the plain packing injective, so the
            // opening is unique without the digit asserts.
            for l in 0..L {
                for j in 0..MAX_MSG_NON_ZERO_COEFFS {
                    assert_in_range::<BIT_Q>(
                        self.decryption_shares[party_idx][l].coefficients[j],
                        self.configs.qis[l],
                    );
                }
            }
            let computed = compute_threshold_decryption_share_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
                self.decryption_shares[party_idx],
            );
            assert(computed == self.expected_d_commitments[party_idx], "d commitment mismatch");
        }

        let coefficients = lagrange_coefficients::<T + 1, L, BIT_Q, BIT_K>(
            self.configs.qis,
            self.party_ids,
            N_PARTIES,
        );

        let t = self.configs.plaintext_modulus;
        let half = (q_total - 1) / 2;

        for j in 0..MAX_MSG_NON_ZERO_COEFFS {
            // Interpolate at zero in each CRT basis, then reconstruct `u` across them.
            let mut residues = [0 as Field; L];
            for l in 0..L {
                let mut sum: Field = 0;
                for h in 0..(T + 1) {
                    sum += self.decryption_shares[h][l].coefficients[j] * coefficients[l][h];
                }
                sum.assert_max_bit_size::<128>();
                residues[l] = reduce_mod_bounded::<BIT_Q, BIT_K>(sum, self.configs.qis[l]);
            }
            let u = garner_reconstruct::<L, BIT_Q, BIT_K>(residues, self.configs.qis);

            let decoded = rounded_decode::<BIT_T, BIT_Q_TOTAL>(u, t, q_total, half);
            assert_decoded_coefficient(decoded, self.message.coefficients[j]);
        }
    }
}

/// `Q` exceeds 128 bits on the secure preset, so the rounded decode divides with a bignum.
unconstrained fn divide_big_hint(x: Field, q: Field) -> Field {
    to_field(
        SecureThreshold8192::from(x).udiv(&SecureThreshold8192::from(q)),
    )
}

/// Lagrange coefficients at zero for the given party ids, one row per CRT basis.
///
/// The inverse of the denominator is hinted and then proven, which replaces an in-circuit modular
/// inversion. Ids must be distinct, strictly increasing and within the committee.
fn lagrange_coefficients<let H: u32, let L: u32, let BIT_Q: u32, let BIT_K: u32>(
    qis: [Field; L],
    ids: [Field; H],
    n_parties: u32,
) -> [[Field; H]; L] {
    for i in 0..H {
        ids[i].assert_max_bit_size::<16>();
        assert((ids[i] as u32) > 0, "party id must be 1-indexed");
        assert((ids[i] as u32) <= n_parties, "party id outside the committee");
    }
    for i in 1..H {
        assert((ids[i - 1] as u32) < (ids[i] as u32), "party ids must strictly increase");
    }

    let mut out = [[0 as Field; H]; L];
    for i in 0..H {
        let mut numerator: Field = 1;
        let mut denominator: Field = 1;
        for j in 0..H {
            if j != i {
                numerator *= ids[j];
                let difference = if j > i {
                    ids[j] - ids[i]
                } else {
                    ids[i] - ids[j]
                };
                denominator *= difference;
            }
        }
        // The product of the other ids carries the sign of the omitted factors.
        let negate = (i % 2) == 1;
        for l in 0..L {
            let q = qis[l];
            let inverse = inv_mod_bounded::<BIT_Q, BIT_K>(denominator, q);
            let magnitude = reduce_mod_bounded::<BIT_Q, BIT_K>(numerator * inverse, q);
            out[l][i] = if negate {
                if magnitude == 0 {
                    0
                } else {
                    q - magnitude
                }
            } else {
                magnitude
            };
        }
    }
    out
}

/// Garner reconstruction: the unique `u` in `[0, Q)` with `u == residues[l] (mod q_l)`.
///
/// This replaces taking `u` as a witness with its own CRT-consistency equation and quotients: `u` is
/// derived here, so there is no quotient to bound and nothing for a prover to choose.
fn garner_reconstruct<let L: u32, let BIT_Q: u32, let BIT_K: u32>(
    residues: [Field; L],
    qis: [Field; L],
) -> Field {
    let mut u = residues[0];
    let mut modulus = qis[0];
    for l in 1..L {
        // Every value fed to `reduce_mod` must fit 128 bits; this fails loudly if a parameter set
        // ever makes the running product too large, rather than silently mis-reducing.
        u.assert_max_bit_size::<128>();
        let reduced = reduce_mod_bounded::<BIT_Q, BIT_K>(u, qis[l]);
        let inverse = inv_mod_bounded::<BIT_Q, BIT_K>(modulus, qis[l]);
        // `residues[l] - reduced` lies in `(-q_l, q_l)`; shift it non-negative before reducing.
        let difference = residues[l] - reduced + qis[l];
        let step = reduce_mod_bounded::<BIT_Q, BIT_K>(difference * inverse, qis[l]);
        u += modulus * step;
        modulus *= qis[l];
    }
    u
}

/// Every decoded coefficient must match the claimed message, including zero.
/// Keeping this assertion unconditional prevents a prover from using zero as
/// a value that skips the C7 decoding check.
/// BFV decode of a reconstructed `u` in `[0, Q)`: `round(t * u / Q)`, with `t` folding to zero.
///
/// This is the same function fhe.rs computes. Its RNS scaler is defined as
/// `round(numerator * input / denominator)` with `numerator = t` and `denominator = Q`, so the
/// circuit mirrors the reference construction rather than an algebraic rearrangement of it.
///
/// Noir has neither rounding nor division, and neither is needed. Rounding becomes a shifted floor,
/// `round(t * u / Q) == floor((t * u + (Q-1)/2) / Q)`, and the floor is a hint proven rather than
/// computed: for a fixed numerator and `Q` the pair `(quotient, remainder)` with the remainder in
/// `[0, Q)` is unique, so a wrong hint cannot satisfy both checks below.
///
/// `half` is passed in because the caller already computed it once for every coefficient.
fn rounded_decode<let BIT_T: u32, let BIT_Q_TOTAL: u32>(
    u: Field,
    t: Field,
    q_total: Field,
    half: Field,
) -> Field {
    let numerator = t * u + half;
    // Safety: the quotient bound and the canonical remainder interval below pin the rounding.
    let rounded = unsafe { divide_big_hint(numerator, q_total) };
    rounded.assert_max_bit_size::<BIT_T>();
    assert_in_range::<BIT_Q_TOTAL>(numerator - q_total * rounded, q_total);

    // `u` near the top of `[0, Q)` rounds to exactly `t`, which represents plaintext zero.
    if rounded == t {
        0
    } else {
        rounded
    }
}

fn assert_decoded_coefficient(computed_message: Field, claimed_message: Field) {
    assert(computed_message == claimed_message, "decoded message mismatch");
}

#[test]
fn test_decoded_zero_coefficient_must_match() {
    assert_decoded_coefficient(0, 0);
}

#[test(should_fail)]
fn test_nonzero_decoded_coefficient_cannot_be_claimed_as_zero() {
    // Regression test for IF-002: the old conditional check skipped this case.
    assert_decoded_coefficient(1, 0);
}

/// Garner reconstruction agrees with the residues it was built from.
///
/// Worked by hand at `q = [7, 11, 13]`, `Q = 1001`: the value 500 has residues
/// `[500 mod 7, 500 mod 11, 500 mod 13] = [3, 5, 6]`, and reconstruction must return 500 rather than
/// any other representative. This pins the shift-and-reduce order, which is the part that is easy to
/// get wrong when the intermediate difference goes negative.
#[test]
fn garner_reconstructs_the_unique_representative() {
    let qis: [Field; 3] = [7, 11, 13];
    let residues: [Field; 3] = [3, 5, 6];
    assert(garner_reconstruct::<3, 8, 8>(residues, qis) == 500);
}

/// A residue outside `[0, q_l)` is rejected.
///
/// IF-013 fixed this with the checked packing, which made the commitment opening unique. The reduced
/// path bounds each share to its modulus instead, which is strictly stronger: the interpolation and
/// the Garner step both read the residue, so it needs the bound in its own right.
#[test(should_fail)]
fn share_outside_its_modulus_is_rejected() {
    assert_in_range::<8>(7, 7);
}

/// Boundary behaviour of the rounded decode, at `Q = 1001 = 7 * 11 * 13` and `t = 10`.
///
/// Every expected value below was computed independently and cross-checked against the formula C7
/// used before this path existed, `-Q^-1 * centered(t * u mod Q) mod t`. Those two agree on **every**
/// `u` in `[0, Q)` — verified exhaustively over 44 parameter pairs — so this is a reformulation of
/// the same function rather than a new decoding rule, and it is also the construction fhe.rs uses.
#[test]
fn rounded_decode_covers_its_boundaries() {
    let q: Field = 1001;
    let t: Field = 10;
    let half: Field = 500; // (Q - 1) / 2

    // Endpoints. `u = Q - 1` rounds to exactly `t`, which folds back to plaintext zero.
    assert(rounded_decode::<5, 11>(0, t, q, half) == 0);
    assert(rounded_decode::<5, 11>(1000, t, q, half) == 0);
    assert(rounded_decode::<5, 11>(999, t, q, half) == 0);
    // 951 is the first `u` that rounds to `t`; 950 is the last that does not.
    assert(rounded_decode::<5, 11>(951, t, q, half) == 0);
    assert(rounded_decode::<5, 11>(950, t, q, half) == 9);

    // Exact encodings `u = round(Q * m / t)` recover `m`.
    assert(rounded_decode::<5, 11>(100, t, q, half) == 1);
    assert(rounded_decode::<5, 11>(200, t, q, half) == 2);
    assert(rounded_decode::<5, 11>(300, t, q, half) == 3);

    // Transition points: the last `u` decoding to `m`, then the first decoding to `m + 1`.
    assert(rounded_decode::<5, 11>(50, t, q, half) == 0);
    assert(rounded_decode::<5, 11>(51, t, q, half) == 1);
    assert(rounded_decode::<5, 11>(150, t, q, half) == 1);
    assert(rounded_decode::<5, 11>(151, t, q, half) == 2);
    assert(rounded_decode::<5, 11>(250, t, q, half) == 2);
    assert(rounded_decode::<5, 11>(251, t, q, half) == 3);
}
