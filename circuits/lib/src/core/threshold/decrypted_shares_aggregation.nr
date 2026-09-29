// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::compute_threshold_decryption_share_commitment;
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
                residues[l] = reduce_mod::<BIT_Q, BIT_K>(sum, self.configs.qis[l]);
            }
            let u = garner_reconstruct::<L, BIT_Q, BIT_K>(residues, self.configs.qis);

            // BFV decode: `round(t * u / Q)`, with `t` folding to zero. The quotient bound and the
            // canonical remainder together pin the rounding, so no decoded value is free.
            let numerator = t * u + half;
            // Safety: `rounded` is constrained by its bound and the remainder interval below.
            let rounded = unsafe { divide_big_hint(numerator, q_total) };
            rounded.assert_max_bit_size::<BIT_T>();
            assert_in_range::<BIT_Q_TOTAL>(numerator - q_total * rounded, q_total);

            let decoded = if rounded == t { 0 } else { rounded };
            assert_decoded_coefficient(decoded, self.message.coefficients[j]);
        }
    }
}

/// Hints below are not trusted. Every consequence is proven by the caller.
unconstrained fn divide_u128_hint(x: Field, q: Field) -> Field {
    ((x as u128) / (q as u128)) as Field
}

/// `Q` exceeds 128 bits on the secure preset, so the rounded decode divides with a bignum.
unconstrained fn divide_big_hint(x: Field, q: Field) -> Field {
    to_field(
        SecureThreshold8192::from(x).udiv(&SecureThreshold8192::from(q)),
    )
}

/// `a^(q-2) mod q`, the inverse by Fermat. `q` is prime and below 2^63, so squaring fits u128.
unconstrained fn inverse_hint(a: Field, q: Field) -> Field {
    let modulus = q as u128;
    let mut base = (a as u128) % modulus;
    let mut exponent = (q as u64) - 2;
    let mut acc: u128 = 1;
    for _ in 0..64 {
        if exponent != 0 {
            if (exponent & 1) == 1 {
                acc = (acc * base) % modulus;
            }
            base = (base * base) % modulus;
            exponent = exponent >> 1;
        }
    }
    acc as Field
}

/// Proves `0 <= v < upper`.
fn assert_in_range<let BIT: u32>(v: Field, upper: Field) {
    v.assert_max_bit_size::<BIT>();
    (upper - 1 - v).assert_max_bit_size::<BIT>();
}

/// `x mod q`, in `[0, q)`. `x` must fit 128 bits, which the callers assert.
fn reduce_mod<let BIT_Q: u32, let BIT_K: u32>(x: Field, q: Field) -> Field {
    // Safety: the quotient bound and the canonical remainder interval fix the division.
    let k = unsafe { divide_u128_hint(x, q) };
    k.assert_max_bit_size::<BIT_K>();
    let remainder = x - q * k;
    assert_in_range::<BIT_Q>(remainder, q);
    remainder
}

/// The inverse of `a` modulo prime `q`, proven by `a * inverse == 1 (mod q)`.
fn modular_inverse<let BIT_Q: u32, let BIT_K: u32>(a: Field, q: Field) -> Field {
    // Safety: the range check and the product below pin the inverse; a bad hint cannot satisfy both.
    let inverse = unsafe { inverse_hint(a, q) };
    assert_in_range::<BIT_Q>(inverse, q);
    a.assert_max_bit_size::<128>();
    let reduced = reduce_mod::<BIT_Q, BIT_K>(a, q);
    assert(reduce_mod::<BIT_Q, BIT_K>(reduced * inverse, q) == 1, "modular inverse mismatch");
    inverse
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
            let inverse = modular_inverse::<BIT_Q, BIT_K>(denominator, q);
            let magnitude = reduce_mod::<BIT_Q, BIT_K>(numerator * inverse, q);
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
        let reduced = reduce_mod::<BIT_Q, BIT_K>(u, qis[l]);
        let inverse = modular_inverse::<BIT_Q, BIT_K>(modulus, qis[l]);
        // `residues[l] - reduced` lies in `(-q_l, q_l)`; shift it non-negative before reducing.
        let difference = residues[l] - reduced + qis[l];
        let step = reduce_mod::<BIT_Q, BIT_K>(difference * inverse, qis[l]);
        u += modulus * step;
        modulus *= qis[l];
    }
    u
}

/// Every decoded coefficient must match the claimed message, including zero.
/// Keeping this assertion unconditional prevents a prover from using zero as
/// a value that skips the C7 decoding check.
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
