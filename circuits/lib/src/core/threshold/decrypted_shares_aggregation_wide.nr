// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C7 for ciphertext moduli wider than [`decrypted_shares_aggregation`] supports (secure-16384,
//! Q of about 2^312, beyond the field).
//!
//! Same construction as the bounded C7: the shares are range-checked residues, `u` is derived from
//! them by Garner reconstruction, and the decode `round(t * u / Q)` is pinned by a unique quotient
//! and remainder. Nothing about `u` is a witness, so a prover has nothing to choose. Two steps
//! change because their values no longer fit:
//!
//! - Garner works in mixed radix. Each digit is computed with arithmetic modulo one CRT prime, so
//!   no intermediate value exceeds 128 bits, and `u = sum(digit_i * q_0 ... q_{i-1})` is assembled
//!   only at the end, in U384. `Q` itself is only ever a U384.
//! - The decode numerator `t * u + (Q - 1) / 2` exceeds the field, so it is formed in U384 and
//!   divided with the library's constrained `udiv_mod`.

use crate::core::threshold::decrypted_shares_aggregation::{
    assert_decoded_coefficient, Configs, lagrange_coefficients,
};
use crate::math::commitments::compute_threshold_decryption_share_commitment;
use crate::math::helpers::assert_in_residue_range;
use crate::math::modulo::U128::{inv_mod_bounded, reduce_mod_bounded};
use crate::math::polynomial::Polynomial;
use ::bignum::BigNum;
use ::bignum::bignum::to_field;
use ::bignum::U384;

/// Decrypted shares aggregation (C7) for wide ciphertext moduli.
///
/// **Role:** Combine partial decryption shares into the plaintext message (CRT + decode).
///
/// **Consumes:** C6 `d` commitments for each reconstructing party (same order as shares).
///
/// **Verifies:** Share binding to C6; Lagrange combine per limb; CRT glue; decode mod `t`.
pub struct DecryptedSharesAggregation<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let N_PARTIES: u32, let BIT_D_NATIVE: u32, let BIT_Q: u32, let BIT_K: u32> {
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

impl<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let N_PARTIES: u32, let BIT_D_NATIVE: u32, let BIT_Q: u32, let BIT_K: u32> DecryptedSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, N_PARTIES, BIT_D_NATIVE, BIT_Q, BIT_K> {
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
        let q_bn = q_total_u384::<L, BIT_Q>(self.configs.qis);

        for party_idx in 0..(T + 1) {
            // Each share is a native residue in `[0, q_l)`: the interpolation and Garner read it, and
            // the bound makes the plain packing injective, so the opening is unique.
            for l in 0..L {
                for j in 0..MAX_MSG_NON_ZERO_COEFFS {
                    assert_in_residue_range::<BIT_Q>(
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
        // `t * u + half` is below `t * Q + Q / 2`; keeping `t` below `2^(384 - L * BIT_Q - 1)` keeps
        // it below `2^384`, so the U384 arithmetic in the decode never wraps.
        t.assert_max_bit_size::<384 - L * BIT_Q - 1>();
        // `Q` is a product of odd primes, so `Q - 1` halves exactly.
        let (half, odd) = (q_bn - U384::from(1)).udiv_mod(&U384::from(2));
        assert(odd == U384::from(0), "the ciphertext modulus must be odd");

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
            let u = garner_mixed_radix::<L, BIT_Q, BIT_K>(residues, self.configs.qis);

            let decoded = rounded_decode_wide(u, t, half, q_bn);
            assert_decoded_coefficient(decoded, self.message.coefficients[j]);
        }
    }
}

/// `Q = q_0 * ... * q_{L-1}` as a U384. The product is exact, since each factor is below
/// `2^BIT_Q` and `L * BIT_Q` is below 384.
fn q_total_u384<let L: u32, let BIT_Q: u32>(qis: [Field; L]) -> U384 {
    std::static_assert(L * BIT_Q < 384, "the modulus is too wide for U384");
    let mut q_bn = U384::from(1);
    for l in 0..L {
        qis[l].assert_max_bit_size::<BIT_Q>();
        q_bn = q_bn * U384::from(qis[l]);
    }
    q_bn
}

/// Garner reconstruction in mixed radix: the unique `u` in `[0, Q)` with `u == residues[l] (mod q_l)`.
///
/// The digits `v_l` satisfy `u = v_0 + v_1 q_0 + v_2 q_0 q_1 + ...` with `v_l` in `[0, q_l)`. Digit
/// `l` needs `u mod q_l` over the digits found so far and `(q_0 ... q_{l-1}) mod q_l`, both computed
/// with arithmetic modulo `q_l` alone, so every reduction stays below 128 bits. With every digit in
/// range the sum lies in `[0, Q)`, and the digit equation makes it congruent to each residue.
/// The sum is formed in U384: `Q` can exceed the field.
fn garner_mixed_radix<let L: u32, let BIT_Q: u32, let BIT_K: u32>(
    residues: [Field; L],
    qis: [Field; L],
) -> U384 {
    // Each reduction below has a quotient under `2 * q_l`, and `q * quotient` must stay below the
    // field for the reduction to be an integer identity.
    assert(BIT_K > BIT_Q, "the quotient bound must exceed the modulus width");
    assert(BIT_Q + BIT_K < 253, "a reduction could wrap the field");

    let mut digits = [0 as Field; L];
    digits[0] = residues[0];
    for l in 1..L {
        let q = qis[l];
        // `prefix` is `(digits[0] + digits[1] q_0 + ... ) mod q`, `radix` is `(q_0 ... q_{i-1}) mod q`.
        let mut prefix: Field = 0;
        let mut radix: Field = 1;
        for i in 0..l {
            prefix = reduce_mod_bounded::<BIT_Q, BIT_K>(prefix + digits[i] * radix, q);
            radix = reduce_mod_bounded::<BIT_Q, BIT_K>(radix * qis[i], q);
        }
        let inverse = inv_mod_bounded::<BIT_Q, BIT_K>(radix, q);
        // `residues[l] - prefix` lies in `(-q, q)`; shift it non-negative before reducing.
        digits[l] = reduce_mod_bounded::<BIT_Q, BIT_K>((residues[l] - prefix + q) * inverse, q);
    }

    let mut u = U384::from(0);
    let mut place = U384::from(1);
    for l in 0..L {
        u = u + U384::from(digits[l]) * place;
        place = place * U384::from(qis[l]);
    }
    u
}

/// BFV decode of a reconstructed `u` in `[0, Q)`: `round(t * u / Q)`, with `t` folding to zero.
///
/// The same function as the bounded C7's decode, which mirrors fhe.rs. Rounding is the shifted
/// floor `floor((t * u + (Q - 1) / 2) / Q)`. The numerator reaches about `t * Q`, beyond the field,
/// so it is formed in U384, whose arithmetic wraps only at `2^384`. `udiv_mod` proves the quotient
/// and a remainder in `[0, Q)`, which fixes the floor uniquely.
fn rounded_decode_wide(u: U384, t: Field, half: U384, q_bn: U384) -> Field {
    let numerator = U384::from(t) * u + half;
    let (rounded_bn, _) = numerator.udiv_mod(&q_bn);
    let rounded = to_field(rounded_bn);

    // `u` near the top of `[0, Q)` rounds to exactly `t`, which represents plaintext zero.
    if rounded == t {
        0
    } else {
        rounded
    }
}

/// The secure-16384 CRT moduli: six 53-bit primes, `Q` about 2^312.
global SECURE_16384_QIS: [Field; 6] = [
    4503599637200897,
    4503599635628033,
    4503599634644993,
    4503599634579457,
    4503599633989633,
    4503599632613377,
];

/// Garner agrees with the residues it was built from (`500` at `q = [7, 11, 13]`).
#[test]
fn garner_reconstructs_the_unique_representative() {
    let qis: [Field; 3] = [7, 11, 13];
    let residues: [Field; 3] = [3, 5, 6];
    assert(garner_mixed_radix::<3, 8, 9>(residues, qis) == U384::from(500));
}

/// At secure-16384 Garner returns `Q - 1` from the residues `q_l - 1`; `Q` exceeds the field.
#[test]
fn garner_reconstructs_the_top_of_a_wide_modulus() {
    let q_bn = q_total_u384::<6, 53>(SECURE_16384_QIS);
    let mut residues = [0 as Field; 6];
    for l in 0..6 {
        residues[l] = SECURE_16384_QIS[l] - 1;
    }
    assert(garner_mixed_radix::<6, 53, 59>(residues, SECURE_16384_QIS) == q_bn - U384::from(1));
}

/// Boundary behaviour of the rounded decode at `Q = 1001 = 7 * 11 * 13` and `t = 10`; the same
/// values as the bounded C7's test.
#[test]
fn rounded_decode_covers_its_boundaries() {
    let q_bn = U384::from(1001);
    let t: Field = 10;
    let half = U384::from(500);
    let decode = |u: Field| rounded_decode_wide(U384::from(u), t, half, q_bn);

    assert(decode(0) == 0);
    assert(decode(1000) == 0);
    assert(decode(951) == 0);
    assert(decode(950) == 9);
    assert(decode(100) == 1);
    assert(decode(300) == 3);
    assert(decode(50) == 0);
    assert(decode(51) == 1);
    assert(decode(250) == 2);
    assert(decode(251) == 3);
}

/// At secure-16384 the decode handles `u` and a numerator beyond the field: `u = Q - 1` decodes to
/// zero and the exact encoding of `m = 7` decodes to 7, with `t = 65537`.
#[test]
fn rounded_decode_handles_a_wide_numerator() {
    let q_bn = q_total_u384::<6, 53>(SECURE_16384_QIS);
    let t: Field = 65537;
    let (half, _) = (q_bn - U384::from(1)).udiv_mod(&U384::from(2));
    assert(rounded_decode_wide(q_bn - U384::from(1), t, half, q_bn) == 0);

    // round(Q * 7 / t), the honest encoding of 7.
    let encoded = (q_bn * U384::from(7) + U384::from(32768)).udiv(&U384::from(t));
    assert(rounded_decode_wide(encoded, t, half, q_bn) == 7);
}
