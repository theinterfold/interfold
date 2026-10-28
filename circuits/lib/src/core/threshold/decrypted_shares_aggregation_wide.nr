// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C7 for ciphertext moduli wider than [`decrypted_shares_aggregation`] supports (secure-16384,
//! Q of about 2^250; secure-16384-simd, Q of about 2^276; secure-16384-simd-d6, Q of about 2^427).
//!
//! Same construction as the bounded C7: the shares are range-checked residues, `u` is derived from
//! them by Garner reconstruction, and the decode `round(t * u / Q)` is pinned by a unique quotient
//! and remainder. Nothing about `u` is a witness, so a prover has nothing to choose. Two steps
//! change because their values no longer fit:
//!
//! - Garner works in mixed radix. Each digit is computed with arithmetic modulo one CRT prime, so
//!   no intermediate value exceeds 128 bits, and `u = sum(digit_i * q_0 ... q_{i-1})` is assembled
//!   only at the end. That sum is below `Q`, which [`exact_q_total`] proves is below the field.
//! - The decode numerator `t * u + (Q - 1) / 2` exceeds the field, so it is formed in U384 and
//!   divided with the library's constrained `udiv_mod`.
//!
//! When `Q` itself passes the field (`BIT_Q_TOTAL` above 252, as at secure-16384-simd), `Q` and `u`
//! have no field representative either. The same construction then runs with `Q` and `u` held as
//! U384 values: the digit sum, the numerator and the quotient are exact integers below `2^384`.
//! Only the decoded coefficient, at most `t`, returns to the field. When `Q` is wider than 352 bits
//! (secure-16384-simd-d6), the numerator `t * Q` could reach `2^384`, so the same construction runs
//! with U512 values instead; the `*_512` functions repeat the U384 ones with the wider type.

use crate::core::threshold::decrypted_shares_aggregation::{
    assert_decoded_coefficient, Configs, lagrange_coefficients,
};
use crate::math::commitments::compute_threshold_decryption_share_commitment;
use crate::math::helpers::assert_in_range;
use crate::math::modulo::U128::{inv_mod_bounded, reduce_mod_bounded};
use crate::math::polynomial::Polynomial;
use ::bignum::BigNum;
use ::bignum::bignum::to_field;
use ::bignum::U384;
use ::bignum::U512;

/// Decrypted shares aggregation (C7) for wide ciphertext moduli.
///
/// **Role:** Combine partial decryption shares into the plaintext message (CRT + decode).
///
/// **Consumes:** C6 `d` commitments for each reconstructing party (same order as shares).
///
/// **Verifies:** Share binding to C6; Lagrange combine per limb; CRT glue; decode mod `t`.
pub struct DecryptedSharesAggregation<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let N_PARTIES: u32, let BIT_D_NATIVE: u32, let BIT_Q: u32, let BIT_K: u32, let BIT_Q_TOTAL: u32> {
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

impl<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let N_PARTIES: u32, let BIT_D_NATIVE: u32, let BIT_Q: u32, let BIT_K: u32, let BIT_Q_TOTAL: u32> DecryptedSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, N_PARTIES, BIT_D_NATIVE, BIT_Q, BIT_K, BIT_Q_TOTAL> {
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
    ///
    /// `BIT_Q_TOTAL` is a compile-time constant, so exactly one of the three branches is compiled.
    pub fn execute(self) {
        // Q < 2^252 < the field modulus, so Q and u are field elements.
        if BIT_Q_TOTAL < 253 {
            self.execute_in_field();
        } else if BIT_Q_TOTAL < 352 {
            self.execute_beyond_field();
        } else {
            self.execute_beyond_field_512();
        }
    }

    /// The checks for a `Q` that is a field element.
    fn execute_in_field(self) {
        let (q_total, q_bn) = exact_q_total::<L, BIT_Q>(self.configs.qis);

        for party_idx in 0..(T + 1) {
            // Each share is a native residue in `[0, q_l)`: the interpolation and Garner read it, and
            // the bound makes the plain packing injective, so the opening is unique.
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
        // `Q` is odd, so the field halving of `Q - 1` is the integer one.
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
            let u = garner_mixed_radix::<L, BIT_Q, BIT_K>(residues, self.configs.qis);

            let decoded = rounded_decode_wide(u, t, half, q_bn);
            assert_decoded_coefficient(decoded, self.message.coefficients[j]);
        }
    }

    /// The checks for a `Q` above the field: `Q` and `u` are U384 values.
    fn execute_beyond_field(self) {
        let q_bn = exact_q_total_bn::<L, BIT_Q>(self.configs.qis);
        let one = U384::from(1);
        // `Q` is odd, so `(Q - 1) / 2` is the exact integer half.
        let half = (q_bn - one).udiv(&U384::from(2));

        for party_idx in 0..(T + 1) {
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

        for j in 0..MAX_MSG_NON_ZERO_COEFFS {
            let mut residues = [0 as Field; L];
            for l in 0..L {
                let mut sum: Field = 0;
                for h in 0..(T + 1) {
                    sum += self.decryption_shares[h][l].coefficients[j] * coefficients[l][h];
                }
                sum.assert_max_bit_size::<128>();
                residues[l] = reduce_mod_bounded::<BIT_Q, BIT_K>(sum, self.configs.qis[l]);
            }
            let u = garner_mixed_radix_bn::<L, BIT_Q, BIT_K>(residues, self.configs.qis);

            let decoded = rounded_decode_beyond_field(u, t, half, q_bn);
            assert_decoded_coefficient(decoded, self.message.coefficients[j]);
        }
    }

    /// The checks for a `Q` of 352 bits or more: `Q` and `u` are U512 values.
    fn execute_beyond_field_512(self) {
        let q_bn = exact_q_total_bn_512::<L, BIT_Q>(self.configs.qis);
        let one = U512::from(1);
        // `Q` is odd, so `(Q - 1) / 2` is the exact integer half.
        let half = (q_bn - one).udiv(&U512::from(2));

        for party_idx in 0..(T + 1) {
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

        for j in 0..MAX_MSG_NON_ZERO_COEFFS {
            let mut residues = [0 as Field; L];
            for l in 0..L {
                let mut sum: Field = 0;
                for h in 0..(T + 1) {
                    sum += self.decryption_shares[h][l].coefficients[j] * coefficients[l][h];
                }
                sum.assert_max_bit_size::<128>();
                residues[l] = reduce_mod_bounded::<BIT_Q, BIT_K>(sum, self.configs.qis[l]);
            }
            let u = garner_mixed_radix_bn_512::<L, BIT_Q, BIT_K>(residues, self.configs.qis);

            let decoded = rounded_decode_beyond_field_512(u, t, half, q_bn);
            assert_decoded_coefficient(decoded, self.message.coefficients[j]);
        }
    }
}

/// `Q = q_0 * ... * q_{L-1}` as a field element and as a U384, proven equal.
///
/// The U384 product is the exact integer, since each factor is below `2^BIT_Q` and `L * BIT_Q` is
/// far below 384. A field element is always below the field prime, so the equality proves `Q` is
/// too: the field product did not wrap, and every value bounded by `Q` below is an integer.
fn exact_q_total<let L: u32, let BIT_Q: u32>(qis: [Field; L]) -> (Field, U384) {
    // The U384 product is exact only while it cannot reach 2^384.
    assert(L * BIT_Q < 384, "the modulus is too wide for U384");
    let mut q_field: Field = 1;
    let mut q_bn = U384::from(1);
    for l in 0..L {
        qis[l].assert_max_bit_size::<BIT_Q>();
        q_field *= qis[l];
        q_bn = q_bn * U384::from(qis[l]);
    }
    assert(q_bn == U384::from(q_field), "ciphertext modulus exceeds the field");
    (q_field, q_bn)
}

/// `Q = q_0 * ... * q_{L-1}` as an exact U384, for a `Q` that may pass the field.
///
/// The product is exact only while it cannot reach `2^384`, which the width assertion guarantees.
/// Each `q_l` is a compile-time constant of the configuration; its width bound makes the assertion
/// meaningful for any configuration.
fn exact_q_total_bn<let L: u32, let BIT_Q: u32>(qis: [Field; L]) -> U384 {
    assert(L * BIT_Q < 384, "the modulus is too wide for U384");
    let mut q_bn = U384::from(1);
    for l in 0..L {
        qis[l].assert_max_bit_size::<BIT_Q>();
        q_bn = q_bn * U384::from(qis[l]);
    }
    q_bn
}

/// `Q = q_0 * ... * q_{L-1}` as an exact U512, for a `Q` of 352 bits or more.
///
/// The width assertion keeps the product and the decode numerator `t * Q` below `2^512`: it leaves
/// 32 bits for `t`, and `t` is below `2^32` in every supported preset.
fn exact_q_total_bn_512<let L: u32, let BIT_Q: u32>(qis: [Field; L]) -> U512 {
    assert(L * BIT_Q < 480, "the modulus is too wide for U512");
    let mut q_bn = U512::from(1);
    for l in 0..L {
        qis[l].assert_max_bit_size::<BIT_Q>();
        q_bn = q_bn * U512::from(qis[l]);
    }
    q_bn
}

/// Garner reconstruction like [`garner_mixed_radix`], with `u` assembled as an exact U384.
///
/// The digits are the same field values, each in `[0, q_l)`. The sum `v_0 + v_1 q_0 + ...` lies in
/// `[0, Q)`, which is below `2^384` but may be above the field, so the places and the sum are U384.
fn garner_mixed_radix_bn<let L: u32, let BIT_Q: u32, let BIT_K: u32>(
    residues: [Field; L],
    qis: [Field; L],
) -> U384 {
    assert(BIT_K > BIT_Q, "the quotient bound must exceed the modulus width");
    assert(BIT_Q + BIT_K < 253, "a reduction could wrap the field");

    let mut digits = [0 as Field; L];
    digits[0] = residues[0];
    for l in 1..L {
        let q = qis[l];
        let mut prefix: Field = 0;
        let mut radix: Field = 1;
        for i in 0..l {
            prefix = reduce_mod_bounded::<BIT_Q, BIT_K>(prefix + digits[i] * radix, q);
            radix = reduce_mod_bounded::<BIT_Q, BIT_K>(radix * qis[i], q);
        }
        let inverse = inv_mod_bounded::<BIT_Q, BIT_K>(radix, q);
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

/// [`garner_mixed_radix_bn`] with `u` assembled as an exact U512.
fn garner_mixed_radix_bn_512<let L: u32, let BIT_Q: u32, let BIT_K: u32>(
    residues: [Field; L],
    qis: [Field; L],
) -> U512 {
    assert(BIT_K > BIT_Q, "the quotient bound must exceed the modulus width");
    assert(BIT_Q + BIT_K < 253, "a reduction could wrap the field");

    let mut digits = [0 as Field; L];
    digits[0] = residues[0];
    for l in 1..L {
        let q = qis[l];
        let mut prefix: Field = 0;
        let mut radix: Field = 1;
        for i in 0..l {
            prefix = reduce_mod_bounded::<BIT_Q, BIT_K>(prefix + digits[i] * radix, q);
            radix = reduce_mod_bounded::<BIT_Q, BIT_K>(radix * qis[i], q);
        }
        let inverse = inv_mod_bounded::<BIT_Q, BIT_K>(radix, q);
        digits[l] = reduce_mod_bounded::<BIT_Q, BIT_K>((residues[l] - prefix + q) * inverse, q);
    }

    let mut u = U512::from(0);
    let mut place = U512::from(1);
    for l in 0..L {
        u = u + U512::from(digits[l]) * place;
        place = place * U512::from(qis[l]);
    }
    u
}

/// BFV decode of a reconstructed `u` in `[0, Q)` held as U384: `round(t * u / Q)`, with `t` folding
/// to zero. `half` is `(Q - 1) / 2`. The numerator is below `t * Q + Q`, far below `2^384`.
fn rounded_decode_beyond_field(u: U384, t: Field, half: U384, q_bn: U384) -> Field {
    let numerator = U384::from(t) * u + half;
    let (rounded_bn, _) = numerator.udiv_mod(&q_bn);
    let rounded = to_field(rounded_bn);

    if rounded == t {
        0
    } else {
        rounded
    }
}

/// [`rounded_decode_beyond_field`] with `u`, `half` and `Q` held as U512.
fn rounded_decode_beyond_field_512(u: U512, t: Field, half: U512, q_bn: U512) -> Field {
    let numerator = U512::from(t) * u + half;
    let (rounded_bn, _) = numerator.udiv_mod(&q_bn);
    let rounded = to_field(rounded_bn);

    if rounded == t {
        0
    } else {
        rounded
    }
}

/// Garner reconstruction in mixed radix: the unique `u` in `[0, Q)` with `u == residues[l] (mod q_l)`.
///
/// The digits `v_l` satisfy `u = v_0 + v_1 q_0 + v_2 q_0 q_1 + ...` with `v_l` in `[0, q_l)`. Digit
/// `l` needs `u mod q_l` over the digits found so far and `(q_0 ... q_{l-1}) mod q_l`, both computed
/// with arithmetic modulo `q_l` alone, so every reduction stays below 128 bits. With every digit in
/// range the sum lies in `[0, Q)`, and the digit equation makes it congruent to each residue.
fn garner_mixed_radix<let L: u32, let BIT_Q: u32, let BIT_K: u32>(
    residues: [Field; L],
    qis: [Field; L],
) -> Field {
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

    let mut u: Field = 0;
    let mut place: Field = 1;
    for l in 0..L {
        u += digits[l] * place;
        place *= qis[l];
    }
    u
}

/// BFV decode of a reconstructed `u` in `[0, Q)`: `round(t * u / Q)`, with `t` folding to zero.
///
/// The same function as the bounded C7's decode, which mirrors fhe.rs. Rounding is the shifted
/// floor `floor((t * u + (Q - 1) / 2) / Q)`. The numerator reaches about `t * Q`, beyond the field,
/// so it is formed in U384, whose arithmetic wraps only at `2^384`. `udiv_mod` proves the quotient
/// and a remainder in `[0, Q)`, which fixes the floor uniquely.
fn rounded_decode_wide(u: Field, t: Field, half: Field, q_bn: U384) -> Field {
    let numerator = U384::from(t) * U384::from(u) + U384::from(half);
    let (rounded_bn, _) = numerator.udiv_mod(&q_bn);
    let rounded = to_field(rounded_bn);

    // `u` near the top of `[0, Q)` rounds to exactly `t`, which represents plaintext zero.
    if rounded == t {
        0
    } else {
        rounded
    }
}

/// The secure-16384 CRT moduli.
global SECURE_16384_QIS: [Field; 5] =
    [1125899917262849, 1125899915886593, 1125899915231233, 1125899915100161, 1125899914510337];

/// Garner agrees with the residues it was built from (`500` at `q = [7, 11, 13]`).
#[test]
fn garner_reconstructs_the_unique_representative() {
    let qis: [Field; 3] = [7, 11, 13];
    let residues: [Field; 3] = [3, 5, 6];
    assert(garner_mixed_radix::<3, 8, 9>(residues, qis) == 500);
}

/// At secure-16384 Garner returns `Q - 1` from the residues `q_l - 1`, where the bounded C7's
/// running value would pass 128 bits.
#[test]
fn garner_reconstructs_the_top_of_a_wide_modulus() {
    let (q_total, _) = exact_q_total::<5, 51>(SECURE_16384_QIS);
    let mut residues = [0 as Field; 5];
    for l in 0..5 {
        residues[l] = SECURE_16384_QIS[l] - 1;
    }
    assert(garner_mixed_radix::<5, 51, 57>(residues, SECURE_16384_QIS) == q_total - 1);
}

/// A modulus whose product passes the field is rejected rather than wrapped.
#[test(should_fail_with = "ciphertext modulus exceeds the field")]
fn modulus_beyond_the_field_is_rejected() {
    let qis: [Field; 6] = [
        1125899917262849,
        1125899915886593,
        1125899915231233,
        1125899915100161,
        1125899914510337,
        1125899914379265,
    ];
    let _ = exact_q_total::<6, 51>(qis);
}

/// Boundary behaviour of the rounded decode at `Q = 1001 = 7 * 11 * 13` and `t = 10`; the same
/// values as the bounded C7's test.
#[test]
fn rounded_decode_covers_its_boundaries() {
    let q_bn = U384::from(1001);
    let t: Field = 10;
    let half: Field = 500;

    assert(rounded_decode_wide(0, t, half, q_bn) == 0);
    assert(rounded_decode_wide(1000, t, half, q_bn) == 0);
    assert(rounded_decode_wide(951, t, half, q_bn) == 0);
    assert(rounded_decode_wide(950, t, half, q_bn) == 9);
    assert(rounded_decode_wide(100, t, half, q_bn) == 1);
    assert(rounded_decode_wide(300, t, half, q_bn) == 3);
    assert(rounded_decode_wide(50, t, half, q_bn) == 0);
    assert(rounded_decode_wide(51, t, half, q_bn) == 1);
    assert(rounded_decode_wide(250, t, half, q_bn) == 2);
    assert(rounded_decode_wide(251, t, half, q_bn) == 3);
}

/// At secure-16384 the decode handles a numerator beyond the field: `u = Q - 1` decodes to zero and
/// the exact encoding of `m = 7` decodes to 7.
#[test]
fn rounded_decode_handles_a_wide_numerator() {
    let (q_total, q_bn) = exact_q_total::<5, 51>(SECURE_16384_QIS);
    let t: Field = 1000;
    let half = (q_total - 1) / 2;
    assert(rounded_decode_wide(q_total - 1, t, half, q_bn) == 0);

    // round(Q * 7 / 1000), computed in U384 and brought back to the field.
    let encoded = to_field(
        (q_bn * U384::from(7) + U384::from(500)).udiv(&U384::from(1000)),
    );
    assert(rounded_decode_wide(encoded, t, half, q_bn) == 7);
}

/// The secure-16384-simd CRT moduli: five 56-bit primes, `Q` of about `2^276`.
global SECURE_16384_SIMD_QIS: [Field; 5] =
    [36028797029253121, 36028797027680257, 36028797026762753, 36028797026500609, 36028797025124353];

/// Garner in U384 agrees with the residues it was built from (`500` at `q = [7, 11, 13]`).
#[test]
fn garner_bn_reconstructs_the_unique_representative() {
    let qis: [Field; 3] = [7, 11, 13];
    let residues: [Field; 3] = [3, 5, 6];
    assert(garner_mixed_radix_bn::<3, 8, 9>(residues, qis) == U384::from(500));
}

/// At secure-16384-simd `Q` passes the field. Garner returns `Q - 1` from the residues `q_l - 1`.
#[test]
fn garner_bn_reconstructs_the_top_of_a_modulus_beyond_the_field() {
    let q_bn = exact_q_total_bn::<5, 56>(SECURE_16384_SIMD_QIS);
    let mut residues = [0 as Field; 5];
    for l in 0..5 {
        residues[l] = SECURE_16384_SIMD_QIS[l] - 1;
    }
    let u = garner_mixed_radix_bn::<5, 56, 62>(residues, SECURE_16384_SIMD_QIS);
    assert(u + U384::from(1) == q_bn);
}

/// Boundary behaviour of the U384 decode at `Q = 1001` and `t = 10`; the values of the field decode.
#[test]
fn rounded_decode_beyond_field_covers_its_boundaries() {
    let q_bn = U384::from(1001);
    let half = U384::from(500);
    let t: Field = 10;

    assert(rounded_decode_beyond_field(U384::from(0), t, half, q_bn) == 0);
    assert(rounded_decode_beyond_field(U384::from(1000), t, half, q_bn) == 0);
    assert(rounded_decode_beyond_field(U384::from(951), t, half, q_bn) == 0);
    assert(rounded_decode_beyond_field(U384::from(950), t, half, q_bn) == 9);
    assert(rounded_decode_beyond_field(U384::from(100), t, half, q_bn) == 1);
    assert(rounded_decode_beyond_field(U384::from(50), t, half, q_bn) == 0);
    assert(rounded_decode_beyond_field(U384::from(51), t, half, q_bn) == 1);
}

/// At secure-16384-simd `u = Q - 1` decodes to zero and the exact encoding of `m = 7` decodes to 7,
/// with `t = 65537` and a numerator above the field.
#[test]
fn rounded_decode_beyond_field_handles_the_simd_modulus() {
    let q_bn = exact_q_total_bn::<5, 56>(SECURE_16384_SIMD_QIS);
    let half = (q_bn - U384::from(1)).udiv(&U384::from(2));
    let t: Field = 65537;
    assert(rounded_decode_beyond_field(q_bn - U384::from(1), t, half, q_bn) == 0);

    // round(Q * 7 / t), computed in U384.
    let encoded = (q_bn * U384::from(7) + U384::from(32768)).udiv(&U384::from(65537));
    assert(rounded_decode_beyond_field(encoded, t, half, q_bn) == 7);
}

/// The secure-16384-simd-d6 CRT moduli: three 55-bit and five 54-bit primes, `Q` of about `2^427`.
global SECURE_16384_SIMD_D6_QIS: [Field; 8] = [
    18014398525603841,
    18014398524424193,
    18014398521016321,
    9007199267782657,
    9007199267389441,
    9007199267258369,
    9007199266471937,
    9007199264636929,
];

/// Garner in U512 agrees with the residues it was built from (`500` at `q = [7, 11, 13]`).
#[test]
fn garner_bn_512_reconstructs_the_unique_representative() {
    let qis: [Field; 3] = [7, 11, 13];
    let residues: [Field; 3] = [3, 5, 6];
    assert(garner_mixed_radix_bn_512::<3, 8, 9>(residues, qis) == U512::from(500));
}

/// At secure-16384-simd-d6 `Q` is about `2^427`. Garner returns `Q - 1` from the residues `q_l - 1`.
#[test]
fn garner_bn_512_reconstructs_the_top_of_the_d6_modulus() {
    let q_bn = exact_q_total_bn_512::<8, 55>(SECURE_16384_SIMD_D6_QIS);
    let mut residues = [0 as Field; 8];
    for l in 0..8 {
        residues[l] = SECURE_16384_SIMD_D6_QIS[l] - 1;
    }
    let u = garner_mixed_radix_bn_512::<8, 55, 60>(residues, SECURE_16384_SIMD_D6_QIS);
    assert(u + U512::from(1) == q_bn);
}

/// Boundary behaviour of the U512 decode at `Q = 1001` and `t = 10`; the values of the U384 decode.
#[test]
fn rounded_decode_beyond_field_512_covers_its_boundaries() {
    let q_bn = U512::from(1001);
    let half = U512::from(500);
    let t: Field = 10;

    assert(rounded_decode_beyond_field_512(U512::from(0), t, half, q_bn) == 0);
    assert(rounded_decode_beyond_field_512(U512::from(1000), t, half, q_bn) == 0);
    assert(rounded_decode_beyond_field_512(U512::from(951), t, half, q_bn) == 0);
    assert(rounded_decode_beyond_field_512(U512::from(950), t, half, q_bn) == 9);
    assert(rounded_decode_beyond_field_512(U512::from(100), t, half, q_bn) == 1);
    assert(rounded_decode_beyond_field_512(U512::from(50), t, half, q_bn) == 0);
    assert(rounded_decode_beyond_field_512(U512::from(51), t, half, q_bn) == 1);
}

/// At secure-16384-simd-d6 `u = Q - 1` decodes to zero and the exact encoding of `m = 7` decodes to
/// 7, with `t = 65537` and a numerator of about 444 bits.
#[test]
fn rounded_decode_beyond_field_512_handles_the_d6_modulus() {
    let q_bn = exact_q_total_bn_512::<8, 55>(SECURE_16384_SIMD_D6_QIS);
    let half = (q_bn - U512::from(1)).udiv(&U512::from(2));
    let t: Field = 65537;
    assert(rounded_decode_beyond_field_512(q_bn - U512::from(1), t, half, q_bn) == 0);

    // round(Q * 7 / t), computed in U512.
    let encoded = (q_bn * U512::from(7) + U512::from(32768)).udiv(&U512::from(65537));
    assert(rounded_decode_beyond_field_512(encoded, t, half, q_bn) == 7);
}
