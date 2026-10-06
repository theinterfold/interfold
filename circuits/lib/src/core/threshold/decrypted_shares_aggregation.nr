// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_partial_decryption_c0_commitment, compute_threshold_decryption_share_commitment,
};
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::Polynomial;
use ::bignum::BigNum;
use ::bignum::bignum::to_field;
use ::bignum::U384;

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
/// **Verifies:** Share binding to C6; sum of partial shares plus `c0`; CRT glue; decode mod `t`.
pub struct DecryptedSharesAggregation<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let BIT_NOISE: u32, let BIT_D_NATIVE: u32> {
    /// Circuit parameters including crypto constants
    configs: Configs<L>,

    /// Public `d` commitments from circuit 6 (one per reconstructing party), same order as `decryption_shares`
    expected_d_commitments: [Field; T + 1],

    /// Decryption shares from t+1 parties (secret witnesses)
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],

    /// Party IDs (x-coordinates), in strictly increasing order (public witnesses)
    party_ids: [Field; T + 1],

    /// Message polynomial m(x) (public witness)
    message: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,

    /// Global u polynomial (secret witness)
    u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,

    /// CRT quotient polynomials (secret witnesses)
    crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],

    /// Low-degree `c0` coefficients, ascending degree. Same order as `decryption_shares`.
    ct0: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],

    /// Commitment to that `c0` prefix. C6 publishes the same value.
    c0_commitment: Field,
}

impl<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let BIT_NOISE: u32, let BIT_D_NATIVE: u32> DecryptedSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, BIT_NOISE, BIT_D_NATIVE> {
    pub fn new(
        configs: Configs<L>,
        expected_d_commitments: [Field; T + 1],
        decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
        party_ids: [Field; T + 1],
        message: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
        u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
        crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
        ct0: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
        c0_commitment: Field,
    ) -> Self {
        DecryptedSharesAggregation {
            configs,
            expected_d_commitments,
            decryption_shares,
            party_ids,
            message,
            u_global,
            crt_quotients,
            ct0,
            c0_commitment,
        }
    }

    /// Run all checks (no return value; asserts hold or the proof fails).
    pub fn execute(self) {
        for party_idx in 0..(T + 1) {
            let computed = compute_threshold_decryption_share_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
                self.decryption_shares[party_idx],
            );
            assert(computed == self.expected_d_commitments[party_idx], "d commitment mismatch");
        }
        let computed_c0 = compute_partial_decryption_c0_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
            self.ct0,
        );
        assert(computed_c0 == self.c0_commitment, "c0 commitment mismatch");

        // Sum the partial shares and add c0 once. Lagrange already sits inside each share.
        let u_crts = sum_partial_shares::<MAX_MSG_NON_ZERO_COEFFS, L, T>(
            self.configs.qis,
            self.decryption_shares,
            self.ct0,
        );

        // Step 3: Verify CRT reconstruction: u^{(l)} + r^{(l)} * q_l = u_global
        verify_crt_reconstruction::<MAX_MSG_NON_ZERO_COEFFS, L>(
            self.configs.qis,
            self.u_global,
            self.crt_quotients,
            u_crts,
        );

        // Step 4: Verify decoding
        self.verify_decoding();
    }

    /// Verifies decoding using BigNum for large Q values
    fn verify_decoding(self) {
        // Compute Q as product of all CRT moduli
        let mut q_modulus = 1 as Field;
        for l in 0..L {
            q_modulus *= self.configs.qis[l];
        }

        // For centered arithmetic
        let q_bn = U384::from(q_modulus);

        let q_half_bn = q_bn.udiv(&U384::from(2));

        for coeff_idx in 0..MAX_MSG_NON_ZERO_COEFFS {
            let computed_message = decode_coefficient(
                self.u_global.coefficients[coeff_idx],
                q_bn,
                q_half_bn,
                self.configs.plaintext_modulus,
                self.configs.q_inverse_mod_t,
            );

            assert_decoded_coefficient(computed_message, self.message.coefficients[coeff_idx]);
        }
    }
}

fn decode_coefficient(
    u_global: Field,
    q_bn: U384,
    q_half_bn: U384,
    plaintext_modulus: Field,
    q_inverse_mod_t: Field,
) -> Field {
    // secure-16384 needs 260 bits for t * (Q - 1), which does not fit in U256.
    let u_bn = U384::from(u_global);
    let t_bn = U384::from(plaintext_modulus);
    let t_times_u_bn_q = (t_bn.umod(&q_bn) * u_bn.umod(&q_bn)).umod(&q_bn);
    // t is about 1000, so values reduced modulo t fit in ModU64.
    let m = ModU64::new(plaintext_modulus as u64);

    if t_times_u_bn_q > q_half_bn {
        let centered_positive = q_bn - t_times_u_bn_q;
        let centered_field = to_field(centered_positive.umod(&t_bn));
        m.mul_mod(q_inverse_mod_t, centered_field)
    } else {
        let reduced_field = to_field(t_times_u_bn_q.umod(&t_bn));
        let product = m.mul_mod(q_inverse_mod_t, reduced_field);
        if product == 0 {
            0
        } else {
            plaintext_modulus - product
        }
    }
}

/// Every decoded coefficient must match the claimed message, including zero.
/// Keeping this assertion unconditional prevents a prover from using zero as
/// a value that skips the C7 decoding check.
fn assert_decoded_coefficient(computed_message: Field, claimed_message: Field) {
    assert(computed_message == claimed_message, "decoded message mismatch");
}

/// `u^{(l)} = c0^{(l)} + Σ_i p_i^{(l)}` modulo `q_l`.
///
/// Coefficient 0 is the constant term. `c0` and each partial share use that order.
pub fn sum_partial_shares<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32>(
    qis: [Field; L],
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
    ct0: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
) -> [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L] {
    let mut u_crts: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L] =
        [Polynomial::new([0; MAX_MSG_NON_ZERO_COEFFS]); L];

    for basis_idx in 0..L {
        let q_l = qis[basis_idx];
        let m = ModU64::new(q_l as u64);
        let mut u_coeffs = [0 as Field; MAX_MSG_NON_ZERO_COEFFS];
        for coeff_idx in 0..MAX_MSG_NON_ZERO_COEFFS {
            let mut u_coeff = ct0[basis_idx].coefficients[coeff_idx];
            for party_idx in 0..(T + 1) {
                u_coeff = u_coeff + decryption_shares[party_idx][basis_idx].coefficients[coeff_idx];
            }
            u_coeffs[coeff_idx] = m.reduce_mod(u_coeff);
        }
        u_crts[basis_idx] = Polynomial::new(u_coeffs);
    }

    u_crts
}

/// Verifies CRT reconstruction: u^{(l)} + r^{(l)} * q_l = u_global for all bases l
pub fn verify_crt_reconstruction<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32>(
    qis: [Field; L],
    u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
    u_crts: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
) {
    for basis_idx in 0..L {
        let q_l = qis[basis_idx];

        // Compute r^{(l)} * q_l
        let r_times_q = crt_quotients[basis_idx].mul_scalar(q_l);

        // Compute u^{(l)} + r^{(l)} * q_l
        let reconstructed = u_crts[basis_idx].add(r_times_q);

        // Verify: u^{(l)} + r^{(l)} * q_l = u_global
        // Must hold for every coefficient
        for coeff_idx in 0..MAX_MSG_NON_ZERO_COEFFS {
            assert(
                reconstructed.coefficients[coeff_idx] == u_global.coefficients[coeff_idx],
                "CRT reconstruction verification failed",
            );
        }
    }
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

#[test]
fn test_secure_16384_decode_does_not_wrap_u256() {
    let qis: [Field; 5] =
        [1125899917262849, 1125899915886593, 1125899915231233, 1125899915100161, 1125899914510337];
    let mut q_modulus = 1 as Field;
    for index in 0..qis.len() {
        q_modulus *= qis[index];
    }
    let q_bn = U384::from(q_modulus);
    let q_half_bn = q_bn.udiv(&U384::from(2));

    assert(decode_coefficient(q_modulus - 1, q_bn, q_half_bn, 1000, 953) == 0);
}
