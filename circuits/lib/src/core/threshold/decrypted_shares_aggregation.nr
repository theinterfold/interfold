// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::compute_threshold_decryption_share_commitment;
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::Polynomial;
use crate::math::secure_arithmetic::{
    divide_big_hint, divide_u128_hint, divisible, native, range, TH_Q, TH_T,
};
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
pub struct DecryptedSharesAggregation<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32, let BIT_NOISE: u32, let BIT_D_NATIVE: u32> {
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

    /// Global u polynomial (secret witness)
    u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,

    /// CRT quotient polynomials (secret witnesses)
    crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
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
    ) -> Self {
        DecryptedSharesAggregation {
            configs,
            expected_d_commitments,
            decryption_shares,
            party_ids,
            message,
            u_global,
            crt_quotients,
        }
    }

    /// Run all checks (no return value; asserts hold or the proof fails).
    pub fn execute(self) {
        if L == 3 {
            prove_secure::<MAX_MSG_NON_ZERO_COEFFS, L, T + 1, 2 * T + 1, BIT_D_NATIVE>(
                self.configs,
                self.expected_d_commitments,
                self.party_ids,
                self.message,
                self.decryption_shares,
            );
        } else {
            for party_idx in 0..(T + 1) {
                let computed = compute_threshold_decryption_share_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
                    self.decryption_shares[party_idx],
                );
                assert(computed == self.expected_d_commitments[party_idx], "d commitment mismatch");
            }

            // Step 1: Compute Lagrange coefficients in-circuit
            let lagrange_coeffs =
                compute_all_lagrange_coeffs::<T, L>(self.configs.qis, self.party_ids);

            // Step 2: Compute u^{(l)} for each CRT basis via Lagrange interpolation
            let u_crts = compute_crt_components::<MAX_MSG_NON_ZERO_COEFFS, L, T>(
                self.configs.qis,
                self.decryption_shares,
                lagrange_coeffs,
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
    }

    /// Verifies decoding using BigNum for large Q values
    fn verify_decoding(self) {
        // Compute Q as product of all CRT moduli
        let mut q_modulus = 1 as Field;
        for l in 0..L {
            q_modulus *= self.configs.qis[l];
        }

        // For centered arithmetic
        let q_bn = SecureThreshold8192::from(q_modulus);

        let q_half_bn = q_bn.udiv(&SecureThreshold8192::from(2));

        for coeff_idx in 0..MAX_MSG_NON_ZERO_COEFFS {
            // Compute (t * u_global) mod Q using BigNum
            let u_bn = SecureThreshold8192::from(self.u_global.coefficients[coeff_idx]);
            let t_bn = SecureThreshold8192::from(self.configs.plaintext_modulus);
            // Q is at most 208 bits and t is about 10 bits, so t * u fits in BN254.
            let u_bn_mod_q = u_bn.umod(&q_bn);
            let t_bn_mod_q = t_bn.umod(&q_bn);
            let t_times_u_bn_q = (t_bn_mod_q * u_bn_mod_q).umod(&q_bn);

            // t ~ 1000; all inputs < t; quotient < t << 2^64: safe for ModU64.
            let m = ModU64::new(self.configs.plaintext_modulus as u64);

            // Check if centering is needed
            let needs_centering = t_times_u_bn_q > q_half_bn;

            let computed_message = if needs_centering {
                // When (t*u) mod Q >= Q/2: treat as negative in centered form
                // Centered value is conceptually negative: (t_times_u_mod_q - Q)
                // -Q^{-1} * (negative) = positive result
                let centered_positive = q_bn - t_times_u_bn_q;
                let centered_positive_mod_t = centered_positive.umod(&t_bn);
                let centered_field = to_field(centered_positive_mod_t);
                m.mul_mod(self.configs.q_inverse_mod_t, centered_field)
            } else {
                // When (t*u) mod Q < Q/2: stays positive in centered form
                // -Q^{-1} * (positive) = negative result = t - result
                let t_times_u_bn_t = t_times_u_bn_q.umod(&t_bn);
                let t_times_u_field = to_field(t_times_u_bn_t);
                let product = m.mul_mod(self.configs.q_inverse_mod_t, t_times_u_field);
                if product == 0 {
                    0
                } else {
                    self.configs.plaintext_modulus - product
                }
            };

            assert_decoded_coefficient(computed_message, self.message.coefficients[coeff_idx]);
        }
    }
}

/// Every decoded coefficient must match the claimed message, including zero.
/// Keeping this assertion unconditional prevents a prover from using zero as
/// a value that skips the C7 decoding check.
fn assert_decoded_coefficient(computed_message: Field, claimed_message: Field) {
    assert(computed_message == claimed_message, "decoded message mismatch");
}

/// Computes all Lagrange coefficients using optimized modular arithmetic
pub fn compute_all_lagrange_coeffs<let T: u32, let L: u32>(
    qis: [Field; L],
    party_ids: [Field; T + 1],
) -> [[Field; T + 1]; L] {
    let mut lagrange_coeffs = [[0 as Field; T + 1]; L];

    // Step 1: Cache |x_i - x_j| factors for all party pairs
    let mut diffs = [[0 as Field; T + 1]; T + 1];
    for i in 0..(T + 1) {
        for j in (i + 1)..(T + 1) {
            let diff = party_ids[j] - party_ids[i];
            diffs[i][j] = diff;
            diffs[j][i] = diff;
        }
    }

    // Step 2: Determine signs (same for all parties within a basis)
    let numerator_sign_negative = (T % 2) == 1;

    // Step 3: For each CRT basis, compute Lagrange coefficients
    for basis_idx in 0..L {
        let q_l = qis[basis_idx];
        // party_ids are small (1-indexed, <= T+1); quotient < T+1 << 2^64: safe for ModU64.
        let m = ModU64::new(q_l as u64);

        // Compute product of all party IDs: PRODUCT(j=0..T) x_j mod q_l
        let mut product_x = 1 as Field;
        for j in 0..(T + 1) {
            product_x = m.mul_mod(product_x, party_ids[j]);
        }

        // For each party i, compute L_i(0) mod q_l
        for party_idx in 0..(T + 1) {
            // Numerator (absolute value): PRODUCT(j!=party_idx) x_j
            let numerator_abs = m.div_mod(product_x, party_ids[party_idx]);

            // Denominator (absolute value): PRODUCT(j!=party_idx) |x_party_idx - x_j|
            let mut denominator_abs = 1 as Field;
            for j in 0..(T + 1) {
                if j != party_idx {
                    denominator_abs = m.mul_mod(denominator_abs, diffs[party_idx][j]);
                }
            }

            // Determine denominator sign
            let num_greater = T - party_idx;
            let denom_sign_negative = (num_greater % 2) == 1;

            // Compute unsigned result: |numerator| / |denominator| mod q_l
            let result_abs = m.div_mod(numerator_abs, denominator_abs);

            // Apply combined sign
            let should_negate = numerator_sign_negative != denom_sign_negative;
            let result = if should_negate {
                m.reduce_mod(q_l - result_abs)
            } else {
                result_abs
            };

            lagrange_coeffs[basis_idx][party_idx] = result;
        }
    }

    lagrange_coeffs
}

/// Computes u^{(l)} for each CRT basis via Lagrange interpolation
pub fn compute_crt_components<let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let T: u32>(
    qis: [Field; L],
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
    lagrange_coeffs: [[Field; T + 1]; L],
) -> [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L] {
    let mut u_crts: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L] =
        [Polynomial::new([0; MAX_MSG_NON_ZERO_COEFFS]); L];

    for basis_idx in 0..L {
        let q_l = qis[basis_idx];
        // d_coeff < 2^59 (BIT_D_NATIVE=59), l_i_0 < q_l < 2^62; quotient < 2^59: safe for ModU64.
        let m = ModU64::new(q_l as u64);
        let mut u_coeffs = [0 as Field; MAX_MSG_NON_ZERO_COEFFS];

        // For each coefficient position
        for coeff_idx in 0..MAX_MSG_NON_ZERO_COEFFS {
            let mut u_coeff = 0 as Field;

            // Sum all contributions: u = SUM(i=0..T) [d_i * L_i(0)] mod q_l
            for party_idx in 0..(T + 1) {
                let d_coeff = decryption_shares[party_idx][basis_idx].coefficients[coeff_idx];
                let l_i_0 = lagrange_coeffs[basis_idx][party_idx];

                let term = m.mul_mod(d_coeff, l_i_0);
                u_coeff = m.reduce_mod(u_coeff + term);
            }

            u_coeffs[coeff_idx] = u_coeff;
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

// All hint arithmetic is public-parameter-bounded. Callers separately prove every result.
unconstrained fn lagrange_hint(n: Field, d: Field, q: Field, neg: bool) -> Field {
    let modulus = q as u128;
    let mut base = d as u128;
    let exponent = (q as u64) - 2;
    let mut inverse = 1 as u128;
    for bit in 0..64 {
        if ((exponent >> bit) & 1) == 1 {
            inverse = (inverse * base) % modulus;
        }
        base = (base * base) % modulus;
    }
    let value = ((n as u128) * inverse) % modulus;
    if neg & (value != 0) {
        (modulus - value) as Field
    } else {
        value as Field
    }
}

fn reduce<let BQ: u32>(x: Field, q: Field) -> Field {
    // Safety: a bounded quotient and canonical remainder constrain the division.
    let k = unsafe { divide_u128_hint(x, q) };
    k.assert_max_bit_size::<BQ>();
    let remainder = x - q * k;
    native(Polynomial::new([remainder]), q);
    remainder
}

pub fn lagrange<let H: u32, let P: u32>(ids: [Field; H]) -> [[Field; H]; 3] {
    assert(((P == 3) & (H == 2)) | ((P == 9) & (H == 5)) | ((P == 19) & (H == 10)));
    for i in 0..H {
        ids[i].assert_max_bit_size::<5>();
        assert((ids[i] as u32) > 0);
        assert((ids[i] as u32) <= P);
    }
    for i in 1..H {
        assert((ids[i - 1] as u32) < (ids[i] as u32));
    }
    let mut out = [[0 as Field; H]; 3];
    for i in 0..H {
        let mut n: Field = 1;
        let mut d: Field = 1;
        for j in 0..H {
            if j != i {
                n *= ids[j];
                let difference = if j > i {
                    ids[j] - ids[i]
                } else {
                    ids[i] - ids[j]
                };
                d *= difference;
            }
        }
        let neg = i % 2 == 1;
        for l in 0..3 {
            let q = TH_Q[l];
            // Safety: canonical residues and exact divisibility constrain the inverse relation.
            let coefficient = unsafe { lagrange_hint(n, d, q, neg) };
            native(Polynomial::new([coefficient]), q);
            // n,d < 19^9 < 2^39 < q, so this is a nonnegative <2^98 integer.
            let signed_term = if neg { n } else { q - n };
            let numerator = d * coefficient + signed_term;
            divisible::<40>(numerator, q);
            out[l][i] = coefficient;
        }
    }
    out
}

// Caller must already constrain each residue to [0,q_l).
// Garner reconstruction gives the unique U in [0,Q). No global CRT witness is accepted.
pub fn reconstruct(r: [Field; 3]) -> Field {
    let q0 = TH_Q[0];
    let q1 = TH_Q[1];
    let q2 = TH_Q[2];
    // These are inverse(q0) modulo q1 and inverse(q0*q1) modulo q2.
    let inv01: Field = 14411408858559267;
    let inv012: Field = 135437144770778859;
    let a = reduce::<60>((r[1] - r[0] + 2 * q1) * inv01, q1);
    let u01 = r[0] + q0 * a;
    let rem01 = reduce::<60>(u01, q2);
    let b = reduce::<60>((r[2] - rem01 + q2) * inv012, q2);
    u01 + (q0 * q1) * b
}

fn prove_secure<let K: u32, let L: u32, let H: u32, let P: u32, let BD: u32>(
    configs: Configs<L>,
    expected: [Field; H],
    ids: [Field; H],
    message: Polynomial<K>,
    shares: [[Polynomial<K>; L]; H],
) {
    assert(L == 3);
    assert(configs.plaintext_modulus == TH_T);
    assert(configs.q_inverse_mod_t == 536833);
    for l in 0..L {
        assert(configs.qis[l] == TH_Q[l]);
    }
    for h in 0..H {
        for l in 0..L {
            native(shares[h][l], TH_Q[l]);
        }
        assert(compute_threshold_decryption_share_commitment::<K, L, BD>(shares[h]) == expected[h]);
    }
    let coefficients = lagrange::<H, P>(ids);
    let q = TH_Q[0] * TH_Q[1] * TH_Q[2];
    let half = (q - 1) / 2;
    for j in 0..K {
        let mut residues = [0 as Field; 3];
        for l in 0..L {
            let mut sum: Field = 0;
            for h in 0..H {
                sum += shares[h][l].coefficients[j] * coefficients[l][h];
            }
            // H<=10 and both operands <q_l: sum<2^119, quotient<2^62.
            residues[l] = reduce::<62>(sum, TH_Q[l]);
        }
        let u = reconstruct(residues);
        // 0<=u<Q; t*Q has 191 bits. No native-field wrap is possible.
        let numerator = TH_T * u + half;
        // Safety: the quotient bound and exact remainder interval constrain rounding.
        let rounded = unsafe { divide_big_hint(numerator, q) };
        rounded.assert_max_bit_size::<20>();
        range::<172>(numerator - q * rounded, q);
        let decoded = if rounded == TH_T { 0 } else { rounded };
        assert(decoded == message.coefficients[j], "decoded message mismatch");
    }
}

#[test]
fn garner_small_residue_cases() {
    let q = TH_Q[0] * TH_Q[1] * TH_Q[2];
    assert(reconstruct([0, 0, 0]) == 0);
    assert(reconstruct([1, 1, 1]) == 1);
    assert(reconstruct([TH_Q[0] - 1, TH_Q[1] - 1, TH_Q[2] - 1]) == q - 1);
}
#[test]
fn minimal_lagrange() {
    let a = lagrange::<2, 3>([1, 3]);
    for l in 0..3 {
        assert(((2 * a[l][0] - 3) == 0) | ((2 * a[l][0] - 3) == TH_Q[l]));
    }
}
#[test(should_fail)]
fn reject_duplicate_ids() {
    let _ = lagrange::<2, 3>([1, 1]);
}
#[test(should_fail)]
fn reject_zero_id() {
    let _ = lagrange::<2, 3>([0, 2]);
}
#[test(should_fail)]
fn reject_noncommittee_id() {
    let _ = lagrange::<2, 3>([1, 4]);
}

#[test]
fn zero_decoding_is_checked() {
    let p = Polynomial::new([0]);
    let share = [p; 3];
    let commitment = compute_threshold_decryption_share_commitment::<1, 3, 58>(share);
    let cfg = Configs::new(TH_Q, TH_T, 536833);
    let circuit: DecryptedSharesAggregation<1, 3, 1, 1, 58> =
        DecryptedSharesAggregation::new(cfg, [commitment; 2], [share; 2], [1, 3], p, p, share);
    circuit.execute();
}
#[test(should_fail)]
fn wrong_claimed_message_cannot_pass() {
    let p = Polynomial::new([0]);
    let share = [p; 3];
    let commitment = compute_threshold_decryption_share_commitment::<1, 3, 58>(share);
    let cfg = Configs::new(TH_Q, TH_T, 536833);
    let circuit: DecryptedSharesAggregation<1, 3, 1, 1, 58> = DecryptedSharesAggregation::new(
        cfg,
        [commitment; 2],
        [share; 2],
        [1, 3],
        Polynomial::new([1]),
        p,
        share,
    );
    circuit.execute();
}
