// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Configuration Verification Circuit (pre-deployment).
///
/// This circuit verifies all cryptographic parameters used across both BFV (for DKG share encryption)
/// and Threshold BFV (for user data encryption and decryption) schemes. It runs once per deployment to establish
/// the mathematical foundation that all subsequent circuits depend on.
///
/// Rather than trusting parameter configuration, this circuit provides public proof that:
///
/// - CRT moduli products are correctly computed
/// - Error bounds satisfy security requirements
/// - Scaling factors have correct multiplicative inverses
/// - Reed-Solomon parity matrices for Shamir sharing are properly constructed
/// - BFV and Threshold BFV parameter sets are mutually consistent

use lib::configs::default::{N_PARTIES, T};
use lib::configs::secure::dkg::{
    L as DKG_L, L_THRESHOLD, N as DKG_N, PARITY_MATRIX, PLAINTEXT_MODULUS as DKG_PLAINTEXT_MODULUS,
    Q_MOD_T as DKG_Q_MOD_T, Q_MOD_T_CENTERED as DKG_Q_MOD_T_CENTERED, QIS as DKG_QIS, QIS_THRESHOLD,
    SHARE_ENCRYPTION_ALPHA, SHARE_ENCRYPTION_BETA, SHARE_ENCRYPTION_BIT_Q0, SHARE_ENCRYPTION_BIT_Q1,
    SHARE_ENCRYPTION_CT0_R_BOUNDS, SHARE_ENCRYPTION_CT1_R_BOUNDS, SHARE_ENCRYPTION_DELTA,
    SHARE_ENCRYPTION_E0_BOUND, SHARE_ENCRYPTION_E1_BOUND, SHARE_ENCRYPTION_K0IS,
    SHARE_ENCRYPTION_MSG_BOUND, SHARE_ENCRYPTION_PK_BOUNDS, SHARE_ENCRYPTION_Q0_OFFSET,
    SHARE_ENCRYPTION_Q1_OFFSET, SHARE_ENCRYPTION_SCALE_K, SHARE_ENCRYPTION_SCALED_QUOTIENT,
    SHARE_ENCRYPTION_SMALL_D, SHARE_ENCRYPTION_T_GAP, SHARE_ENCRYPTION_T_GAP_BIT,
    SHARE_ENCRYPTION_T_POW_BIT, SHARE_ENCRYPTION_U_BOUND,
};

use lib::configs::secure::threshold::{
    // Structural parameters
    N as THRESHOLD_N, L as THRESHOLD_L, PARAMS_SEARCH_Z as N_CIPHERTEXTS,
    // Moduli
    QIS as THRESHOLD_QIS,
    // Derived values
    PLAINTEXT_MODULUS as THRESHOLD_PLAINTEXT_MODULUS, Q_MOD_T as THRESHOLD_Q_MOD_T,
    Q_MOD_T_CENTERED as THRESHOLD_Q_MOD_T_CENTERED, Q_INVERSE_MOD_T as THRESHOLD_Q_INVERSE_MOD_T,
    // pk_generation bounds
    PK_GENERATION_EEK_BOUND, PK_GENERATION_SK_BOUND, PK_GENERATION_E_SM_BOUND,
    PK_GENERATION_R_BOUNDS, PK_GENERATION_B_ENC,
    // share_decryption bounds
    THRESHOLD_SHARE_DECRYPTION_R_BOUNDS,
    // user_data_encryption bounds
    USER_DATA_ENCRYPTION_K0IS, USER_DATA_ENCRYPTION_PK_BOUNDS, USER_DATA_ENCRYPTION_E0_BOUND,
    USER_DATA_ENCRYPTION_E1_BOUND, USER_DATA_ENCRYPTION_U_BOUND, USER_DATA_ENCRYPTION_K1_LOW_BOUND,
    USER_DATA_ENCRYPTION_K1_UP_BOUND, USER_DATA_ENCRYPTION_CT0_R_BOUNDS,
    USER_DATA_ENCRYPTION_CT1_R_BOUNDS,
};

use lib::math::modulo::U128::ModU128;

/// Centers a value from [0, modulus) to [-modulus/2, modulus/2).
///
/// This function converts values from standard representation [0, modulus) to
/// centered representation [-modulus/2, modulus/2), which is used in BFV for
/// efficient arithmetic and correct decoding.
///
/// - For odd modulus: center if raw > modulus/2
/// - For even modulus: center if raw >= modulus/2
pub fn center(raw: Field, modulus: Field) -> Field {
    let needs_centering = if (modulus as u128 % 2) == 1 {
        raw as u128 > modulus as u128 / 2
    } else {
        raw as u128 >= modulus as u128 / 2
    };

    if needs_centering {
        raw - modulus
    } else {
        raw
    }
}

/// Main entry point for configuration verification circuit.
///
/// Verifies all cryptographic parameters across four categories:
/// 1. DKG (BFV) derived values and bounds
/// 2. Threshold BFV derived values and bounds
/// 3. User data encryption bounds
/// 4. Cross-configuration consistency
///
/// This function will panic if any verification fails, preventing deployment
/// with incorrect parameters.
fn main() {
    // DKG (BFV) Verification
    verify_dkg_derived_values();
    verify_dkg_bounds();

    // Threshold (TRBFV) Verification
    verify_threshold_derived_values();
    verify_threshold_bounds();

    // user_data_encryption Verification
    verify_user_data_encryption_bounds();

    // Cross-Config Consistency
    verify_cross_config_consistency();
}

// === DKG Derived Values ===

/// Verifies DKG-specific derived values.
///
/// Checks:
/// - Q_MOD_T computation (product of CRT moduli mod t)
/// - Q_MOD_T_CENTERED (centered representation)
/// - Reed-Solomon parity matrices for Shamir sharing
fn verify_dkg_derived_values() {
    verify_dkg_q_mod_t();
    verify_dkg_q_mod_t_centered();
    verify_dkg_parity_matrix();
}

/// Verifies DKG: Q_MOD_T = (product of QIS) mod t.
fn verify_dkg_q_mod_t() {
    let t = DKG_PLAINTEXT_MODULUS;
    let m = ModU128::new(t);

    let mut product: Field = 1;
    for i in 0..DKG_L {
        product = m.mul_mod(product, DKG_QIS[i]);
    }

    assert(product == DKG_Q_MOD_T, "DKG Q_MOD_T verification failed");
}

/// Verifies DKG: Q_MOD_T_CENTERED = center(Q_MOD_T).
fn verify_dkg_q_mod_t_centered() {
    assert(
        center(DKG_Q_MOD_T, DKG_PLAINTEXT_MODULUS) == DKG_Q_MOD_T_CENTERED,
        "DKG Q_MOD_T_CENTERED verification failed",
    );
}

/// Verifies Reed-Solomon parity matrix: H * G^T = 0 (mod q_l) for each modulus.
///
/// For Shamir Secret Sharing with threshold T, shares must satisfy the parity check
/// equation H * shares^T = 0, where H is the parity check matrix. This function
/// verifies that the precomputed PARITY_MATRIX is correct by checking it against
/// the Vandermonde generator matrix G.
///
/// The generator matrix G is constructed as G[i][j] = j^i mod q_l (Vandermonde structure).
/// For valid Shamir shares, H * G^T must equal zero for all entries.
fn verify_dkg_parity_matrix() {
    // For each CRT modulus
    for l in 0..L_THRESHOLD {
        let q_l = QIS_THRESHOLD[l];
        let m = ModU128::new(q_l);

        // Build generator matrix G (Vandermonde)
        // G[i][j] = j^i mod q_l
        // G is (T+1) * (N_PARTIES+1)
        let mut g: [[Field; N_PARTIES + 1]; T + 1] = [[0; N_PARTIES + 1]; T + 1];

        for j in 0..(N_PARTIES + 1) {
            let eval_point = j as Field;
            let mut power: Field = 1;
            for i in 0..(T + 1) {
                g[i][j] = power;
                power = m.mul_mod(power, eval_point);
            }
        }

        // Verify H * G^T = 0 (mod q_l)
        // H is (N_PARTIES - T) * (N_PARTIES + 1)
        // G^T is (N_PARTIES + 1) * (T + 1)
        // Result is (N_PARTIES - T) * (T + 1)
        for row in 0..(N_PARTIES - T) {
            for col in 0..(T + 1) {
                let mut sum: Field = 0;
                for k in 0..(N_PARTIES + 1) {
                    // H[l][row][k] * G[col][k]
                    sum = m.add(sum, m.mul_mod(PARITY_MATRIX[l][row][k], g[col][k]));
                }
                assert(sum == 0, "Parity matrix verification failed: H · G^T != 0");
            }
        }
    }
}

// === DKG Bounds ===

/// Verifies all DKG share encryption bounds (used in circuits C3a/C3b).
///
/// Checks bounds for:
/// - Encryption randomness u (ternary, bound = 1)
/// - Error terms e0, e1 (bound = 20)
/// - Message bound (t - 1)
/// - Public key bounds per CRT modulus
/// - Quotient bounds r1, r2, p1, p2
/// - Scaling factors k0[i] satisfy k0[i] * t == -1 (mod q_i)
fn verify_dkg_bounds() {
    let n: u128 = DKG_N as u128;
    let t: u128 = DKG_PLAINTEXT_MODULUS as u128;
    let u_bound: u128 = SHARE_ENCRYPTION_U_BOUND as u128;
    let e0_bound: u128 = SHARE_ENCRYPTION_E0_BOUND as u128;
    let e1_bound: u128 = SHARE_ENCRYPTION_E1_BOUND as u128;

    // u_bound = 1 (ternary)
    assert(SHARE_ENCRYPTION_U_BOUND == 1, "SHARE_ENCRYPTION_U_BOUND should be 1 for ternary");

    // e0_bound = 20
    assert(SHARE_ENCRYPTION_E0_BOUND == 20, "SHARE_ENCRYPTION_E0_BOUND should be 20");

    // e1_bound = 20
    assert(SHARE_ENCRYPTION_E1_BOUND == 20, "SHARE_ENCRYPTION_E1_BOUND should be 20");

    // msg_bound = t. `range_check_standard` takes an exclusive upper bound, so the message range
    // `[0, t)` needs `t` here; `t - 1` rejected the legitimate coefficient `t - 1`.
    assert(SHARE_ENCRYPTION_MSG_BOUND as u128 == t, "SHARE_ENCRYPTION_MSG_BOUND mismatch");

    for i in 0..DKG_L {
        let qi: u128 = DKG_QIS[i] as u128;
        let qi_bound: u128 = (qi - 1) / 2;
        let k0i: u128 = SHARE_ENCRYPTION_K0IS[i] as u128;

        // pk_bounds[i] = (q_i - 1) / 2
        assert(
            SHARE_ENCRYPTION_PK_BOUNDS[i] as u128 == qi_bound,
            "SHARE_ENCRYPTION_PK_BOUNDS mismatch",
        );

        // ct1_r_bounds[i] = ((n * u_bound + 2) * qi_bound + e1_bound) / q_i
        //
        // `r` is the quotient of the mod-q reduction in `ct = pk * u + e + q * r` (mod X^N + 1).
        // Folding does not change the bound, so this is the expression the unreduced `p1` used.
        let expected_ct1_r: u128 = ((n * u_bound + 2) * qi_bound + e1_bound) / qi;
        assert(
            SHARE_ENCRYPTION_CT1_R_BOUNDS[i] as u128 == expected_ct1_r,
            "SHARE_ENCRYPTION_CT1_R_BOUNDS mismatch",
        );

        // k0is[i] verification: k0i * t = -1 mod q_i
        let m = ModU128::new(DKG_QIS[i]);
        let product = m.mul_mod(SHARE_ENCRYPTION_K0IS[i], DKG_PLAINTEXT_MODULUS);
        let neg_one = DKG_QIS[i] - 1;
        assert(product == neg_one, "SHARE_ENCRYPTION_K0IS mismatch");
        // ct0_r_bounds[i] = ((t - 1) * k0i + ((n * u + 2) * qi_bound + e0_i)) / q_i
        //
        // Same shape plus the `k0is * k1` term. `k1` lies in `[0, t - 1]`.
        let e0_bound_i: u128 = e0_bound % qi;
        let expected_ct0_r: u128 =
            ((t - 1) * k0i + ((n * u_bound + 2) * qi_bound + e0_bound_i)) / qi;
        assert(
            SHARE_ENCRYPTION_CT0_R_BOUNDS[i] as u128 == expected_ct0_r,
            "SHARE_ENCRYPTION_CT0_R_BOUNDS mismatch",
        );
    }

    verify_scaled_quotient();
}

/// `2^BITS` as a `u128`. Noir's shift operator wants both operands the same width, and this file is
/// `u128` throughout, so a comptime-unrolled product keeps the call sites readable.
fn pow2_u128<let BITS: u32>() -> u128 {
    let mut out: u128 = 1;
    for _ in 0..BITS {
        out = out * 2;
    }
    out
}

/// Re-derives C3's scaled-quotient constants from the moduli, `t` and `k0is`.
///
/// The substitution `k0 * k1 = q * (ALPHA * m - BETA * z) - SMALL_D * m + z` only holds over the
/// integers if both numerators divide `q` exactly, so these are equalities rather than bounds. A
/// generator that rounded instead of dividing would be caught here.
///
/// `BIT_Q0_DIFF` is deliberately not re-derived: it needs `gap * (msg - 1)` where `gap` is about
/// 2^79, so the product is ~2^137 and overflows the `u128` arithmetic this file uses. The
/// honest-witness completeness check covers that width instead.
fn verify_scaled_quotient() {
    if SHARE_ENCRYPTION_SCALED_QUOTIENT {
        let t: u128 = DKG_PLAINTEXT_MODULUS as u128;
        let scale: u128 = DKG_Q_MOD_T as u128;
        let delta: u128 = SHARE_ENCRYPTION_DELTA as u128;
        let k: u128 = SHARE_ENCRYPTION_SCALE_K as u128;
        let n: u128 = DKG_N as u128;
        let u_bound: u128 = SHARE_ENCRYPTION_U_BOUND as u128;
        let msg: u128 = SHARE_ENCRYPTION_MSG_BOUND as u128;

        // k must be a power of two, else SMALL_D is not small across limbs.
        assert(k != 0, "SHARE_ENCRYPTION_SCALE_K must be non-zero when available");
        assert((k & (k - 1)) == 0, "SHARE_ENCRYPTION_SCALE_K must be a power of two");

        // DELTA * t + scale == prod(q)
        let mut product: u128 = 1;
        for i in 0..DKG_L {
            product = product * (DKG_QIS[i] as u128);
        }
        assert(delta * t + scale == product, "SHARE_ENCRYPTION_DELTA mismatch");

        // T = 2^T_POW_BIT + T_GAP, with the gap inside its own width.
        let t_pow: u128 = pow2_u128::<SHARE_ENCRYPTION_T_POW_BIT>();
        assert(t_pow + (SHARE_ENCRYPTION_T_GAP as u128) == t, "SHARE_ENCRYPTION_T_GAP mismatch");
        assert(
            (SHARE_ENCRYPTION_T_GAP as u128) < pow2_u128::<SHARE_ENCRYPTION_T_GAP_BIT>(),
            "SHARE_ENCRYPTION_T_GAP_BIT too narrow",
        );

        let offset0: u128 = SHARE_ENCRYPTION_Q0_OFFSET as u128;
        let offset1: u128 = SHARE_ENCRYPTION_Q1_OFFSET as u128;
        // Both quotients share the negative excursion of the pk * u product.
        assert(offset0 == n * u_bound / 2 + 1, "SHARE_ENCRYPTION_Q0_OFFSET mismatch");
        assert(offset1 == n * u_bound / 2 + 1, "SHARE_ENCRYPTION_Q1_OFFSET mismatch");

        for i in 0..DKG_L {
            let qi: u128 = DKG_QIS[i] as u128;
            let qi_bound: u128 = (qi - 1) / 2;
            let k0: u128 = SHARE_ENCRYPTION_K0IS[i] as u128;
            let sd: u128 = SHARE_ENCRYPTION_SMALL_D[i] as u128;

            // SMALL_D = k * q - DELTA
            assert(sd == k * qi - delta, "SHARE_ENCRYPTION_SMALL_D mismatch");
            // k0 * t + 1 == BETA * q
            assert(
                k0 * t + 1 == (SHARE_ENCRYPTION_BETA[i] as u128) * qi,
                "SHARE_ENCRYPTION_BETA mismatch",
            );
            // k0 * scale + SMALL_D == ALPHA * q
            assert(
                k0 * scale + sd == (SHARE_ENCRYPTION_ALPHA[i] as u128) * qi,
                "SHARE_ENCRYPTION_ALPHA mismatch",
            );

            // The widths must bracket their bounds: wide enough to hold them, and not a bit wider.
            let bound0: u128 = (
                qi_bound
                    + n * qi_bound * u_bound
                    + (SHARE_ENCRYPTION_E0_BOUND as u128) % qi
                    + sd * (msg - 1)
                    + scale
            )
                / qi;
            let shifted0: u128 = bound0 + offset0;
            assert(
                shifted0 < pow2_u128::<SHARE_ENCRYPTION_BIT_Q0>(),
                "SHARE_ENCRYPTION_BIT_Q0 too narrow",
            );
            assert(
                // `shifted0 >= 2^(BIT-1)`, written to avoid a `BIT - 1` generic argument.
                shifted0 * 2 >= pow2_u128::<SHARE_ENCRYPTION_BIT_Q0>(),
                "SHARE_ENCRYPTION_BIT_Q0 wider than needed",
            );

            let bound1: u128 =
                (qi_bound + n * qi_bound * u_bound + (SHARE_ENCRYPTION_E1_BOUND as u128)) / qi;
            let shifted1: u128 = bound1 + offset1;
            assert(
                shifted1 < pow2_u128::<SHARE_ENCRYPTION_BIT_Q1>(),
                "SHARE_ENCRYPTION_BIT_Q1 too narrow",
            );
            assert(
                shifted1 * 2 >= pow2_u128::<SHARE_ENCRYPTION_BIT_Q1>(),
                "SHARE_ENCRYPTION_BIT_Q1 wider than needed",
            );
        }
    }
}

// === Threshold Derived Values ===

/// Verifies Threshold BFV-specific derived values.
///
/// Checks:
/// - Q_MOD_T computation
/// - Q_MOD_T_CENTERED (centered representation)
/// - Q_INVERSE_MOD_T (multiplicative inverse for decoding)
fn verify_threshold_derived_values() {
    verify_threshold_q_mod_t();
    verify_threshold_q_mod_t_centered();
    verify_threshold_q_inverse_mod_t();
}

/// Verifies Threshold: Q_MOD_T = (product of QIS) mod t.
fn verify_threshold_q_mod_t() {
    let t = THRESHOLD_PLAINTEXT_MODULUS;
    let m = ModU128::new(t);

    let mut product: Field = 1;
    for i in 0..THRESHOLD_L {
        product = m.mul_mod(product, THRESHOLD_QIS[i]);
    }

    assert(product == THRESHOLD_Q_MOD_T, "Threshold Q_MOD_T verification failed");
}

/// Verifies Threshold: Q_MOD_T_CENTERED = center(Q_MOD_T).
fn verify_threshold_q_mod_t_centered() {
    assert(
        center(THRESHOLD_Q_MOD_T, THRESHOLD_PLAINTEXT_MODULUS) == THRESHOLD_Q_MOD_T_CENTERED,
        "Threshold Q_MOD_T_CENTERED verification failed",
    );
}

/// Verifies Threshold: Q * Q_INVERSE_MOD_T == 1 (mod t).
///
/// This inverse is used in circuit C7 for final decoding:
/// message = -Q^{-1} * (t * u_global)_Q mod t
fn verify_threshold_q_inverse_mod_t() {
    let t = THRESHOLD_PLAINTEXT_MODULUS;
    let m = ModU128::new(t);

    let product = m.mul_mod(THRESHOLD_Q_MOD_T, THRESHOLD_Q_INVERSE_MOD_T);

    assert(product == 1, "Threshold Q_INVERSE_MOD_T verification failed");
}

// === Threshold Bounds ===

/// Verifies Threshold BFV bounds for key generation and decryption.
///
/// Checks:
/// - Public key generation bounds
/// - Share decryption bounds
fn verify_threshold_bounds() {
    verify_pk_generation_bounds();
    verify_share_decryption_bounds();
}

/// Verifies pk_generation bounds (Circuit C1).
///
/// Checks bounds for:
/// - Secret key sk (ternary, bound = 1)
/// - Error eek (bound = 20)
/// - Smudging noise e_sm (bound for the active statistical security parameter)
/// - Quotients r1, r2 for each CRT modulus
fn verify_pk_generation_bounds() {
    let n: u128 = THRESHOLD_N as u128;
    let eek: u128 = PK_GENERATION_EEK_BOUND as u128;

    // sk_bound = 1 (ternary)
    assert(PK_GENERATION_SK_BOUND == 1, "PK_GENERATION_SK_BOUND should be 1 for ternary");

    // eek_bound = 20
    assert(PK_GENERATION_EEK_BOUND == 20, "PK_GENERATION_EEK_BOUND should be 20");

    // r_bounds for each modulus. The identity is checked reduced modulo X^N + 1, so the
    // cyclotomic quotient's term is identically zero and there is no r2 bound left to derive.
    for i in 0..THRESHOLD_L {
        let qi: u128 = THRESHOLD_QIS[i] as u128;
        let qi_bound: u128 = (qi - 1) / 2;

        // r_bounds[i] = ((n * sk_bound + 2) * qi_bound + eek_bound) / q_i, from bounding the other
        // terms of pk0 = -(a * sk mod X^N + 1) + eek + q * r: the negacyclic product of n terms with
        // |a| <= qi_bound, the centered pk0 itself, and eek. sk_bound is 1 (asserted above), so this
        // is the same expression the unreduced r1 bound used -- the reduced quotient is no wider.
        let sk: u128 = PK_GENERATION_SK_BOUND as u128;
        let expected_r: u128 = ((n * sk + 2) * qi_bound + eek) / qi;
        assert(PK_GENERATION_R_BOUNDS[i] as u128 == expected_r, "PK_GENERATION_R_BOUNDS mismatch");
    }

    verify_e_sm_bound();
}

/// Verifies e_sm_bound (smudging noise bound).
///
/// The smudging noise bound is critical for threshold decryption security.
/// The bound is 2^(lambda + 1) * degree * B_C, where B_C includes the
/// encryption error and the threshold committee's key and public-key errors.
fn verify_e_sm_bound() {
    let n: Field = THRESHOLD_N as Field;
    let committee_n: Field = N_PARTIES as Field;
    let e_norm: Field = committee_n * 20;
    let b_e: Field = 20;
    let sk_norm: Field = committee_n;
    let num_ciphertexts: Field = N_CIPHERTEXTS as Field;

    // b_fresh = N * e_norm + b_enc + N * b_e * sk_norm
    let b_fresh = n * e_norm + PK_GENERATION_B_ENC + n * b_e * sk_norm;

    // b_c = N_CIPHERTEXTS * (b_fresh + Q_MOD_T)
    let b_c = num_ciphertexts * (b_fresh + THRESHOLD_Q_MOD_T);

    // lambda = 45 for the secure preset.
    let two_pow_lambda_plus_one: Field = 0x400000000000;
    let expected_e_sm_bound = two_pow_lambda_plus_one * n * b_c;

    assert(expected_e_sm_bound == PK_GENERATION_E_SM_BOUND, "PK_GENERATION_E_SM_BOUND mismatch");
}

/// Verifies share_decryption bounds (Circuit C6).
///
/// Checks quotient bounds r1, r2 used in the threshold decryption share equation.
fn verify_share_decryption_bounds() {
    let n: u128 = THRESHOLD_N as u128;

    for i in 0..THRESHOLD_L {
        let qi: u128 = THRESHOLD_QIS[i] as u128;
        let qi_bound: u128 = (qi - 1) / 2;

        // The identity is checked reduced modulo X^N + 1, so the cyclotomic quotient's term is
        // identically zero and there is no r2 bound left to derive.
        //
        // r_bounds[i] = (((q_i-1)/2)^2 * n + 4 * (q_i-1)/2) / q_i, from bounding the other terms of
        // d = ct0 + (ct1 * sk mod X^N + 1) + e_sm + q * r: the negacyclic product of n terms with
        // both operands centered, plus d, ct0 and e_sm. Same expression the unreduced r1 bound used,
        // so the reduced quotient is no wider.
        //
        // `qi_bound^2 * n` overflows u128 for 60-bit moduli, so the square is divided by q_i first.
        // With qi_bound^2 = a * q_i + b, the bound is n * a + (n * b + 4 * qi_bound) / q_i exactly.
        let square: u128 = qi_bound * qi_bound;
        let expected_r: u128 = n * (square / qi) + (n * (square % qi) + 4 * qi_bound) / qi;
        assert(
            THRESHOLD_SHARE_DECRYPTION_R_BOUNDS[i] as u128 == expected_r,
            "SHARE_DECRYPTION_R_BOUNDS mismatch",
        );
    }
}

// === User Data Encryption Bounds ===

/// Verifies user_data_encryption bounds.
///
/// These bounds are used in Phase 3 when users encrypt data to the aggregated
/// threshold public key. Uses Threshold BFV parameters with specific constraints
/// for the user data encryption zero-knowledge proof.
fn verify_user_data_encryption_bounds() {
    let n: u128 = THRESHOLD_N as u128;
    let t: u128 = THRESHOLD_PLAINTEXT_MODULUS as u128;
    let u_bound: u128 = USER_DATA_ENCRYPTION_U_BOUND as u128;
    let e1_bound: u128 = USER_DATA_ENCRYPTION_E1_BOUND as u128;

    // u_bound = 1 (ternary)
    assert(USER_DATA_ENCRYPTION_U_BOUND == 1, "USER_DATA_ENCRYPTION_U_BOUND should be 1");

    // e1_bound = 20 (variance * 2)
    assert(USER_DATA_ENCRYPTION_E1_BOUND == 20, "USER_DATA_ENCRYPTION_E1_BOUND should be 20");

    // e0_bound = sqrt(3 * error1_variance) = PK_GENERATION_B_ENC (same parameter set)
    assert(
        USER_DATA_ENCRYPTION_E0_BOUND == PK_GENERATION_B_ENC,
        "USER_DATA_ENCRYPTION_E0_BOUND should equal PK_GENERATION_B_ENC",
    );

    // Plaintext coefficients use non-centered values in [0, t).
    let expected_k1_up: u128 = t - 1;
    assert(
        USER_DATA_ENCRYPTION_K1_UP_BOUND as u128 == expected_k1_up,
        "USER_DATA_ENCRYPTION_K1_UP_BOUND mismatch",
    );

    let expected_k1_low: u128 = 0;
    assert(
        USER_DATA_ENCRYPTION_K1_LOW_BOUND as u128 == expected_k1_low,
        "USER_DATA_ENCRYPTION_K1_LOW_BOUND mismatch",
    );

    for i in 0..THRESHOLD_L {
        let qi: u128 = THRESHOLD_QIS[i] as u128;
        let qi_bound: u128 = (qi - 1) / 2;
        let k0i: u128 = USER_DATA_ENCRYPTION_K0IS[i] as u128;

        // pk_bounds[i] = (q_i - 1) / 2
        assert(
            USER_DATA_ENCRYPTION_PK_BOUNDS[i] as u128 == qi_bound,
            "USER_DATA_ENCRYPTION_PK_BOUNDS mismatch",
        );

        // r2_bounds[i] = (q_i - 1) / 2
        // ct1_r_bounds[i] = ((n * u_bound + 2) * qi_bound + e1_bound) / q_i
        //
        // `r` is the quotient of the mod-q reduction in `ct = pk * u + e + q * r` (mod X^N + 1).
        // Bounding `|pk * u| <= n * qi_bound`, `|ct| <= qi_bound` and `|e1| <= e1_bound`, then
        // dividing by q_i, bounds it. ct1 has no `k0is * k1` term.
        let expected_ct1_r: u128 = ((n * u_bound + 2) * qi_bound + e1_bound) / qi;
        assert(
            USER_DATA_ENCRYPTION_CT1_R_BOUNDS[i] as u128 == expected_ct1_r,
            "USER_DATA_ENCRYPTION_CT1_R_BOUNDS mismatch",
        );
        let m = ModU128::new(THRESHOLD_QIS[i]);
        let product = m.mul_mod(USER_DATA_ENCRYPTION_K0IS[i], THRESHOLD_PLAINTEXT_MODULUS);
        let neg_one = THRESHOLD_QIS[i] - 1;
        assert(product == neg_one, "USER_DATA_ENCRYPTION_K0IS mismatch");

        // ct0_r_bounds[i] = (k1_max * k0i + (n * u_bound + 2) * qi_bound + e0_bound) / q_i
        //
        // Same shape as ct1 plus the `k0is * k1` term. This takes the *lifted* `e0_bound`, not its
        // residue at q_i: the reduced identity reads the lifted `e0` directly now that the CRT split
        // and `e0is` are gone. `k1` lies in `[0, t - 1]`, so `k1_max` is `expected_k1_up`.
        let expected_ct0_r: u128 = (
            expected_k1_up * k0i
                + (n * u_bound + 2) * qi_bound
                + (USER_DATA_ENCRYPTION_E0_BOUND as u128)
        )
            / qi;
        assert(
            USER_DATA_ENCRYPTION_CT0_R_BOUNDS[i] as u128 == expected_ct0_r,
            "USER_DATA_ENCRYPTION_CT0_R_BOUNDS mismatch",
        );
    }
}

// === Cross-Config Consistency ===

/// Verifies consistency between BFV and Threshold BFV parameter sets.
fn verify_cross_config_consistency() {
    // N is consistent
    assert(DKG_N == THRESHOLD_N, "N mismatch between DKG and Threshold configs");

    // L_THRESHOLD in dkg.nr matches L in threshold.nr
    assert(L_THRESHOLD == THRESHOLD_L, "L_THRESHOLD mismatch between config files");

    // QIS_THRESHOLD in dkg.nr matches QIS in threshold.nr
    for i in 0..THRESHOLD_L {
        assert(
            QIS_THRESHOLD[i] == THRESHOLD_QIS[i],
            "QIS_THRESHOLD mismatch between dkg.nr and threshold.nr",
        );
    }
}
