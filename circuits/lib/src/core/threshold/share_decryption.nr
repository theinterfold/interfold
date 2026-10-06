// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_aggregated_shares_commitment, compute_ciphertext_commitment,
    compute_partial_decryption_c0_commitment, compute_threshold_decryption_share_commitment,
    compute_threshold_share_decryption_challenge,
};
use crate::math::modulo::U64::ModU64;
use crate::math::prf::prf_decryption_mask;
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// Parameters for threshold share decryption (C6).
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bounds for r1 polynomials (modulus switching quotients) for each CRT basis
    pub r1_bounds: [Field; L],
    /// Bounds for r2 polynomials (cyclotomic reduction quotients) for each CRT basis
    pub r2_bounds: [Field; L],
    /// Absolute bound on each fresh smudging coefficient.
    pub e_fresh_bound: Field,
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L], r1_bounds: [Field; L], r2_bounds: [Field; L]) -> Self {
        Configs { qis, r1_bounds, r2_bounds, e_fresh_bound: 0 }
    }

    pub fn with_fresh_bound(mut self, e_fresh_bound: Field) -> Self {
        self.e_fresh_bound = e_fresh_bound;
        self
    }
}

/// Threshold share decryption (C6).
///
/// **Role:** Prove one party's partial decryption share.
///
/// The share is `λ · c1 · sh + e_fresh + r`. `λ` is `L_i(0)` for this party in the
/// public decryptor set. `e_fresh` is local smudging. `r` is the PRF mask. `c0` is
/// not part of the share.
///
/// **Consumes:** `expected_sk_commitment` (C4a) and `ct_commitment`.
///
/// **Produces:** Truncated-`d` commitment for C7, and the `c0` prefix commitment C7 adds.
pub struct ShareDecryption<let N: u32, let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_D: u32, let BIT_D_NATIVE: u32, let KEY_BITS: u32, let N_PARTIES: u32, let H: u32> {
    /// Circuit parameters including bounds and cryptographic constants
    configs: Configs<L>,

    /// Expected commitment to aggregated sk shares (from C4 / protocol transcript)
    /// (public witness)
    expected_sk_commitment: Field,

    /// Expected commitment to the full ciphertext (ct0 limbs + ct1 limbs), aligned with C3 / user_data_encryption.
    ct_commitment: Field,

    /// Commitment to the low-degree native `c0` prefix. C7 adds this polynomial once.
    c0_commitment: Field,

    /// Ciphertext components (witness-only)
    /// ct0 components for each CRT basis (degree N-1 polynomials with N coefficients)
    ct0: [Polynomial<N>; L],
    /// ct1 components for each CRT basis (degree N-1 polynomials with N coefficients)
    ct1: [Polynomial<N>; L],

    /// Aggregated sum of sk shares (secret witness)
    sk: [Polynomial<N>; L],

    /// Fresh smudging noise. Not scaled by `λ` and not a DKG secret.
    e_fresh: [Polynomial<N>; L],

    /// Quotient polynomials for lifting to Z (secret witnesses)
    r1: [Polynomial<2 * N - 1>; L],
    r2: [Polynomial<N - 1>; L],

    /// Party's computed decryption share (secret witness)
    d: [Polynomial<N>; L],

    /// Low-degree tail of `d` in **native** \([0, q)\) form per coefficient (matches C7
    /// `decryption_shares` / `from_fhe` truncation). Coefficients are in the same JSON order
    /// as C7 (ascending degree within each limb). `d_commitment` hashes this, not the
    /// reversed+centered `d` prefix, so DecryptionAggregator can link C6 fold to C7.
    d_native_trunc: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],

    /// 0-based party that produces this decryption share.
    party_idx: u32,
    /// Strictly increasing 1-based decryptor ids.
    decryptors: [Field; H],
    outgoing_key_bits: [[Field; KEY_BITS]; N_PARTIES],
    incoming_key_bits: [[Field; KEY_BITS]; N_PARTIES],
    outgoing_key_commitments: [Field; N_PARTIES],
    incoming_key_commitments: [Field; N_PARTIES],
}

impl<let N: u32, let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_D: u32, let BIT_D_NATIVE: u32, let KEY_BITS: u32, let N_PARTIES: u32, let H: u32> ShareDecryption<N, MAX_MSG_NON_ZERO_COEFFS, L, BIT_CT, BIT_SK, BIT_E_SM, BIT_R1, BIT_R2, BIT_D, BIT_D_NATIVE, KEY_BITS, N_PARTIES, H> {
    pub fn new(
        configs: Configs<L>,
        expected_sk_commitment: Field,
        ct_commitment: Field,
        c0_commitment: Field,
        ct0: [Polynomial<N>; L],
        ct1: [Polynomial<N>; L],
        sk: [Polynomial<N>; L],
        e_fresh: [Polynomial<N>; L],
        r1: [Polynomial<2 * N - 1>; L],
        r2: [Polynomial<N - 1>; L],
        d: [Polynomial<N>; L],
        d_native_trunc: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
        party_idx: u32,
        decryptors: [Field; H],
        outgoing_key_bits: [[Field; KEY_BITS]; N_PARTIES],
        incoming_key_bits: [[Field; KEY_BITS]; N_PARTIES],
        outgoing_key_commitments: [Field; N_PARTIES],
        incoming_key_commitments: [Field; N_PARTIES],
    ) -> Self {
        assert(MAX_MSG_NON_ZERO_COEFFS <= N);
        ShareDecryption {
            configs,
            expected_sk_commitment,
            ct_commitment,
            c0_commitment,
            ct0,
            ct1,
            sk,
            e_fresh,
            r1,
            r2,
            d,
            d_native_trunc,
            party_idx,
            decryptors,
            outgoing_key_bits,
            incoming_key_bits,
            outgoing_key_commitments,
            incoming_key_commitments,
        }
    }

    /// `u` in \([0, q)\); `w` is the matching centered coeff from `d` (reversed+centered layout).
    /// Uses 64 bits (not `BIT_D`): `u` spans full native mod `q`, which can exceed the packing width
    /// used for centered `d` coefficients (e.g. insecure preset moduli are ~37 bits).
    fn assert_native_coeff_matches_centered_d(u: Field, w: Field, q: Field) {
        let half = (q - 1) / 2;
        u.assert_max_bit_size::<64>();
        (q - 1 - u).assert_max_bit_size::<64>();
        let centered_from_u = if (u as u128) > (half as u128) {
            u - q
        } else {
            u
        };
        assert(centered_from_u == w);
    }

    /// Bind each `d_native_trunc` coeff to the tail of `d` under `center(mod q)` / reverse layout.
    fn verify_d_native_trunc_binding(self) {
        for limb in 0..L {
            let q = self.configs.qis[limb];
            for j in 0..MAX_MSG_NON_ZERO_COEFFS {
                let w = self.d[limb].coefficients[N - 1 - j];
                // `d_native_trunc` uses the same limb coefficient order as C7 witness JSON (ascending degree).
                let u = self.d_native_trunc[limb].coefficients[j];
                Self::assert_native_coeff_matches_centered_d(u, w, q);
            }
        }
    }

    /// Verifies that aggregated secret shares hash to expected_sk_commitment
    fn verify_agg_sk_commitment(self) {
        assert(
            compute_aggregated_shares_commitment::<N, L, BIT_SK>(self.sk)
                == self.expected_sk_commitment,
            "S commitment mismatch",
        );
    }

    /// Low-degree native `c0`, ascending degree, matching the C7 witness order.
    fn ct0_low(self) -> [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L] {
        let mut limbs: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L] =
            [Polynomial::new([0; MAX_MSG_NON_ZERO_COEFFS]); L];
        for limb in 0..L {
            let mut coeffs = [0; MAX_MSG_NON_ZERO_COEFFS];
            for j in 0..MAX_MSG_NON_ZERO_COEFFS {
                coeffs[j] = self.ct0[limb].coefficients[N - 1 - j];
            }
            limbs[limb] = Polynomial::new(coeffs);
        }
        limbs
    }

    fn verify_c0_commitment(self) {
        let computed = compute_partial_decryption_c0_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
            self.ct0_low(),
        );
        assert(computed == self.c0_commitment, "c0 commitment mismatch");
    }

    fn verify_ct_commitment(self) {
        let computed = compute_ciphertext_commitment::<N, L, BIT_CT>(self.ct0, self.ct1);
        assert(computed == self.ct_commitment, "Ciphertext commitment mismatch");
    }

    /// Build the Fiat-Shamir absorb list. The challenge is squeezed from this list.
    ///
    /// The list binds `party_idx`, the decryptor ids, and every polynomial in the share
    /// equation, including `e_fresh`. `sk` enters as `expected_sk_commitment`.
    fn payload(self) -> [Field] {
        let mut inputs = [
            self.expected_sk_commitment, self.ct_commitment, self.c0_commitment,
        ]
            .as_vector();
        inputs = inputs.push_back(self.party_idx as Field);
        for i in 0..H {
            inputs = inputs.push_back(self.decryptors[i]);
        }

        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct0);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct1);
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2);
        inputs = flatten::<N, L, BIT_D>(inputs, self.d);
        inputs = flatten::<N, L, BIT_E_SM>(inputs, self.e_fresh);
        for party in 0..N_PARTIES {
            inputs = inputs.push_back(self.outgoing_key_commitments[party]);
            inputs = inputs.push_back(self.incoming_key_commitments[party]);
        }

        inputs
    }

    /// Returns the C7-facing commitment to the first `MAX_MSG_NON_ZERO_COEFFS` coeffs of `d` per limb.
    pub fn execute(self) -> Field {
        // Step 1: Verify sk commitment matches expected
        self.verify_agg_sk_commitment();

        self.verify_ct_commitment();
        self.verify_c0_commitment();
        self.check_range_bounds();

        self.verify_d_native_trunc_binding();
        let d_commitment = compute_threshold_decryption_share_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
            self.d_native_trunc,
        );

        // Step 5: Generate Fiat-Shamir challenge from the transcript
        let mask = prf_decryption_mask(
            self.party_idx,
            self.decryptors,
            self.outgoing_key_bits,
            self.incoming_key_bits,
            self.outgoing_key_commitments,
            self.incoming_key_commitments,
            self.ct0,
            self.ct1,
            self.configs.qis,
        );

        let gamma = self.generate_challenge();

        // Step 6: Verify decryption share computation for each CRT basis.
        // cyclo_at_gamma is identical across all bases (same gamma, same N); compute once.
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let lambdas = lagrange_coeffs_for_set::<H, L>(self.configs.qis, self.decryptors);
        let self_id = (self.party_idx + 1) as Field;
        let mut slot = 0;
        let mut found = false;
        for i in 0..H {
            if self.decryptors[i] == self_id {
                slot = i;
                found = true;
            }
        }
        assert(found, "Party is outside the decryptor set");
        let mut lambda_by_limb = [0; L];
        for basis_idx in 0..L {
            lambda_by_limb[basis_idx] = lambdas[basis_idx][slot];
        }
        for i in 0..L {
            self.verify_decryption_share_computation(i, gamma, cyclo_at_gamma, mask, lambda_by_limb);
        }

        d_commitment
    }

    /// Performs range checks on quotient polynomial witnesses.
    ///
    /// This function constrains quotient polynomials to be within their expected bounds
    /// as specified in the `configs`. This is critical for security because it prevents
    /// attacks where malicious provers provide out-of-range values that could break the
    /// security properties of the Threshold scheme.
    ///
    /// Note: `sk` / `e_sm` coefficients are not range-checked again here:
    /// - `verify_agg_sk_commitment` / `verify_agg_e_sm_commitment` bind to the C4 aggregate commitments.
    /// - C4 formed those aggregates from per-party shares verified against C2 in `dkg/share_decryption`.
    /// - This step only range-checks fresh quotient witnesses `r1`, `r2`.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any quotient coefficient is
    /// outside its expected bounds.
    fn check_range_bounds(self) {
        for basis_idx in 0..L {
            self.e_fresh[basis_idx].range_check_2bounds::<BIT_E_SM>(
                self.configs.e_fresh_bound,
                self.configs.e_fresh_bound,
            );
            // r_1 quotients can be negative (modulus quotients)
            self.r1[basis_idx].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[basis_idx],
                self.configs.r1_bounds[basis_idx],
            );
            // r_2 quotients (cyclotomic quotients)
            self.r2[basis_idx].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[basis_idx],
                self.configs.r2_bounds[basis_idx],
            );
        }
    }

    /// Generates Fiat-Shamir challenge value using the SAFE cryptographic sponge.
    ///
    /// This function implements the Fiat-Shamir transform for the decryption share circuit:
    /// 1. Flattens the transcript (`sk` commitment, ciphertext, quotients, `d`, `e_fresh`, party index, decryptor ids, and key commitments) into one array
    /// 2. Absorbs the flattened data into the SAFE sponge
    /// 3. Squeezes a single challenge value
    ///
    /// The challenge is used to evaluate polynomials for the Schwartz-Zippel lemma,
    /// which allows verification of polynomial equations by checking them at a random
    /// point rather than checking all coefficients.
    ///
    /// # Returns
    /// A single challenge value `gamma` used as the evaluation point for verifying
    /// the decryption share computation formula for all CRT bases.
    fn generate_challenge(self) -> Field {
        let inputs = self.payload();

        compute_threshold_share_decryption_challenge::<L>(inputs)
    }

    /// Verifies the lifted decryption share computation formula for a specific CRT basis using the Schwartz-Zippel lemma.
    ///
    /// This function verifies that the decryption share for basis `i` satisfies:
    /// `d_i(gamma) = c_0i(gamma) + c_1i(gamma) * s_i(gamma) + e_i(gamma) + r_2i(gamma) * cyclo(gamma) + r_1i(gamma) * q_i`
    ///
    /// Where:
    /// - `c_0i`, `c_1i` are ciphertext components for basis i
    /// - `s_i` is the aggregated secret key shares for basis i
    /// - `e_i` is the aggregated noise shares for basis i
    /// - `r_1i`, `r_2i` are quotient witnesses for basis i
    /// - `cyclo(gamma) = gamma^N + 1` is the cyclotomic polynomial evaluated at gamma
    /// - `q_i` is the CRT modulus for basis i
    ///
    /// The Schwartz-Zippel lemma ensures that if this equation holds at a random point
    /// `gamma`, then the polynomials are identical with high probability.
    ///
    /// # Arguments
    /// * `basis_idx` - The index of the CRT basis to verify (0 <= basis_idx < L)
    /// * `gamma` - The Fiat-Shamir challenge value used as the evaluation point
    ///
    /// # Panics
    /// The circuit will fail if the decryption share computation formula doesn't hold for the specified basis.
    fn verify_decryption_share_computation(
        self,
        basis_idx: u32,
        gamma: Field,
        cyclo_at_gamma: Field,
        mask: [Polynomial<N>; L],
        lambda_by_limb: [Field; L],
    ) {
        let c_1_at_gamma = self.ct1[basis_idx].eval(gamma);

        let sk_at_gamma = self.sk[basis_idx].eval(gamma);
        let e_fresh_at_gamma = self.e_fresh[basis_idx].eval(gamma);
        let r_1_at_gamma = self.r1[basis_idx].eval(gamma);
        let r_2_at_gamma = self.r2[basis_idx].eval(gamma);
        let lambda = lambda_by_limb[basis_idx];

        // p = λ·c1·sh + e_fresh + mask + r2·(X^N+1) + r1·q
        let expected_decryption_share = lambda * c_1_at_gamma * sk_at_gamma
            + e_fresh_at_gamma
            + mask[basis_idx].eval(gamma)
            + r_2_at_gamma * cyclo_at_gamma
            + r_1_at_gamma * self.configs.qis[basis_idx];

        // Evaluate the party's claimed decryption share at gamma
        let computed_decryption_share = self.d[basis_idx].eval(gamma);

        // Enforce equality: computed decryption share must match expected value
        assert(
            computed_decryption_share == expected_decryption_share,
            "Decryption share computation failed",
        );
    }
}

/// Lagrange coefficients `L_i(0)` for a designated decryptor set.
///
/// `party_ids` are 1-based Shamir points. The result is one coefficient per
/// party, reduced modulo each CRT prime. C6 multiplies only `c1 * sh` by `L_i(0)`.
pub fn lagrange_coeffs_for_set<let SET: u32, let L: u32>(
    qis: [Field; L],
    party_ids: [Field; SET],
) -> [[Field; SET]; L] {
    let mut lagrange_coeffs = [[0 as Field; SET]; L];
    let mut diffs = [[0 as Field; SET]; SET];
    for i in 0..SET {
        for j in (i + 1)..SET {
            let diff = party_ids[j] - party_ids[i];
            diffs[i][j] = diff;
            diffs[j][i] = diff;
        }
    }

    let threshold = SET - 1;
    let numerator_sign_negative = (threshold % 2) == 1;

    for basis_idx in 0..L {
        let q_l = qis[basis_idx];
        let m = ModU64::new(q_l as u64);
        let mut product_x = 1 as Field;
        for j in 0..SET {
            product_x = m.mul_mod(product_x, party_ids[j]);
        }
        for party_idx in 0..SET {
            let numerator_abs = m.div_mod(product_x, party_ids[party_idx]);
            let mut denominator_abs = 1 as Field;
            for j in 0..SET {
                if j != party_idx {
                    denominator_abs = m.mul_mod(denominator_abs, diffs[party_idx][j]);
                }
            }
            let num_greater = threshold - party_idx;
            let denom_sign_negative = (num_greater % 2) == 1;
            let result_abs = m.div_mod(numerator_abs, denominator_abs);
            let should_negate = numerator_sign_negative != denom_sign_negative;
            let result = if should_negate { m.reduce_mod(q_l - result_abs) } else { result_abs };
            lagrange_coeffs[basis_idx][party_idx] = result;
        }
    }

    lagrange_coeffs
}
