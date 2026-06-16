// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_aggregated_shares_commitment, compute_ciphertext_commitment,
    compute_threshold_decryption_share_commitment, compute_threshold_share_decryption_challenge,
};
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
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L], r1_bounds: [Field; L], r2_bounds: [Field; L]) -> Self {
        Configs { qis, r1_bounds, r2_bounds }
    }
}

/// Threshold share decryption (C6).
///
/// **Role:** Prove one party's partial decryption share `d` is consistent with the ciphertext and
/// with aggregate `sk` / `e_sm` commitments from C4.
///
/// **Consumes:** `expected_sk_commitment`, `expected_e_sm_commitment` (C4), `ct_commitment` (cross-phase /
/// user data encryption); ciphertext limbs `ct0`, `ct1` as witness.
///
/// **Produces:** Truncated-`d` commitment for C7 (`decrypted_shares_aggregation`).
pub struct ShareDecryption<let N: u32, let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_D: u32, let BIT_D_NATIVE: u32> {
    /// Circuit parameters including bounds and cryptographic constants
    configs: Configs<L>,

    /// Expected commitment to aggregated sk shares (from C4 / protocol transcript)
    /// (public witness)
    expected_sk_commitment: Field,

    /// Expected commitment to aggregated e_sm shares (from C4 / protocol transcript)
    /// (public witness)
    expected_e_sm_commitment: Field,

    /// Expected commitment to the full ciphertext (ct0 limbs + ct1 limbs), aligned with C3 / user_data_encryption.
    ct_commitment: Field,

    /// Ciphertext components (witness-only)
    /// ct0 components for each CRT basis (degree N-1 polynomials with N coefficients)
    ct0: [Polynomial<N>; L],
    /// ct1 components for each CRT basis (degree N-1 polynomials with N coefficients)
    ct1: [Polynomial<N>; L],

    /// Aggregated sum of sk shares (secret witness)
    sk: [Polynomial<N>; L],

    /// Aggregated sum of e_sm shares (secret witness, direct input)
    /// e_sm[basis] - sum of e_sm shares for each CRT basis (degree N-1 with N coefficients)
    e_sm: [Polynomial<N>; L],

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
}

impl<let N: u32, let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_D: u32, let BIT_D_NATIVE: u32> ShareDecryption<N, MAX_MSG_NON_ZERO_COEFFS, L, BIT_CT, BIT_SK, BIT_E_SM, BIT_R1, BIT_R2, BIT_D, BIT_D_NATIVE> {
    pub fn new(
        configs: Configs<L>,
        expected_sk_commitment: Field,
        expected_e_sm_commitment: Field,
        ct_commitment: Field,
        ct0: [Polynomial<N>; L],
        ct1: [Polynomial<N>; L],
        sk: [Polynomial<N>; L],
        e_sm: [Polynomial<N>; L],
        r1: [Polynomial<2 * N - 1>; L],
        r2: [Polynomial<N - 1>; L],
        d: [Polynomial<N>; L],
        d_native_trunc: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
    ) -> Self {
        assert(MAX_MSG_NON_ZERO_COEFFS <= N);
        ShareDecryption {
            configs,
            expected_sk_commitment,
            expected_e_sm_commitment,
            ct_commitment,
            ct0,
            ct1,
            sk,
            e_sm,
            r1,
            r2,
            d,
            d_native_trunc,
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

    /// Verifies that aggregated noise shares hash to expected_e_sm_commitment
    fn verify_agg_e_sm_commitment(self) {
        assert(
            compute_aggregated_shares_commitment::<N, L, BIT_E_SM>(self.e_sm)
                == self.expected_e_sm_commitment,
            "E commitment mismatch",
        );
    }

    fn verify_ct_commitment(self) {
        let computed = compute_ciphertext_commitment::<N, L, BIT_CT>(self.ct0, self.ct1);
        assert(computed == self.ct_commitment, "Ciphertext commitment mismatch");
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation.
    ///
    /// This function serializes all polynomial coefficients (both public inputs and
    /// secret witnesses) into a 1D array in a deterministic order. The flattened data
    /// is used to generate the Fiat-Shamir challenge via the SAFE sponge API.
    ///
    /// The order of serialization is:
    /// 1. Commitment to aggregated secret shares `sk` (expected_sk_commitment)
    /// 2. Commitment to aggregated noise shares `e_sm` (expected_e_sm_commitment)
    /// 3. Ciphertext components `c_0` for each CRT basis (serialized coefficients)
    /// 4. Ciphertext components `c_1` for each CRT basis (serialized coefficients)
    /// 5. Quotient polynomials `r_1` for each CRT basis (serialized coefficients)
    /// 6. Quotient polynomials `r_2` for each CRT basis (serialized coefficients)
    /// 7. Full decryption share polynomials `d` for each CRT basis (all N coefficients per limb)
    ///
    /// Note: Aggregated secret shares `sk` and noise shares `e_sm` are represented by their
    /// commitments rather than serialized coefficients. This saves constraints while
    /// still binding them to the transcript.
    ///
    /// # Returns
    /// A vector containing commitments and polynomial coefficients in flattened form,
    /// ready for hashing to generate the Fiat-Shamir challenge.
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Use commitments instead of full polynomials (saves constraints)
        inputs.push(self.expected_sk_commitment);
        inputs.push(self.expected_e_sm_commitment);

        // Flatten ciphertext components (witness)
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct0);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct1);

        // Flatten quotient polynomials (secret witnesses)
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2);

        // Full `d` fixes the C7 prefix commitment (computed separately as the public output)
        inputs = flatten::<N, L, BIT_D>(inputs, self.d);

        inputs
    }

    /// Returns the C7-facing commitment to the first `MAX_MSG_NON_ZERO_COEFFS` coeffs of `d` per limb.
    pub fn execute(self) -> Field {
        // Step 1: Verify sk commitment matches expected
        self.verify_agg_sk_commitment();

        // Step 2: Verify e_sm commitment matches expected
        self.verify_agg_e_sm_commitment();

        // Step 3: Bind witness ciphertext to the public ct_commitment
        self.verify_ct_commitment();

        // Step 4: Range-check quotient polynomials (r1, r2).
        // sk and e_sm are enforced only via `verify_agg_*_commitment` against C4 outputs; C4
        // aggregated per-party shares that passed verification against C2 (see `dkg/share_decryption`).
        self.check_range_bounds();

        self.verify_d_native_trunc_binding();
        let d_commitment = compute_threshold_decryption_share_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
            self.d_native_trunc,
        );

        // Step 5: Generate Fiat-Shamir challenge from the transcript
        let gamma = self.generate_challenge();

        // Step 6: Verify decryption share computation for each CRT basis.
        // cyclo_at_gamma is identical across all bases (same gamma, same N); compute once.
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        for i in 0..L {
            self.verify_decryption_share_computation(i, gamma, cyclo_at_gamma);
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
        // Check quotient polynomials are within bounds
        for basis_idx in 0..L {
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
    /// 1. Flattens all witness data (commitments for sk/e_sm, ciphertexts c_0/c_1, quotients r_1/r_2, full d) into a single array
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
    ) {
        // Evaluate ciphertext components at gamma
        let c_0_at_gamma = self.ct0[basis_idx].eval(gamma);
        let c_1_at_gamma = self.ct1[basis_idx].eval(gamma);

        // Evaluate aggregated sums at gamma
        let sk_at_gamma = self.sk[basis_idx].eval(gamma);
        let e_sm_at_gamma = self.e_sm[basis_idx].eval(gamma);

        // Evaluate quotient polynomials at gamma
        let r_1_at_gamma = self.r1[basis_idx].eval(gamma);
        let r_2_at_gamma = self.r2[basis_idx].eval(gamma);

        // Compute expected decryption share using the lifted formula:
        // d_i = c_0i + c_1i * sk_i + e_sm_i + r_2i * (X^N + 1) + r_1i * q_i
        let expected_decryption_share = c_0_at_gamma
            + c_1_at_gamma * sk_at_gamma
            + e_sm_at_gamma
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
