// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_aggregated_shares_commitment_checked, compute_ciphertext_commitment_checked,
    compute_threshold_decryption_share_commitment, compute_threshold_share_decryption_challenge,
};
use crate::math::helpers::{flatten, flatten_checked};
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Parameters for threshold share decryption (C6).
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bounds for the `r` polynomials: the mod-q quotients of the identity reduced modulo
    /// `X^N + 1`. Reducing the identity makes the cyclotomic quotient's term identically zero, so
    /// the separate `r2` bound is gone and this one covers what `r1` and `r2` carried between them.
    pub r_bounds: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L], r_bounds: [Field; L]) -> Self {
        Configs { qis, r_bounds }
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
pub struct ShareDecryption<let N: u32, let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R: u32, let BIT_D: u32, let BIT_D_NATIVE: u32> {
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

    /// Mod-q quotients of the identity reduced modulo `X^N + 1` (secret witnesses).
    ///
    /// The unreduced identity needed two: `r1` of degree `2N-1` for the modulus switch and `r2` of
    /// degree `N-1` for the cyclotomic reduction. Checking the identity in the reduced ring makes
    /// the `r2` term identically zero and shortens `r1` to `N` coefficients, so one witness of
    /// degree `N-1` replaces both. `r[l]` is `r1[l] mod X^N + 1`.
    r: [Polynomial<N>; L],

    /// Party's computed decryption share (secret witness)
    d: [Polynomial<N>; L],

    /// Low-degree tail of `d` in **native** \([0, q)\) form per coefficient (matches C7
    /// `decryption_shares` / `from_fhe` truncation). Coefficients are in the same JSON order
    /// as C7 (ascending degree within each limb). `d_commitment` hashes this, not the
    /// reversed+centered `d` prefix, so DecryptionAggregator can link C6 fold to C7.
    d_native_trunc: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
}

impl<let N: u32, let MAX_MSG_NON_ZERO_COEFFS: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R: u32, let BIT_D: u32, let BIT_D_NATIVE: u32> ShareDecryption<N, MAX_MSG_NON_ZERO_COEFFS, L, BIT_CT, BIT_SK, BIT_E_SM, BIT_R, BIT_D, BIT_D_NATIVE> {
    pub fn new(
        configs: Configs<L>,
        expected_sk_commitment: Field,
        expected_e_sm_commitment: Field,
        ct_commitment: Field,
        ct0: [Polynomial<N>; L],
        ct1: [Polynomial<N>; L],
        sk: [Polynomial<N>; L],
        e_sm: [Polynomial<N>; L],
        r: [Polynomial<N>; L],
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
            r,
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
            compute_aggregated_shares_commitment_checked::<N, L, BIT_SK>(self.sk)
                == self.expected_sk_commitment,
            "S commitment mismatch",
        );
    }

    /// Verifies that aggregated noise shares hash to expected_e_sm_commitment
    fn verify_agg_e_sm_commitment(self) {
        assert(
            compute_aggregated_shares_commitment_checked::<N, L, BIT_E_SM>(self.e_sm)
                == self.expected_e_sm_commitment,
            "E commitment mismatch",
        );
    }

    fn verify_ct_commitment(self) {
        let computed = compute_ciphertext_commitment_checked::<N, L, BIT_CT>(self.ct0, self.ct1);
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
    fn payload(self) -> [Field] {
        // Use commitments instead of full polynomials (saves constraints)
        let mut inputs = [self.expected_sk_commitment, self.expected_e_sm_commitment].as_vector();

        // Flatten ciphertext components (witness)
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct0);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct1);

        // Flatten the reduced quotient polynomials. The unreduced form absorbed `r1` at degree
        // 2N-1 and `r2` on top of it; the reduced one absorbs neither.
        inputs = flatten::<_, _, BIT_R>(inputs, self.r);

        // `d` carries no range bound of its own, so absorb it through the checked packing: the
        // digit asserts make the transcript injective, which is what lets Schwartz-Zippel pin
        // `d` to the evaluated identity. `ct0`/`ct1` are bounded by `verify_ct_commitment` and
        // `r` by `check_range_bounds`, so plain `flatten` is already injective for them.
        // Full `d` fixes the C7 prefix commitment (computed separately as the public output)
        inputs = flatten_checked::<N, L, BIT_D>(inputs, self.d);

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

        // Step 4: Range-check the reduced quotient polynomial `r`.
        // sk and e_sm are enforced only via `verify_agg_*_commitment` against C4 outputs; C4
        // aggregated per-party shares that passed verification against C2 (see `dkg/share_decryption`).
        self.check_range_bounds();

        self.verify_d_native_trunc_binding();
        let d_commitment = compute_threshold_decryption_share_commitment::<MAX_MSG_NON_ZERO_COEFFS, L, BIT_D_NATIVE>(
            self.d_native_trunc,
        );

        // Step 5: Generate Fiat-Shamir challenge from the transcript
        let gamma = self.generate_challenge();

        // Step 6: Verify the reduced decryption-share identity for each CRT basis.
        for i in 0..L {
            self.verify_decryption_share_computation(i, gamma);
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
    /// Note: `sk` / `e_sm` coefficients carry no bound of their own here, and do not need one:
    /// - `verify_agg_sk_commitment` / `verify_agg_e_sm_commitment` open the C4 aggregate commitments
    ///   with the checked packing helper, which makes the opening unique and so forces the witness to
    ///   equal the value C4 committed after `normalize_aggregated` reduced and centered it.
    /// - Binding to the commitment alone was not enough: without the digit assert the same
    ///   commitment opened to other coefficient vectors, so a prover could decrypt under a key share
    ///   C4 never anchored.
    /// - This step only range-checks the fresh quotient witness `r`.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any quotient coefficient is
    /// outside its expected bounds.
    fn check_range_bounds(self) {
        for basis_idx in 0..L {
            // `r` is the only fresh quotient the reduced identity leaves to bound. It can be
            // negative, so the check is two-sided.
            self.r[basis_idx].range_check_2bounds::<BIT_R>(
                self.configs.r_bounds[basis_idx],
                self.configs.r_bounds[basis_idx],
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
    fn verify_decryption_share_computation(self, basis_idx: u32, gamma: Field) {
        // `negacyclic_kernel(sk, gamma)[j]` is `(X^(N-1-j) * sk mod X^N + 1)(gamma)`, so
        // `ct1.dot(kernel)` evaluates `ct1 * sk mod X^N + 1` at gamma without the product entering
        // the witness. `sk` differs per limb here, so each limb needs its own kernel -- unlike C1,
        // where one kernel served every modulus because `sk` was shared.
        let kernel = negacyclic_kernel(self.sk[basis_idx], gamma);

        // Every term except the product moves to one side:
        //   d - ct0 - e_sm - q * r  ==  ct1 * sk   (mod X^N + 1)
        // The unreduced form carried an extra `r2 * (gamma^N + 1)`; reducing makes that term
        // identically zero, so the witness and its range check disappear rather than being checked.
        let mut residual: [Field; N] = [0; N];
        for j in 0..N {
            residual[j] = self.d[basis_idx].coefficients[j]
                - self.ct0[basis_idx].coefficients[j]
                - self.e_sm[basis_idx].coefficients[j]
                - self.configs.qis[basis_idx] * self.r[basis_idx].coefficients[j];
        }

        assert(
            Polynomial::new(residual).eval(gamma) == self.ct1[basis_idx].dot(kernel),
            "Decryption share computation failed",
        );
    }
}

/// IF-013: before `payload` absorbed `d` through the checked packing, a prover could swap `d`
/// *after* the challenge was fixed.
///
/// `pack` lays `group` coefficients into one field element as base-`radix` digits, so adding `delta`
/// to one coefficient and `-radix * delta` to the next leaves the carrier unchanged. With `d`
/// carrying no range bound, both digits stayed satisfiable and `gamma` did not move. The shift below
/// is solved so `d(gamma)` is preserved too, so the evaluation check also still passed — the circuit
/// accepted a decryption share the committed `sk` / `e_sm` / `ct` never produced.
///
/// `flatten_checked` asserts each digit fits its slot, so the second challenge computation now
/// fails and the swap is unreachable.
#[test(should_fail)]
fn forged_d_with_same_transcript_is_rejected() {
    let z = Polynomial::new([0; 8]);
    let anchor = compute_aggregated_shares_commitment_checked::<8, 1, 35>([z]);
    let ct = compute_ciphertext_commitment_checked::<8, 1, 35>([z], [z]);
    let mut d = z;
    d.coefficients[7] = 1;
    let mut c: ShareDecryption<8, 1, 1, 35, 35, 35, 43, 35, 36> = ShareDecryption::new(
        Configs::new([68719403009], [1]),
        anchor,
        anchor,
        ct,
        [z],
        [z],
        [z],
        [z],
        [z],
        [d],
        [Polynomial::new([1])],
    );
    let gamma = c.generate_challenge();

    // Carry `shift` from slot 0 into slot 1: the packed carrier, and so `gamma`, is unchanged.
    let radix: Field = 1099511627776;
    let shift = -1 / (gamma.pow_32(6) * (gamma - radix));
    c.d[0].coefficients[0] += shift;
    c.d[0].coefficients[1] -= radix * shift;

    // Rejected here: the shifted coefficients no longer fit their digit slots.
    assert(c.generate_challenge() == gamma);
    let _ = c.execute();
}

/// The reduced identity accepts an honest witness.
///
/// Worked at `N = 4`, `L = 1`, `q = 97`, so the negacyclic product is checkable by hand:
/// `ct1 * sk mod X^4 + 1` is `[57, -26, -1, 38]`, and `ct0 + that + e_sm` is `[100, -67, 41, 89]`,
/// which `r = [-1, 1, 0, -1]` brings into the centered window as `d = [3, 30, 41, -8]`.
///
/// This pins the coefficient-order convention. `eval` is Horner from index 0, so `Polynomial::new`
/// takes coefficients **highest degree first**, and `negacyclic_kernel` is built to match; reverse
/// either and the identity silently stops holding. `r` is deliberately nonzero in three positions,
/// so a fold that dropped the quotient term would fail rather than pass by coincidence.
#[test]
fn honest_reduced_identity_holds() {
    let ct0 = Polynomial::new([40, -45, 44, 46]);
    let ct1 = Polynomial::new([30, 11, -20, 7]);
    let sk = Polynomial::new([1, -1, 0, 1]);
    let e_sm = Polynomial::new([3, 4, -2, 5]);
    let r = Polynomial::new([-1, 1, 0, -1]);
    let d = Polynomial::new([3, 30, 41, -8]);

    let sk_anchor = compute_aggregated_shares_commitment_checked::<4, 1, 7>([sk]);
    let e_sm_anchor = compute_aggregated_shares_commitment_checked::<4, 1, 7>([e_sm]);
    let ct_anchor = compute_ciphertext_commitment_checked::<4, 1, 7>([ct0], [ct1]);

    // qis, r_bounds. The generated bound at this modulus would be 96; 1 is the tight honest value.
    let c: ShareDecryption<4, 1, 1, 7, 7, 7, 7, 7, 7> = ShareDecryption::new(
        Configs::new([97], [1]),
        sk_anchor,
        e_sm_anchor,
        ct_anchor,
        [ct0],
        [ct1],
        [sk],
        [e_sm],
        [r],
        [d],
        // d's tail coefficient is d[N-1] = -8; its native form mod 97 is 89.
        [Polynomial::new([89])],
    );
    let _ = c.execute();
}

/// A tampered quotient must break the evaluation check.
///
/// `r` is the only witness the reduction left to carry the mod-q slack, so this is what stops a
/// prover choosing `d` freely: shifting one coefficient of `r` moves `d` off the identity by a
/// multiple of `q`, and Schwartz-Zippel rejects it.
#[test(should_fail)]
fn tampered_quotient_is_rejected() {
    let ct0 = Polynomial::new([40, -45, 44, 46]);
    let ct1 = Polynomial::new([30, 11, -20, 7]);
    let sk = Polynomial::new([1, -1, 0, 1]);
    let e_sm = Polynomial::new([3, 4, -2, 5]);
    // Honest r is [-1, 1, 0, -1]; flip the sign of the last coefficient.
    let r = Polynomial::new([-1, 1, 0, 1]);
    let d = Polynomial::new([3, 30, 41, -8]);

    let sk_anchor = compute_aggregated_shares_commitment_checked::<4, 1, 7>([sk]);
    let e_sm_anchor = compute_aggregated_shares_commitment_checked::<4, 1, 7>([e_sm]);
    let ct_anchor = compute_ciphertext_commitment_checked::<4, 1, 7>([ct0], [ct1]);

    let c: ShareDecryption<4, 1, 1, 7, 7, 7, 7, 7, 7> = ShareDecryption::new(
        Configs::new([97], [1]),
        sk_anchor,
        e_sm_anchor,
        ct_anchor,
        [ct0],
        [ct1],
        [sk],
        [e_sm],
        [r],
        [d],
        // d's tail coefficient is d[N-1] = -8; its native form mod 97 is 89.
        [Polynomial::new([89])],
    );
    let _ = c.execute();
}
