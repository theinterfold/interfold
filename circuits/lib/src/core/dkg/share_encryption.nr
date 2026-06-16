// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_ciphertext_commitment, compute_share_encryption_challenge,
    compute_share_encryption_commitment_from_message,
};
use crate::math::commitments::compute_dkg_pk_commitment;
use crate::math::helpers::flatten;
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::Polynomial;

/// Parameters for DKG share encryption (C3).
pub struct Configs<let L: u32> {
    /// Plaintext modulus t
    pub t: Field,
    /// Q mod t: product of all CRT moduli modulo the plaintext modulus, used for message scaling
    pub q_mod_t: Field,
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Scaling factors k0[i] satisfying `k0[i] * t == -1 (mod q_i)` for each CRT modulus
    pub k0is: [Field; L],
    /// Coefficient bounds for public key polynomials per CRT modulus: (q_i - 1) / 2
    pub pk_bounds: [Field; L],
    /// Coefficient bound for the global error polynomial e0
    pub e0_bound: Field,
    /// Coefficient bound for the error polynomial e1
    pub e1_bound: Field,
    /// Coefficient bound for the ternary randomness polynomial u (= 1)
    pub u_bound: Field,
    /// Lower bounds for r1 modulus switching quotient coefficients per CRT modulus
    pub r1_low_bounds: [Field; L],
    /// Upper bounds for r1 modulus switching quotient coefficients per CRT modulus
    pub r1_up_bounds: [Field; L],
    /// Coefficient bounds for r2 cyclotomic reduction quotients per CRT modulus
    pub r2_bounds: [Field; L],
    /// Coefficient bounds for p1 modulus switching quotients per CRT modulus
    pub p1_bounds: [Field; L],
    /// Coefficient bounds for p2 cyclotomic reduction quotients per CRT modulus
    pub p2_bounds: [Field; L],
    /// Bound for the raw message (share) polynomial coefficients: t - 1
    pub msg_bound: Field,
}

impl<let L: u32> Configs<L> {
    pub fn new(
        t: Field,
        q_mod_t: Field,
        qis: [Field; L],
        k0is: [Field; L],
        pk_bounds: [Field; L],
        e0_bound: Field,
        e1_bound: Field,
        u_bound: Field,
        r1_low_bounds: [Field; L],
        r1_up_bounds: [Field; L],
        r2_bounds: [Field; L],
        p1_bounds: [Field; L],
        p2_bounds: [Field; L],
        msg_bound: Field,
    ) -> Self {
        Configs {
            t,
            q_mod_t,
            qis,
            k0is,
            pk_bounds,
            e0_bound,
            e1_bound,
            u_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            p1_bounds,
            p2_bounds,
            msg_bound,
        }
    }
}

/// DKG share encryption (C3a / C3b).
///
/// **Role:** Prove BFV encryption of a share under the recipient DKG public key. Run twice per
/// recipient (sk share and e_sm share).
///
/// **Consumes:** `expected_pk_commitment` (C0); `expected_message_commitment` (C2 sk or C2 e_sm).
///
/// **Produces:** Public `ct_commitment` (hash of ct0/ct1 limbs) for cross-phase binding; witness ct0/ct1 feed C4 off-transcript.
pub struct ShareEncryption<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_MSG: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_P1: u32, let BIT_P2: u32> {
    /// Circuit parameters
    configs: Configs<L>,
    /// Expected commitment to the DKG public key (from C0: pk).
    /// (public witness)
    expected_pk_commitment: Field,
    /// Expected commitment to the share (message) being encrypted.
    /// - C3a: commit(sk_share[party_idx][mod_idx]) produced by C2a
    /// - C3b: commit(e_sm_share[party_idx][mod_idx]) produced by C2b
    /// (public witness)
    expected_message_commitment: Field,
    /// Public key component 0 for each CRT basis (committed witnesses)
    pk0is: [Polynomial<N>; L],
    /// Public key component 1 for each CRT basis (committed witnesses)
    pk1is: [Polynomial<N>; L],
    /// Ciphertext component 0 for each CRT basis (public witnesses)
    ct0is: [Polynomial<N>; L],
    /// Ciphertext component 1 for each CRT basis (public witnesses)
    ct1is: [Polynomial<N>; L],
    /// Random ternary polynomial u (secret witness)
    u: Polynomial<N>,
    /// Error polynomial e0 (secret witness)
    e0: Polynomial<N>,
    /// Per-basis error polynomials e0[l] (secret witnesses)
    e0is: [Polynomial<N>; L],
    /// CRT quotients for e0 (secret witnesses)
    e0_quotients: [Polynomial<N>; L],
    /// Error polynomial e1 (secret witness)
    e1: Polynomial<N>,
    /// Raw message polynomial (secret witness)
    message: Polynomial<N>,
    /// Modulus switching quotient polynomials r1 (secret witnesses, degree 2N-1)
    r1is: [Polynomial<(2 * N) - 1>; L],
    /// Cyclotomic reduction quotient polynomials r2 (secret witnesses, degree N-1)
    r2is: [Polynomial<N - 1>; L],
    /// Modulus switching quotient polynomials p1 (secret witnesses, degree 2N-1)
    p1is: [Polynomial<(2 * N) - 1>; L],
    /// Cyclotomic reduction quotient polynomials p2 (secret witnesses, degree N-1)
    p2is: [Polynomial<N - 1>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_MSG: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_P1: u32, let BIT_P2: u32> ShareEncryption<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_MSG, BIT_R1, BIT_R2, BIT_P1, BIT_P2> {
    pub fn new(
        configs: Configs<L>,
        expected_pk_commitment: Field,
        expected_message_commitment: Field,
        pk0is: [Polynomial<N>; L],
        pk1is: [Polynomial<N>; L],
        ct0is: [Polynomial<N>; L],
        ct1is: [Polynomial<N>; L],
        u: Polynomial<N>,
        e0: Polynomial<N>,
        e0is: [Polynomial<N>; L],
        e0_quotients: [Polynomial<N>; L],
        e1: Polynomial<N>,
        message: Polynomial<N>,
        r1is: [Polynomial<2 * N - 1>; L],
        r2is: [Polynomial<N - 1>; L],
        p1is: [Polynomial<2 * N - 1>; L],
        p2is: [Polynomial<N - 1>; L],
    ) -> Self {
        ShareEncryption {
            configs,
            expected_pk_commitment,
            expected_message_commitment,
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            u,
            e0,
            e0is,
            e0_quotients,
            e1,
            message,
            r1is,
            r2is,
            p1is,
            p2is,
        }
    }

    /// Verifies that the DKG public key hashes to the expected commitment from C0.
    ///
    /// Ensures the ciphernode encrypted under the same key they committed to in C0,
    /// preventing key substitution attacks.
    fn verify_pk_commitment(self) {
        assert(
            compute_dkg_pk_commitment::<N, L, BIT_PK>(self.pk0is, self.pk1is)
                == self.expected_pk_commitment,
            "Public key commitment mismatch",
        );
    }

    /// Verifies that the message (share) polynomial hashes to the expected commitment
    /// produced in C2a (for C3a) or C2b (for C3b).
    ///
    /// This is the binding check: the plaintext being encrypted must be exactly the share
    /// that was verified in C2. Any deviation, encrypting a different value, substituting
    /// a forged share, will cause this assertion to fail.
    fn verify_message_commitment(self) {
        assert(
            compute_share_encryption_commitment_from_message::<N, BIT_MSG>(self.message)
                == self.expected_message_commitment,
            "Message commitment mismatch",
        );
    }

    /// Computes the scaled message polynomial k1 from the raw share.
    ///
    /// Each coefficient is transformed as:
    ///   k1[i] = (Q_mod_t * message[i]) mod t
    /// then centered to [-t/2, t/2) to produce the BFV plaintext encoding.
    fn compute_scaled_message(self) -> Polynomial<N> {
        let t = self.configs.t;
        // t < 2^62 (plaintext modulus); q_mod_t, msg_i < t: all safe for ModU64.
        let t_mod = ModU64::new(t as u64);
        let q_mod_t: Field = self.configs.q_mod_t;
        let mut k1_coeffs: [Field; N] = [0; N];

        // Integer division for t_half; t < 2^62 so u64 is sufficient.
        let t_half: u64 = (t as u64) / 2;

        for i in 0..N {
            let msg_i: Field = self.message.coefficients[i];
            let q_times_m_mod_t = t_mod.mul_mod(q_mod_t, msg_i);

            // Check if centering is needed (value > t/2 means negative in centered form)
            let needs_centering = (q_times_m_mod_t as u64) > t_half;

            k1_coeffs[i] = if needs_centering {
                // Value is in (t/2, t), negative in centered form
                // Represent as P - magnitude (i.e., 0 - magnitude in Field)
                let magnitude = t - q_times_m_mod_t;
                0 - magnitude
            } else {
                // Value is in [0, t/2], stays positive
                q_times_m_mod_t
            };
        }

        Polynomial { coefficients: k1_coeffs }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation.
    ///
    /// Uses commitments in place of full pk and message polynomials to reduce
    /// constraint count while preserving binding properties. The computed k1 is
    /// included explicitly since it is derived, not directly committed.
    fn payload(self, k1: Polynomial<N>) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Use pk commitment instead of full pk polynomials
        inputs.push(self.expected_pk_commitment);

        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct0is);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct1is);

        inputs = flatten::<_, _, BIT_E0>(inputs, [self.e0]);
        inputs = flatten::<_, _, BIT_E1>(inputs, [self.e1]);
        inputs = flatten::<_, _, BIT_U>(inputs, [self.u]);

        // Use message commitment instead of full message
        inputs.push(self.expected_message_commitment);

        // Include computed k1 in payload
        for i in 0..N {
            inputs.push(k1.coefficients[i]);
        }

        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1is);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2is);
        inputs = flatten::<_, _, BIT_P1>(inputs, self.p1is);
        inputs = flatten::<_, _, BIT_P2>(inputs, self.p2is);

        inputs
    }

    /// Verifies CRT consistency for the e0 error polynomial.
    ///
    /// Confirms that each per-modulus representation e0is[l] is correctly derived
    /// from the global e0 via:
    ///   e0[j] == e0is[l][j] + e0_quotients[l][j] * q_l
    ///
    /// This ensures the error is consistently decomposed across all CRT moduli.
    fn check_e0_crt_consistency(self) {
        for i in 0..L {
            for j in 0..N {
                assert(
                    self.e0.coefficients[j]
                        == self.e0is[i].coefficients[j]
                            + self.e0_quotients[i].coefficients[j] * self.configs.qis[i],
                );
            }
        }
    }

    /// Executes the share encryption circuit and returns the ciphertext commitment (C3 public output).
    pub fn execute(self) -> Field {
        // Step 1: Verify public key commitment matches expected
        self.verify_pk_commitment();

        // Step 2: Verify message commitment matches expected
        self.verify_message_commitment();

        // Step 3: Perform range checks
        self.check_range_bounds();

        // Step 4: Check CRT consistency for e0
        self.check_e0_crt_consistency();

        // Step 5: Compute scaled message k1 from message
        let k1 = self.compute_scaled_message();

        // Step 6: Generate Fiat-Shamir challenges
        let gammas = self.generate_challenge(k1);

        // Step 7: Verify encryption constraints
        self.verify_evaluations(gammas, k1);

        compute_ciphertext_commitment::<N, L, BIT_CT>(self.ct0is, self.ct1is)
    }

    /// Performs range checks on all secret witness polynomial coefficients.
    fn check_range_bounds(self) {
        self.u.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e0.range_check_2bounds::<BIT_E0>(self.configs.e0_bound, self.configs.e0_bound);
        self.e1.range_check_2bounds::<BIT_E1>(self.configs.e1_bound, self.configs.e1_bound);

        // Message should be in [0, t)
        self.message.range_check_standard::<BIT_MSG>(self.configs.msg_bound);

        for i in 0..L {
            self.pk0is[i].range_check_2bounds::<BIT_PK>(
                self.configs.pk_bounds[i],
                self.configs.pk_bounds[i],
            );
            self.pk1is[i].range_check_2bounds::<BIT_PK>(
                self.configs.pk_bounds[i],
                self.configs.pk_bounds[i],
            );

            self.r1is[i].range_check_2bounds::<BIT_R1>(
                self.configs.r1_up_bounds[i],
                self.configs.r1_low_bounds[i],
            );
            self.r2is[i].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[i],
                self.configs.r2_bounds[i],
            );

            self.p1is[i].range_check_2bounds::<BIT_P1>(
                self.configs.p1_bounds[i],
                self.configs.p1_bounds[i],
            );
            self.p2is[i].range_check_2bounds::<BIT_P2>(
                self.configs.p2_bounds[i],
                self.configs.p2_bounds[i],
            );
        }
    }

    /// Generates Fiat-Shamir challenge values using the SAFE cryptographic sponge.
    ///
    /// Returns 2*L challenge values: one primary gamma at index 0 for evaluating all
    /// polynomials, L-1 weights at indices 1..L-1 for batching ct0 equations across
    /// moduli, and L weights at indices L..2L-1 for batching ct1 equations.
    fn generate_challenge(self, k1: Polynomial<N>) -> Vec<Field> {
        let inputs = self.payload(k1);

        compute_share_encryption_challenge::<L>(inputs)
    }

    /// Verifies BFV encryption equations using Schwartz-Zippel with batched modulus verification.
    ///
    /// For each CRT modulus l, checks at the primary challenge point gamma:
    ///   ct0[l](gamma) = pk0[l](gamma)*u(gamma) + e0[l](gamma) + k1(gamma)*k0[l] + r1[l](gamma)*q_l + r2[l](gamma)*(gamma^N + 1)
    ///   ct1[l](gamma) = pk1[l](gamma)*u(gamma) + e1(gamma) + p2[l](gamma)*(gamma^N + 1) + p1[l](gamma)*q_l
    ///
    /// Rather than asserting each equation independently, both sides are accumulated
    /// into a weighted batch sum using additional challenge values as weights.
    /// A deviation in any single equation will cause the accumulated sums to diverge
    /// with overwhelming probability (Schwartz-Zippel soundness).
    fn verify_evaluations(self, gammas: Vec<Field>, k1: Polynomial<N>) {
        let gamma = gammas.get(0);
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let u_at_gamma = self.u.eval(gamma);
        let e1_at_gamma = self.e1.eval(gamma);
        let k1_at_gamma = k1.eval(gamma);

        let mut sum = (0, 0);
        for i in 0..L {
            let pk0is_at_gamma = self.pk0is[i].eval(gamma);
            let r1i_at_gamma = self.r1is[i].eval(gamma);
            let r2i_at_gamma = self.r2is[i].eval(gamma);
            let e0is_at_gamma = self.e0is[i].eval(gamma);

            // ct0[l] = pk0[l]*u + e0[l] + k1*k0[l] + r1[l]*q_l + r2[l]*(gamma^N + 1)
            let mut ct0_rhs = (pk0is_at_gamma * u_at_gamma) + e0is_at_gamma;
            ct0_rhs += k1_at_gamma * self.configs.k0is[i];
            ct0_rhs += r1i_at_gamma * self.configs.qis[i];
            ct0_rhs += r2i_at_gamma * cyclo_at_gamma;
            let ct0_lhs = self.ct0is[i].eval(gamma);

            // ct1[l] = pk1[l]*u + e1 + p2[l]*(gamma^N + 1) + p1[l]*q_l
            let pk1is_at_gamma = self.pk1is[i].eval(gamma);
            let p1is_at_gamma = self.p1is[i].eval(gamma);
            let p2is_at_gamma = self.p2is[i].eval(gamma);
            let mut ct1_rhs = (pk1is_at_gamma * u_at_gamma) + e1_at_gamma;
            ct1_rhs += p2is_at_gamma * cyclo_at_gamma;
            ct1_rhs += p1is_at_gamma * self.configs.qis[i];
            let ct1_lhs = self.ct1is[i].eval(gamma);

            // Accumulate into batched sum using per-modulus challenge weights
            let gamma_i = if i == 0 { 1 } else { gammas.get(i) };
            sum = (
                sum.0 + ct0_lhs * gamma_i + ct1_lhs * gammas.get(i + L),
                sum.1 + ct0_rhs * gamma_i + ct1_rhs * gammas.get(i + L),
            );
        }

        assert(sum.0 == sum.1);
    }
}
