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
use crate::math::helpers::{assert_in_range, flatten};
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

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
    /// Bounds on the ct0-leg reduction quotient `ct0_r`, per CRT modulus
    pub ct0_r_bounds: [Field; L],
    /// Bounds on the ct1-leg reduction quotient `ct1_r`, per CRT modulus
    pub ct1_r_bounds: [Field; L],
    /// Exclusive bound for the raw message (share) polynomial coefficients: t
    pub msg_bound: Field,
    /// Whether the parameter set admits the scaled-quotient form of the `k0 * k1` term. False for
    /// `L = 1`, where `floor(prod(q) / t) < q` leaves no small `SMALL_D`; the direct `k1` path is
    /// used instead. Generated alongside the constants below, so a parameter set either gets the
    /// form or is excluded -- never silently given wrong constants.
    pub scaled_quotient: bool,
    /// `k * q_i - floor(prod(q) / t)`, small because every modulus sits just above a power of two.
    pub small_d: [Field; L],
    /// `(k0_i * q_mod_t + small_d_i) / q_i`, exact by construction.
    pub alpha: [Field; L],
    /// `(k0_i * t + 1) / q_i`, exact by construction.
    pub beta: [Field; L],
    /// Negative excursion of the combined quotients, from the `pk * u` product: `N * u / 2 + 1`.
    pub q0_offset: Field,
    /// Twice `q0_offset`: a difference of two quotients carries one excursion from each.
    pub q0_diff_offset: Field,
    pub q1_offset: Field,
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
        ct0_r_bounds: [Field; L],
        ct1_r_bounds: [Field; L],
        msg_bound: Field,
        scaled_quotient: bool,
        small_d: [Field; L],
        alpha: [Field; L],
        beta: [Field; L],
        q0_offset: Field,
        q0_diff_offset: Field,
        q1_offset: Field,
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
            ct0_r_bounds,
            ct1_r_bounds,
            msg_bound,
            scaled_quotient,
            small_d,
            alpha,
            beta,
            q0_offset,
            q0_diff_offset,
            q1_offset,
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
pub struct ShareEncryption<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_MSG: u32, let BIT_CT0_R: u32, let BIT_CT1_R: u32, let BIT_Z: u32, let BIT_Q0: u32, let BIT_Q0_DIFF: u32, let BIT_Q1: u32> {
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
    /// Error polynomial e0 (secret witness).
    /// DKG `e0_bound` (2 * variance) stays far below every `q_i / 2`, so the centered residue of
    /// e0 at each modulus equals e0. The equations use e0 directly, with no CRT decomposition.
    e0: Polynomial<N>,
    /// Error polynomial e1 (secret witness)
    e1: Polynomial<N>,
    /// Raw message polynomial (secret witness)
    message: Polynomial<N>,
    /// Reduction quotient for the ct0 leg, already reduced modulo `X^N + 1` by the prover. The
    /// cyclotomic quotient the unreduced identity needed is gone: `X^N = -1` makes its term zero.
    ct0_r: [Polynomial<N>; L],
    /// Reduction quotient for the ct1 leg, same form.
    ct1_r: [Polynomial<N>; L],

    /// Rounding carries for the scaled message: `k1 == q_mod_t * m - t * z`.
    ///
    /// A witness rather than an in-circuit hint, which is how every other quotient here is handled:
    /// the prover supplies it and the circuit pins it. Unused on the direct path.
    z: [Polynomial<N>; 1],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_MSG: u32, let BIT_CT0_R: u32, let BIT_CT1_R: u32, let BIT_Z: u32, let BIT_Q0: u32, let BIT_Q0_DIFF: u32, let BIT_Q1: u32> ShareEncryption<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_MSG, BIT_CT0_R, BIT_CT1_R, BIT_Z, BIT_Q0, BIT_Q0_DIFF, BIT_Q1> {
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
        e1: Polynomial<N>,
        message: Polynomial<N>,
        ct0_r: [Polynomial<N>; L],
        ct1_r: [Polynomial<N>; L],
        z: [Polynomial<N>; 1],
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
            e1,
            message,
            ct0_r,
            ct1_r,
            z,
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
    /// Rounding carries `z` with `k1 == q_mod_t * m - t * z`, so the scaled message need never be
    /// materialised.
    ///
    /// `k1` is `q_mod_t * m` reduced into the centred window modulo `t`. Writing that reduction as a
    /// carry makes it an affine term the quotient can absorb: see `scaled_quotient_terms`.
    ///
    /// `z` is a hint, pinned by the shifted remainder: `q_mod_t * m - t * z + (t - 1) / 2` lies in
    /// `[0, t)` for exactly one `z`, because any `t` consecutive integers hold one representative of
    /// each residue class. `BIT_Z` bounds `z` so the subtraction is an integer identity rather than a
    /// modular one -- `z` is at most `q_mod_t`, since `m < t`.
    fn check_rounding_carries(self) -> Polynomial<N> {
        let t = self.configs.t;
        let half = (t - 1) / 2;
        let z = self.z[0];

        for j in 0..N {
            let scaled = self.configs.q_mod_t * self.message.coefficients[j];
            // `BIT_Z` keeps `t * z` far below the field prime, so the subtraction below is an
            // integer identity rather than a modular one. `z` is at most `q_mod_t`, since `m < t`.
            z.coefficients[j].assert_max_bit_size::<BIT_Z>();
            // Exactly one `z` puts the shifted remainder in `[0, t)`, because any `t` consecutive
            // integers hold one representative of each residue class. That fixes `z` uniquely.
            assert_in_range::<BIT_MSG>(scaled + half - t * z.coefficients[j], t);
        }

        z
    }

    /// The combined quotients `Q0` of the scaled form, one per CRT basis.
    ///
    /// Substituting `k1 = q_mod_t * m - t * z` into `ct0 = pk0 * u + e0 + k0 * k1 + q * r` and using
    /// `k0 * t = beta * q - 1` and `k0 * q_mod_t = alpha * q - small_d` gives
    ///
    /// ```text
    ///   ct0 = pk0 * u + e0 - small_d * m + z + q * (r + alpha * m - beta * z)
    /// ```
    ///
    /// so `Q0 = r + alpha * m - beta * z` carries what `r` and the `k0 * k1` term carried between
    /// them. It is far narrower than `r`: the `small_d * m / q` term dominates it and `small_d` is
    /// only as large as the modulus's gap above its power of two.
    fn scaled_quotient_terms(self, z: Polynomial<N>) -> [Polynomial<N>; L] {
        let mut q0 = [Polynomial::new([0; N]); L];

        for i in 0..L {
            let mut coeffs: [Field; N] = [0; N];
            for j in 0..N {
                coeffs[j] = self.ct0_r[i].coefficients[j]
                    + self.configs.alpha[i] * self.message.coefficients[j]
                    - self.configs.beta[i] * z.coefficients[j];
            }
            q0[i] = Polynomial::new(coeffs);
        }

        q0
    }

    /// Range-checks the combined quotients.
    ///
    /// Each check reads `(value + offset) < 2^BIT`, i.e. `value` in `[-offset, 2^BIT - offset]`. The
    /// window is asymmetric because `small_d * m` is non-negative and dominates the positive side,
    /// while the negative side only reaches the `pk * u` excursion.
    ///
    /// Only the first limb's `Q0` gets the full width. The others are bounded through their
    /// difference from it, which is far narrower: every limb carries `small_d_i * m / q_i`, and
    /// those coefficients differ only in their low digits, so the shared part cancels.
    fn check_scaled_quotient_bounds(self, q0: [Polynomial<N>; L]) {
        for j in 0..N {
            // One-sided: `assert_max_bit_size` also forces non-negativity, so the shifted value
            // landing below `2^BIT_Q0` is the whole two-sided window in a single assert.
            (q0[0].coefficients[j] + self.configs.q0_offset).assert_max_bit_size::<BIT_Q0>();
        }

        for i in 1..L {
            for j in 0..N {
                let difference = q0[i].coefficients[j] - q0[0].coefficients[j];
                (difference + self.configs.q0_diff_offset).assert_max_bit_size::<BIT_Q0_DIFF>();
            }
        }

        for i in 0..L {
            for j in 0..N {
                (self.ct1_r[i].coefficients[j] + self.configs.q1_offset)
                    .assert_max_bit_size::<BIT_Q1>();
            }
        }
    }

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
    /// Transcript for the scaled form.
    ///
    /// Two things leave it relative to [`Self::payload`]. `k1` is gone: the direct path pushes all
    /// `N` of its coefficients in unpacked, one sponge absorption each, and the scaled form never
    /// builds it. And `ct0_r` is replaced by the narrower `Q0`, which determines it given the
    /// committed message and the carries derived from that message.
    fn payload_scaled(self, q0: [Polynomial<N>; L]) -> [Field] {
        let mut inputs = [self.expected_pk_commitment].as_vector();

        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct0is);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct1is);
        inputs = flatten::<_, _, BIT_E0>(inputs, [self.e0]);
        inputs = flatten::<_, _, BIT_E1>(inputs, [self.e1]);
        inputs = flatten::<_, _, BIT_U>(inputs, [self.u]);
        inputs = inputs.push_back(self.expected_message_commitment);

        // `Q0` is bounded by `check_scaled_quotient_bounds` and `ct1_r` with it, so plain packing is
        // injective for both.
        inputs = flatten::<_, _, BIT_Q0>(inputs, q0);
        inputs = flatten::<_, _, BIT_Q1>(inputs, self.ct1_r);

        inputs
    }

    /// The scaled identity, per CRT basis:
    /// `ct0 = pk0 * u + e0 - small_d * m + z + q * Q0` and `ct1 = pk1 * u + e1 + q * ct1_r`.
    ///
    /// The `k0 * k1` term is gone; `- small_d * m + z` replaces it, which is two scalar multiplies
    /// against values already in hand.
    fn verify_evaluations_scaled(self, gammas: [Field], z: Polynomial<N>, q0: [Polynomial<N>; L]) {
        let x = gammas[0];
        let kernel = negacyclic_kernel(self.u, x);

        for i in 0..L {
            let mut ct0_residual = [0; N];
            let mut ct1_residual = [0; N];
            for j in 0..N {
                ct0_residual[j] = self.ct0is[i].coefficients[j] - self.e0.coefficients[j]
                    + self.configs.small_d[i] * self.message.coefficients[j]
                    - z.coefficients[j]
                    - self.configs.qis[i] * q0[i].coefficients[j];
                ct1_residual[j] = self.ct1is[i].coefficients[j]
                    - self.e1.coefficients[j]
                    - self.configs.qis[i] * self.ct1_r[i].coefficients[j];
            }
            assert(
                Polynomial::new(ct0_residual).eval(x) == self.pk0is[i].dot(kernel),
                "ct0 encryption check failed",
            );
            assert(
                Polynomial::new(ct1_residual).eval(x) == self.pk1is[i].dot(kernel),
                "ct1 encryption check failed",
            );
        }
    }

    fn payload(self, k1: Polynomial<N>) -> [Field] {
        // Use pk commitment instead of full pk polynomials
        let mut inputs = [self.expected_pk_commitment].as_vector();

        // Every vector below is bounded by `check_range_bounds`, so the plain packing is injective.
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct0is);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct1is);

        inputs = flatten::<_, _, BIT_E0>(inputs, [self.e0]);
        inputs = flatten::<_, _, BIT_E1>(inputs, [self.e1]);
        inputs = flatten::<_, _, BIT_U>(inputs, [self.u]);

        // Use message commitment instead of full message
        inputs = inputs.push_back(self.expected_message_commitment);

        // Include computed k1 in payload
        for i in 0..N {
            inputs = inputs.push_back(k1.coefficients[i]);
        }

        // The two reduction quotients replace `r1is` / `r2is` / `p1is` / `p2is` in the transcript.
        inputs = flatten::<_, _, BIT_CT0_R>(inputs, self.ct0_r);
        inputs = flatten::<_, _, BIT_CT1_R>(inputs, self.ct1_r);

        inputs
    }

    /// Executes the share encryption circuit and returns the ciphertext commitment (C3 public output).
    pub fn execute(self) -> Field {
        // Step 1: Verify public key commitment matches expected
        self.verify_pk_commitment();

        // Step 2: Verify message commitment matches expected
        self.verify_message_commitment();

        // Step 3: Range-check everything the identity reads except the quotients, whose form
        // depends on which path runs.
        self.check_range_bounds();

        // Steps 4-6. `scaled_quotient` is a generated flag, so this resolves at compile time and the
        // unused branch costs nothing. The scaled form folds `k0 * k1` into the quotient, which drops
        // both the per-coefficient modular multiply and `k1`'s unpacked absorptions; parameter sets
        // that cannot support it keep the direct path.
        if self.configs.scaled_quotient {
            let z = self.check_rounding_carries();
            let q0 = self.scaled_quotient_terms(z);
            self.check_scaled_quotient_bounds(q0);
            let gammas = compute_share_encryption_challenge::<L>(self.payload_scaled(q0));
            self.verify_evaluations_scaled(gammas, z, q0);
        } else {
            self.check_quotient_bounds();
            let k1 = self.compute_scaled_message();
            let gammas = self.generate_challenge(k1);
            self.verify_evaluations(gammas, k1);
        }

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

            // `ct0is` / `ct1is` are centered residues mod `q_i`. The reduced identity is checked at
            // one point, so they need a bound for the field equality to imply the integer one; that
            // also makes their plain packing injective and retires the IF-013 digit asserts.
            self.ct0is[i].range_check_2bounds::<BIT_CT>(
                self.configs.pk_bounds[i],
                self.configs.pk_bounds[i],
            );
            self.ct1is[i].range_check_2bounds::<BIT_CT>(
                self.configs.pk_bounds[i],
                self.configs.pk_bounds[i],
            );
        }
    }

    /// Quotient bounds for the direct path. The scaled path bounds `Q0` and `ct1_r` instead, at far
    /// narrower widths, so these are not applied there.
    fn check_quotient_bounds(self) {
        for i in 0..L {
            self.ct0_r[i].range_check_2bounds::<BIT_CT0_R>(
                self.configs.ct0_r_bounds[i],
                self.configs.ct0_r_bounds[i],
            );
            self.ct1_r[i].range_check_2bounds::<BIT_CT1_R>(
                self.configs.ct1_r_bounds[i],
                self.configs.ct1_r_bounds[i],
            );
        }
    }

    /// Generates Fiat-Shamir challenge values using the SAFE cryptographic sponge.
    ///
    /// Returns 2*L challenge values: one primary gamma at index 0 for evaluating all
    /// polynomials, L-1 weights at indices 1..L-1 for batching ct0 equations across
    /// moduli, and L weights at indices L..2L-1 for batching ct1 equations.
    fn generate_challenge(self, k1: Polynomial<N>) -> [Field] {
        let inputs = self.payload(k1);

        compute_share_encryption_challenge::<L>(inputs)
    }

    /// Checks both reduced encryption identities at one transcript-derived challenge point:
    ///
    ///   ct0is = pk0is * u + e0 + k0is * k1 + q_i * ct0_r   (mod X^N + 1)
    ///   ct1is = pk1is * u + e1            + q_i * ct1_r   (mod X^N + 1)
    ///
    /// `negacyclic_kernel` supplies the reduced products at `x`, so neither product enters the
    /// witness and the cyclotomic quotients are gone with them. One kernel serves all `2 * L`
    /// products, which is where most of the saving comes from.
    fn verify_evaluations(self, gammas: [Field], k1: Polynomial<N>) {
        let x = gammas[0];
        let kernel = negacyclic_kernel(self.u, x);

        for i in 0..L {
            let mut ct0_residual = [0; N];
            let mut ct1_residual = [0; N];
            for j in 0..N {
                ct0_residual[j] = self.ct0is[i].coefficients[j]
                    - self.e0.coefficients[j]
                    - self.configs.k0is[i] * k1.coefficients[j]
                    - self.configs.qis[i] * self.ct0_r[i].coefficients[j];
                ct1_residual[j] = self.ct1is[i].coefficients[j]
                    - self.e1.coefficients[j]
                    - self.configs.qis[i] * self.ct1_r[i].coefficients[j];
            }
            assert(
                Polynomial::new(ct0_residual).eval(x) == self.pk0is[i].dot(kernel),
                "ct0 encryption check failed",
            );
            assert(
                Polynomial::new(ct1_residual).eval(x) == self.pk1is[i].dot(kernel),
                "ct1 encryption check failed",
            );
        }
    }
}

/// An honest witness satisfies both reduced legs, with nonzero quotients on each.
///
/// Worked by hand at `N = 4`, `q = 97`, `t = 5`, `q_mod_t = 2`, `k0 = -t^-1 mod q = 58`.
/// `message = [0, 0, 1, 2]` scales to the centered `k1 = [0, 0, 2, -1]`, so the ct0 right-hand side
/// is `[-50, -30, -10, -50] + [0, 0, 0, 1] + 58 * k1 = [-50, -30, 106, -107]`. Three coefficients
/// fall outside `+/-(q-1)/2`, giving `ct0is = [47, -30, 9, -10]` and `ct0_r = [1, 0, -1, 1]`. The
/// ct1 leg has no `k0 * k1` term: `[20, 60, -40, -19]` centers to `[20, -37, -40, -19]` with
/// `ct1_r = [0, -1, 0, 0]`.
///
/// Both legs share one `negacyclic_kernel`, so this also pins that the shared kernel is correct for
/// two different left operands.
#[test]
fn honest_reduced_identity_holds() {
    let _ = reduced_identity_fixture().execute();
}

fn reduced_identity_fixture() -> ShareEncryption<4, 1, 6, 6, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3> {
    let pk0 = Polynomial::new([30, 40, -20, 10]);
    let pk1 = Polynomial::new([10, -20, 30, 40]);
    let u = Polynomial::new([0, 1, 0, -1]);
    let e0 = Polynomial::new([0, 0, 0, 1]);
    let e1 = Polynomial::new([0, 0, 0, 1]);
    let message = Polynomial::new([0, 0, 1, 2]);
    let ct0 = Polynomial::new([47, -30, 9, -10]);
    let ct1 = Polynomial::new([20, -37, -40, -19]);
    let ct0_r = Polynomial::new([1, 0, -1, 1]);
    let ct1_r = Polynomial::new([0, -1, 0, 0]);

    // t, q_mod_t, qis, k0is, pk_bounds, e0_bound, e1_bound, u_bound, ct0_r, ct1_r, msg_bound,
    // then the scaled-quotient constants. `scaled_quotient` is false here, so this fixture exercises
    // the direct `k1` path -- the one insecure-512 uses in production.
    let configs: Configs<1> = Configs::new(
        5,
        2,
        [97],
        [58],
        [48],
        1,
        1,
        1,
        [3],
        [3],
        5,
        false,
        [0],
        [0],
        [0],
        0,
        0,
        0,
    );

    let c: ShareEncryption<4, 1, 6, 6, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3> = ShareEncryption::new(
        configs,
        compute_dkg_pk_commitment::<4, 1, 6>([pk0], [pk1]),
        compute_share_encryption_commitment_from_message::<4, 3>(message),
        [pk0],
        [pk1],
        [ct0],
        [ct1],
        u,
        e0,
        e1,
        message,
        [ct0_r],
        [ct1_r],
        // `z` is unused on the direct path this fixture exercises.
        [Polynomial::new([0; 4])],
    );
    c
}

/// The largest legitimate plaintext coefficient, `t - 1`, is accepted.
#[test]
fn largest_plaintext_coefficient_is_accepted() {
    let mut c = reduced_identity_fixture();
    c.message.coefficients[0] = 4;
    c.check_range_bounds();
}

/// A plaintext coefficient at `t` is rejected.
#[test(should_fail)]
fn plaintext_coefficient_at_t_is_rejected() {
    let mut c = reduced_identity_fixture();
    c.message.coefficients[0] = 5;
    c.check_range_bounds();
}

/// C3 bounds each ciphertext component before it creates the commitment.
#[test(should_fail)]
fn ct0_above_centered_bound_is_rejected() {
    let mut c = reduced_identity_fixture();
    c.ct0is[0].coefficients[0] = 49;
    c.check_range_bounds();
}

#[test(should_fail)]
fn ct0_below_centered_bound_is_rejected() {
    let mut c = reduced_identity_fixture();
    c.ct0is[0].coefficients[0] = -49;
    c.check_range_bounds();
}

#[test(should_fail)]
fn ct1_above_centered_bound_is_rejected() {
    let mut c = reduced_identity_fixture();
    c.ct1is[0].coefficients[0] = 49;
    c.check_range_bounds();
}

#[test(should_fail)]
fn ct1_below_centered_bound_is_rejected() {
    let mut c = reduced_identity_fixture();
    c.ct1is[0].coefficients[0] = -49;
    c.check_range_bounds();
}

/// Fixture for the scaled-quotient path, at `N = 4`, `L = 2`, `q = [101, 103]`, `t = 13`.
///
/// The constants satisfy the same identities the generator derives and `bin/config` re-checks:
/// `DELTA = floor(101 * 103 / 13) = 800`, `k = 8`, `SMALL_D = [8 * 101 - 800, 8 * 103 - 800]`,
/// `BETA = [(31 * 13 + 1) / 101, (95 * 13 + 1) / 103]`, and
/// `ALPHA = [(31 * 3 + 8) / 101, (95 * 3 + 24) / 103]`.
///
/// `message = [0, 1, 2, 3]` gives carries `z = [0, 0, 0, 1]` and so `k1 = [0, 3, 6, -4]`, inside the
/// centred window `+/-6`.
fn scaled_fixture(
    z: Polynomial<4>,
    ct0_r: [Polynomial<4>; 2],
) -> ShareEncryption<4, 2, 6, 6, 1, 2, 2, 4, 4, 4, 2, 4, 4, 4> {
    let pk0 = [Polynomial::new([20, -30, 10, 5]), Polynomial::new([25, -15, 30, -20])];
    let pk1 = [Polynomial::new([5, 10, -5, 15]), Polynomial::new([-10, 20, -25, 5])];
    let ct0 = [Polynomial::new([-9, 27, -47, 2]), Polynomial::new([6, -29, -1, -36])];
    let ct1 = [Polynomial::new([-10, 6, 0, -26]), Polynomial::new([-15, -14, 35, -26])];
    let u = Polynomial::new([0, 1, 0, -1]);
    let e0 = Polynomial::new([1, 0, -1, 0]);
    let e1 = Polynomial::new([0, 1, 0, -1]);
    let message = Polynomial::new([0, 1, 2, 3]);
    let ct1_r = [Polynomial::new([0, 0, 0, 0]), Polynomial::new([0, 0, 0, 0])];

    // ..., msg_bound, scaled_quotient, small_d, alpha, beta, q0_offset, q0_diff_offset, q1_offset
    let configs: Configs<2> = Configs::new(
        13,
        3,
        [101, 103],
        [31, 95],
        [50, 51],
        1,
        1,
        1,
        [5, 5],
        [5, 5],
        13,
        true,
        [8, 24],
        [1, 3],
        [4, 12],
        3,
        6,
        3,
    );

    ShareEncryption::new(
        configs,
        compute_dkg_pk_commitment::<4, 2, 6>(pk0, pk1),
        compute_share_encryption_commitment_from_message::<4, 4>(message),
        pk0,
        pk1,
        ct0,
        ct1,
        u,
        e0,
        e1,
        message,
        ct0_r,
        ct1_r,
        [z],
    )
}

/// The honest ct0 quotients for [`scaled_fixture`], before `ALPHA * m - BETA * z` folds in.
fn honest_scaled_quotients() -> [Polynomial<4>; 2] {
    [Polynomial::new([0, -1, -2, 1]), Polynomial::new([0, -3, -5, 3])]
}

/// The scaled path accepts an honest witness on both legs and both limbs.
///
/// This is the only test that exercises it: every other C3 test runs the direct `k1` path, which is
/// what insecure-512 uses. Without this the production path would be the untested one.
#[test]
fn scaled_quotient_path_accepts_honest_witness() {
    let _ = scaled_fixture(Polynomial::new([0, 0, 0, 1]), honest_scaled_quotients()).execute();
}

/// A tampered carry must be rejected.
///
/// `z` is prover-supplied now rather than hinted in-circuit, so this is the check that it is pinned:
/// `q_mod_t * m - t * z + (t - 1) / 2` lies in `[0, t)` for exactly one `z`, and moving any
/// coefficient off that value leaves the window.
#[test(should_fail)]
fn tampered_rounding_carry_is_rejected() {
    // Honest carries are [0, 0, 0, 1]; claim a zero for the last coefficient.
    let _ = scaled_fixture(Polynomial::new([0, 0, 0, 0]), honest_scaled_quotients()).execute();
}

/// A carry inflated the other way must also be rejected, not just a deflated one.
#[test(should_fail)]
fn inflated_rounding_carry_is_rejected() {
    let _ = scaled_fixture(Polynomial::new([1, 0, 0, 1]), honest_scaled_quotients()).execute();
}

/// A tampered ct0 quotient must break the evaluation check.
///
/// `Q0 = r + ALPHA * m - BETA * z` carries the mod-q slack on the ct0 leg, so this is what stops a
/// prover choosing `ct0is` freely. Shifting one coefficient of `r` moves `Q0` and the identity stops
/// holding at the challenge point.
#[test(should_fail)]
fn tampered_scaled_quotient_is_rejected() {
    let mut tampered = honest_scaled_quotients();
    tampered[0] = Polynomial::new([0, -1, -2, 2]);
    let _ = scaled_fixture(Polynomial::new([0, 0, 0, 1]), tampered).execute();
}

/// The same on the second limb, which is bounded only through its difference from the first.
///
/// `BIT_Q0` applies to limb zero; every other limb is covered by `BIT_Q0_DIFF` against it. This pins
/// that the narrower route still rejects a wrong quotient.
#[test(should_fail)]
fn tampered_second_limb_quotient_is_rejected() {
    let mut tampered = honest_scaled_quotients();
    tampered[1] = Polynomial::new([0, -3, -5, 4]);
    let _ = scaled_fixture(Polynomial::new([0, 0, 0, 1]), tampered).execute();
}
