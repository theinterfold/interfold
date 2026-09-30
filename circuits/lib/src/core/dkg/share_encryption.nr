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
pub struct ShareEncryption<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_MSG: u32, let BIT_CT0_R: u32, let BIT_CT1_R: u32> {
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
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_MSG: u32, let BIT_CT0_R: u32, let BIT_CT1_R: u32> ShareEncryption<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_MSG, BIT_CT0_R, BIT_CT1_R> {
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

        // Step 3: Perform range checks
        self.check_range_bounds();

        // Step 4: Compute scaled message k1 from message
        let k1 = self.compute_scaled_message();

        // Step 5: Generate Fiat-Shamir challenges
        let gammas = self.generate_challenge(k1);

        // Step 6: Verify encryption constraints
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

    /// Verifies BFV encryption equations using Schwartz-Zippel with batched modulus verification.
    ///
    /// For each CRT modulus l, checks at the primary challenge point gamma:
    ///   ct0[l](gamma) = pk0[l](gamma)*u(gamma) + e0(gamma) + k1(gamma)*k0[l] + r1[l](gamma)*q_l + r2[l](gamma)*(gamma^N + 1)
    ///   ct1[l](gamma) = pk1[l](gamma)*u(gamma) + e1(gamma) + p2[l](gamma)*(gamma^N + 1) + p1[l](gamma)*q_l
    ///
    /// Rather than asserting each equation independently, both sides are accumulated
    /// into a weighted batch sum using additional challenge values as weights.
    /// A deviation in any single equation will cause the accumulated sums to diverge
    /// with overwhelming probability (Schwartz-Zippel soundness).
    /// Checks both legs in reduced form, at one challenge point:
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

fn reduced_identity_fixture() -> ShareEncryption<4, 1, 6, 6, 1, 1, 1, 3, 3, 3> {
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

    // t, q_mod_t, qis, k0is, pk_bounds, e0_bound, e1_bound, u_bound, ct0_r, ct1_r, msg_bound
    let configs: Configs<1> = Configs::new(5, 2, [97], [58], [48], 1, 1, 1, [3], [3], 5);

    let c: ShareEncryption<4, 1, 6, 6, 1, 1, 1, 3, 3, 3> = ShareEncryption::new(
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
