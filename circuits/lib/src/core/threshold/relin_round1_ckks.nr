// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_ciphertext_commitment, compute_share_computation_sk_commitment,
    compute_threshold_pk_challenge,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// Parameters for the CKKS relinearization round-1 share proof (C8-CKKS).
///
/// `garner` is the flattened `L x L` matrix of PUBLIC constants
/// `g_i mod q_j` (centered), indexed `i * L + j`, where `g_i` is the i-th
/// garner constant of the RNS basis at the key's level.
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Centered garner constants `g_i mod q_j`, flattened at `i * L + j`.
    pub garner: [Field; L * L],
    /// Bound for the secret key polynomial (s) coefficients
    pub sk_bound: Field,
    /// Bound for the ephemeral secret polynomial (u) coefficients
    pub u_bound: Field,
    /// Bound for the error polynomials (e0[i], e1[i]) coefficients
    pub e_bound: Field,
    /// Bounds for r1 quotients (modulus switching), per limb j
    pub r1_bounds: [Field; L],
    /// Bounds for r2 quotients (cyclotomic reduction), per limb j
    pub r2_bounds: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(
        qis: [Field; L],
        garner: [Field; L * L],
        sk_bound: Field,
        u_bound: Field,
        e_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        Configs { qis, garner, sk_bound, u_bound, e_bound, r1_bounds, r2_bounds }
    }
}

/// CKKS relinearization key generation, round-1 share proof (C8-CKKS).
///
/// **Role:** Prove one party's round-1 share of the two-round CRP-based
/// relinearization key ceremony is well formed, from hidden `s`, `u`,
/// per-index errors and quotients. The CRP polynomials `a[i]` are public.
///
/// **Verifies** for each decomposition index `i` and limb `j`
/// (`idx = i * L + j`) at the FS challenge `gamma`:
/// - `h0[idx] = -a[idx]*u + (g_i mod q_j)*s + e0[i] + r1_h0[idx]*q_j + r2_h0[idx]*cyclo`
/// - `h1[idx] = a[idx]*s + e1[i] + r1_h1[idx]*q_j + r2_h1[idx]*cyclo`
///
/// **Produces (tuple order):**
/// - `commit(s)` — binds the party's secret key share.
/// - `commit(u)` — binds the ephemeral secret reused in round 2.
/// - `commit(h0 || h1)` — binds the published round-1 share.
pub struct RelinRound1<let N: u32, let L: u32, let BIT_A: u32, let BIT_SK: u32, let BIT_U: u32, let BIT_E: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_H: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    configs: Configs<L>,

    /// CRP polynomial limbs (public witnesses): a[i * L + j] = limb j of CRP i.
    a: [Polynomial<N>; L * L],

    /// This party's secret key share polynomial (secret witness, small).
    s: Polynomial<N>,

    /// This party's ephemeral secret polynomial (secret witness, small).
    u: Polynomial<N>,

    /// Error polynomials for the h0 leg, one per decomposition index i.
    e0: [Polynomial<N>; L],

    /// Error polynomials for the h1 leg, one per decomposition index i.
    e1: [Polynomial<N>; L],

    /// Modulus-switching quotients for the h0 leg (per i,j; can be negative).
    r1_h0: [Polynomial<2 * N - 1>; L * L],
    /// Cyclotomic-reduction quotients for the h0 leg (per i,j).
    r2_h0: [Polynomial<N - 1>; L * L],
    /// Modulus-switching quotients for the h1 leg (per i,j).
    r1_h1: [Polynomial<2 * N - 1>; L * L],
    /// Cyclotomic-reduction quotients for the h1 leg (per i,j).
    r2_h1: [Polynomial<N - 1>; L * L],

    /// Published round-1 share, first component (committed witness).
    h0: [Polynomial<N>; L * L],
    /// Published round-1 share, second component (committed witness).
    h1: [Polynomial<N>; L * L],
}

impl<let N: u32, let L: u32, let BIT_A: u32, let BIT_SK: u32, let BIT_U: u32, let BIT_E: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_H: u32> RelinRound1<N, L, BIT_A, BIT_SK, BIT_U, BIT_E, BIT_R1, BIT_R2, BIT_H> {
    pub fn new(
        configs: Configs<L>,
        a: [Polynomial<N>; L * L],
        s: Polynomial<N>,
        u: Polynomial<N>,
        e0: [Polynomial<N>; L],
        e1: [Polynomial<N>; L],
        r1_h0: [Polynomial<2 * N - 1>; L * L],
        r2_h0: [Polynomial<N - 1>; L * L],
        r1_h1: [Polynomial<2 * N - 1>; L * L],
        r2_h1: [Polynomial<N - 1>; L * L],
        h0: [Polynomial<N>; L * L],
        h1: [Polynomial<N>; L * L],
    ) -> Self {
        RelinRound1 { configs, a, s, u, e0, e1, r1_h0, r2_h0, r1_h1, r2_h1, h0, h1 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation.
    ///
    /// Uses commitments for s, u, and the share rather than full polynomials
    /// to reduce constraint count while maintaining binding properties.
    fn payload(self, s_commitment: Field, u_commitment: Field, share_commitment: Field) -> [Field] {
        let mut inputs: [Field] = [].as_vector();

        // Flatten CRP polynomial limbs (L*L polynomials of degree N)
        inputs = flatten::<_, _, BIT_A>(inputs, self.a);

        // Flatten error polynomials (L each)
        inputs = flatten::<_, _, BIT_E>(inputs, self.e0);
        inputs = flatten::<_, _, BIT_E>(inputs, self.e1);

        // Use commitments instead of full polynomials
        inputs = inputs.push_back(s_commitment);
        inputs = inputs.push_back(u_commitment);
        inputs = inputs.push_back(share_commitment);

        // Flatten quotient polynomials (L*L each)
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1_h0);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2_h0);
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1_h1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2_h1);

        inputs
    }

    /// Executes the relinearization round-1 share circuit.
    ///
    /// Returns `(commit(s), commit(u), commit(h0 || h1))` as documented on the struct.
    pub fn execute(self) -> (Field, Field, Field) {
        // Step 1: Range-check secret witnesses (s, u, errors, quotients).
        self.perform_range_checks();

        // Step 2: Derive commitments for the FS transcript.
        let s_commitment = compute_share_computation_sk_commitment::<N, BIT_SK>(self.s);
        let u_commitment = compute_share_computation_sk_commitment::<N, BIT_U>(self.u);
        let share_commitment = compute_ciphertext_commitment::<N, L * L, BIT_H>(self.h0, self.h1);

        // Step 3: Fiat-Shamir challenge and per-(i,j) evaluation checks.
        let gamma = self.generate_challenge(s_commitment, u_commitment, share_commitment);
        self.verify_evaluations(gamma);

        // Step 4: Return commitments for downstream circuits.
        (s_commitment, u_commitment, share_commitment)
    }

    /// Generates the Fiat-Shamir challenge using the SAFE cryptographic sponge.
    fn generate_challenge(
        self,
        s_commitment: Field,
        u_commitment: Field,
        share_commitment: Field,
    ) -> Field {
        let inputs = self.payload(s_commitment, u_commitment, share_commitment);

        compute_threshold_pk_challenge(inputs)
    }

    /// Performs range checks on all secret witness values.
    fn perform_range_checks(self) {
        self.s.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);
        self.u.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);

        for i in 0..L {
            self.e0[i].range_check_2bounds::<BIT_E>(self.configs.e_bound, self.configs.e_bound);
            self.e1[i].range_check_2bounds::<BIT_E>(self.configs.e_bound, self.configs.e_bound);
        }

        for idx in 0..L * L {
            let j = idx % L;
            self.r1_h0[idx].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[j],
                self.configs.r1_bounds[j],
            );
            self.r2_h0[idx].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[j],
                self.configs.r2_bounds[j],
            );
            self.r1_h1[idx].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[j],
                self.configs.r1_bounds[j],
            );
            self.r2_h1[idx].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[j],
                self.configs.r2_bounds[j],
            );
        }
    }

    /// Verifies the round-1 relations for every (i, j) using Schwartz-Zippel.
    ///
    /// At the challenge point gamma, for `idx = i * L + j`:
    /// - `h0[idx](gamma) = -a[idx](gamma)*u(gamma) + garner[idx]*s(gamma) + e0[i](gamma)
    ///    + r1_h0[idx](gamma)*q_j + r2_h0[idx](gamma)*(gamma^N + 1)`
    /// - `h1[idx](gamma) = a[idx](gamma)*s(gamma) + e1[i](gamma)
    ///    + r1_h1[idx](gamma)*q_j + r2_h1[idx](gamma)*(gamma^N + 1)`
    fn verify_evaluations(self, gamma: Field) {
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let s_at_gamma = self.s.eval(gamma);
        let u_at_gamma = self.u.eval(gamma);

        let mut e0_at_gamma = [0; L];
        let mut e1_at_gamma = [0; L];
        for i in 0..L {
            e0_at_gamma[i] = self.e0[i].eval(gamma);
            e1_at_gamma[i] = self.e1[i].eval(gamma);
        }

        for idx in 0..L * L {
            let i = idx / L;
            let j = idx % L;
            let a_at_gamma = self.a[idx].eval(gamma);

            let expected_h0 = -a_at_gamma * u_at_gamma
                + self.configs.garner[idx] * s_at_gamma
                + e0_at_gamma[i]
                + self.r1_h0[idx].eval(gamma) * self.configs.qis[j]
                + self.r2_h0[idx].eval(gamma) * cyclo_at_gamma;
            assert(self.h0[idx].eval(gamma) == expected_h0, "Relin round-1 h0 equation failed");

            let expected_h1 = a_at_gamma * s_at_gamma
                + e1_at_gamma[i]
                + self.r1_h1[idx].eval(gamma) * self.configs.qis[j]
                + self.r2_h1[idx].eval(gamma) * cyclo_at_gamma;
            assert(self.h1[idx].eval(gamma) == expected_h1, "Relin round-1 h1 equation failed");
        }
    }
}
