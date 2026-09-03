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

/// Parameters for the CKKS HYBRID relinearization round-1 share proof
/// (C8-CKKS, hybrid gadget).
///
/// The share lives over `Q·P`: `LT = L + k` limbs (`L` ciphertext moduli
/// followed by `k` special primes) and `D = dnum` gadget digits.
/// `gadget` is the flattened `D x LT` matrix of PUBLIC constants
/// `c[j][l] = (P·g_j) mod q_l` indexed `j * LT + l`, where
/// `g_j = (Q/D_j)·[(Q/D_j)^{-1}]_{D_j}` is the CRT gadget of digit `j`
/// (Han–Ki hybrid key switching, fhe.rs `ckks/hybrid.rs`). On the `k`
/// special-prime limbs `P·g_j ≡ 0`, so those entries are 0.
pub struct Configs<let D: u32, let LT: u32> {
    /// Moduli of `Q·P`: `[q_0, …, q_{L-1}, p_0, …, p_{k-1}]`.
    pub qis: [Field; LT],
    /// `(P·g_j) mod q_l` (plain representative in `[0, q_l)`), at `j * LT + l`.
    pub gadget: [Field; D * LT],
    /// Bound for the secret key polynomial (s) coefficients
    pub sk_bound: Field,
    /// Bound for the ephemeral secret polynomial (u) coefficients
    pub u_bound: Field,
    /// Bound for the error polynomials (e0[j], e1[j]) coefficients
    pub e_bound: Field,
    /// Bounds for r1 quotients (modulus switching), per limb l
    pub r1_bounds: [Field; LT],
    /// Bounds for r2 quotients (cyclotomic reduction), per limb l
    pub r2_bounds: [Field; LT],
}

impl<let D: u32, let LT: u32> Configs<D, LT> {
    pub fn new(
        qis: [Field; LT],
        gadget: [Field; D * LT],
        sk_bound: Field,
        u_bound: Field,
        e_bound: Field,
        r1_bounds: [Field; LT],
        r2_bounds: [Field; LT],
    ) -> Self {
        Configs { qis, gadget, sk_bound, u_bound, e_bound, r1_bounds, r2_bounds }
    }
}

/// CKKS HYBRID relinearization key generation, round-1 share proof
/// (C8-CKKS, hybrid gadget).
///
/// **Role:** Prove one party's round-1 share of the two-round CRP-based
/// HYBRID relinearization key ceremony (fhe.rs
/// `CkksHybridRelinKeyGenerator::round_1`) is well formed, from hidden
/// `s`, `u`, per-digit errors and quotients. The CRP polynomials `a[j]`
/// over `Q·P` are public.
///
/// **Verifies** for each digit `j` and limb `l` of `Q·P`
/// (`idx = j * LT + l`) at the FS challenge `gamma`:
/// - `h0[idx] = -a[idx]*u + gadget[idx]*s + e0[j] + r1_h0[idx]*q_l + r2_h0[idx]*cyclo`
/// - `h1[idx] = a[idx]*s + e1[j] + r1_h1[idx]*q_l + r2_h1[idx]*cyclo`
///
/// The SAME small integer polynomials `s`, `u`, `e0[j]`, `e1[j]` are
/// reduced on every limb (ciphertext AND special-prime), which is how the
/// generator builds them (`CkksQpPoly::from_small_coeffs`).
///
/// **Produces (tuple order):**
/// - `commit(s)` — binds the party's secret key share.
/// - `commit(u)` — binds the ephemeral secret reused in round 2.
/// - `commit(h0 || h1)` — binds the published round-1 share.
pub struct RelinRound1Hybrid<let N: u32, let D: u32, let LT: u32, let BIT_A: u32, let BIT_SK: u32, let BIT_U: u32, let BIT_E: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_H: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    configs: Configs<D, LT>,

    /// CRP polynomial limbs (public witnesses): a[j * LT + l] = limb l of CRP j.
    a: [Polynomial<N>; D * LT],

    /// This party's secret key share polynomial (secret witness, small).
    s: Polynomial<N>,

    /// This party's ephemeral secret polynomial (secret witness, small).
    u: Polynomial<N>,

    /// Error polynomials for the h0 leg, one per digit j.
    e0: [Polynomial<N>; D],

    /// Error polynomials for the h1 leg, one per digit j.
    e1: [Polynomial<N>; D],

    /// Modulus-switching quotients for the h0 leg (per j,l; can be negative).
    r1_h0: [Polynomial<2 * N - 1>; D * LT],
    /// Cyclotomic-reduction quotients for the h0 leg (per j,l).
    r2_h0: [Polynomial<N - 1>; D * LT],
    /// Modulus-switching quotients for the h1 leg (per j,l).
    r1_h1: [Polynomial<2 * N - 1>; D * LT],
    /// Cyclotomic-reduction quotients for the h1 leg (per j,l).
    r2_h1: [Polynomial<N - 1>; D * LT],

    /// Published round-1 share, first component (committed witness).
    h0: [Polynomial<N>; D * LT],
    /// Published round-1 share, second component (committed witness).
    h1: [Polynomial<N>; D * LT],
}

impl<let N: u32, let D: u32, let LT: u32, let BIT_A: u32, let BIT_SK: u32, let BIT_U: u32, let BIT_E: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_H: u32> RelinRound1Hybrid<N, D, LT, BIT_A, BIT_SK, BIT_U, BIT_E, BIT_R1, BIT_R2, BIT_H> {
    pub fn new(
        configs: Configs<D, LT>,
        a: [Polynomial<N>; D * LT],
        s: Polynomial<N>,
        u: Polynomial<N>,
        e0: [Polynomial<N>; D],
        e1: [Polynomial<N>; D],
        r1_h0: [Polynomial<2 * N - 1>; D * LT],
        r2_h0: [Polynomial<N - 1>; D * LT],
        r1_h1: [Polynomial<2 * N - 1>; D * LT],
        r2_h1: [Polynomial<N - 1>; D * LT],
        h0: [Polynomial<N>; D * LT],
        h1: [Polynomial<N>; D * LT],
    ) -> Self {
        RelinRound1Hybrid { configs, a, s, u, e0, e1, r1_h0, r2_h0, r1_h1, r2_h1, h0, h1 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation.
    ///
    /// Uses commitments for s, u, and the share rather than full polynomials
    /// to reduce constraint count while maintaining binding properties.
    fn payload(self, s_commitment: Field, u_commitment: Field, share_commitment: Field) -> [Field] {
        let mut inputs: [Field] = [].as_vector();

        // Flatten CRP polynomial limbs (D*LT polynomials of degree N)
        inputs = flatten::<_, _, BIT_A>(inputs, self.a);

        // Flatten error polynomials (D each)
        inputs = flatten::<_, _, BIT_E>(inputs, self.e0);
        inputs = flatten::<_, _, BIT_E>(inputs, self.e1);

        // Use commitments instead of full polynomials
        inputs = inputs.push_back(s_commitment);
        inputs = inputs.push_back(u_commitment);
        inputs = inputs.push_back(share_commitment);

        // Flatten quotient polynomials (D*LT each)
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1_h0);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2_h0);
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1_h1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2_h1);

        inputs
    }

    /// Executes the hybrid relinearization round-1 share circuit.
    ///
    /// Returns `(commit(s), commit(u), commit(h0 || h1))` as documented on the struct.
    pub fn execute(self) -> (Field, Field, Field) {
        // Step 1: Range-check secret witnesses (s, u, errors, quotients).
        self.perform_range_checks();

        // Step 2: Derive commitments for the FS transcript.
        let s_commitment = compute_share_computation_sk_commitment::<N, BIT_SK>(self.s);
        let u_commitment = compute_share_computation_sk_commitment::<N, BIT_U>(self.u);
        let share_commitment = compute_ciphertext_commitment::<N, D * LT, BIT_H>(self.h0, self.h1);

        // Step 3: Fiat-Shamir challenge and per-(j,l) evaluation checks.
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

        for j in 0..D {
            self.e0[j].range_check_2bounds::<BIT_E>(self.configs.e_bound, self.configs.e_bound);
            self.e1[j].range_check_2bounds::<BIT_E>(self.configs.e_bound, self.configs.e_bound);
        }

        for idx in 0..D * LT {
            let l = idx % LT;
            self.r1_h0[idx].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[l],
                self.configs.r1_bounds[l],
            );
            self.r2_h0[idx].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[l],
                self.configs.r2_bounds[l],
            );
            self.r1_h1[idx].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[l],
                self.configs.r1_bounds[l],
            );
            self.r2_h1[idx].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[l],
                self.configs.r2_bounds[l],
            );
        }
    }

    /// Verifies the round-1 relations for every (j, l) using Schwartz-Zippel.
    ///
    /// At the challenge point gamma, for `idx = j * LT + l`:
    /// - `h0[idx](gamma) = -a[idx](gamma)*u(gamma) + gadget[idx]*s(gamma) + e0[j](gamma)
    ///    + r1_h0[idx](gamma)*q_l + r2_h0[idx](gamma)*(gamma^N + 1)`
    /// - `h1[idx](gamma) = a[idx](gamma)*s(gamma) + e1[j](gamma)
    ///    + r1_h1[idx](gamma)*q_l + r2_h1[idx](gamma)*(gamma^N + 1)`
    fn verify_evaluations(self, gamma: Field) {
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let s_at_gamma = self.s.eval(gamma);
        let u_at_gamma = self.u.eval(gamma);

        let mut e0_at_gamma = [0; D];
        let mut e1_at_gamma = [0; D];
        for j in 0..D {
            e0_at_gamma[j] = self.e0[j].eval(gamma);
            e1_at_gamma[j] = self.e1[j].eval(gamma);
        }

        for idx in 0..D * LT {
            let j = idx / LT;
            let l = idx % LT;
            let a_at_gamma = self.a[idx].eval(gamma);

            let expected_h0 = -a_at_gamma * u_at_gamma
                + self.configs.gadget[idx] * s_at_gamma
                + e0_at_gamma[j]
                + self.r1_h0[idx].eval(gamma) * self.configs.qis[l]
                + self.r2_h0[idx].eval(gamma) * cyclo_at_gamma;
            assert(
                self.h0[idx].eval(gamma) == expected_h0,
                "Hybrid relin round-1 h0 equation failed",
            );

            let expected_h1 = a_at_gamma * s_at_gamma
                + e1_at_gamma[j]
                + self.r1_h1[idx].eval(gamma) * self.configs.qis[l]
                + self.r2_h1[idx].eval(gamma) * cyclo_at_gamma;
            assert(
                self.h1[idx].eval(gamma) == expected_h1,
                "Hybrid relin round-1 h1 equation failed",
            );
        }
    }
}
