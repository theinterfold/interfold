// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_rlk_d0_commitment, compute_rlk_d2_commitment, compute_rlk_generation_challenge,
    compute_rlk_r_commitment, compute_sc_sk_secret_root_from_polynomial,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// Parameters for l-BFV relinearization key generation (new circuit, row-level).
pub struct Configs<let N: u32, let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bound for the ephemeral `r` polynomial coefficients (same distribution as `sk`).
    pub r_bound: Field,
    /// Bound for secret key polynomial (`sk`) coefficients.
    pub sk_bound: Field,
    /// Bound for `e0` (d0's error) coefficients.
    pub e0_bound: Field,
    /// Bound for `e2` (d2's error) coefficients.
    pub e2_bound: Field,
    /// Bounds for r1_d0 (d0 modulus-switching quotients) for each CRT basis.
    pub r1_d0_bounds: [Field; L],
    /// Bounds for r2_d0 (d0 cyclotomic-reduction quotients) for each CRT basis.
    pub r2_d0_bounds: [Field; L],
    /// Bounds for r1_d2 (d2 modulus-switching quotients) for each CRT basis.
    pub r1_d2_bounds: [Field; L],
    /// Bounds for r2_d2 (d2 cyclotomic-reduction quotients) for each CRT basis.
    pub r2_d2_bounds: [Field; L],
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        r_bound: Field,
        sk_bound: Field,
        e0_bound: Field,
        e2_bound: Field,
        r1_d0_bounds: [Field; L],
        r2_d0_bounds: [Field; L],
        r1_d2_bounds: [Field; L],
        r2_d2_bounds: [Field; L],
    ) -> Self {
        Configs {
            qis,
            r_bound,
            sk_bound,
            e0_bound,
            e2_bound,
            r1_d0_bounds,
            r2_d0_bounds,
            r1_d2_bounds,
            r2_d2_bounds,
        }
    }
}

/// l-BFV relinearization key contribution for one gadget row (new circuit,
/// analogous to `pk_generation` (C1) but for the RLK's `(d0, d2)` pair).
///
/// **Role:** Prove one party's row-`j` RLK contribution from hidden `sk`, `r`,
/// `e0`, `e2`, and quotients. `d1` is the row's URS; `a` is the CRS - the SAME
/// `a` used by `pk_generation` for this row (critical linkage: caller must pass
/// the identical CRS to both circuits for a given row).
///
/// **Verifies:** Range checks on witnesses; evaluation form of
/// `d0 = -d1*sk + e0 + g*r` and `d2 = a*r + e2 + g*sk` at the FS challenge,
/// per CRT limb (`g` is a public per-row scalar, the Garner gadget coefficient).
///
/// **Produces (tuple order):**
/// - `commit(sk)` -> must match the same row's C1 `sk_commitment` (same party, same sk).
/// - `commit(r)` -> must match all RLK rows from the same party.
/// - `commit(d0)` -> RLK aggregation.
/// - `commit(d2)` -> RLK aggregation.
pub struct RlkGeneration<let N: u32, let L: u32, let BIT_R: u32, let BIT_SK: u32, let BIT_E0: u32, let BIT_E2: u32, let BIT_R1_D0: u32, let BIT_R2_D0: u32, let BIT_R1_D2: u32, let BIT_R2_D2: u32, let BIT_D: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    configs: Configs<N, L>,

    /// URS polynomials for this row (public witnesses), one per modulus.
    d1: [Polynomial<N>; L],
    /// CRS polynomials for this row (public witnesses), one per modulus - must
    /// be the same `a` passed to `pk_generation` for this row.
    a: [Polynomial<N>; L],
    /// Garner gadget scalar for this row (public constant).
    g: Field,

    /// Secret key polynomial (secret witness) - same `sk` as this row's C1 proof.
    sk: Polynomial<N>,
    /// Ephemeral secret polynomial (secret witness), sampled like `sk`.
    r: Polynomial<N>,
    /// Error polynomial for the d0 equation (secret witness), shared across
    /// this row's L limbs (mirrors how `pk_generation` shares `eek`).
    e0: Polynomial<N>,
    /// Error polynomial for the d2 equation (secret witness), shared across
    /// this row's L limbs.
    e2: Polynomial<N>,

    /// Quotients from the d0 equation (secret witnesses).
    r1_d0: [Polynomial<2 * N - 1>; L],
    r2_d0: [Polynomial<N - 1>; L],
    /// Quotients from the d2 equation (secret witnesses).
    r1_d2: [Polynomial<2 * N - 1>; L],
    r2_d2: [Polynomial<N - 1>; L],

    /// RLK `d0` component per modulus (committed witness).
    d0: [Polynomial<N>; L],
    /// RLK `d2` component per modulus (committed witness).
    d2: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_R: u32, let BIT_SK: u32, let BIT_E0: u32, let BIT_E2: u32, let BIT_R1_D0: u32, let BIT_R2_D0: u32, let BIT_R1_D2: u32, let BIT_R2_D2: u32, let BIT_D: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> RlkGeneration<N, L, BIT_R, BIT_SK, BIT_E0, BIT_E2, BIT_R1_D0, BIT_R2_D0, BIT_R1_D2, BIT_R2_D2, BIT_D, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        configs: Configs<N, L>,
        d1: [Polynomial<N>; L],
        a: [Polynomial<N>; L],
        g: Field,
        sk: Polynomial<N>,
        r: Polynomial<N>,
        e0: Polynomial<N>,
        e2: Polynomial<N>,
        r1_d0: [Polynomial<2 * N - 1>; L],
        r2_d0: [Polynomial<N - 1>; L],
        r1_d2: [Polynomial<2 * N - 1>; L],
        r2_d2: [Polynomial<N - 1>; L],
        d0: [Polynomial<N>; L],
        d2: [Polynomial<N>; L],
    ) -> Self {
        RlkGeneration { configs, d1, a, g, sk, r, e0, e2, r1_d0, r2_d0, r1_d2, r2_d2, d0, d2 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation.
    fn payload(
        self,
        sk_commitment: Field,
        r_commitment: Field,
        d0_commitment: Field,
        d2_commitment: Field,
    ) -> [Field] {
        let mut inputs: [Field] = [].as_vector();

        inputs = flatten::<_, _, BIT_D>(inputs, self.d1);
        inputs = flatten::<_, _, BIT_D>(inputs, self.a);
        inputs = inputs.push_back(self.g);

        inputs = flatten::<_, _, BIT_E0>(inputs, [self.e0]);
        inputs = flatten::<_, _, BIT_E2>(inputs, [self.e2]);

        inputs = inputs.push_back(sk_commitment);
        inputs = inputs.push_back(r_commitment);
        inputs = inputs.push_back(d0_commitment);
        inputs = inputs.push_back(d2_commitment);

        inputs = flatten::<_, _, BIT_R1_D0>(inputs, self.r1_d0);
        inputs = flatten::<_, _, BIT_R2_D0>(inputs, self.r2_d0);
        inputs = flatten::<_, _, BIT_R1_D2>(inputs, self.r1_d2);
        inputs = flatten::<_, _, BIT_R2_D2>(inputs, self.r2_d2);

        inputs
    }

    /// Executes the l-BFV RLK generation circuit for one gadget row.
    ///
    /// Returns `(commit(sk), commit(r), commit(d0), commit(d2))` as documented on the struct.
    pub fn execute(self) -> (Field, Field, Field, Field) {
        // Step 1: Range-check secret witnesses (sk, r, e0, e2, quotients).
        self.perform_range_checks();

        // Step 2: Derive commitments for the FS transcript.
        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let r_commitment = compute_rlk_r_commitment::<N, BIT_R>(self.r);
        let d0_commitment = compute_rlk_d0_commitment::<N, L, BIT_D>(self.d0);
        let d2_commitment = compute_rlk_d2_commitment::<N, L, BIT_D>(self.d2);

        // Step 3: Fiat-Shamir challenge and per-modulus evaluation checks.
        let gamma =
            self.generate_challenge(sk_commitment, r_commitment, d0_commitment, d2_commitment);
        self.verify_evaluations(gamma);

        // Step 4: Return commitments for downstream circuits.
        (sk_commitment, r_commitment, d0_commitment, d2_commitment)
    }

    /// Generates the Fiat-Shamir challenge using the SAFE cryptographic sponge.
    fn generate_challenge(
        self,
        sk_commitment: Field,
        r_commitment: Field,
        d0_commitment: Field,
        d2_commitment: Field,
    ) -> Field {
        let inputs = self.payload(sk_commitment, r_commitment, d0_commitment, d2_commitment);

        compute_rlk_generation_challenge(inputs)
    }

    /// Performs range checks on all secret witness values.
    fn perform_range_checks(self) {
        self.sk.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);
        self.r.range_check_2bounds::<BIT_R>(self.configs.r_bound, self.configs.r_bound);
        self.e0.range_check_2bounds::<BIT_E0>(self.configs.e0_bound, self.configs.e0_bound);
        self.e2.range_check_2bounds::<BIT_E2>(self.configs.e2_bound, self.configs.e2_bound);

        for i in 0..L {
            self.d0[i].range_check_2bounds::<BIT_D>(
                self.configs.r2_d0_bounds[i],
                self.configs.r2_d0_bounds[i],
            );
            self.d2[i].range_check_2bounds::<BIT_D>(
                self.configs.r2_d2_bounds[i],
                self.configs.r2_d2_bounds[i],
            );
            self.r1_d0[i].range_check_2bounds::<BIT_R1_D0>(
                self.configs.r1_d0_bounds[i],
                self.configs.r1_d0_bounds[i],
            );
            self.r2_d0[i].range_check_2bounds::<BIT_R2_D0>(
                self.configs.r2_d0_bounds[i],
                self.configs.r2_d0_bounds[i],
            );
            self.r1_d2[i].range_check_2bounds::<BIT_R1_D2>(
                self.configs.r1_d2_bounds[i],
                self.configs.r1_d2_bounds[i],
            );
            self.r2_d2[i].range_check_2bounds::<BIT_R2_D2>(
                self.configs.r2_d2_bounds[i],
                self.configs.r2_d2_bounds[i],
            );
        }
    }

    /// Verifies l-BFV RLK generation equations for all CRT moduli using Schwartz-Zippel.
    ///
    /// For each CRT modulus i, verifies at the challenge point gamma:
    /// - `d0[i](gamma) = -d1[i](gamma)*sk(gamma) + e0(gamma) + g*r(gamma)
    ///                    + r2_d0[i](gamma)*(gamma^N + 1) + r1_d0[i](gamma) * q_i`
    /// - `d2[i](gamma) = a[i](gamma)*r(gamma) + e2(gamma) + g*sk(gamma)
    ///                    + r2_d2[i](gamma)*(gamma^N + 1) + r1_d2[i](gamma) * q_i`
    fn verify_evaluations(self, gamma: Field) {
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let sk_at_gamma = self.sk.eval(gamma);
        let r_at_gamma = self.r.eval(gamma);
        let e0_at_gamma = self.e0.eval(gamma);
        let e2_at_gamma = self.e2.eval(gamma);

        for i in 0..L {
            let expected_d0 = -self.d1[i].eval(gamma) * sk_at_gamma
                + e0_at_gamma
                + self.g * r_at_gamma
                + self.r2_d0[i].eval(gamma) * cyclo_at_gamma
                + self.r1_d0[i].eval(gamma) * self.configs.qis[i];

            assert(self.d0[i].eval(gamma) == expected_d0, "RLK d0 equation failed");

            let expected_d2 = self.a[i].eval(gamma) * r_at_gamma
                + e2_at_gamma
                + self.g * sk_at_gamma
                + self.r2_d2[i].eval(gamma) * cyclo_at_gamma
                + self.r1_d2[i].eval(gamma) * self.configs.qis[i];

            assert(self.d2[i].eval(gamma) == expected_d2, "RLK d2 equation failed");
        }
    }
}
