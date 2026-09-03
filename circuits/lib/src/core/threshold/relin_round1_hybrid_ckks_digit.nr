// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::core::threshold::relin_round1_hybrid_ckks::Configs;
use crate::math::commitments::{
    compute_ciphertext_commitment, compute_share_computation_sk_commitment,
    compute_threshold_pk_challenge,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// CKKS HYBRID relinearization round-1 share proof, ONE GADGET DIGIT
/// (C8-CKKS hybrid, per-digit split).
///
/// **Role:** The whole-share circuit (`RelinRound1Hybrid`) proves all
/// `D * LT` rows in one statement, which does not fit memory at the
/// ParamSet-2 shape (`D = 13`, `LT = 41`). This circuit proves the rows of
/// ONE digit `j` (`h0[j][l]`, `h1[j][l]` for every limb `l` of `Q·P`); the
/// `D` per-digit proofs are bound together by the PUBLIC `s` and `u`
/// commitments, which every proof must reproduce from its private `s`/`u`
/// witnesses — so one party's `D` proofs attest to one share under one
/// secret pair. The digit index is public too: the gadget row
/// `(P·g_j) mod q_l` comes from the config table (`Configs<D, LT>`), so a
/// prover cannot pick a convenient row.
///
/// **Verifies** for every limb `l` at the FS challenge `gamma`:
/// - `h0[l] = -a[l]*u + gadget[j][l]*s + e0 + r1_h0[l]*q_l + r2_h0[l]*cyclo`
/// - `h1[l] = a[l]*s + e1 + r1_h1[l]*q_l + r2_h1[l]*cyclo`
/// - `s_commitment == commit(s)`, `u_commitment == commit(u)` (public inputs)
///
/// **Produces:** `commit(h0[j] || h1[j])` — the per-digit share commitment;
/// the verifier links the `D` outputs to the published share.
pub struct RelinRound1HybridDigit<let N: u32, let D: u32, let LT: u32, let BIT_A: u32, let BIT_SK: u32, let BIT_U: u32, let BIT_E: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_H: u32> {
    /// Cryptographic parameters (full gadget table; this proof reads row `digit`).
    configs: Configs<D, LT>,
    /// Expected commitment to `s` (public input, shared by all digit proofs).
    s_commitment: Field,
    /// Expected commitment to `u` (public input, shared by all digit proofs).
    u_commitment: Field,
    /// The gadget digit this proof covers (public input, `< D`).
    digit: Field,
    /// CRP limbs of digit `j` (public witnesses): a[l] = limb l of CRP j.
    a: [Polynomial<N>; LT],
    /// This party's secret key share polynomial (secret witness, small).
    s: Polynomial<N>,
    /// This party's ephemeral secret polynomial (secret witness, small).
    u: Polynomial<N>,
    /// Error polynomial of the h0 leg for digit j.
    e0: Polynomial<N>,
    /// Error polynomial of the h1 leg for digit j.
    e1: Polynomial<N>,
    r1_h0: [Polynomial<2 * N - 1>; LT],
    r2_h0: [Polynomial<N - 1>; LT],
    r1_h1: [Polynomial<2 * N - 1>; LT],
    r2_h1: [Polynomial<N - 1>; LT],
    /// Published round-1 share rows of digit j (committed witnesses).
    h0: [Polynomial<N>; LT],
    h1: [Polynomial<N>; LT],
}

impl<let N: u32, let D: u32, let LT: u32, let BIT_A: u32, let BIT_SK: u32, let BIT_U: u32, let BIT_E: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_H: u32> RelinRound1HybridDigit<N, D, LT, BIT_A, BIT_SK, BIT_U, BIT_E, BIT_R1, BIT_R2, BIT_H> {
    pub fn new(
        configs: Configs<D, LT>,
        s_commitment: Field,
        u_commitment: Field,
        digit: Field,
        a: [Polynomial<N>; LT],
        s: Polynomial<N>,
        u: Polynomial<N>,
        e0: Polynomial<N>,
        e1: Polynomial<N>,
        r1_h0: [Polynomial<2 * N - 1>; LT],
        r2_h0: [Polynomial<N - 1>; LT],
        r1_h1: [Polynomial<2 * N - 1>; LT],
        r2_h1: [Polynomial<N - 1>; LT],
        h0: [Polynomial<N>; LT],
        h1: [Polynomial<N>; LT],
    ) -> Self {
        RelinRound1HybridDigit {
            configs,
            s_commitment,
            u_commitment,
            digit,
            a,
            s,
            u,
            e0,
            e1,
            r1_h0,
            r2_h0,
            r1_h1,
            r2_h1,
            h0,
            h1,
        }
    }

    /// Fiat-Shamir transcript: same layout as the whole-share circuit for
    /// one digit, plus the digit index so transcripts of different digits
    /// never collide.
    fn payload(self, share_commitment: Field) -> [Field] {
        let mut inputs: [Field] = [].as_vector();

        inputs = inputs.push_back(self.digit);
        inputs = flatten::<_, _, BIT_A>(inputs, self.a);
        inputs = flatten::<_, _, BIT_E>(inputs, [self.e0]);
        inputs = flatten::<_, _, BIT_E>(inputs, [self.e1]);

        inputs = inputs.push_back(self.s_commitment);
        inputs = inputs.push_back(self.u_commitment);
        inputs = inputs.push_back(share_commitment);

        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1_h0);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2_h0);
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1_h1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2_h1);

        inputs
    }

    /// Executes the per-digit circuit. Returns `commit(h0[j] || h1[j])`.
    pub fn execute(self) -> Field {
        self.perform_range_checks();

        // The public commitments MUST be reproduced from the private s / u:
        // this is what links the D digit proofs to one secret pair.
        let s_commitment = compute_share_computation_sk_commitment::<N, BIT_SK>(self.s);
        let u_commitment = compute_share_computation_sk_commitment::<N, BIT_U>(self.u);
        assert(s_commitment == self.s_commitment, "s commitment mismatch");
        assert(u_commitment == self.u_commitment, "u commitment mismatch");

        let share_commitment = compute_ciphertext_commitment::<N, LT, BIT_H>(self.h0, self.h1);

        let gamma = compute_threshold_pk_challenge(self.payload(share_commitment));
        self.verify_evaluations(gamma);

        share_commitment
    }

    fn perform_range_checks(self) {
        self.s.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);
        self.u.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e0.range_check_2bounds::<BIT_E>(self.configs.e_bound, self.configs.e_bound);
        self.e1.range_check_2bounds::<BIT_E>(self.configs.e_bound, self.configs.e_bound);

        for l in 0..LT {
            self.r1_h0[l].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[l],
                self.configs.r1_bounds[l],
            );
            self.r2_h0[l].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[l],
                self.configs.r2_bounds[l],
            );
            self.r1_h1[l].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[l],
                self.configs.r1_bounds[l],
            );
            self.r2_h1[l].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[l],
                self.configs.r2_bounds[l],
            );
        }
    }

    /// The gadget row of this proof's digit, read from the config table at
    /// the PUBLIC index (`digit < D` enforced).
    fn gadget_row(self) -> [Field; LT] {
        let j = self.digit as u32;
        assert(j < D, "digit index out of range");
        let mut row = [0; LT];
        for l in 0..LT {
            row[l] = self.configs.gadget[j * LT + l];
        }
        row
    }

    fn verify_evaluations(self, gamma: Field) {
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let s_at_gamma = self.s.eval(gamma);
        let u_at_gamma = self.u.eval(gamma);
        let e0_at_gamma = self.e0.eval(gamma);
        let e1_at_gamma = self.e1.eval(gamma);
        let gadget = self.gadget_row();

        for l in 0..LT {
            let a_at_gamma = self.a[l].eval(gamma);

            let expected_h0 = -a_at_gamma * u_at_gamma
                + gadget[l] * s_at_gamma
                + e0_at_gamma
                + self.r1_h0[l].eval(gamma) * self.configs.qis[l]
                + self.r2_h0[l].eval(gamma) * cyclo_at_gamma;
            assert(
                self.h0[l].eval(gamma) == expected_h0,
                "Hybrid relin round-1 digit h0 equation failed",
            );

            let expected_h1 = a_at_gamma * s_at_gamma
                + e1_at_gamma
                + self.r1_h1[l].eval(gamma) * self.configs.qis[l]
                + self.r2_h1[l].eval(gamma) * cyclo_at_gamma;
            assert(
                self.h1[l].eval(gamma) == expected_h1,
                "Hybrid relin round-1 digit h1 equation failed",
            );
        }
    }
}
