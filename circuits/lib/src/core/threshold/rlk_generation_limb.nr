// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_rlk_limb_challenge, compute_rlk_limb_d0_commitment, compute_rlk_limb_d2_commitment,
    compute_rlk_limb_e0_commitment, compute_rlk_limb_e2_commitment, compute_rlk_r_commitment,
    compute_sc_sk_secret_root_from_polynomial,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// Prove the two RLK equations for one row and one CRT limb.
pub struct RlkGenerationLimb<let N: u32, let BIT_R: u32, let BIT_SK: u32, let BIT_E0: u32, let BIT_E2: u32, let BIT_R1_D0: u32, let BIT_R2_D0: u32, let BIT_R1_D2: u32, let BIT_R2_D2: u32, let BIT_D: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    r_bound: Field,
    sk_bound: Field,
    e0_bound: Field,
    e2_bound: Field,
    r1_d0_bound: Field,
    r2_d0_bound: Field,
    r1_d2_bound: Field,
    r2_d2_bound: Field,
    qi: Field,
    d1: Polynomial<N>,
    a: Polynomial<N>,
    g: Field,
    row_index: u32,
    limb_index: u32,
    sk: Polynomial<N>,
    r: Polynomial<N>,
    e0: Polynomial<N>,
    e2: Polynomial<N>,
    r1_d0: Polynomial<2 * N - 1>,
    r2_d0: Polynomial<N - 1>,
    r1_d2: Polynomial<2 * N - 1>,
    r2_d2: Polynomial<N - 1>,
    d0: Polynomial<N>,
    d2: Polynomial<N>,
}

impl<let N: u32, let BIT_R: u32, let BIT_SK: u32, let BIT_E0: u32, let BIT_E2: u32, let BIT_R1_D0: u32, let BIT_R2_D0: u32, let BIT_R1_D2: u32, let BIT_R2_D2: u32, let BIT_D: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> RlkGenerationLimb<N, BIT_R, BIT_SK, BIT_E0, BIT_E2, BIT_R1_D0, BIT_R2_D0, BIT_R1_D2, BIT_R2_D2, BIT_D, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        r_bound: Field,
        sk_bound: Field,
        e0_bound: Field,
        e2_bound: Field,
        r1_d0_bound: Field,
        r2_d0_bound: Field,
        r1_d2_bound: Field,
        r2_d2_bound: Field,
        qi: Field,
        d1: Polynomial<N>,
        a: Polynomial<N>,
        g: Field,
        row_index: u32,
        limb_index: u32,
        sk: Polynomial<N>,
        r: Polynomial<N>,
        e0: Polynomial<N>,
        e2: Polynomial<N>,
        r1_d0: Polynomial<2 * N - 1>,
        r2_d0: Polynomial<N - 1>,
        r1_d2: Polynomial<2 * N - 1>,
        r2_d2: Polynomial<N - 1>,
        d0: Polynomial<N>,
        d2: Polynomial<N>,
    ) -> Self {
        RlkGenerationLimb {
            r_bound,
            sk_bound,
            e0_bound,
            e2_bound,
            r1_d0_bound,
            r2_d0_bound,
            r1_d2_bound,
            r2_d2_bound,
            qi,
            d1,
            a,
            g,
            row_index,
            limb_index,
            sk,
            r,
            e0,
            e2,
            r1_d0,
            r2_d0,
            r1_d2,
            r2_d2,
            d0,
            d2,
        }
    }

    pub fn execute(self) -> (Field, Field, Field, Field, Field, Field) {
        self.perform_range_checks();

        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let r_commitment = compute_rlk_r_commitment::<N, BIT_R>(self.r);
        let e0_commitment = compute_rlk_limb_e0_commitment::<N, BIT_E0>(self.row_index, self.e0);
        let e2_commitment = compute_rlk_limb_e2_commitment::<N, BIT_E2>(self.row_index, self.e2);
        let d0_limb_commitment =
            compute_rlk_limb_d0_commitment::<N, BIT_D>(self.row_index, self.limb_index, self.d0);
        let d2_limb_commitment =
            compute_rlk_limb_d2_commitment::<N, BIT_D>(self.row_index, self.limb_index, self.d2);

        let gamma = self.generate_challenge(
            sk_commitment,
            r_commitment,
            e0_commitment,
            e2_commitment,
            d0_limb_commitment,
            d2_limb_commitment,
        );
        self.verify_evaluations(gamma);

        (
            sk_commitment, r_commitment, e0_commitment, e2_commitment, d0_limb_commitment,
            d2_limb_commitment,
        )
    }

    fn perform_range_checks(self) {
        self.sk.range_check_2bounds::<BIT_SK>(self.sk_bound, self.sk_bound);
        self.r.range_check_2bounds::<BIT_R>(self.r_bound, self.r_bound);
        self.e0.range_check_2bounds::<BIT_E0>(self.e0_bound, self.e0_bound);
        self.e2.range_check_2bounds::<BIT_E2>(self.e2_bound, self.e2_bound);
        self.r1_d0.range_check_2bounds::<BIT_R1_D0>(self.r1_d0_bound, self.r1_d0_bound);
        self.r2_d0.range_check_2bounds::<BIT_R2_D0>(self.r2_d0_bound, self.r2_d0_bound);
        self.r1_d2.range_check_2bounds::<BIT_R1_D2>(self.r1_d2_bound, self.r1_d2_bound);
        self.r2_d2.range_check_2bounds::<BIT_R2_D2>(self.r2_d2_bound, self.r2_d2_bound);
        self.d0.range_check_2bounds::<BIT_D>(self.r2_d0_bound, self.r2_d0_bound);
        self.d2.range_check_2bounds::<BIT_D>(self.r2_d2_bound, self.r2_d2_bound);
    }

    fn generate_challenge(
        self,
        sk_commitment: Field,
        r_commitment: Field,
        e0_commitment: Field,
        e2_commitment: Field,
        d0_limb_commitment: Field,
        d2_limb_commitment: Field,
    ) -> Field {
        let mut payload = [self.row_index as Field, self.limb_index as Field].as_vector();
        payload = flatten::<_, _, BIT_D>(payload, [self.d1]);
        payload = flatten::<_, _, BIT_D>(payload, [self.a]);
        payload = payload.push_back(self.g);
        payload = payload.push_back(self.qi);
        payload = flatten::<_, _, BIT_E0>(payload, [self.e0]);
        payload = flatten::<_, _, BIT_E2>(payload, [self.e2]);
        payload = payload.push_back(sk_commitment);
        payload = payload.push_back(r_commitment);
        payload = payload.push_back(e0_commitment);
        payload = payload.push_back(e2_commitment);
        payload = payload.push_back(d0_limb_commitment);
        payload = payload.push_back(d2_limb_commitment);
        payload = flatten::<_, _, BIT_R1_D0>(payload, [self.r1_d0]);
        payload = flatten::<_, _, BIT_R2_D0>(payload, [self.r2_d0]);
        payload = flatten::<_, _, BIT_R1_D2>(payload, [self.r1_d2]);
        payload = flatten::<_, _, BIT_R2_D2>(payload, [self.r2_d2]);
        compute_rlk_limb_challenge(payload)
    }

    fn verify_evaluations(self, gamma: Field) {
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let sk_at_gamma = self.sk.eval(gamma);
        let r_at_gamma = self.r.eval(gamma);

        let expected_d0 = -self.d1.eval(gamma) * sk_at_gamma
            + self.e0.eval(gamma)
            + self.g * r_at_gamma
            + self.r2_d0.eval(gamma) * cyclo_at_gamma
            + self.r1_d0.eval(gamma) * self.qi;
        assert(self.d0.eval(gamma) == expected_d0, "RLK d0 equation failed");

        let expected_d2 = self.a.eval(gamma) * r_at_gamma
            + self.e2.eval(gamma)
            + self.g * sk_at_gamma
            + self.r2_d2.eval(gamma) * cyclo_at_gamma
            + self.r1_d2.eval(gamma) * self.qi;
        assert(self.d2.eval(gamma) == expected_d2, "RLK d2 equation failed");
    }
}
