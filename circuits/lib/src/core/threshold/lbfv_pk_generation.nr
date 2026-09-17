// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_lbfv_pk_limb_challenge, compute_lbfv_pk_limb_commitment,
    compute_lbfv_pk_limb_eek_commitment, compute_sc_sk_secret_root_from_polynomial,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// Prove one CRT limb of one l-BFV public-key row.
pub struct LbfvPkGenerationLimb<let N: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    eek_bound: Field,
    sk_bound: Field,
    r1_bound: Field,
    r2_bound: Field,
    qi: Field,
    a: Polynomial<N>,
    row_index: u32,
    limb_index: u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1: Polynomial<2 * N - 1>,
    r2: Polynomial<N - 1>,
    pk0: Polynomial<N>,
}

impl<let N: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> LbfvPkGenerationLimb<N, BIT_EEK, BIT_SK, BIT_R1, BIT_R2, BIT_PK, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        eek_bound: Field,
        sk_bound: Field,
        r1_bound: Field,
        r2_bound: Field,
        qi: Field,
        a: Polynomial<N>,
        row_index: u32,
        limb_index: u32,
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r1: Polynomial<2 * N - 1>,
        r2: Polynomial<N - 1>,
        pk0: Polynomial<N>,
    ) -> Self {
        LbfvPkGenerationLimb {
            eek_bound,
            sk_bound,
            r1_bound,
            r2_bound,
            qi,
            a,
            row_index,
            limb_index,
            eek,
            sk,
            r1,
            r2,
            pk0,
        }
    }

    pub fn execute(self) -> (Field, Field, Field) {
        self.perform_range_checks();

        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let eek_commitment =
            compute_lbfv_pk_limb_eek_commitment::<N, BIT_EEK>(self.row_index, self.eek);
        let pk_limb_commitment =
            compute_lbfv_pk_limb_commitment::<N, BIT_PK>(self.row_index, self.limb_index, self.pk0);
        let gamma = self.generate_challenge(sk_commitment, eek_commitment, pk_limb_commitment);
        self.verify_evaluation(gamma);

        (sk_commitment, eek_commitment, pk_limb_commitment)
    }

    fn perform_range_checks(self) {
        self.eek.range_check_2bounds::<BIT_EEK>(self.eek_bound, self.eek_bound);
        self.sk.range_check_2bounds::<BIT_SK>(self.sk_bound, self.sk_bound);
        self.r1.range_check_2bounds::<BIT_R1>(self.r1_bound, self.r1_bound);
        self.r2.range_check_2bounds::<BIT_R2>(self.r2_bound, self.r2_bound);
    }

    fn generate_challenge(
        self,
        sk_commitment: Field,
        eek_commitment: Field,
        pk_limb_commitment: Field,
    ) -> Field {
        let mut payload = [self.row_index as Field, self.limb_index as Field].as_vector();
        payload = flatten::<_, _, BIT_PK>(payload, [self.a]);
        payload = flatten::<_, _, BIT_EEK>(payload, [self.eek]);
        payload = payload.push_back(sk_commitment);
        payload = payload.push_back(eek_commitment);
        payload = payload.push_back(pk_limb_commitment);
        payload = flatten::<_, _, BIT_R1>(payload, [self.r1]);
        payload = flatten::<_, _, BIT_R2>(payload, [self.r2]);
        payload = payload.push_back(self.qi);
        compute_lbfv_pk_limb_challenge(payload)
    }

    fn verify_evaluation(self, gamma: Field) {
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let expected_pk0 = -self.a.eval(gamma) * self.sk.eval(gamma)
            + self.eek.eval(gamma)
            + self.r2.eval(gamma) * cyclo_at_gamma
            + self.r1.eval(gamma) * self.qi;
        assert(self.pk0.eval(gamma) == expected_pk0, "Public key equation failed");
    }
}

#[test]
fn test_lbfv_pk_generation_limb_accepts_valid_equation() {
    let zero: Polynomial<4> = Polynomial::new([0, 0, 0, 0]);
    let circuit: LbfvPkGenerationLimb<4, 2, 2, 2, 2, 2, 1, 4> = LbfvPkGenerationLimb::new(
        1,
        1,
        1,
        1,
        17,
        zero,
        0,
        0,
        zero,
        zero,
        Polynomial::new([0, 0, 0, 0, 0, 0, 0]),
        Polynomial::new([0, 0, 0]),
        zero,
    );
    let _ = circuit.execute();
}

#[test(should_fail)]
fn test_lbfv_pk_generation_limb_rejects_invalid_equation() {
    let zero: Polynomial<4> = Polynomial::new([0, 0, 0, 0]);
    let circuit: LbfvPkGenerationLimb<4, 2, 2, 2, 2, 2, 1, 4> = LbfvPkGenerationLimb::new(
        1,
        1,
        1,
        1,
        17,
        zero,
        0,
        0,
        zero,
        zero,
        Polynomial::new([0, 0, 0, 0, 0, 0, 0]),
        Polynomial::new([0, 0, 0]),
        Polynomial::new([1, 0, 0, 0]),
    );
    let _ = circuit.execute();
}
