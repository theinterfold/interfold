// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User-data encryption - ct1 leg (P3).
//!
//! See `UserDataEncryptionCt1` for the circuit contract.

use crate::math::commitments::compute_multiple_polynomial_commitment;
use crate::math::commitments::compute_single_polynomial_commitment;
use crate::math::commitments::compute_user_data_encryption_ct1_challenge;
use crate::math::commitments::DS_CIPHERTEXT;
use crate::math::commitments::DS_PK_AGGREGATION;
use crate::math::commitments::DS_USER_DATA_ENCRYPTION_COMMITMENT;
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;
use crate::math::secure_arithmetic::{
    append, centered, challenge, dot, fold_negacyclic, kernel, parameters,
};

/// Parameters for user-data encryption ct1 (P3).
pub struct Configs<let N: u32, let L: u32> {
    pub qis: [Field; L],
    pub e1_bound: Field,
    pub u_bound: Field,
    pub p1_bounds: [Field; L],
    pub p2_bounds: [Field; L],
}
impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        e1_bound: Field,
        u_bound: Field,
        p1_bounds: [Field; L],
        p2_bounds: [Field; L],
    ) -> Self {
        Configs { qis, e1_bound, u_bound, p1_bounds, p2_bounds }
    }
}

/// User-data encryption ct1 (P3).
///
/// **Role:** Second ciphertext leg; `u` must match the ct0 `u_commitment`.
///
/// **Produces:** `(pk1_commitment, ct1_commitment, u_commitment)` public outputs.
pub struct UserDataEncryptionCt1<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_P1: u32, let BIT_P2: u32> {
    configs: Configs<N, L>,
    pk1is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    /// Re-witnessed privately; checked against `u_commitment` from ct0 (same P3 flow).
    u: Polynomial<N>,
    e1: Polynomial<N>,
    p1is: [Polynomial<(2 * N) - 1>; L],
    p2is: [Polynomial<N - 1>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_P1: u32, let BIT_P2: u32> UserDataEncryptionCt1<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E1, BIT_P1, BIT_P2> {

    pub fn new(
        configs: Configs<N, L>,
        pk1is: [Polynomial<N>; L],
        ct1is: [Polynomial<N>; L],
        u: Polynomial<N>,
        e1: Polynomial<N>,
        p1is: [Polynomial<2 * N - 1>; L],
        p2is: [Polynomial<N - 1>; L],
    ) -> Self {
        UserDataEncryptionCt1 { configs, pk1is, ct1is, u, e1, p1is, p2is }
    }

    fn check_range_bounds(self) {
        self.e1.range_check_2bounds::<BIT_E1>(self.configs.e1_bound, self.configs.e1_bound);

        for i in 0..L {
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

    fn generate_commitments(self) -> (Field, Field, Field) {
        let pk1_commitment =
            compute_multiple_polynomial_commitment::<N, L, BIT_PK>(self.pk1is, DS_PK_AGGREGATION);
        let ct1_commitment =
            compute_multiple_polynomial_commitment::<N, L, BIT_CT>(self.ct1is, DS_CIPHERTEXT);
        let u_commitment = compute_single_polynomial_commitment::<N, BIT_U>(
            self.u,
            DS_USER_DATA_ENCRYPTION_COMMITMENT,
        );

        (pk1_commitment, ct1_commitment, u_commitment)
    }

    fn generate_challenge(
        self,
        pk1_commitment: Field,
        ct1_commitment: Field,
        u_commitment: Field,
    ) -> [Field] {
        let mut payload = [pk1_commitment, ct1_commitment, u_commitment].as_vector();

        payload = flatten::<_, _, BIT_E1>(payload, [self.e1]);
        payload = flatten::<_, _, BIT_P1>(payload, self.p1is);
        payload = flatten::<_, _, BIT_P2>(payload, self.p2is);

        compute_user_data_encryption_ct1_challenge::<L>(payload)
    }

    fn verify_evaluations(self, gammas: [Field]) -> bool {
        let gamma = gammas[0];
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let u_at_gamma = self.u.eval(gamma);
        let e1_at_gamma = self.e1.eval(gamma);

        let mut sum = (0, 0);
        for i in 0..L {
            let pk1is_at_gamma = self.pk1is[i].eval(gamma);
            let p1is_at_gamma = self.p1is[i].eval(gamma);
            let p2is_at_gamma = self.p2is[i].eval(gamma);

            let mut ct1_rhs = pk1is_at_gamma * u_at_gamma + e1_at_gamma;
            ct1_rhs += p1is_at_gamma * self.configs.qis[i];
            ct1_rhs += p2is_at_gamma * cyclo_at_gamma;

            let ct1_lhs = self.ct1is[i].eval(gamma);
            let gamma_i = gammas[i + L];

            sum = (sum.0 + ct1_lhs * gamma_i, sum.1 + ct1_rhs * gamma_i);
        }

        sum.0 == sum.1
    }

    /// Returns `(pk1_commitment, ct1_commitment, u_commitment)`.
    pub fn execute(self) -> (Field, Field, Field) {
        if (N == 8192) & (L == 3) {
            let mut q_short = [Polynomial::new([0; N]); L];
            for l in 0..L {
                q_short[l] = fold_negacyclic(self.p1is[l]);
            }
            // This path accepts arbitrary public keys. Do not select the fixed-CRP specialization.
            prove_secure::<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E1>(
                self.configs,
                self.pk1is,
                self.ct1is,
                self.u,
                self.e1,
                q_short,
            )
        } else {
            // Step 1: Witness bounds.
            self.check_range_bounds();

            // Step 2: Commitments for the FS transcript.
            let (pk1_commitment, ct1_commitment, u_commitment) = self.generate_commitments();

            // Step 3: Fiat-Shamir challenge and evaluation check of ct1 equations.
            let gammas = self.generate_challenge(pk1_commitment, ct1_commitment, u_commitment);

            assert(self.verify_evaluations(gammas), "ct1 encryption check failed");

            (pk1_commitment, ct1_commitment, u_commitment)
        }
    }
}

fn prove_secure<let N: u32, let L: u32, let BP: u32, let BC: u32, let BU: u32, let BE: u32>(
    configs: Configs<N, L>,
    pk1: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
    u: Polynomial<N>,
    e1: Polynomial<N>,
    q_short: [Polynomial<N>; L],
) -> (Field, Field, Field) {
    parameters::<N, L>(configs.qis);
    assert(configs.u_bound == 1);
    assert(configs.e1_bound == 20);
    assert(BU == 1);
    assert(BE == 5);
    u.range_check_2bounds::<BU>(1, 1);
    e1.range_check_2bounds::<BE>(20, 20);
    for l in 0..L {
        centered(pk1[l], configs.qis[l]);
        centered(ct1[l], configs.qis[l]);
        for j in 0..N {
            (q_short[l].coefficients[j] + 8192).assert_max_bit_size::<14>();
        }
    }
    let pc = compute_multiple_polynomial_commitment::<N, L, BP>(pk1, DS_PK_AGGREGATION);
    let cc = compute_multiple_polynomial_commitment::<N, L, BC>(ct1, DS_CIPHERTEXT);
    let uc = compute_single_polynomial_commitment::<N, BU>(u, DS_USER_DATA_ENCRYPTION_COMMITMENT);
    let mut payload = [131, N as Field, L as Field, pc, cc, uc, 0].as_vector();
    payload = append::<N, 6>(payload, e1, 20);
    for l in 0..L {
        payload = payload.push_back(configs.qis[l]);
        payload = append::<N, 14>(payload, q_short[l], 8192);
    }
    let x = challenge(payload);
    let k = kernel(u, x);
    for l in 0..L {
        let mut residual = [0; N];
        for j in 0..N {
            residual[j] = ct1[l].coefficients[j]
                - e1.coefficients[j]
                - configs.qis[l] * q_short[l].coefficients[j];
        }
        assert(Polynomial::new(residual).eval(x) == dot(pk1[l], k));
    }
    (pc, cc, uc)
}
