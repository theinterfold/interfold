// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User-data encryption - ct0 leg (P3).
//!
//! See `UserDataEncryptionCt0` for the circuit contract.

use crate::math::commitments::compute_multiple_polynomial_commitment;
use crate::math::commitments::compute_single_polynomial_commitment;
use crate::math::commitments::compute_user_data_encryption_ct0_challenge;
use crate::math::commitments::DS_CIPHERTEXT;
use crate::math::commitments::DS_PK_AGGREGATION;
use crate::math::commitments::DS_USER_DATA_ENCRYPTION_COMMITMENT;
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;
use crate::math::secure_arithmetic::{
    append, centered, challenge, dot, fold_negacyclic, kernel, parameters,
};

/// Parameters for user-data encryption ct0 (P3).
pub struct Configs<let N: u32, let L: u32> {
    pub qis: [Field; L],
    pub k0is: [Field; L],
    pub e0_bound: Field,
    pub u_bound: Field,
    pub r1_low_bounds: [Field; L],
    pub r1_up_bounds: [Field; L],
    pub r2_bounds: [Field; L],
    pub k1_low_bound: Field,
    pub k1_up_bound: Field,
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        k0is: [Field; L],
        e0_bound: Field,
        u_bound: Field,
        r1_low_bounds: [Field; L],
        r1_up_bounds: [Field; L],
        r2_bounds: [Field; L],
        k1_low_bound: Field,
        k1_up_bound: Field,
    ) -> Self {
        Configs {
            qis,
            k0is,
            e0_bound,
            u_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            k1_low_bound,
            k1_up_bound,
        }
    }
}

/// User-data encryption ct0 (P3).
///
/// **Role:** Prove the first ciphertext leg and publish `pk0`, `ct0`, `k1`, and `u` commitments
/// for the wrapper and ct1 circuit.
///
/// **Consumes:** Threshold PK from C5 (`pk0is` witness path).
///
/// **Produces:** `(pk0_commitment, ct0_commitment, k1_commitment, u_commitment)` public outputs.
pub struct UserDataEncryptionCt0<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32> {
    configs: Configs<N, L>,
    /// Aggregated threshold `pk0` limb (from C5).
    pk0is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e0is: [Polynomial<N>; L],
    e0_quotients: [Polynomial<N>; L],
    k1: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32> UserDataEncryptionCt0<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_K, BIT_R1, BIT_R2> {

    pub fn new(
        configs: Configs<N, L>,
        pk0is: [Polynomial<N>; L],
        ct0is: [Polynomial<N>; L],
        u: Polynomial<N>,
        e0: Polynomial<N>,
        e0is: [Polynomial<N>; L],
        e0_quotients: [Polynomial<N>; L],
        k1: Polynomial<N>,
        r1is: [Polynomial<(2 * N) - 1>; L],
        r2is: [Polynomial<N - 1>; L],
    ) -> Self {
        UserDataEncryptionCt0 { configs, pk0is, ct0is, u, e0, e0is, e0_quotients, k1, r1is, r2is }
    }

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

    fn check_range_bounds(self) {
        self.u.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e0.range_check_2bounds::<BIT_E0>(self.configs.e0_bound, self.configs.e0_bound);
        self.k1.range_check_2bounds::<BIT_K>(self.configs.k1_up_bound, self.configs.k1_low_bound);

        for i in 0..L {
            self.r1is[i].range_check_2bounds::<BIT_R1>(
                self.configs.r1_up_bounds[i],
                self.configs.r1_low_bounds[i],
            );
            self.r2is[i].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[i],
                self.configs.r2_bounds[i],
            );
        }
    }

    fn generate_commitments(self) -> (Field, Field, Field, Field) {
        let pk0_commitment =
            compute_multiple_polynomial_commitment::<N, L, BIT_PK>(self.pk0is, DS_PK_AGGREGATION);
        let ct0_commitment =
            compute_multiple_polynomial_commitment::<N, L, BIT_CT>(self.ct0is, DS_CIPHERTEXT);
        let k1_commitment = compute_single_polynomial_commitment::<N, BIT_K>(
            self.k1,
            DS_USER_DATA_ENCRYPTION_COMMITMENT,
        );
        let u_commitment = compute_single_polynomial_commitment::<N, BIT_U>(
            self.u,
            DS_USER_DATA_ENCRYPTION_COMMITMENT,
        );

        (pk0_commitment, ct0_commitment, k1_commitment, u_commitment)
    }

    fn generate_challenge(
        self,
        pk0_commitment: Field,
        ct0_commitment: Field,
        k1_commitment: Field,
        u_commitment: Field,
    ) -> [Field] {
        let mut payload = [pk0_commitment, ct0_commitment, k1_commitment, u_commitment].as_vector();

        payload = flatten::<_, _, BIT_E0>(payload, [self.e0]);
        payload = flatten::<_, _, BIT_R1>(payload, self.r1is);
        payload = flatten::<_, _, BIT_R2>(payload, self.r2is);

        let gammas = compute_user_data_encryption_ct0_challenge::<L>(payload);

        gammas
    }

    fn verify_evaluations(self, gammas: [Field]) -> bool {
        let gamma = gammas[0];
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let u_at_gamma = self.u.eval(gamma);
        let k1_at_gamma = self.k1.eval(gamma);

        let mut sum = (0, 0);
        for i in 0..L {
            let pk0is_at_gamma = self.pk0is[i].eval(gamma);
            let r1i_at_gamma = self.r1is[i].eval(gamma);
            let r2i_at_gamma = self.r2is[i].eval(gamma);
            let e0is_at_gamma = self.e0is[i].eval(gamma);

            let mut ct0_rhs = pk0is_at_gamma * u_at_gamma + e0is_at_gamma;
            ct0_rhs += k1_at_gamma * self.configs.k0is[i];
            ct0_rhs += r1i_at_gamma * self.configs.qis[i];
            ct0_rhs += r2i_at_gamma * cyclo_at_gamma;

            let ct0_lhs = self.ct0is[i].eval(gamma);
            let gamma_i = if i == 0 { 1 } else { gammas[i] };

            sum = (sum.0 + ct0_lhs * gamma_i, sum.1 + ct0_rhs * gamma_i);
        }

        sum.0 == sum.1
    }

    /// Returns `(pk0_commitment, ct0_commitment, k1_commitment, u_commitment)`.
    pub fn execute(self) -> (Field, Field, Field, Field) {
        if (N == 8192) & (L == 3) {
            self.check_e0_crt_consistency();
            let mut q_short = [Polynomial::new([0; N]); L];
            for l in 0..L {
                q_short[l] = fold_negacyclic(self.r1is[l]).sub(self.e0_quotients[l]);
            }
            if BIT_E0 > 80 {
                prove_secure::<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_K, BIT_E0 - 54>(
                    self.configs,
                    self.pk0is,
                    self.ct0is,
                    self.u,
                    self.e0,
                    self.k1,
                    q_short,
                )
            } else {
                prove_secure::<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_K, 26>(
                    self.configs,
                    self.pk0is,
                    self.ct0is,
                    self.u,
                    self.e0,
                    self.k1,
                    q_short,
                )
            }
        } else {
            // Step 1: Witness bounds and CRT consistency of `e0`.
            self.check_range_bounds();
            self.check_e0_crt_consistency();

            // Step 2: Domain-separated commitments for the FS transcript.
            let (pk0_commitment, ct0_commitment, k1_commitment, u_commitment) =
                self.generate_commitments();

            // Step 3: Fiat-Shamir challenge and batched evaluation check of ct0 equations.
            let gammas = self.generate_challenge(
                pk0_commitment,
                ct0_commitment,
                k1_commitment,
                u_commitment,
            );

            assert(self.verify_evaluations(gammas), "ct0 encryption check failed");

            (pk0_commitment, ct0_commitment, k1_commitment, u_commitment)
        }
    }
}

fn prove_secure<let N: u32, let L: u32, let BP: u32, let BC: u32, let BU: u32, let BE: u32, let BK: u32, let R: u32>(
    configs: Configs<N, L>,
    pk0: [Polynomial<N>; L],
    ct0: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    k1: Polynomial<N>,
    q_short: [Polynomial<N>; L],
) -> (Field, Field, Field, Field) {
    parameters::<N, L>(configs.qis);
    assert(configs.u_bound == 1);
    assert(BU == 1);
    assert(BE <= 180);
    assert(BK <= 22);
    assert(R >= 26);
    assert(R + 54 >= BE);
    assert(R <= 128);
    configs.e0_bound.assert_max_bit_size::<BE>();
    configs.k1_up_bound.assert_max_bit_size::<BK>();
    configs.k1_low_bound.assert_max_bit_size::<BK>();
    u.range_check_2bounds::<BU>(1, 1);
    // This is the LARGE threshold-encryption error, not C3's 20-coefficient error.
    e0.range_check_2bounds::<BE>(configs.e0_bound, configs.e0_bound);
    k1.range_check_2bounds::<BK>(configs.k1_up_bound, configs.k1_low_bound);
    let offset = 2.pow_32((R - 1) as Field);
    for l in 0..L {
        centered(pk0[l], configs.qis[l]);
        centered(ct0[l], configs.qis[l]);
        assert((configs.k0is[l] as u64) < (configs.qis[l] as u64));
        for j in 0..N {
            (q_short[l].coefficients[j] + offset).assert_max_bit_size::<R>();
        }
    }
    let pc = compute_multiple_polynomial_commitment::<N, L, BP>(pk0, DS_PK_AGGREGATION);
    let cc = compute_multiple_polynomial_commitment::<N, L, BC>(ct0, DS_CIPHERTEXT);
    let kc = compute_single_polynomial_commitment::<N, BK>(k1, DS_USER_DATA_ENCRYPTION_COMMITMENT);
    let uc = compute_single_polynomial_commitment::<N, BU>(u, DS_USER_DATA_ENCRYPTION_COMMITMENT);
    let mut payload = [130, N as Field, L as Field, R as Field, pc, cc, kc, uc].as_vector();
    payload = append::<N, BE + 1>(payload, e0, configs.e0_bound);
    for l in 0..L {
        payload = payload.push_back(configs.qis[l]);
        payload = payload.push_back(configs.k0is[l]);
        payload = append::<N, R>(payload, q_short[l], offset);
    }
    let x = challenge(payload);
    let k = kernel(u, x);
    for l in 0..L {
        let mut residual = [0; N];
        for j in 0..N {
            residual[j] = ct0[l].coefficients[j]
                - e0.coefficients[j]
                - configs.k0is[l] * k1.coefficients[j]
                - configs.qis[l] * q_short[l].coefficients[j];
        }
        assert(Polynomial::new(residual).eval(x) == dot(pk0[l], k));
    }
    (pc, cc, kc, uc)
}
