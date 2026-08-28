// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS user-data encryption - ct0 leg.
//!
//! CKKS variant of `user_data_encryption_ct0`. The proven relation per CRT
//! limb `i` is:
//!
//! `ct0i = pk0i*u + e0i + mi + r1i*qi + r2i*cyclo`
//!
//! Differences from the BFV circuit:
//! - No `k1*k0i` term: the CKKS message enters the ciphertext directly as a
//!   scaled ring element `m = round(delta * encode(z))`, so there is no
//!   plaintext-modulus CRT scaling.
//! - The `k1` witness and its `[k1_low, k1_up]` bounds are replaced by the
//!   message polynomial `m` with the symmetric bound `m_bound >= delta * B`,
//!   where `B` bounds the magnitude of the encoded values. This is the
//!   coefficient-domain input-validity check.
//! - `m` gets the same CRT-consistency treatment as `e0` (per-limb `mis`
//!   plus quotients), because `m` mod Q must be consistent across limbs.
//!
//! The ct1 leg is scheme-independent (no message term) and reuses
//! `user_data_encryption_ct1` unchanged.
//!
//! See `UserDataEncryptionCkksCt0` for the circuit contract.

use crate::math::commitments::compute_multiple_polynomial_commitment;
use crate::math::commitments::compute_single_polynomial_commitment;
use crate::math::commitments::compute_user_data_encryption_ct0_challenge;
use crate::math::commitments::DS_CIPHERTEXT;
use crate::math::commitments::DS_PK_AGGREGATION;
use crate::math::commitments::DS_USER_DATA_ENCRYPTION_COMMITMENT;
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// Parameters for CKKS user-data encryption ct0.
pub struct Configs<let N: u32, let L: u32> {
    pub qis: [Field; L],
    pub e0_bound: Field,
    pub u_bound: Field,
    /// Symmetric bound on the scaled message coefficients: `delta * B`.
    pub m_bound: Field,
    pub r1_low_bounds: [Field; L],
    pub r1_up_bounds: [Field; L],
    pub r2_bounds: [Field; L],
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        e0_bound: Field,
        u_bound: Field,
        m_bound: Field,
        r1_low_bounds: [Field; L],
        r1_up_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        Configs { qis, e0_bound, u_bound, m_bound, r1_low_bounds, r1_up_bounds, r2_bounds }
    }
}

/// CKKS user-data encryption ct0.
///
/// **Role:** Prove the first ciphertext leg of a CKKS public-key encryption
/// and publish `pk0`, `ct0`, `m`, and `u` commitments for the wrapper and the
/// (reused) ct1 circuit.
///
/// **Consumes:** Threshold PK (`pk0is` witness path).
///
/// **Produces:** `(pk0_commitment, ct0_commitment, m_commitment, u_commitment)`
/// public outputs.
pub struct UserDataEncryptionCkksCt0<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_M: u32, let BIT_R1: u32, let BIT_R2: u32> {
    configs: Configs<N, L>,
    /// Aggregated threshold `pk0` limb.
    pk0is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e0is: [Polynomial<N>; L],
    e0_quotients: [Polynomial<N>; L],
    /// The scaled message polynomial `m` (mod Q, centered).
    m: Polynomial<N>,
    mis: [Polynomial<N>; L],
    m_quotients: [Polynomial<N>; L],
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_M: u32, let BIT_R1: u32, let BIT_R2: u32> UserDataEncryptionCkksCt0<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_M, BIT_R1, BIT_R2> {

    pub fn new(
        configs: Configs<N, L>,
        pk0is: [Polynomial<N>; L],
        ct0is: [Polynomial<N>; L],
        u: Polynomial<N>,
        e0: Polynomial<N>,
        e0is: [Polynomial<N>; L],
        e0_quotients: [Polynomial<N>; L],
        m: Polynomial<N>,
        mis: [Polynomial<N>; L],
        m_quotients: [Polynomial<N>; L],
        r1is: [Polynomial<(2 * N) - 1>; L],
        r2is: [Polynomial<N - 1>; L],
    ) -> Self {
        UserDataEncryptionCkksCt0 {
            configs,
            pk0is,
            ct0is,
            u,
            e0,
            e0is,
            e0_quotients,
            m,
            mis,
            m_quotients,
            r1is,
            r2is,
        }
    }

    /// `x[j] == xis[i][j] + quotients[i][j] * qi` for `x` in `{e0, m}`.
    fn check_crt_consistency(self) {
        for i in 0..L {
            for j in 0..N {
                assert(
                    self.e0.coefficients[j]
                        == self.e0is[i].coefficients[j]
                            + self.e0_quotients[i].coefficients[j] * self.configs.qis[i],
                );
                assert(
                    self.m.coefficients[j]
                        == self.mis[i].coefficients[j]
                            + self.m_quotients[i].coefficients[j] * self.configs.qis[i],
                );
            }
        }
    }

    fn check_range_bounds(self) {
        self.u.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e0.range_check_2bounds::<BIT_E0>(self.configs.e0_bound, self.configs.e0_bound);
        // Input-validity: every coefficient of the scaled message is in
        // [-m_bound, m_bound], i.e. |encode(z)| <= B at scale delta.
        self.m.range_check_2bounds::<BIT_M>(self.configs.m_bound, self.configs.m_bound);

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
        let m_commitment = compute_single_polynomial_commitment::<N, BIT_M>(
            self.m,
            DS_USER_DATA_ENCRYPTION_COMMITMENT,
        );
        let u_commitment = compute_single_polynomial_commitment::<N, BIT_U>(
            self.u,
            DS_USER_DATA_ENCRYPTION_COMMITMENT,
        );

        (pk0_commitment, ct0_commitment, m_commitment, u_commitment)
    }

    fn generate_challenge(
        self,
        pk0_commitment: Field,
        ct0_commitment: Field,
        m_commitment: Field,
        u_commitment: Field,
    ) -> [Field] {
        let mut payload = [pk0_commitment, ct0_commitment, m_commitment, u_commitment].as_vector();

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

        let mut sum = (0, 0);
        for i in 0..L {
            let pk0is_at_gamma = self.pk0is[i].eval(gamma);
            let r1i_at_gamma = self.r1is[i].eval(gamma);
            let r2i_at_gamma = self.r2is[i].eval(gamma);
            let e0is_at_gamma = self.e0is[i].eval(gamma);
            let mis_at_gamma = self.mis[i].eval(gamma);

            // ct0i = pk0i*u + e0i + mi + r1i*qi + r2i*cyclo
            let mut ct0_rhs = pk0is_at_gamma * u_at_gamma + e0is_at_gamma;
            ct0_rhs += mis_at_gamma;
            ct0_rhs += r1i_at_gamma * self.configs.qis[i];
            ct0_rhs += r2i_at_gamma * cyclo_at_gamma;

            let ct0_lhs = self.ct0is[i].eval(gamma);
            let gamma_i = if i == 0 { 1 } else { gammas[i] };

            sum = (sum.0 + ct0_lhs * gamma_i, sum.1 + ct0_rhs * gamma_i);
        }

        sum.0 == sum.1
    }

    /// Returns `(pk0_commitment, ct0_commitment, m_commitment, u_commitment)`.
    pub fn execute(self) -> (Field, Field, Field, Field) {
        // Step 1: Witness bounds and CRT consistency of `e0` and `m`.
        self.check_range_bounds();
        self.check_crt_consistency();

        // Step 2: Domain-separated commitments for the FS transcript.
        let (pk0_commitment, ct0_commitment, m_commitment, u_commitment) =
            self.generate_commitments();

        // Step 3: Fiat-Shamir challenge and batched evaluation check of ct0 equations.
        let gammas =
            self.generate_challenge(pk0_commitment, ct0_commitment, m_commitment, u_commitment);

        assert(self.verify_evaluations(gammas), "ckks ct0 encryption check failed");

        (pk0_commitment, ct0_commitment, m_commitment, u_commitment)
    }
}
