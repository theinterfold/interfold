// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User-data encryption - ct0 leg (P3).
//!
//! See `UserDataEncryptionCt0` for the circuit contract.

use crate::math::commitments::compute_multiple_polynomial_commitment_checked;
use crate::math::commitments::compute_single_polynomial_commitment;
use crate::math::commitments::compute_user_data_encryption_ct0_challenge;
use crate::math::commitments::DS_CIPHERTEXT;
use crate::math::commitments::DS_PK_AGGREGATION;
use crate::math::commitments::DS_USER_DATA_ENCRYPTION_COMMITMENT;
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// Parameters for user-data encryption ct0 (P3).
pub struct Configs<let N: u32, let L: u32> {
    pub qis: [Field; L],
    pub k0is: [Field; L],
    /// Bound for the lifted error polynomial (e0) coefficients
    pub e0_bound: Field,
    /// Bounds for the per-modulus residues of e0: (q_i - 1) / 2
    pub e0is_bounds: [Field; L],
    /// Bounds for the CRT quotients of e0: (e0_bound + (q_i - 1) / 2) / q_i
    pub e0_quotient_bounds: [Field; L],
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
        e0is_bounds: [Field; L],
        e0_quotient_bounds: [Field; L],
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
            e0is_bounds,
            e0_quotient_bounds,
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
pub struct UserDataEncryptionCt0<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E0IS: u32, let BIT_E0_QUOTIENT: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32> {
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

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E0IS: u32, let BIT_E0_QUOTIENT: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32> UserDataEncryptionCt0<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E0IS, BIT_E0_QUOTIENT, BIT_K, BIT_R1, BIT_R2> {

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

    /// Binds each per-modulus residue `e0is[i]` to the lifted `e0`.
    ///
    /// `q_i` is invertible modulo the proof-system prime, so this equation alone holds for any
    /// `e0is`. It constrains the witnesses only together with the `e0`, `e0is` and `e0_quotients`
    /// bounds in `check_range_bounds`, which keep every term far below the prime and thus make
    /// the equation hold over the integers.
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
            // e0is[i] must be the centered residue of e0 at q_i, and e0_quotients[i] the matching
            // CRT quotient. Without both, check_e0_crt_consistency is satisfiable for any e0is.
            self.e0is[i].range_check_2bounds::<BIT_E0IS>(
                self.configs.e0is_bounds[i],
                self.configs.e0is_bounds[i],
            );
            self.e0_quotients[i].range_check_2bounds::<BIT_E0_QUOTIENT>(
                self.configs.e0_quotient_bounds[i],
                self.configs.e0_quotient_bounds[i],
            );

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
        // `pk0is` and `ct0is` carry no range bound of their own and reach the transcript only
        // through these commitments, so both are packed with the digit asserts. `pk0is` needs it to
        // transfer C5's bound: the on-chain caller substitutes the registry's committee key into the
        // surfaced pk commitment, and only an injective packing makes that value pin `pk0is`.
        // `ct0is` needs it so the transcript binds before `gamma` is drawn, which is what lets
        // Schwartz-Zippel force `ct0is` to the encryption identity. `k1` and `u` are bounded by
        // `check_range_bounds`, so their plain commitments are already injective.
        let pk0_commitment = compute_multiple_polynomial_commitment_checked::<N, L, BIT_PK>(
            self.pk0is,
            DS_PK_AGGREGATION,
        );
        let ct0_commitment = compute_multiple_polynomial_commitment_checked::<N, L, BIT_CT>(
            self.ct0is,
            DS_CIPHERTEXT,
        );
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
        // Step 1: Witness bounds and CRT consistency of `e0`.
        self.check_range_bounds();
        self.check_e0_crt_consistency();

        // Step 2: Domain-separated commitments for the FS transcript.
        let (pk0_commitment, ct0_commitment, k1_commitment, u_commitment) =
            self.generate_commitments();

        // Step 3: Fiat-Shamir challenge and batched evaluation check of ct0 equations.
        let gammas =
            self.generate_challenge(pk0_commitment, ct0_commitment, k1_commitment, u_commitment);

        assert(self.verify_evaluations(gammas), "ct0 encryption check failed");

        (pk0_commitment, ct0_commitment, k1_commitment, u_commitment)
    }
}

/// IF-013: before the commitments carried the digit asserts, `pk0is` had a second opening.
///
/// The public key is anchored off-circuit, not in-circuit: the on-chain caller substitutes the
/// registry's committee key into the pk commitment it verifies against, so nothing here bounds
/// `pk0is` and the anchor rests entirely on that commitment having one opening. `pack` lays
/// coefficients into one carrier as base-`radix` digits, so adding `delta` to slot 0 and
/// `-radix * delta` to slot 1 left the commitment unchanged — a voter could encrypt under a perturbed
/// key while the chain-supplied commitment still matched.
///
/// With the checked commitment the shifted coefficient no longer fits its digit.
#[test(should_fail)]
fn second_opening_of_pk0is_is_rejected() {
    let z = Polynomial::new([0; 8]);
    let configs: Configs<8, 1> = Configs::new(
        [68719403009],
        [1],
        20,
        [34359701504],
        [1],
        1,
        [1],
        [1],
        [1],
        1,
        1,
    );
    let mut c: UserDataEncryptionCt0<8, 1, 35, 35, 1, 5, 35, 5, 9, 35, 35> = UserDataEncryptionCt0::new(
        configs,
        [z],
        [z],
        z,
        z,
        [z],
        [z],
        z,
        [Polynomial::new([0; 15])],
        [Polynomial::new([0; 7])],
    );
    let before = c.generate_commitments();

    // Carry 1 from slot 0 into slot 1: both indices share a carrier, so under the unchecked packing
    // the pk commitment did not move.
    let radix: Field = 1099511627776;
    c.pk0is[0].coefficients[0] += 1;
    c.pk0is[0].coefficients[1] -= radix;

    // Rejected here: slot 1 no longer holds its digit.
    let after = c.generate_commitments();
    assert(after.0 == before.0);
}
