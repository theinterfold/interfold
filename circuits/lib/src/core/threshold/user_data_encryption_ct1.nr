// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User-data encryption - ct1 leg (P3).
//!
//! See `UserDataEncryptionCt1` for the circuit contract.

use crate::math::commitments::compute_multiple_polynomial_commitment_checked;
use crate::math::commitments::compute_single_polynomial_commitment_checked;
use crate::math::commitments::compute_user_data_encryption_ct1_challenge;
use crate::math::commitments::DS_CIPHERTEXT;
use crate::math::commitments::DS_PK_AGGREGATION;
use crate::math::commitments::DS_USER_DATA_ENCRYPTION_COMMITMENT;
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

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
        // None of `pk1is`, `ct1is`, `u` is range-checked here, and all three reach the transcript
        // only through these commitments, so all three are packed with the digit asserts. `pk1is`
        // transfers C5's bound, `ct1is` is then forced by the encryption identity once the transcript
        // binds, and `u` transfers ct0's `u_bound` through the equality the
        // `user_data_encryption` fold asserts between the two `u` commitments.
        let pk1_commitment = compute_multiple_polynomial_commitment_checked::<N, L, BIT_PK>(
            self.pk1is,
            DS_PK_AGGREGATION,
        );
        let ct1_commitment = compute_multiple_polynomial_commitment_checked::<N, L, BIT_CT>(
            self.ct1is,
            DS_CIPHERTEXT,
        );
        let u_commitment = compute_single_polynomial_commitment_checked::<N, BIT_U>(
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

/// IF-013: before the commitments carried the digit asserts, `u` had a second opening here.
///
/// ct0 range-checks `u` to `u_bound` and the `user_data_encryption` fold asserts ct0's and ct1's `u`
/// commitments are equal, so the intent is that ct1 encrypts under the same randomness. ct1 bounded
/// `u` nowhere, though, and `pack` lays coefficients into one carrier as base-`radix` digits, so
/// adding `delta` to slot 0 and `-radix * delta` to slot 1 left the commitment — and so the fold's
/// equality — untouched. ct1 could use different randomness from ct0 and still satisfy it.
///
/// With the checked commitment the shifted `u` no longer fits its digit, so recomputing the
/// commitments fails and the substitution is unreachable.
#[test(should_fail)]
fn second_opening_of_u_is_rejected() {
    let z = Polynomial::new([0; 8]);
    let one = Polynomial::new([0, 0, 0, 0, 0, 0, 0, 1]);
    let mut c: UserDataEncryptionCt1<8, 1, 35, 35, 1, 5, 9, 35> = UserDataEncryptionCt1::new(
        Configs::new([68719403009], 32, 1, [256], [34359701504]),
        [one],
        [one],
        z,
        z,
        [Polynomial::new([0; 15])],
        [Polynomial::new([0; 7])],
    );
    let before = c.generate_commitments();
    let gamma = c.generate_challenge(before.0, before.1, before.2)[0];

    // Carry `shift` from slot 0 into slot 1: under the unchecked packing the carrier did not move.
    let shift = 1 / (gamma.pow_32(6) * (gamma - 256));
    c.u.coefficients[0] += shift;
    c.u.coefficients[1] -= 256 * shift;

    // Rejected here: slot 1 no longer holds its digit.
    let after = c.execute();
    assert(after.2 == before.2);
}
