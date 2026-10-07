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
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Parameters for user-data encryption ct0 (P3).
pub struct Configs<let N: u32, let L: u32> {
    pub qis: [Field; L],
    pub k0is: [Field; L],
    /// Bound for the lifted error polynomial (e0) coefficients
    pub e0_bound: Field,
    pub u_bound: Field,
    /// Bounds on `r`, the quotient of the mod-`q` reduction.
    pub r_bounds: [Field; L],
    pub k1_low_bound: Field,
    pub k1_up_bound: Field,
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        k0is: [Field; L],
        e0_bound: Field,
        u_bound: Field,
        r_bounds: [Field; L],
        k1_low_bound: Field,
        k1_up_bound: Field,
    ) -> Self {
        Configs { qis, k0is, e0_bound, u_bound, r_bounds, k1_low_bound, k1_up_bound }
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
pub struct UserDataEncryptionCt0<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R: u32> {
    configs: Configs<N, L>,
    /// Aggregated threshold `pk0` limb (from C5).
    pk0is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    k1: Polynomial<N>,
    /// Quotient of the mod-`q` reduction, already reduced modulo `X^N + 1` by the prover. It absorbs
    /// what `e0is`, `r1is` and `r2is` carried between them: substituting the CRT split removes `e0is`,
    /// and `X^N = -1` makes the cyclotomic quotient's term identically zero.
    r: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R: u32> UserDataEncryptionCt0<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_K, BIT_R> {

    pub fn new(
        configs: Configs<N, L>,
        pk0is: [Polynomial<N>; L],
        ct0is: [Polynomial<N>; L],
        u: Polynomial<N>,
        e0: Polynomial<N>,
        k1: Polynomial<N>,
        r: [Polynomial<N>; L],
    ) -> Self {
        UserDataEncryptionCt0 { configs, pk0is, ct0is, u, e0, k1, r }
    }

    /// Bounds every value the reduced identity is checked over.
    ///
    /// The identity is verified at one random point, so each coefficient needs a bound for the field
    /// equality to imply the integer one. `pk0is` / `ct0is` are centered residues mod `q_i`, and `r`
    /// is the prover-supplied reduction quotient.
    fn check_range_bounds(self) {
        self.u.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);
        self.e0.range_check_2bounds::<BIT_E0>(self.configs.e0_bound, self.configs.e0_bound);
        self.k1.range_check_2bounds::<BIT_K>(self.configs.k1_up_bound, self.configs.k1_low_bound);

        for i in 0..L {
            let half = (self.configs.qis[i] - 1) / 2;
            self.pk0is[i].range_check_2bounds::<BIT_PK>(half, half);
            self.ct0is[i].range_check_2bounds::<BIT_CT>(half, half);
            self.r[i].range_check_2bounds::<BIT_R>(
                self.configs.r_bounds[i],
                self.configs.r_bounds[i],
            );
        }
    }

    fn generate_commitments(self) -> (Field, Field, Field, Field) {
        // `check_range_bounds` bounds all four vectors, so the plain packing is already injective and
        // the digit asserts would be redundant.
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
        // `r` replaces `e0is`, `r1is` and `r2is` in the transcript, and it is bounded, so the plain
        // packing stays injective.
        payload = flatten::<_, _, BIT_R>(payload, self.r);

        compute_user_data_encryption_ct0_challenge::<L>(payload)
    }

    /// Checks `ct0is = pk0is * u + e0 + k0is * k1 + q_i * r` modulo `X^N + 1`, at one point.
    ///
    /// `negacyclic_kernel` supplies the reduced product `pk0is * u mod X^N + 1` evaluated at `x`, so
    /// the product never enters the witness and the cyclotomic quotient is gone with it.
    fn verify_evaluations(self, gammas: [Field]) -> bool {
        let x = gammas[0];
        let k = negacyclic_kernel(self.u, x);

        let mut holds = true;
        for i in 0..L {
            let mut residual = [0; N];
            for j in 0..N {
                residual[j] = self.ct0is[i].coefficients[j]
                    - self.e0.coefficients[j]
                    - self.configs.k0is[i] * self.k1.coefficients[j]
                    - self.configs.qis[i] * self.r[i].coefficients[j];
            }
            holds = holds & (Polynomial::new(residual).eval(x) == self.pk0is[i].dot(k));
        }

        holds
    }

    /// Returns `(pk0_commitment, ct0_commitment, k1_commitment, u_commitment)`.
    pub fn execute(self) -> (Field, Field, Field, Field) {
        // Step 1: bound everything the reduced identity is read over.
        self.check_range_bounds();

        // Step 2: Domain-separated commitments for the FS transcript.
        let (pk0_commitment, ct0_commitment, k1_commitment, u_commitment) =
            self.generate_commitments();

        // Step 3: Fiat-Shamir challenge and evaluation check of the reduced ct0 equation.
        let gammas =
            self.generate_challenge(pk0_commitment, ct0_commitment, k1_commitment, u_commitment);

        assert(self.verify_evaluations(gammas), "ct0 encryption check failed");

        (pk0_commitment, ct0_commitment, k1_commitment, u_commitment)
    }
}

/// An honest witness satisfies the reduced ct0 identity, with a nonzero `r`.
///
/// Worked by hand at `N = 4`, `q = 97`, `k0 = 5`: `pk0 * u mod X^4 + 1` is `[-50, -30, -10, -50]`,
/// and adding `e0 = [0, 0, 0, 1]` and `k0 * k1 = 5 * [0, 0, 1, 0]` gives `[-50, -30, -5, -49]`. Two
/// coefficients fall below `-(q-1)/2`, so the centered ciphertext is `[47, -30, -5, 48]` and the
/// reduction quotient is `r = [1, 0, 0, 1]`.
#[test]
fn honest_reduced_identity_holds() {
    let pk0 = Polynomial::new([30, 40, -20, 10]);
    let u = Polynomial::new([0, 1, 0, -1]);
    let e0 = Polynomial::new([0, 0, 0, 1]);
    let k1 = Polynomial::new([0, 0, 1, 0]);
    let ct0 = Polynomial::new([47, -30, -5, 48]);
    let r = Polynomial::new([1, 0, 0, 1]);

    // qis, k0is, e0_bound, u_bound, r_bounds, k1_low_bound, k1_up_bound
    let configs: Configs<4, 1> = Configs::new([97], [5], 1, 1, [3], 1, 1);
    let c: UserDataEncryptionCt0<4, 1, 6, 6, 1, 1, 1, 3> =
        UserDataEncryptionCt0::new(configs, [pk0], [ct0], u, e0, k1, [r]);
    let _ = c.execute();
}
