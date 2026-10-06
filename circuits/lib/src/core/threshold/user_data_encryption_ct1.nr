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
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Parameters for user-data encryption ct1 (P3).
pub struct Configs<let N: u32, let L: u32> {
    pub qis: [Field; L],
    pub e1_bound: Field,
    pub u_bound: Field,
    /// Bound on `r`, the quotient of the mod-`q` reduction.
    pub r_bounds: [Field; L],
}
impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(qis: [Field; L], e1_bound: Field, u_bound: Field, r_bounds: [Field; L]) -> Self {
        Configs { qis, e1_bound, u_bound, r_bounds }
    }
}

/// User-data encryption ct1 (P3).
///
/// **Role:** Second ciphertext leg; `u` must match the ct0 `u_commitment`.
///
/// **Produces:** `(pk1_commitment, ct1_commitment, u_commitment)` public outputs.
pub struct UserDataEncryptionCt1<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_R: u32> {
    configs: Configs<N, L>,
    pk1is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    /// Re-witnessed privately; checked against `u_commitment` from ct0 (same P3 flow).
    u: Polynomial<N>,
    e1: Polynomial<N>,
    /// Quotient of the mod-`q` reduction, already reduced modulo `X^N + 1` by the prover. Degree `N`
    /// rather than `2N - 1`, and the cyclotomic quotient the unreduced identity needed is gone
    /// entirely, because `X^N = -1` makes its term identically zero.
    r: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_R: u32> UserDataEncryptionCt1<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E1, BIT_R> {

    pub fn new(
        configs: Configs<N, L>,
        pk1is: [Polynomial<N>; L],
        ct1is: [Polynomial<N>; L],
        u: Polynomial<N>,
        e1: Polynomial<N>,
        r: [Polynomial<N>; L],
    ) -> Self {
        UserDataEncryptionCt1 { configs, pk1is, ct1is, u, e1, r }
    }

    /// Bounds every value the reduced identity is checked over.
    ///
    /// The identity is verified at one random point, so each coefficient needs a bound for the
    /// field equality to imply the integer one. `pk1is` / `ct1is` are centered residues mod `q_i`;
    /// `u` finally uses `configs.u_bound`, which the unreduced path left unread.
    fn check_range_bounds(self) {
        self.e1.range_check_2bounds::<BIT_E1>(self.configs.e1_bound, self.configs.e1_bound);
        self.u.range_check_2bounds::<BIT_U>(self.configs.u_bound, self.configs.u_bound);

        for i in 0..L {
            let half = (self.configs.qis[i] - 1) / 2;
            self.pk1is[i].range_check_2bounds::<BIT_PK>(half, half);
            self.ct1is[i].range_check_2bounds::<BIT_CT>(half, half);
            self.r[i].range_check_2bounds::<BIT_R>(
                self.configs.r_bounds[i],
                self.configs.r_bounds[i],
            );
        }
    }

    fn generate_commitments(self) -> (Field, Field, Field) {
        // `check_range_bounds` bounds `pk1is`, `ct1is` and `u`, so the plain packing is already
        // injective for all three and the digit asserts would be redundant.
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
        // `r` replaces `p1is` and `p2is` in the transcript, and it is bounded, so the plain packing
        // stays injective.
        payload = flatten::<_, _, BIT_R>(payload, self.r);

        compute_user_data_encryption_ct1_challenge::<L>(payload)
    }

    /// Checks `ct1is = pk1is * u + e1 + q_i * r` modulo `X^N + 1`, at one challenge point.
    ///
    /// `negacyclic_kernel` supplies the reduced product `pk1is * u mod X^N + 1` evaluated at `x`, so
    /// the product never enters the witness and the cyclotomic quotient is gone with it.
    fn verify_evaluations(self, gammas: [Field]) -> bool {
        let x = gammas[0];
        let k = negacyclic_kernel(self.u, x);

        let mut holds = true;
        for i in 0..L {
            let mut residual = [0; N];
            for j in 0..N {
                residual[j] = self.ct1is[i].coefficients[j]
                    - self.e1.coefficients[j]
                    - self.configs.qis[i] * self.r[i].coefficients[j];
            }
            holds = holds & (Polynomial::new(residual).eval(x) == self.pk1is[i].dot(k));
        }

        holds
    }

    /// Returns `(pk1_commitment, ct1_commitment, u_commitment)`.
    pub fn execute(self) -> (Field, Field, Field) {
        // Step 1: bound everything the reduced identity is read over.
        self.check_range_bounds();

        // Step 2: Commitments for the FS transcript.
        let (pk1_commitment, ct1_commitment, u_commitment) = self.generate_commitments();

        // Step 3: Fiat-Shamir challenge and evaluation check of the reduced ct1 equation.
        let gammas = self.generate_challenge(pk1_commitment, ct1_commitment, u_commitment);

        assert(self.verify_evaluations(gammas), "ct1 encryption check failed");

        (pk1_commitment, ct1_commitment, u_commitment)
    }
}

/// IF-013 / reduced identity: a `u` outside `u_bound` is rejected.
///
/// Before the reduced path, ct1 bounded `u` nowhere: it relied on ct0's bound reaching it through the
/// equality the `user_data_encryption` fold asserts between the two `u` commitments, and the plain
/// packing let a carry (`+delta` in slot 0, `-radix * delta` in slot 1) satisfy that equality with
/// different randomness. The reduced identity needs `u` bounded in its own right — the field equality
/// at one point only implies the integer one when every coefficient is bounded — so `configs.u_bound`
/// is finally read, and the shifted `u` is now rejected outright rather than via its commitment.
#[test(should_fail)]
fn u_outside_its_bound_is_rejected() {
    let z = Polynomial::new([0; 8]);
    let one = Polynomial::new([0, 0, 0, 0, 0, 0, 0, 1]);
    let mut c: UserDataEncryptionCt1<8, 1, 35, 35, 1, 5, 9> = UserDataEncryptionCt1::new(
        Configs::new([68719403009], 32, 1, [5]),
        [one],
        [one],
        z,
        z,
        [Polynomial::new([0; 8])],
    );
    c.u.coefficients[0] = 1000;
    let _ = c.execute();
}

/// An honest witness satisfies the reduced identity, with a nonzero `r`.
///
/// Worked by hand at `N = 4`, `q = 97`: `pk1 * u mod X^4 + 1` is `[-50, -30, -10, -50]`, plus
/// `e1 = [0, 0, 0, 1]` gives `[-50, -30, -10, -49]`. Two coefficients fall below `-(q-1)/2`, so the
/// centered ciphertext is `[47, -30, -10, 48]` and the reduction quotient is `r = [1, 0, 0, 1]`.
#[test]
fn honest_reduced_identity_holds() {
    let pk1 = Polynomial::new([30, 40, -20, 10]);
    let u = Polynomial::new([0, 1, 0, -1]);
    let e1 = Polynomial::new([0, 0, 0, 1]);
    let ct1 = Polynomial::new([47, -30, -10, 48]);
    let r = Polynomial::new([1, 0, 0, 1]);

    let c: UserDataEncryptionCt1<4, 1, 6, 6, 1, 1, 3> =
        UserDataEncryptionCt1::new(Configs::new([97], 1, 1, [3]), [pk1], [ct1], u, e1, [r]);
    let _ = c.execute();
}
