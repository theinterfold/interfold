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
use crate::math::helpers::flatten_exact_width;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Parameters for user-data encryption ct1 (P3).
pub struct Configs<let N: u32, let L: u32> {
    pub qis: [Field; L],
    pub e1_bound: Field,
    pub u_bound: Field,
    /// Bound on `r`, the quotient of the mod-`q` reduction, that honest witnesses meet. The circuit
    /// checks the power-of-two window `[-2^BIT_R, 2^BIT_R)` that covers it.
    pub r_bounds: [Field; L],
}
impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(qis: [Field; L], e1_bound: Field, u_bound: Field, r_bounds: [Field; L]) -> Self {
        Configs { qis, e1_bound, u_bound, r_bounds }
    }
}

/// User-data encryption ct1 (P3).
///
/// **Role:** Second ciphertext leg. Standalone, it bounds and commits `u` itself (`execute`); inside
/// `user_data_encryption` it reads ct0's `u` and reuses ct0's commitment (`execute_with_u_commitment`).
///
/// **Produces:** `(pk1_commitment, ct1_commitment, u_commitment)` public outputs.
pub struct UserDataEncryptionCt1<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_R: u32> {
    configs: Configs<N, L>,
    /// The circuit-constant CRS `CRP`, the second component of every committee key. C5 commits it as
    /// `pk1_agg`, so the binary passes the same constant and nothing here is witnessed: its
    /// coefficients are centred residues by construction, so this leg does not range-check them.
    pk1is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    /// The encryption randomness, the same `u` as ct0's.
    u: Polynomial<N>,
    e1: Polynomial<N>,
    /// Quotient of the mod-`q` reduction, already reduced modulo `X^N + 1` by the prover. Degree `N`
    /// rather than `2N - 1`, and the cyclotomic quotient the unreduced identity needed is gone
    /// entirely, because `X^N = -1` makes its term identically zero.
    r: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E1: u32, let BIT_R: u32> UserDataEncryptionCt1<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E1, BIT_R> {

    /// `pk1is` must be the circuit-constant CRS that C5 commits as `pk1_agg` (the binary passes
    /// `CRP`). This leg neither range-checks nor digit-checks it, so a witnessed `pk1is` would give
    /// the key commitment a second opening and the committee-key anchor would no longer bind it.
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
    /// field equality to imply the integer one.
    /// - `ct1is` are exact centred residues mod `q_i`, `e1` exact to its bound, and `u` ternary
    ///   (`u_bound` is 1). Inside `user_data_encryption` ct0 bounds the shared `u` instead.
    /// - `pk1is` is the constant CRS (see the field), so it needs no check.
    /// - `r` only needs to stay small. With every other term exactly bounded, the integer identity
    ///   fixes `r = (ct1 - pk1 * u - e1) / q_i`, so a window `[-2^BIT_R, 2^BIT_R)` that covers
    ///   `r_bounds` and keeps `q_i * r` far below the field modulus pins it as well as the exact
    ///   bound did.
    fn check_range_bounds(self) {
        assert(self.configs.u_bound == 1, "the ternary check needs u_bound == 1");
        self.u.assert_ternary();
        self.check_range_bounds_except_u();
    }

    /// Everything [`Self::check_range_bounds`] bounds except `u`.
    fn check_range_bounds_except_u(self) {
        self.e1.range_check_2bounds::<BIT_E1>(self.configs.e1_bound, self.configs.e1_bound);

        for i in 0..L {
            let half = (self.configs.qis[i] - 1) / 2;
            self.ct1is[i].range_check_2bounds::<BIT_CT>(half, half);
            self.r[i].range_check_signed_power_of_two::<BIT_R>();
        }
    }

    fn generate_commitments(self) -> (Field, Field, Field) {
        let (pk1_commitment, ct1_commitment) = self.generate_commitments_except_u();
        // `check_range_bounds` makes `u` ternary, so its plain packing is injective.
        let u_commitment = compute_single_polynomial_commitment::<N, BIT_U>(
            self.u,
            DS_USER_DATA_ENCRYPTION_COMMITMENT,
        );

        (pk1_commitment, ct1_commitment, u_commitment)
    }

    /// `(pk1_commitment, ct1_commitment)`.
    fn generate_commitments_except_u(self) -> (Field, Field) {
        // `ct1is` is range-checked, so its plain packing is injective. `pk1is` is the constant CRS,
        // so its commitment is a constant too, the one C5 computes.
        let pk1_commitment =
            compute_multiple_polynomial_commitment::<N, L, BIT_PK>(self.pk1is, DS_PK_AGGREGATION);
        let ct1_commitment =
            compute_multiple_polynomial_commitment::<N, L, BIT_CT>(self.ct1is, DS_CIPHERTEXT);

        (pk1_commitment, ct1_commitment)
    }

    fn generate_challenge(
        self,
        pk1_commitment: Field,
        ct1_commitment: Field,
        u_commitment: Field,
    ) -> [Field] {
        let mut payload = [pk1_commitment, ct1_commitment, u_commitment].as_vector();

        // `check_range_bounds_except_u` holds `e1 + e1_bound` in `[0, 2 * e1_bound]`, which fits
        // `BIT_E1 + 1` bits, and `r + 2^BIT_R` in `[0, 2^(BIT_R + 1))`. Packing each at exactly that
        // width is injective and needs about half the carriers of the nibble-aligned packing.
        let e1_bound = self.configs.e1_bound;
        payload = flatten_exact_width::<N, BIT_E1 + 1, _>(payload, |j| {
            self.e1.coefficients[j] + e1_bound
        });
        // `r` replaces `p1is` and `p2is` in the transcript.
        let shift = 2.pow_32(BIT_R as Field);
        for i in 0..L {
            payload = flatten_exact_width::<N, BIT_R + 1, _>(payload, |j| {
                self.r[i].coefficients[j] + shift
            });
        }

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

    /// The `u` this leg reads.
    pub(crate) fn u(self) -> Polynomial<N> {
        self.u
    }

    /// ct1 inside the merged `user_data_encryption` circuit, which proves ct0 over the same `u`
    /// witness first. ct0 constrains that `u` to `{-1, 0, 1}` and commits it, so this leg takes its
    /// commitment for the transcript instead of checking and committing `u` again.
    ///
    /// Only sound when `u_commitment` is ct0's commitment to this leg's own `u`, after ct0 bounded
    /// it. Crate-private for that reason: `user_data_encryption::execute` is the one caller, and it
    /// asserts both legs read the same `u`.
    ///
    /// Returns `(pk1_commitment, ct1_commitment)`.
    pub(crate) fn execute_with_u_commitment(self, u_commitment: Field) -> (Field, Field) {
        self.check_range_bounds_except_u();

        let (pk1_commitment, ct1_commitment) = self.generate_commitments_except_u();

        let gammas = self.generate_challenge(pk1_commitment, ct1_commitment, u_commitment);

        assert(self.verify_evaluations(gammas), "ct1 encryption check failed");

        (pk1_commitment, ct1_commitment)
    }
}

/// IF-013 / reduced identity: a `u` outside `u_bound` is rejected.
///
/// Before the reduced path, ct1 bounded `u` nowhere: it relied on ct0's bound reaching it through the
/// equality the former `user_data_encryption` fold asserted between the two `u` commitments, and the plain
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

/// In the merged circuit ct1 takes ct0's `u` commitment instead of committing `u` itself. Given the
/// commitment of its own `u`, it returns the same commitments and passes the same check as `execute`.
#[test]
fn shared_u_commitment_matches_standalone_execution() {
    let u = Polynomial::new([0, 1, 0, -1]);
    let c: UserDataEncryptionCt1<4, 1, 6, 6, 1, 1, 3> = UserDataEncryptionCt1::new(
        Configs::new([97], 1, 1, [3]),
        [Polynomial::new([30, 40, -20, 10])],
        [Polynomial::new([47, -30, -10, 48])],
        u,
        Polynomial::new([0, 0, 0, 1]),
        [Polynomial::new([1, 0, 0, 1])],
    );
    let (pk1_commitment, ct1_commitment, u_commitment) = c.execute();
    let shared = c.execute_with_u_commitment(u_commitment);
    assert(shared == (pk1_commitment, ct1_commitment));
}
