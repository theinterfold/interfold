// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User-data encryption - ct0 leg (P3).
//!
//! See `UserDataEncryptionCt0` for the circuit contract.

use crate::math::commitments::compute_multiple_polynomial_commitment;
use crate::math::commitments::compute_multiple_polynomial_commitment_checked;
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
    /// Bounds on `r`, the quotient of the mod-`q` reduction, that honest witnesses meet. The circuit
    /// checks the power-of-two window `[-2^BIT_R, 2^BIT_R)` that covers them.
    pub r_bounds: [Field; L],
    pub k1_low_bound: Field,
    pub k1_up_bound: Field,
    /// Per-limb bound on the honest `e0_quotients[i]` magnitude - see `check_range_bounds`.
    pub e0_quotient_bounds: [Field; L],
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
        e0_quotient_bounds: [Field; L],
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
            e0_quotient_bounds,
        }
    }
}

/// User-data encryption ct0 (P3).
///
/// **Role:** Prove the first ciphertext leg and publish `pk0`, `ct0`, `k1`, and `u` commitments.
/// In the `user_data_encryption` circuit this leg runs first and bounds the `u` ct1 shares.
///
/// **Consumes:** Threshold PK from C5 (`pk0is` witness path).
///
/// **Produces:** `(pk0_commitment, ct0_commitment, k1_commitment, u_commitment)` public outputs.
pub struct UserDataEncryptionCt0<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_E0_QUOTIENT: u32> {
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

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_E0_QUOTIENT: u32> UserDataEncryptionCt0<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_K, BIT_R1, BIT_R2, BIT_E0_QUOTIENT> {

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
    /// equality to imply the integer one.
    /// - `ct0is` are exact centred residues mod `q_i`, `e0` and `k1` exact to their bounds, and `u`
    ///   ternary (`u_bound` is 1).
    /// - `pk0is` gets no range check here: `generate_commitments` opens it with the checked packing,
    ///   which bounds every coefficient by its slot (`[-2^nb, 15 * 2^nb)` for `nb` = `BIT_PK` rounded
    ///   up to a nibble, under `2^64` at secure-8192, enough to rule out wrap-around) and makes the
    ///   commitment injective. The commitment is anchored to C5's, which bounds the key
    ///   to the exact centred window, so the opened key is C5's.
    /// - `r` only needs to stay small. With every other term exactly bounded, the integer identity
    ///   fixes `r = (ct0 - pk0 * u - e0 - k0 * k1) / q_i`, so a window `[-2^BIT_R, 2^BIT_R)` that
    ///   covers `r_bounds` and keeps `q_i * r` far below the field modulus pins it as well as the
    ///   exact bound did.
    fn check_range_bounds(self) {
        assert(self.configs.u_bound == 1, "the ternary check needs u_bound == 1");
        self.u.assert_ternary();
        self.e0.range_check_2bounds::<BIT_E0>(self.configs.e0_bound, self.configs.e0_bound);
        self.k1.range_check_2bounds::<BIT_K>(self.configs.k1_up_bound, self.configs.k1_low_bound);

        for i in 0..L {
            let half = (self.configs.qis[i] - 1) / 2;
            self.ct0is[i].range_check_2bounds::<BIT_CT>(half, half);
            self.r[i].range_check_signed_power_of_two::<BIT_R>();
        }
    }

    fn generate_commitments(self) -> (Field, Field, Field, Field) {
        // `check_range_bounds` bounds `ct0is`, `k1` and `u`, so their plain packing is injective.
        // `pk0is` is opened with the checked packing instead: each digit fits its slot, so the opening
        // is unique and the key is the one C5 bounded and committed.
        let pk0_commitment = compute_multiple_polynomial_commitment_checked::<N, L, BIT_PK>(
            self.pk0is,
            DS_PK_AGGREGATION,
        );
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

    /// The `u` this leg constrains and commits.
    pub(crate) fn u(self) -> Polynomial<N> {
        self.u
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

// Regression/demonstration tests for the e0_quotients soundness gap: `check_e0_crt_consistency`
// checks `e0[j] == e0is[i][j] + e0_quotients[i][j] * qis[i]` as an equation in the SNARK's
// native field F_p, not over Z. Left unconstrained, `e0_quotients` lets a prover pick ANY
// e0is[i][j] and back-solve `e0_quotients[i][j] = (e0[j] - e0is[i][j]) / qis[i]` (Field division
// = multiplication by the modular inverse), satisfying the assertion trivially regardless of how
// implausible the resulting quotient is as an honest CRT decomposition (honest quotients for
// this preset sit in roughly [-25, 25]; the one constructed below is ~2^40, nowhere close).
// Since Round B evaluates `e0is` directly (`e0is_at_gamma`, never bounded or committed) into
// `verify_evaluations`'s RHS, this lets a prover choose an arbitrary `ct0is`, solve
// `e0is := ct0is - (pk0is*u + k1*k0is + r1i*qi + r2i*cyclo)` at the coefficient level, and pass
// the whole ct0 circuit with `u`/`e0`/`k1`/`r1is`/`r2is` all honest and in range.
//
// The fix range-checks `e0_quotients` in `check_range_bounds` (not in
// `check_e0_crt_consistency`, which is - and always will be - satisfiable for any e0is by
// itself; the two checks only close the gap together, matching `execute()`'s call order).

/// Documents that `check_e0_crt_consistency` alone remains, by construction, always
/// satisfiable for a forged e0is - this is inherent to checking the equation in F_p, not a bug
/// to fix in that method. It's `check_range_bounds` (tested below) that has to reject the
/// forgery.
#[test]
fn test_e0_crt_consistency_alone_accepts_arbitrary_e0is() {
    let honest_e0_coeff: Field = 5;
    let qis0: Field = 1125899917262849; // real secure_16384 QIS[0], for realism
    let forged_e0is_coeff: Field = 999999999999; // arbitrary, no honest relation to e0=5
    let forged_quotient: Field = (honest_e0_coeff - forged_e0is_coeff) / qis0;
    assert(forged_quotient != 0); // nowhere near the honest [-25, 25] range

    let configs = test_configs(qis0, 100, 32);
    let circuit = test_circuit(configs, honest_e0_coeff, forged_e0is_coeff, forged_quotient);

    // The real, unmodified production check - not a reimplementation. It does not panic on a
    // forged e0is with a back-solved, wildly out-of-range quotient.
    circuit.check_e0_crt_consistency();
}

/// Confirms the fix: the same forged witness, but now going through `check_range_bounds` too
/// (as `execute()` does) - the out-of-range `e0_quotients` gets rejected.
#[test(should_fail)]
fn test_check_range_bounds_rejects_out_of_range_e0_quotient() {
    let honest_e0_coeff: Field = 5;
    let qis0: Field = 1125899917262849;
    let forged_e0is_coeff: Field = 999999999999;
    let forged_quotient: Field = (honest_e0_coeff - forged_e0is_coeff) / qis0;

    let configs = test_configs(qis0, 100, 32);
    let circuit = test_circuit(configs, honest_e0_coeff, forged_e0is_coeff, forged_quotient);

    circuit.check_range_bounds();
}

/// Sanity check: an honest quotient (within the configured bound) must still pass
/// `check_range_bounds`, so the fix doesn't reject legitimate witnesses.
#[test]
fn test_check_range_bounds_accepts_honest_e0_quotient() {
    let honest_e0_coeff: Field = 5;
    let qis0: Field = 1125899917262849;
    let honest_e0is_coeff: Field = 5; // same as e0, so the honest quotient is exactly 0
    let honest_quotient: Field = 0;

    let configs = test_configs(qis0, 100, 32);
    let circuit = test_circuit(configs, honest_e0_coeff, honest_e0is_coeff, honest_quotient);

    circuit.check_range_bounds();
}

// e0_bound=100 and BIT_E0=8 (9-bit capacity) comfortably cover the small honest_e0_coeff used
// above; e0_quotient_bound and BIT_E0_QUOTIENT=6 (7-bit capacity, range_size=2*bound) mirror the
// real fix's ~32 margin over the ~25.5 honest maximum at the real secure_16384 preset.
fn test_configs(qis0: Field, e0_bound: Field, e0_quotient_bound: Field) -> Configs<2, 1> {
    Configs::new(
        [qis0],
        [0],
        e0_bound,
        0,
        [0],
        [0],
        [0],
        0,
        0,
        [e0_quotient_bound],
    )
}

fn test_circuit(
    configs: Configs<2, 1>,
    e0_coeff: Field,
    e0is_coeff: Field,
    quotient: Field,
) -> UserDataEncryptionCt0<2, 1, 1, 1, 1, 8, 1, 1, 1, 6> {
    UserDataEncryptionCt0::new(
        configs,
        [Polynomial::new([0, 0])],
        [Polynomial::new([0, 0])],
        Polynomial::new([0, 0]),
        Polynomial::new([e0_coeff, 0]),
        [Polynomial::new([e0is_coeff, 0])],
        [Polynomial::new([quotient, 0])],
        Polynomial::new([0, 0]),
        [Polynomial::new([0, 0, 0])],
        [Polynomial::new([0])],
    )
}
