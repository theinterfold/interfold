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
    /// Per-limb bound on the honest `e0_quotients[i]` magnitude - see `check_range_bounds`.
    pub e0_quotient_bounds: [Field; L],
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
/// **Role:** Prove the first ciphertext leg and publish `pk0`, `ct0`, `k1`, and `u` commitments
/// for the wrapper and ct1 circuit.
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
    e0is: [Polynomial<N>; L],
    e0_quotients: [Polynomial<N>; L],
    k1: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_E0_QUOTIENT: u32> UserDataEncryptionCt0<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_K, BIT_R1, BIT_R2, BIT_E0_QUOTIENT> {

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
            // `check_e0_crt_consistency`'s equation holds in F_p, not Z: an unbounded
            // `e0_quotients[i]` lets a prover satisfy it for an arbitrary `e0is[i]` by solving
            // `e0_quotients[i] := (e0 - e0is[i]) / qis[i]` via the modular inverse, which then
            // reaches `verify_evaluations` unmediated. Bounding the quotient to the honest range
            // closes that gap; deliberately not bounding `e0is` itself (redundant - any multiple
            // of qis[i] absorbed there is absorbed one-for-one by r1is mod qis[i]).
            self.e0_quotients[i].range_check_2bounds::<BIT_E0_QUOTIENT>(
                self.configs.e0_quotient_bounds[i],
                self.configs.e0_quotient_bounds[i],
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
