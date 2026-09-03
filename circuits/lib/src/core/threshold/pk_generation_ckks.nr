// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_ckks_threshold_pk_commitment, compute_share_computation_e_sm_commitment,
    compute_share_computation_sk_commitment, compute_threshold_pk_challenge,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;

/// Parameters for CKKS threshold public key share generation (C1-CKKS).
///
/// Same shape as the BFV C1 `Configs`; the constants come from the CKKS
/// moduli of one on-chain `ParamSet` (generated `configs/ckks_pk_generation_ps*.nr`).
pub struct Configs<let N: u32, let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}] (the CKKS `Q` at level 0).
    pub qis: [Field; L],
    /// Bound for the key-generation error polynomial (`e`) coefficients.
    pub eek_bound: Field,
    /// Bound for the secret key share polynomial (`sk`) coefficients.
    pub sk_bound: Field,
    /// Bound for the smudging noise polynomial (`e_sm`) coefficients.
    pub e_sm_bound: Field,
    /// Bounds for r1 polynomials (modulus switching quotients), per limb.
    pub r1_bounds: [Field; L],
    /// Bounds for r2 polynomials (cyclotomic reduction quotients), per limb.
    pub r2_bounds: [Field; L],
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        eek_bound: Field,
        sk_bound: Field,
        e_sm_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        Configs { qis, eek_bound, sk_bound, e_sm_bound, r1_bounds, r2_bounds }
    }
}

/// CKKS threshold public key contribution (C1-CKKS).
///
/// **Role:** Prove one party's CKKS public-key share `pk0 = -a*sk + e` (fhe.rs
/// `CkksPublicKeyShare::new`) over the CKKS moduli from hidden `sk`, `e`, `e_sm`
/// and quotients. This is the BFV C1 relation with two differences:
///
/// - the CRP `a` is DERIVED FROM THE E3 SEED (`CkksCrp::from_seed`), so it is a
///   witness instead of a baked constant, and the pk-share commitment binds
///   `pk0 || a` (`compute_ckks_threshold_pk_commitment`) so the proof cannot be
///   attached to a share built over a different CRP;
/// - the moduli are the CKKS `Q` limbs of the param set.
///
/// **Verifies:** Range checks on witnesses; evaluation form of
/// `pk0[i] = -a[i]*sk + e + r2[i]*cyclo + r1[i]*q_i` at the FS challenge.
///
/// **Produces (tuple order, identical to BFV C1):**
/// - `commit(sk)` -> C2a-CKKS (`compute_share_computation_sk_commitment`, the
///   same function/domain/bit width the C2a-CKKS witness and C6-CKKS
///   `expected_sk_commitment` use, so the sibling can link on it).
/// - `commit(pk0 || a)` -> pk aggregation / C5-style verification.
/// - `commit(e_sm)` -> C2b-CKKS.
pub struct PkGenerationCkks<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_PK: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    configs: Configs<N, L>,

    /// Common reference polynomial per limb (witness, bound into `pk_commitment`).
    a: [Polynomial<N>; L],

    /// Key-generation error polynomial (secret witness, CBD with the parameter variance).
    eek: Polynomial<N>,

    /// Secret key share polynomial (secret witness, CBD(0.5): coefficients in {-1, 0, 1}).
    sk: Polynomial<N>,

    /// Smudging noise polynomial per limb (secret witness; the same small integer
    /// polynomial reduced on every limb, like the C2b-CKKS commitment payload).
    e_sm: [Polynomial<N>; L],

    /// r1[i]: modulus-switching quotients for limb i (can be negative, degree 2N-2).
    r1: [Polynomial<2 * N - 1>; L],
    /// r2[i]: cyclotomic-reduction quotients for limb i (degree N-2).
    r2: [Polynomial<N - 1>; L],

    /// Published public-key share first component per limb (committed witness).
    pk0: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_PK: u32> PkGenerationCkks<N, L, BIT_EEK, BIT_SK, BIT_E_SM, BIT_R1, BIT_R2, BIT_PK> {
    pub fn new(
        configs: Configs<N, L>,
        a: [Polynomial<N>; L],
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        e_sm: [Polynomial<N>; L],
        r1: [Polynomial<2 * N - 1>; L],
        r2: [Polynomial<N - 1>; L],
        pk0: [Polynomial<N>; L],
    ) -> Self {
        PkGenerationCkks { configs, a, eek, sk, e_sm, r1, r2, pk0 }
    }

    /// Flattens the witness data into the Fiat-Shamir transcript.
    ///
    /// `a` is already bound through `pk_commitment`, so the transcript carries the
    /// commitments plus the error and quotient polynomials (same layout as BFV C1).
    fn payload(self, sk_commitment: Field, pk_commitment: Field) -> [Field] {
        let mut inputs: [Field] = [].as_vector();

        inputs = flatten::<_, _, BIT_PK>(inputs, self.a);
        inputs = flatten::<_, _, BIT_EEK>(inputs, [self.eek]);

        inputs = inputs.push_back(sk_commitment);
        inputs = inputs.push_back(pk_commitment);

        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2);

        inputs
    }

    /// Executes the CKKS public key share circuit.
    ///
    /// Returns `(commit(sk), commit(pk0 || a), commit(e_sm))`.
    pub fn execute(self) -> (Field, Field, Field) {
        self.perform_range_checks();

        let sk_commitment = compute_share_computation_sk_commitment::<N, BIT_SK>(self.sk);
        let e_sm_commitment =
            compute_share_computation_e_sm_commitment::<N, L, BIT_E_SM>(self.e_sm);
        let pk_commitment = compute_ckks_threshold_pk_commitment::<N, L, BIT_PK>(self.pk0, self.a);

        let gamma = compute_threshold_pk_challenge(self.payload(sk_commitment, pk_commitment));
        self.verify_evaluations(gamma);

        (sk_commitment, pk_commitment, e_sm_commitment)
    }

    /// Range-checks every secret witness against the configured bounds.
    fn perform_range_checks(self) {
        self.eek.range_check_2bounds::<BIT_EEK>(self.configs.eek_bound, self.configs.eek_bound);
        self.sk.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);

        for i in 0..L {
            self.e_sm[i].range_check_2bounds::<BIT_E_SM>(
                self.configs.e_sm_bound,
                self.configs.e_sm_bound,
            );
            self.r1[i].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[i],
                self.configs.r1_bounds[i],
            );
            self.r2[i].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[i],
                self.configs.r2_bounds[i],
            );
        }
    }

    /// For each limb i, at the challenge point gamma:
    /// `pk0[i](gamma) = -a[i](gamma)*sk(gamma) + e(gamma) + r2[i](gamma)*(gamma^N + 1) + r1[i](gamma)*q_i`.
    fn verify_evaluations(self, gamma: Field) {
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let sk_at_gamma = self.sk.eval(gamma);
        let eek_at_gamma = self.eek.eval(gamma);

        for i in 0..L {
            let expected_pk0 = -self.a[i].eval(gamma) * sk_at_gamma
                + eek_at_gamma
                + self.r2[i].eval(gamma) * cyclo_at_gamma
                + self.r1[i].eval(gamma) * self.configs.qis[i];

            assert(
                self.pk0[i].eval(gamma) == expected_pk0,
                "CKKS public key share equation failed",
            );
        }
    }
}
