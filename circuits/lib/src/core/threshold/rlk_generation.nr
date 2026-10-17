// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::configs::default::threshold::{
    GADGET_DIM, L as L_DEFAULT, LBFV_URS_GADGET_ROWS, LBFV_URS_ROW_COMMITMENTS, N as N_DEFAULT,
    PK_AGGREGATION_BIT_PK,
};
use crate::math::commitments::{
    compute_multiple_polynomial_commitment, compute_multiple_polynomial_commitment_checked,
    compute_rlk_limb_d0_commitment, compute_rlk_limb_d0_commitment_bounded,
    compute_rlk_limb_d2_commitment, compute_rlk_limb_d2_commitment_bounded,
    compute_rlk_r_commitment, compute_rlk_row_challenge, compute_rlk_row_commitment_from_limbs,
    compute_sc_sk_secret_root_from_polynomial, DS_PK_AGGREGATION,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Parameters for l-BFV relinearization-key generation.
pub struct Configs<let N: u32, let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bound for the ephemeral `r` polynomial coefficients (same distribution as `sk`).
    pub r_bound: Field,
    /// Bound for secret key polynomial (`sk`) coefficients.
    pub sk_bound: Field,
    /// Bound for `e0` (d0's error) coefficients.
    pub e0_bound: Field,
    /// Bound for `e2` (d2's error) coefficients.
    pub e2_bound: Field,
    /// Bounds for `rd0`, the mod-q_i quotient of the reduced d0 identity, for each CRT basis.
    pub rd0_bounds: [Field; L],
    /// Bounds for `rd2`, the mod-q_i quotient of the reduced d2 identity, for each CRT basis.
    pub rd2_bounds: [Field; L],
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        r_bound: Field,
        sk_bound: Field,
        e0_bound: Field,
        e2_bound: Field,
        rd0_bounds: [Field; L],
        rd2_bounds: [Field; L],
    ) -> Self {
        Configs { qis, r_bound, sk_bound, e0_bound, e2_bound, rd0_bounds, rd2_bounds }
    }
}

/// Prove one l-BFV RLK gadget row: for every CRT limb `l`, the two identities
///   `d0[l] == -(d1[l] * sk mod X^N + 1) + e0 + delta_l * r  + q_l * rd0[l]`
///   `d2[l] ==  (a[l]  * r  mod X^N + 1) + e2 + delta_l * sk + q_l * rd2[l]`
/// over the integers, with `delta_l = (row_index == l)`, in one proof.
///
/// `delta_l` stands in for the row's gadget scalar, the Garner coefficient `g_row`. That
/// coefficient is `1 mod q_row` and `0 mod q_j` for `j != row`, so modulo `q_l` it equals
/// `delta_l`, and the identities fix the same residues `d0`, `d2` that `g_row` does. The Rust test
/// `garner_coefficient_is_the_crt_unit_vector` pins this congruence for the l-BFV presets.
///
/// One proof covers the whole row, so `sk`, `r`, `e0` and `e2` are bound once rather than once per
/// limb, and no recursive verifier ties limbs together. The URS row `d1` and the CRS row `a` are
/// witnesses opened against the generated row commitments with checked packing, so they equal
/// the public rows exactly; compile-time tables cost far more compile memory.
pub struct RlkGenerationRow<let N: u32, let L: u32, let BIT_R: u32, let BIT_SK: u32, let BIT_E0: u32, let BIT_E2: u32, let BIT_RD0: u32, let BIT_RD2: u32, let BIT_D: u32, let BIT_ROW: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    configs: Configs<N, L>,
    urs_row_commitment: Field,
    crs_row_commitment: Field,
    row_index: u32,
    sk: Polynomial<N>,
    r: Polynomial<N>,
    e0: Polynomial<N>,
    e2: Polynomial<N>,
    rd0: [Polynomial<N>; L],
    rd2: [Polynomial<N>; L],
    d0: [Polynomial<N>; L],
    d2: [Polynomial<N>; L],
    urs: [Polynomial<N>; L],
    crs: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_R: u32, let BIT_SK: u32, let BIT_E0: u32, let BIT_E2: u32, let BIT_RD0: u32, let BIT_RD2: u32, let BIT_D: u32, let BIT_ROW: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> RlkGenerationRow<N, L, BIT_R, BIT_SK, BIT_E0, BIT_E2, BIT_RD0, BIT_RD2, BIT_D, BIT_ROW, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        configs: Configs<N, L>,
        urs_row_commitment: Field,
        crs_row_commitment: Field,
        row_index: u32,
        sk: Polynomial<N>,
        r: Polynomial<N>,
        e0: Polynomial<N>,
        e2: Polynomial<N>,
        rd0: [Polynomial<N>; L],
        rd2: [Polynomial<N>; L],
        d0: [Polynomial<N>; L],
        d2: [Polynomial<N>; L],
        urs: [Polynomial<N>; L],
        crs: [Polynomial<N>; L],
    ) -> Self {
        RlkGenerationRow {
            configs,
            urs_row_commitment,
            crs_row_commitment,
            row_index,
            sk,
            r,
            e0,
            e2,
            rd0,
            rd2,
            d0,
            d2,
            urs,
            crs,
        }
    }

    /// Returns `(sk_commitment, r_commitment, d0_commitment, d2_commitment)`. The row commitments
    /// are `compute_rlk_row_commitment_from_limbs` over the limb commitments, the values
    /// `rlk_aggregation` opens.
    pub fn execute(self) -> (Field, Field, Field, Field) {
        self.perform_range_checks();
        assert(
            compute_multiple_polynomial_commitment_checked::<N, L, BIT_ROW>(
                self.urs,
                DS_PK_AGGREGATION,
            )
                == self.urs_row_commitment,
            "URS row does not match its commitment",
        );
        assert(
            compute_multiple_polynomial_commitment_checked::<N, L, BIT_ROW>(
                self.crs,
                DS_PK_AGGREGATION,
            )
                == self.crs_row_commitment,
            "CRS row does not match its commitment",
        );

        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let r_commitment = compute_rlk_r_commitment::<N, BIT_R>(self.r);
        let mut d0_limbs: [Field; L] = [0; L];
        let mut d2_limbs: [Field; L] = [0; L];
        for l in 0..L {
            d0_limbs[l] =
                compute_rlk_limb_d0_commitment_bounded::<N, BIT_D>(self.row_index, l, self.d0[l]);
            d2_limbs[l] =
                compute_rlk_limb_d2_commitment_bounded::<N, BIT_D>(self.row_index, l, self.d2[l]);
        }
        let d0_commitment = compute_rlk_row_commitment_from_limbs(2, self.row_index, d0_limbs);
        let d2_commitment = compute_rlk_row_commitment_from_limbs(3, self.row_index, d2_limbs);

        let gamma =
            self.generate_challenge(sk_commitment, r_commitment, d0_commitment, d2_commitment);
        self.verify_evaluations(gamma);

        (sk_commitment, r_commitment, d0_commitment, d2_commitment)
    }

    /// Bounds every value the reduced identities read.
    ///
    /// The identities are checked at a single point, so each coefficient needs a real bound for
    /// the field equality to imply the integer one. Per coefficient, with `qb = (q_l - 1) / 2` and
    /// `m = max(sk_bound, r_bound)`:
    ///   `|d0|, |d2| <= qb` (checked below), `|d1|, |a| <= qb` (the opened rows are the public,
    ///   centered rows), `|d1 * sk mod X^N + 1|, |a * r mod X^N + 1| <= N * qb * m`,
    ///   `|e0|, |e2| <= e_bound`, `|delta * r|, |delta * sk| <= m`, `|q_l * rd| <= q_l * 2^BIT_RD`.
    /// The window `2^BIT_RD` covers `rd_bound = ((N * m + 2) * qb + e_bound + m) / q_l`, the honest
    /// quotient with one `qb` of margin. For every supported preset the sum of these magnitudes is
    /// below `2^100`,
    /// far below the BN254 prime, so a coefficient of the reduced difference is zero in the field
    /// only when it is zero over the integers.
    ///
    /// These checks also keep every packed digit in its slot, so the plain packing used for `e0`,
    /// `e2`, `rd0`, `rd2`, `d0` and `d2` below is injective.
    fn perform_range_checks(self) {
        let c = self.configs;
        // `sk` and `r` are ternary: `c^3 = c` has exactly the roots {-1, 0, 1}.
        assert(c.sk_bound == 1, "the ternary check needs sk_bound == 1");
        assert(c.r_bound == 1, "the ternary check needs r_bound == 1");
        self.sk.assert_ternary();
        self.r.assert_ternary();
        self.e0.range_check_2bounds::<BIT_E0>(c.e0_bound, c.e0_bound);
        self.e2.range_check_2bounds::<BIT_E2>(c.e2_bound, c.e2_bound);
        for l in 0..L {
            // Every other term of both identities is exactly bounded, so the integer identities fix
            // `rd0` and `rd2`; their bounds only have to rule out wraparound. The windows cover
            // `rd*_bounds` with one assert per coefficient and keep the plain packing injective.
            self.rd0[l].range_check_signed_power_of_two::<BIT_RD0>();
            self.rd2[l].range_check_signed_power_of_two::<BIT_RD2>();
            // `rd0`/`rd2` absorb any multiple of `q_l`, so `d0`/`d2` must be pinned to the centered
            // residue for the key limb to have one opening.
            let d_bound = (c.qis[l] - 1) / 2;
            self.d0[l].range_check_2bounds::<BIT_D>(d_bound, d_bound);
            self.d2[l].range_check_2bounds::<BIT_D>(d_bound, d_bound);
        }
    }

    /// Absorbs every witness the identities read before deriving `gamma`. `sk`, `r`, `d0` and `d2`
    /// enter through their commitments, `e0`, `e2`, `rd0` and `rd2` directly; the URS and CRS rows
    /// are fixed by their commitments, and `delta` is a function of `row_index`.
    fn generate_challenge(
        self,
        sk_commitment: Field,
        r_commitment: Field,
        d0_commitment: Field,
        d2_commitment: Field,
    ) -> Field {
        let mut payload = [
            self.row_index as Field,
            L as Field,
            sk_commitment,
            r_commitment,
            d0_commitment,
            d2_commitment,
        ]
            .as_vector();
        payload = flatten::<_, _, BIT_E0>(payload, [self.e0]);
        payload = flatten::<_, _, BIT_E2>(payload, [self.e2]);
        payload = flatten::<_, _, BIT_RD0>(payload, self.rd0);
        payload = flatten::<_, _, BIT_RD2>(payload, self.rd2);
        compute_rlk_row_challenge(payload)
    }

    /// Checks both reduced identities of every limb at `gamma`.
    ///
    /// `negacyclic_kernel(u, gamma)[j]` is `(X^(N-1-j) * u mod X^N + 1)(gamma)`, so
    /// `d1.dot(k_sk)` evaluates `d1 * sk mod X^N + 1` at gamma without the product entering the
    /// witness, and `a.dot(k_r)` does the same for `a * r`. Every other term has `N` coefficients,
    /// so both sides have degree below `N` and Schwartz-Zippel applies to their difference. The two
    /// kernels, and the evaluations of the shared `sk`, `r`, `e0`, `e2`, serve every limb.
    fn verify_evaluations(self, gamma: Field) {
        let k_sk = negacyclic_kernel(self.sk, gamma);
        let k_r = negacyclic_kernel(self.r, gamma);
        // The last kernel entry is the polynomial itself evaluated at gamma.
        let sk_at = k_sk[N - 1];
        let r_at = k_r[N - 1];
        let e0_at = self.e0.eval(gamma);
        let e2_at = self.e2.eval(gamma);
        for l in 0..L {
            // The row's gadget scalar modulo q_l: entry `l` of the CRT unit vector `e_row`.
            let delta = (self.row_index == l) as Field;
            let q = self.configs.qis[l];
            assert(
                self.d0[l].eval(gamma) - e0_at - delta * r_at - q * self.rd0[l].eval(gamma)
                    == -self.urs[l].dot_materialized(k_sk),
                "RLK d0 equation failed",
            );
            assert(
                self.d2[l].eval(gamma) - e2_at - delta * sk_at - q * self.rd2[l].eval(gamma)
                    == self.crs[l].dot_materialized(k_r),
                "RLK d2 equation failed",
            );
        }
    }
}

// The limb fixture (`N = 4`, `q = 97`) as a two-limb row with both moduli 97: limb 0 is the
// diagonal witness (`delta = 1`), limb 1 the off-diagonal one (`delta = 0`). The row commitments
// are computed the way the generator computes `LBFV_URS_ROW_COMMITMENTS` and
// `LBFV_CRS_ROW_COMMITMENTS`.
type TestRow = RlkGenerationRow<4, 2, 1, 1, 2, 2, 2, 2, 6, 6, 1, 4>;

global TEST_URS: [Field; 4] = [30, -40, 20, -10];
global TEST_CRS: [Field; 4] = [12, 45, -33, 7];

fn test_row(
    committed_urs: [Field; 4],
    rd0: [[Field; 4]; 2],
    d0: [[Field; 4]; 2],
    d2: [[Field; 4]; 2],
) -> TestRow {
    RlkGenerationRow::new(
        Configs::new([97, 97], 1, 1, 3, 3, [3, 3], [3, 3]),
        compute_multiple_polynomial_commitment::<4, 2, 6>(
            [Polynomial::new(committed_urs), Polynomial::new(committed_urs)],
            DS_PK_AGGREGATION,
        ),
        compute_multiple_polynomial_commitment::<4, 2, 6>(
            [Polynomial::new(TEST_CRS), Polynomial::new(TEST_CRS)],
            DS_PK_AGGREGATION,
        ),
        0,
        Polynomial::new([0, 1, -1, 1]),
        Polynomial::new([1, 0, -1, -1]),
        Polynomial::new([1, -2, 0, 3]),
        Polynomial::new([-3, 2, 1, 0]),
        [Polynomial::new(rd0[0]), Polynomial::new(rd0[1])],
        [Polynomial::new([1, 0, 0, 0]), Polynomial::new([1, 0, 0, 0])],
        [Polynomial::new(d0[0]), Polynomial::new(d0[1])],
        [Polynomial::new(d2[0]), Polynomial::new(d2[1])],
        [Polynomial::new(TEST_URS), Polynomial::new(TEST_URS)],
        [Polynomial::new(TEST_CRS), Polynomial::new(TEST_CRS)],
    )
}

global HONEST_RD0: [[Field; 4]; 2] = [[1, -1, 0, 1], [1, -1, 0, 1]];
global HONEST_D0: [[Field; 4]; 2] = [[9, -29, -1, 39], [8, -29, 0, 40]];
global HONEST_D2: [[Field; 4]; 2] = [[44, -21, -19, 39], [44, -22, -18, 38]];

#[test]
fn test_rlk_row_accepts_diagonal_and_off_diagonal_limbs() {
    let (_, _, d0_commitment, d2_commitment) =
        test_row(TEST_URS, HONEST_RD0, HONEST_D0, HONEST_D2).execute();
    // The row commitments are the values `rlk_aggregation` opens from the coefficients.
    let mut d0_limbs: [Field; 2] = [0; 2];
    let mut d2_limbs: [Field; 2] = [0; 2];
    for l in 0..2 {
        d0_limbs[l] = compute_rlk_limb_d0_commitment::<4, 6>(0, l, Polynomial::new(HONEST_D0[l]));
        d2_limbs[l] = compute_rlk_limb_d2_commitment::<4, 6>(0, l, Polynomial::new(HONEST_D2[l]));
    }
    assert(d0_commitment == compute_rlk_row_commitment_from_limbs(2, 0, d0_limbs));
    assert(d2_commitment == compute_rlk_row_commitment_from_limbs(3, 0, d2_limbs));
}

/// A quotient off by one moves `d0` off the identity by `q`.
#[test(should_fail_with = "RLK d0 equation failed")]
fn test_rlk_row_rejects_wrong_quotient() {
    let _ = test_row(
        TEST_URS,
        [[2, -1, 0, 1], [1, -1, 0, 1]],
        HONEST_D0,
        HONEST_D2,
    )
        .execute();
}

/// `d0 + q` with `rd0 + 1` satisfies the identity and keeps `rd0` within its bound, so only the
/// centered `d0` bound rejects the second opening.
#[test(should_fail_with = "assert_max_bit_size")]
fn test_rlk_row_rejects_d0_shifted_by_q() {
    let _ = test_row(
        TEST_URS,
        [[2, -1, 0, 1], [1, -1, 0, 1]],
        [[106, -29, -1, 39], [8, -29, 0, 40]],
        HONEST_D2,
    )
        .execute();
}

/// The diagonal witness on the off-diagonal limb: the gadget term must vanish there.
#[test(should_fail_with = "RLK d0 equation failed")]
fn test_rlk_row_rejects_wrong_delta() {
    let _ = test_row(
        TEST_URS,
        HONEST_RD0,
        [HONEST_D0[0], HONEST_D0[0]],
        HONEST_D2,
    )
        .execute();
}

/// A prover cannot substitute its own `d1`: the opened row must hash to the public commitment.
#[test(should_fail_with = "URS row does not match its commitment")]
fn test_rlk_row_rejects_a_different_urs_row() {
    let _ = test_row([0; 4], HONEST_RD0, HONEST_D0, HONEST_D2).execute();
}

/// The generated URS row commitments must equal the in-circuit hash of each URS row, or every RLK
/// row proof would reject the public `d1`.
#[test]
fn test_generated_urs_row_commitments_match_the_rows() {
    for row in 0..GADGET_DIM {
        let expected = compute_multiple_polynomial_commitment::<N_DEFAULT, L_DEFAULT, PK_AGGREGATION_BIT_PK>(
            LBFV_URS_GADGET_ROWS[row],
            DS_PK_AGGREGATION,
        );
        assert(LBFV_URS_ROW_COMMITMENTS[row] == expected);
    }
}
