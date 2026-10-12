// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_lbfv_pk_limb_commitment_bounded, compute_lbfv_pk_row_challenge,
    compute_lbfv_pk_row_commitment, compute_lbfv_pk_row_commitment_from_limbs,
    compute_multiple_polynomial_commitment, compute_multiple_polynomial_commitment_checked,
    compute_sc_sk_secret_root_from_polynomial, DS_PK_AGGREGATION,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Prove one l-BFV public-key row: every CRT limb of
///   `pk0[l] == -(a[l] * sk mod X^N + 1) + eek + q_l * r[l]`
/// over the integers, for the row's CRS polynomials `a`.
///
/// One proof covers the whole row, so `sk` and `eek` are bound once rather than once per limb, and
/// no recursive verifier is needed to tie limbs together. The CRS row is a witness opened against
/// `crs_row_commitment` (the generated `LBFV_CRS_ROW_COMMITMENTS[row]`) with checked packing, so
/// it equals the public row exactly; a compile-time CRS table costs far more compile memory.
pub struct LbfvPkGenerationRow<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R: u32, let BIT_PK: u32, let BIT_CRS: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    eek_bound: Field,
    sk_bound: Field,
    r_bounds: [Field; L],
    qis: [Field; L],
    crs_row_commitment: Field,
    row_index: u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r: [Polynomial<N>; L],
    pk0: [Polynomial<N>; L],
    crs: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R: u32, let BIT_PK: u32, let BIT_CRS: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> LbfvPkGenerationRow<N, L, BIT_EEK, BIT_SK, BIT_R, BIT_PK, BIT_CRS, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        eek_bound: Field,
        sk_bound: Field,
        r_bounds: [Field; L],
        qis: [Field; L],
        crs_row_commitment: Field,
        row_index: u32,
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r: [Polynomial<N>; L],
        pk0: [Polynomial<N>; L],
        crs: [Polynomial<N>; L],
    ) -> Self {
        LbfvPkGenerationRow {
            eek_bound,
            sk_bound,
            r_bounds,
            qis,
            crs_row_commitment,
            row_index,
            eek,
            sk,
            r,
            pk0,
            crs,
        }
    }

    /// Returns `(sk_commitment, pk_commitment)`. `pk_commitment` is
    /// `compute_lbfv_pk_row_commitment(row_index, pk0)`, the value `lbfv_pk_aggregation` opens.
    pub fn execute(self) -> (Field, Field) {
        self.perform_range_checks();
        assert(
            compute_multiple_polynomial_commitment_checked::<N, L, BIT_CRS>(
                self.crs,
                DS_PK_AGGREGATION,
            )
                == self.crs_row_commitment,
            "CRS row does not match its commitment",
        );

        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let mut limb_commitments: [Field; L] = [0; L];
        for l in 0..L {
            limb_commitments[l] = compute_lbfv_pk_limb_commitment_bounded::<N, BIT_PK>(
                self.row_index,
                l,
                self.pk0[l],
            );
        }
        let pk_commitment =
            compute_lbfv_pk_row_commitment_from_limbs(self.row_index, limb_commitments);

        let gamma = self.generate_challenge(sk_commitment, pk_commitment);
        self.verify_evaluations(gamma);

        (sk_commitment, pk_commitment)
    }

    /// Bounds every value the reduced identities read.
    ///
    /// Each identity is checked at a single point, so each coefficient needs a real bound for the
    /// field equality to imply the integer one. Per coefficient, with `qb = (q_l - 1) / 2`:
    /// `|pk0[l]| <= qb`, `|a[l]| <= qb` (the opened CRS row is the public, centered row),
    /// `|a[l] * sk mod X^N + 1| <= N * qb * sk_bound`, `|eek| <= eek_bound` and
    /// `|q_l * r[l]| <= q_l * r_bounds[l]`. `r_bounds[l] = ((N * sk_bound + 2) * qb + eek_bound) / q_l`
    /// covers the honest quotient with one `qb` of margin. For every supported preset the sum of
    /// these magnitudes is below `2^100`, far below the BN254 prime, so a coefficient of the reduced
    /// difference is zero in the field only when it is zero over the integers.
    ///
    /// These checks also keep every packed digit in its slot, so the plain packing used for `eek`,
    /// `r` and `pk0` below is injective.
    fn perform_range_checks(self) {
        self.eek.range_check_2bounds::<BIT_EEK>(self.eek_bound, self.eek_bound);
        self.sk.range_check_2bounds::<BIT_SK>(self.sk_bound, self.sk_bound);
        for l in 0..L {
            self.r[l].range_check_2bounds::<BIT_R>(self.r_bounds[l], self.r_bounds[l]);
            // `r` absorbs any multiple of `q_l`, so `pk0` must be pinned to its centered residue
            // for its commitment to have one opening.
            let pk_bound: Field = (self.qis[l] - 1) / 2;
            self.pk0[l].range_check_2bounds::<BIT_PK>(pk_bound, pk_bound);
        }
    }

    /// Absorbs every witness the identities read before deriving `gamma`. `sk` and `pk0` enter
    /// through their commitments, `eek` and `r` directly; the CRS row is fixed by its commitment.
    fn generate_challenge(self, sk_commitment: Field, pk_commitment: Field) -> Field {
        let mut payload =
            [self.row_index as Field, L as Field, sk_commitment, pk_commitment].as_vector();
        payload = flatten::<_, _, BIT_EEK>(payload, [self.eek]);
        payload = flatten::<_, _, BIT_R>(payload, self.r);
        compute_lbfv_pk_row_challenge(payload)
    }

    /// Checks each limb's reduced identity at `gamma`.
    ///
    /// `negacyclic_kernel(sk, gamma)[j]` is `(X^(N-1-j) * sk mod X^N + 1)(gamma)`, so
    /// `a[l].dot(kernel)` evaluates `a[l] * sk mod X^N + 1` at `gamma` without the product entering
    /// the witness. Every other term has `N` coefficients, so both sides have degree below `N` and
    /// Schwartz-Zippel applies to their difference. One kernel serves every limb.
    fn verify_evaluations(self, gamma: Field) {
        let kernel = negacyclic_kernel(self.sk, gamma);
        for l in 0..L {
            let mut residual: Field = 0;
            for j in 0..N {
                residual = residual * gamma
                    + (
                        self.pk0[l].coefficients[j]
                            - self.eek.coefficients[j]
                            - self.qis[l] * self.r[l].coefficients[j]
                    );
            }
            assert(residual == -self.crs[l].dot_materialized(kernel), "Public key equation failed");
        }
    }
}

// Worked at `N = 4`, `q = 97`, coefficients highest degree first, as a one-limb row. The honest
// witness folds the schoolbook product `a * sk` with `X^4 = -1` and divides by `q` exactly:
// `-(a * sk mod X^4 + 1) + eek = [67, -87, 52, 29]`, so `r = [-1, 1, -1, 0]` brings it to the
// centered `pk0 = [-30, 10, -45, 29]`. Bounds: eek = 3, sk = 1, r = ((4 + 2) * 48 + 3) / 97 = 3,
// pk0 = 48. The CRS row commitment is computed the way the generator computes
// `LBFV_CRS_ROW_COMMITMENTS`.
type TestRow = LbfvPkGenerationRow<4, 1, 2, 1, 2, 6, 6, 1, 4>;

fn test_row(a: [Field; 4], committed_a: [Field; 4], r: [Field; 4], pk0: [Field; 4]) -> TestRow {
    LbfvPkGenerationRow::new(
        3,
        1,
        [3],
        [97],
        compute_multiple_polynomial_commitment::<4, 1, 6>(
            [Polynomial::new(committed_a)],
            DS_PK_AGGREGATION,
        ),
        0,
        Polynomial::new([1, -2, 0, 3]),
        Polynomial::new([0, 1, -1, 1]),
        [Polynomial::new(r)],
        [Polynomial::new(pk0)],
        [Polynomial::new(a)],
    )
}

#[test]
fn test_lbfv_pk_generation_row_accepts_canonical_pk0() {
    let a = [12, 45, -33, 7];
    let (_, pk_commitment) = test_row(a, a, [-1, 1, -1, 0], [-30, 10, -45, 29]).execute();
    // The row commitment is the value `lbfv_pk_aggregation` opens.
    assert(
        pk_commitment
            == compute_lbfv_pk_row_commitment::<4, 1, 6>(0, [Polynomial::new([-30, 10, -45, 29])]),
    );
}

#[test(should_fail_with = "Public key equation failed")]
fn test_lbfv_pk_generation_row_rejects_wrong_quotient() {
    let a = [12, 45, -33, 7];
    let _ = test_row(a, a, [-1, 1, -1, 1], [-30, 10, -45, 29]).execute();
}

#[test(should_fail_with = "assert_max_bit_size")]
fn test_lbfv_pk_generation_row_rejects_non_canonical_pk0() {
    let a = [12, 45, -33, 7];
    let _ = test_row(a, a, [-1, 1, -1, 1], [-30, 10, -45, 126]).execute();
}

/// A prover cannot substitute its own `a`: the opened row must hash to the public commitment.
#[test(should_fail_with = "CRS row does not match its commitment")]
fn test_lbfv_pk_generation_row_rejects_a_different_crs_row() {
    let _ = test_row([0; 4], [12, 45, -33, 7], [0; 4], [0; 4]).execute();
}
