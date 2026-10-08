// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_rlk_limb_challenge, compute_rlk_limb_d0_commitment, compute_rlk_limb_d2_commitment,
    compute_rlk_limb_e0_commitment, compute_rlk_limb_e2_commitment, compute_rlk_r_commitment,
    compute_sc_sk_secret_root_from_polynomial,
};
use crate::math::helpers::flatten_checked;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Prove the two RLK equations for one row and one CRT limb.
///
/// Each limb checks the identities **reduced modulo `X^N + 1`**, over the integers:
///   `d0 == -(d1 * sk mod X^N + 1) + e0 + delta * r  + q_i * rd0`
///   `d2 ==  (a  * r  mod X^N + 1) + e2 + delta * sk + q_i * rd2`
/// where `delta = (row_index == limb_index)`.
///
/// `delta` stands in for the row's gadget scalar, the Garner coefficient `g_row`. That
/// coefficient is `1 mod q_row` and `0 mod q_j` for `j != row`, so modulo `q_i` it equals
/// `delta`, and the identities fix the same residues `d0`, `d2` that `g_row` does. The Rust test
/// `garner_coefficient_is_the_crt_unit_vector` pins this congruence for the l-BFV presets.
pub struct RlkGenerationLimb<let N: u32, let BIT_R: u32, let BIT_SK: u32, let BIT_E0: u32, let BIT_E2: u32, let BIT_RD0: u32, let BIT_RD2: u32, let BIT_D: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    r_bound: Field,
    sk_bound: Field,
    e0_bound: Field,
    e2_bound: Field,
    rd0_bound: Field,
    rd2_bound: Field,
    qi: Field,
    d1: Polynomial<N>,
    a: Polynomial<N>,
    row_index: u32,
    limb_index: u32,
    sk: Polynomial<N>,
    r: Polynomial<N>,
    e0: Polynomial<N>,
    e2: Polynomial<N>,
    rd0: Polynomial<N>,
    rd2: Polynomial<N>,
    d0: Polynomial<N>,
    d2: Polynomial<N>,
}

impl<let N: u32, let BIT_R: u32, let BIT_SK: u32, let BIT_E0: u32, let BIT_E2: u32, let BIT_RD0: u32, let BIT_RD2: u32, let BIT_D: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> RlkGenerationLimb<N, BIT_R, BIT_SK, BIT_E0, BIT_E2, BIT_RD0, BIT_RD2, BIT_D, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        r_bound: Field,
        sk_bound: Field,
        e0_bound: Field,
        e2_bound: Field,
        rd0_bound: Field,
        rd2_bound: Field,
        qi: Field,
        d1: Polynomial<N>,
        a: Polynomial<N>,
        row_index: u32,
        limb_index: u32,
        sk: Polynomial<N>,
        r: Polynomial<N>,
        e0: Polynomial<N>,
        e2: Polynomial<N>,
        rd0: Polynomial<N>,
        rd2: Polynomial<N>,
        d0: Polynomial<N>,
        d2: Polynomial<N>,
    ) -> Self {
        RlkGenerationLimb {
            r_bound,
            sk_bound,
            e0_bound,
            e2_bound,
            rd0_bound,
            rd2_bound,
            qi,
            d1,
            a,
            row_index,
            limb_index,
            sk,
            r,
            e0,
            e2,
            rd0,
            rd2,
            d0,
            d2,
        }
    }

    pub fn execute(self) -> (Field, Field, Field, Field, Field, Field) {
        self.perform_range_checks();

        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let r_commitment = compute_rlk_r_commitment::<N, BIT_R>(self.r);
        let e0_commitment = compute_rlk_limb_e0_commitment::<N, BIT_E0>(self.row_index, self.e0);
        let e2_commitment = compute_rlk_limb_e2_commitment::<N, BIT_E2>(self.row_index, self.e2);
        let d0_limb_commitment =
            compute_rlk_limb_d0_commitment::<N, BIT_D>(self.row_index, self.limb_index, self.d0);
        let d2_limb_commitment =
            compute_rlk_limb_d2_commitment::<N, BIT_D>(self.row_index, self.limb_index, self.d2);

        let gamma = self.generate_challenge(
            sk_commitment,
            r_commitment,
            e0_commitment,
            e2_commitment,
            d0_limb_commitment,
            d2_limb_commitment,
        );
        self.verify_evaluations(gamma);

        (
            sk_commitment, r_commitment, e0_commitment, e2_commitment, d0_limb_commitment,
            d2_limb_commitment,
        )
    }

    /// Bounds every value the reduced identities read.
    ///
    /// The identities are checked at a single point, so each coefficient needs a real bound for
    /// the field equality to imply the integer one. Per coefficient, with `qb = (q_i - 1) / 2` and
    /// `m = max(sk_bound, r_bound)`:
    ///   `|d0|, |d2| <= qb` (checked below), `|d1|, |a| <= qb` (compile-time rows, stored
    ///   centered), `|d1 * sk mod X^N + 1|, |a * r mod X^N + 1| <= N * qb * m`,
    ///   `|e0|, |e2| <= e_bound`, `|delta * r|, |delta * sk| <= m`, `|q_i * rd| <= q_i * rd_bound`.
    /// `rd_bound = ((N * m + 2) * qb + e_bound + m) / q_i` covers the honest quotient with one
    /// `qb` of margin. For every supported preset the sum of these magnitudes is below `2^100`,
    /// far below the BN254 prime, so a coefficient of the reduced difference is zero in the field
    /// only when it is zero over the integers.
    fn perform_range_checks(self) {
        self.sk.range_check_2bounds::<BIT_SK>(self.sk_bound, self.sk_bound);
        self.r.range_check_2bounds::<BIT_R>(self.r_bound, self.r_bound);
        self.e0.range_check_2bounds::<BIT_E0>(self.e0_bound, self.e0_bound);
        self.e2.range_check_2bounds::<BIT_E2>(self.e2_bound, self.e2_bound);
        self.rd0.range_check_2bounds::<BIT_RD0>(self.rd0_bound, self.rd0_bound);
        self.rd2.range_check_2bounds::<BIT_RD2>(self.rd2_bound, self.rd2_bound);
        // d0/d2 are the RLK key limbs. `rd0`/`rd2` absorb any multiple of `q_i`, so without this
        // bound `d0 + k * q_i` satisfies the same identity and the key limb gets a second
        // opening. Pin them to the centered residue mod q_i, derived here rather than borrowed
        // from a bound that happens to equal it.
        let d_bound = (self.qi - 1) / 2;
        self.d0.range_check_2bounds::<BIT_D>(d_bound, d_bound);
        self.d2.range_check_2bounds::<BIT_D>(d_bound, d_bound);
    }

    /// Absorbs every value the identities read before deriving `gamma`.
    ///
    /// `delta` is a function of `row_index` and `limb_index`, which open the payload, so it needs
    /// no entry of its own.
    fn generate_challenge(
        self,
        sk_commitment: Field,
        r_commitment: Field,
        e0_commitment: Field,
        e2_commitment: Field,
        d0_limb_commitment: Field,
        d2_limb_commitment: Field,
    ) -> Field {
        let mut payload = [self.row_index as Field, self.limb_index as Field].as_vector();
        payload = flatten_checked::<_, _, BIT_D>(payload, [self.d1]);
        payload = flatten_checked::<_, _, BIT_D>(payload, [self.a]);
        payload = payload.push_back(self.qi);
        payload = flatten_checked::<_, _, BIT_E0>(payload, [self.e0]);
        payload = flatten_checked::<_, _, BIT_E2>(payload, [self.e2]);
        payload = payload.push_back(sk_commitment);
        payload = payload.push_back(r_commitment);
        payload = payload.push_back(e0_commitment);
        payload = payload.push_back(e2_commitment);
        payload = payload.push_back(d0_limb_commitment);
        payload = payload.push_back(d2_limb_commitment);
        payload = flatten_checked::<_, _, BIT_RD0>(payload, [self.rd0]);
        payload = flatten_checked::<_, _, BIT_RD2>(payload, [self.rd2]);
        compute_rlk_limb_challenge(payload)
    }

    /// Checks both reduced identities at `gamma`.
    ///
    /// `negacyclic_kernel(u, gamma)[j]` is `(X^(N-1-j) * u mod X^N + 1)(gamma)`, so `d1.dot(k_sk)`
    /// evaluates `d1 * sk mod X^N + 1` at gamma without the product entering the witness, and
    /// `a.dot(k_r)` does the same for `a * r`. Every other term has `N` coefficients, so both
    /// sides have degree below `N` and Schwartz-Zippel applies to their difference.
    fn verify_evaluations(self, gamma: Field) {
        // The row's gadget scalar modulo q_i: entry `limb_index` of the CRT unit vector `e_row`.
        let delta = (self.row_index == self.limb_index) as Field;
        let k_sk = negacyclic_kernel(self.sk, gamma);
        let k_r = negacyclic_kernel(self.r, gamma);

        let mut residual_d0: [Field; N] = [0; N];
        let mut residual_d2: [Field; N] = [0; N];
        for j in 0..N {
            residual_d0[j] = self.d0.coefficients[j]
                - self.e0.coefficients[j]
                - delta * self.r.coefficients[j]
                - self.qi * self.rd0.coefficients[j];
            residual_d2[j] = self.d2.coefficients[j]
                - self.e2.coefficients[j]
                - delta * self.sk.coefficients[j]
                - self.qi * self.rd2.coefficients[j];
        }

        assert(
            Polynomial::new(residual_d0).eval(gamma) == -self.d1.dot(k_sk),
            "RLK d0 equation failed",
        );
        assert(
            Polynomial::new(residual_d2).eval(gamma) == self.a.dot(k_r),
            "RLK d2 equation failed",
        );
    }
}

// Worked at `N = 4`, `q = 97`, coefficients highest degree first. The honest witnesses were
// computed by folding the schoolbook products with `X^4 = -1` and dividing by `q` exactly.
// Bounds: sk = r = 1, e = 3, rd = ((4 + 2) * 48 + 3 + 1) / 97 = 3, d = 48.
type TestLimb = RlkGenerationLimb<4, 1, 1, 2, 2, 2, 2, 6, 1, 4>;

fn test_limb(
    row_index: u32,
    limb_index: u32,
    rd0: [Field; 4],
    rd2: [Field; 4],
    d0: [Field; 4],
    d2: [Field; 4],
) -> TestLimb {
    RlkGenerationLimb::new(
        1,
        1,
        3,
        3,
        3,
        3,
        97,
        Polynomial::new([30, -40, 20, -10]),
        Polynomial::new([12, 45, -33, 7]),
        row_index,
        limb_index,
        Polynomial::new([0, 1, -1, 1]),
        Polynomial::new([1, 0, -1, -1]),
        Polynomial::new([1, -2, 0, 3]),
        Polynomial::new([-3, 2, 1, 0]),
        Polynomial::new(rd0),
        Polynomial::new(rd2),
        Polynomial::new(d0),
        Polynomial::new(d2),
    )
}

/// On the diagonal limb `delta = 1`, so `r` and `sk` enter the identities once.
#[test]
fn test_rlk_limb_accepts_diagonal_witness() {
    let _ = test_limb(
        0,
        0,
        [1, -1, 0, 1],
        [1, 0, 0, 0],
        [9, -29, -1, 39],
        [44, -21, -19, 39],
    )
        .execute();
}

/// Off the diagonal `delta = 0`, so the gadget term vanishes from the limb.
#[test]
fn test_rlk_limb_accepts_off_diagonal_witness() {
    let _ = test_limb(
        0,
        1,
        [1, -1, 0, 1],
        [1, 0, 0, 0],
        [8, -29, 0, 40],
        [44, -22, -18, 38],
    )
        .execute();
}

/// A quotient off by one moves `d0` off the identity by `q`.
#[test(should_fail_with = "RLK d0 equation failed")]
fn test_rlk_limb_rejects_wrong_quotient() {
    let _ = test_limb(
        0,
        0,
        [2, -1, 0, 1],
        [1, 0, 0, 0],
        [9, -29, -1, 39],
        [44, -21, -19, 39],
    )
        .execute();
}

/// `d0 + q` with `rd0 + 1` satisfies the identity and keeps `rd0` within its bound, so only the
/// centered `d0` bound rejects the second opening.
#[test(should_fail_with = "assert_max_bit_size")]
fn test_rlk_limb_rejects_d0_shifted_by_q() {
    let _ = test_limb(
        0,
        0,
        [2, -1, 0, 1],
        [1, 0, 0, 0],
        [106, -29, -1, 39],
        [44, -21, -19, 39],
    )
        .execute();
}

/// The same shift on `d2` is rejected by the same bound.
#[test(should_fail_with = "assert_max_bit_size")]
fn test_rlk_limb_rejects_d2_shifted_by_q() {
    let _ = test_limb(
        0,
        0,
        [1, -1, 0, 1],
        [1, 0, 0, -1],
        [9, -29, -1, 39],
        [44, -21, -19, -58],
    )
        .execute();
}

/// A witness built with the gadget scalar `1` on an off-diagonal limb, where `delta = 0`.
#[test(should_fail_with = "RLK d0 equation failed")]
fn test_rlk_limb_rejects_wrong_delta() {
    let _ = test_limb(
        0,
        1,
        [1, -1, 0, 1],
        [1, 0, 0, 0],
        [9, -29, -1, 39],
        [44, -21, -19, 39],
    )
        .execute();
}
