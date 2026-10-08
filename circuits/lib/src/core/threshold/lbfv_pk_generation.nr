// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_lbfv_pk_limb_challenge, compute_lbfv_pk_limb_commitment,
    compute_lbfv_pk_limb_eek_commitment, compute_sc_sk_secret_root_from_polynomial,
};
use crate::math::helpers::flatten_checked;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};

/// Prove one CRT limb of one l-BFV public-key row.
///
/// The limb checks the identity **reduced modulo `X^N + 1`**, over the integers:
///   `pk0 == -(a * sk mod X^N + 1) + eek + q_i * r`
/// which is the relation C1 checks per modulus, here for one row and one limb.
pub struct LbfvPkGenerationLimb<let N: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    eek_bound: Field,
    sk_bound: Field,
    r_bound: Field,
    qi: Field,
    a: Polynomial<N>,
    row_index: u32,
    limb_index: u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r: Polynomial<N>,
    pk0: Polynomial<N>,
}

impl<let N: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> LbfvPkGenerationLimb<N, BIT_EEK, BIT_SK, BIT_R, BIT_PK, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        eek_bound: Field,
        sk_bound: Field,
        r_bound: Field,
        qi: Field,
        a: Polynomial<N>,
        row_index: u32,
        limb_index: u32,
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r: Polynomial<N>,
        pk0: Polynomial<N>,
    ) -> Self {
        LbfvPkGenerationLimb {
            eek_bound,
            sk_bound,
            r_bound,
            qi,
            a,
            row_index,
            limb_index,
            eek,
            sk,
            r,
            pk0,
        }
    }

    pub fn execute(self) -> (Field, Field, Field) {
        self.perform_range_checks();

        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let eek_commitment =
            compute_lbfv_pk_limb_eek_commitment::<N, BIT_EEK>(self.row_index, self.eek);
        let pk_limb_commitment =
            compute_lbfv_pk_limb_commitment::<N, BIT_PK>(self.row_index, self.limb_index, self.pk0);
        let gamma = self.generate_challenge(sk_commitment, eek_commitment, pk_limb_commitment);
        self.verify_evaluation(gamma);

        (sk_commitment, eek_commitment, pk_limb_commitment)
    }

    /// Bounds every value the reduced identity reads.
    ///
    /// The identity is checked at a single point, so each coefficient needs a real bound for the
    /// field equality to imply the integer one. Per coefficient, with `qb = (q_i - 1) / 2`:
    ///   `|pk0| <= qb` (checked below), `|a| <= qb` (compile-time CRS row, stored centered),
    ///   `|a * sk mod X^N + 1| <= N * qb * sk_bound`, `|eek| <= eek_bound` and
    ///   `|q_i * r| <= q_i * r_bound`.
    /// `r_bound = ((N * sk_bound + 2) * qb + eek_bound) / q_i` covers the honest quotient with one
    /// `qb` of margin. For every supported preset the sum of these magnitudes is below `2^100`,
    /// far below the BN254 prime, so a coefficient of the reduced difference is zero in the field
    /// only when it is zero over the integers.
    fn perform_range_checks(self) {
        self.eek.range_check_2bounds::<BIT_EEK>(self.eek_bound, self.eek_bound);
        self.sk.range_check_2bounds::<BIT_SK>(self.sk_bound, self.sk_bound);
        self.r.range_check_2bounds::<BIT_R>(self.r_bound, self.r_bound);
        // pk0 is committed here and re-opened downstream. `r` absorbs any multiple of `qi`, so
        // without this bound `pk0 + k*qi` satisfies the same equation and the key limb gets a
        // second opening. Pin it to the centered residue, as main's C1 does.
        let pk_bound: Field = (self.qi - 1) / 2;
        self.pk0.range_check_2bounds::<BIT_PK>(pk_bound, pk_bound);
    }

    /// Absorbs every value the identity reads before deriving `gamma`.
    fn generate_challenge(
        self,
        sk_commitment: Field,
        eek_commitment: Field,
        pk_limb_commitment: Field,
    ) -> Field {
        let mut payload = [self.row_index as Field, self.limb_index as Field].as_vector();
        payload = flatten_checked::<_, _, BIT_PK>(payload, [self.a]);
        payload = flatten_checked::<_, _, BIT_EEK>(payload, [self.eek]);
        payload = payload.push_back(sk_commitment);
        payload = payload.push_back(eek_commitment);
        payload = payload.push_back(pk_limb_commitment);
        payload = flatten_checked::<_, _, BIT_R>(payload, [self.r]);
        payload = payload.push_back(self.qi);
        compute_lbfv_pk_limb_challenge(payload)
    }

    /// Checks the reduced identity at `gamma`.
    ///
    /// `negacyclic_kernel(sk, gamma)[j]` is `(X^(N-1-j) * sk mod X^N + 1)(gamma)`, so
    /// `a.dot(kernel)` evaluates `a * sk mod X^N + 1` at gamma without the product entering the
    /// witness. Every other term has `N` coefficients, so both sides have degree below `N` and
    /// Schwartz-Zippel applies to their difference.
    fn verify_evaluation(self, gamma: Field) {
        let kernel = negacyclic_kernel(self.sk, gamma);
        let mut residual: [Field; N] = [0; N];
        for j in 0..N {
            residual[j] = self.pk0.coefficients[j]
                - self.eek.coefficients[j]
                - self.qi * self.r.coefficients[j];
        }
        assert(
            Polynomial::new(residual).eval(gamma) == -self.a.dot(kernel),
            "Public key equation failed",
        );
    }
}

// Worked at `N = 4`, `q = 97`, coefficients highest degree first. The honest witness folds the
// schoolbook product `a * sk` with `X^4 = -1` and divides by `q` exactly:
// `-(a * sk mod X^4 + 1) + eek = [67, -87, 52, 29]`, so `r = [-1, 1, -1, 0]` brings it to the
// centered `pk0 = [-30, 10, -45, 29]`.
// Bounds: eek = 3, sk = 1, r = ((4 + 2) * 48 + 3) / 97 = 3, pk0 = 48.
type TestLimb = LbfvPkGenerationLimb<4, 2, 1, 2, 6, 1, 4>;

fn test_limb(
    a: [Field; 4],
    eek: [Field; 4],
    sk: [Field; 4],
    r: [Field; 4],
    pk0: [Field; 4],
) -> TestLimb {
    LbfvPkGenerationLimb::new(
        3,
        1,
        3,
        97,
        Polynomial::new(a),
        0,
        0,
        Polynomial::new(eek),
        Polynomial::new(sk),
        Polynomial::new(r),
        Polynomial::new(pk0),
    )
}

#[test]
fn test_lbfv_pk_generation_limb_accepts_valid_equation() {
    let _ = test_limb([0; 4], [0; 4], [0; 4], [0; 4], [0; 4]).execute();
}

#[test(should_fail_with = "Public key equation failed")]
fn test_lbfv_pk_generation_limb_rejects_invalid_equation() {
    let _ = test_limb([0; 4], [0; 4], [0; 4], [0; 4], [1, 0, 0, 0]).execute();
}

#[test]
fn test_lbfv_pk_generation_limb_accepts_canonical_pk0() {
    let _ = test_limb(
        [12, 45, -33, 7],
        [1, -2, 0, 3],
        [0, 1, -1, 1],
        [-1, 1, -1, 0],
        [-30, 10, -45, 29],
    )
        .execute();
}

/// A quotient off by one moves `pk0` off the identity by `q`.
#[test(should_fail_with = "Public key equation failed")]
fn test_lbfv_pk_generation_limb_rejects_wrong_quotient() {
    let _ = test_limb(
        [12, 45, -33, 7],
        [1, -2, 0, 3],
        [0, 1, -1, 1],
        [-1, 1, -1, 1],
        [-30, 10, -45, 29],
    )
        .execute();
}

/// `pk0 + q` with `r + 1` satisfies the reduced identity and keeps `r` within its bound, but 126
/// is not the centered residue of 29 mod 97. Only the canonical `pk0` bound rejects this second
/// opening of the same key limb.
#[test(should_fail_with = "assert_max_bit_size")]
fn test_lbfv_pk_generation_limb_rejects_non_canonical_pk0() {
    let _ = test_limb(
        [12, 45, -33, 7],
        [1, -2, 0, 3],
        [0, 1, -1, 1],
        [-1, 1, -1, 1],
        [-30, 10, -45, 126],
    )
        .execute();
}
