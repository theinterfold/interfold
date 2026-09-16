// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round B, ct1 leg: re-supplies `pk1is` and `ct1is`, re-derives both commitments (the same
//! protocol-invariant formulas as `ct1_pk_ct_commit`, for binding against Round A) and evaluates
//! both at the shared `gamma`. Handling both groups in one circuit lets
//! `ct1_eval_chunk_identity` reach them with a single verification.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_PK,
};
use lib::math::commitments::{
    compute_multiple_polynomial_commitment, DS_CIPHERTEXT, DS_PK_AGGREGATION,
};
use lib::math::polynomial::Polynomial;

fn main(
    pk1is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    gamma: pub Field,
) -> pub (Field, [Field; L], Field, [Field; L]) {
    let pk1_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_PK>(
        pk1is,
        DS_PK_AGGREGATION,
    );
    let mut pk1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        pk1is_at_gamma[i] = pk1is[i].eval(gamma);
    }

    let ct1_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_CT>(
        ct1is,
        DS_CIPHERTEXT,
    );
    let mut ct1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        ct1is_at_gamma[i] = ct1is[i].eval(gamma);
    }

    (pk1_commitment, pk1is_at_gamma, ct1_commitment, ct1is_at_gamma)
}
