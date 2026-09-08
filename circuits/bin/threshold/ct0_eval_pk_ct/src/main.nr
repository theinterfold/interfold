// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round B, groups C+D merged (P3): re-supplies `pk0is` and `ct0is`, re-derives both
//! commitments (same protocol-invariant formulas as `ct0_pk_ct_commit`, for binding against
//! Round A) and evaluates both at the shared `gamma`. Replaces the separate `ct0_eval_pk` /
//! `ct0_eval_ct` / `ct0_eval_chunk_pk_ct_combine` chain - see `ct0_pk_ct_commit` for why merging
//! removes the combine step entirely.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_PK,
};
use lib::math::commitments::{
    compute_multiple_polynomial_commitment, DS_CIPHERTEXT, DS_PK_AGGREGATION,
};
use lib::math::polynomial::Polynomial;

fn main(
    pk0is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    gamma: pub Field,
) -> pub (Field, [Field; L], Field, [Field; L]) {
    let pk0_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_PK>(
        pk0is,
        DS_PK_AGGREGATION,
    );
    let mut pk0is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        pk0is_at_gamma[i] = pk0is[i].eval(gamma);
    }

    let ct0_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_CT>(
        ct0is,
        DS_CIPHERTEXT,
    );
    let mut ct0is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        ct0is_at_gamma[i] = ct0is[i].eval(gamma);
    }

    (pk0_commitment, pk0is_at_gamma, ct0_commitment, ct0is_at_gamma)
}
