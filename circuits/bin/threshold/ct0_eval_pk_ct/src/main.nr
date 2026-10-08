// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round B: re-supplies `pk0is` and `ct0is`, re-derives both commitments (the same formulas as
//! `ct0_pk_ct_commit` and C5, for binding against Round A) and evaluates the ciphertext at
//! `gamma`. For the reduced identity it also takes `u` and outputs
//! `(pk0is[i] * u mod X^N + 1)(gamma)` through `negacyclic_kernel`, so the product never enters
//! the witness. `u` is bound by its root, which `ct0_eval_chunk_identity` equates with the
//! range-checked leaf's; the checked packing makes that equality pin `u` to the leaf's values.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT, USER_DATA_ENCRYPTION_CHUNKED_BIT_PK,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_U,
};
use lib::core::threshold::user_data_encryption_chunk::{
    UDE_N_CHUNKS, ude_single_root_from_polynomial,
};
use lib::math::commitments::{
    compute_multiple_polynomial_commitment_checked, DS_CIPHERTEXT, DS_PK_AGGREGATION, UDE_KIND_U,
};
use lib::math::polynomial::{negacyclic_kernel, Polynomial};

fn main(
    pk0is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    u: Polynomial<N>,
    gamma: pub Field,
) -> pub (Field, [Field; L], Field, [Field; L], Field) {
    let pk0_commitment = compute_multiple_polynomial_commitment_checked::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_PK>(
        pk0is,
        DS_PK_AGGREGATION,
    );
    let ct0_commitment = compute_multiple_polynomial_commitment_checked::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(
        ct0is,
        DS_CIPHERTEXT,
    );
    let u_root = ude_single_root_from_polynomial::<N, UDE_N_CHUNKS, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_U>(
        UDE_KIND_U,
        u,
    );

    let kernel = negacyclic_kernel(u, gamma);
    let mut pk0u_at_gamma: [Field; L] = [0; L];
    let mut ct0is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        pk0u_at_gamma[i] = pk0is[i].dot(kernel);
        ct0is_at_gamma[i] = ct0is[i].eval(gamma);
    }

    (pk0_commitment, pk0u_at_gamma, ct0_commitment, ct0is_at_gamma, u_root)
}
