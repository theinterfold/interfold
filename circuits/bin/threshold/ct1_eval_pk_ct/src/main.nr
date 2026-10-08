// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! ct1 public-key circuit: re-derives the `pk1is` commitment and evaluates
//! `(pk1is[i] * u mod X^N + 1)(gamma)` through `negacyclic_kernel`. See `ct0_eval_pk_ct`.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_PK, USER_DATA_ENCRYPTION_CHUNKED_BIT_U,
};
use lib::core::threshold::user_data_encryption_chunk::{
    UDE_N_CHUNKS, ude_single_root_from_polynomial,
};
use lib::math::commitments::{
    compute_multiple_polynomial_commitment_checked, DS_PK_AGGREGATION, UDE_KIND_U,
};
use lib::math::polynomial::{negacyclic_kernel, Polynomial};

fn main(
    pk1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    gamma: pub Field,
) -> pub (Field, [Field; L], Field) {
    let pk1_commitment = compute_multiple_polynomial_commitment_checked::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_PK>(
        pk1is,
        DS_PK_AGGREGATION,
    );
    let u_root = ude_single_root_from_polynomial::<N, UDE_N_CHUNKS, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_U>(
        UDE_KIND_U,
        u,
    );
    let kernel = negacyclic_kernel(u, gamma);
    let mut pk1u_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        pk1u_at_gamma[i] = pk1is[i].dot(kernel);
    }
    (pk1_commitment, pk1u_at_gamma, u_root)
}
