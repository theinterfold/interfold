// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round B ct0 leaf: re-supplies the Round A witness, re-derives the identical commitments for
//! cross-round binding, and evaluates `k1`, `e0` and each `r1is[i]` at `gamma`. `u` is not
//! evaluated here: it enters the identity through `ct0_eval_pk_ct`'s negacyclic kernel.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_R1, USER_DATA_ENCRYPTION_CHUNKED_BIT_U,
    USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
};
use lib::core::threshold::user_data_encryption_chunk::Ct0ChunkLeaf;
use lib::math::polynomial::Polynomial;

fn main(
    u: Polynomial<N>,
    e0: Polynomial<N>,
    k1: Polynomial<N>,
    r1is: [Polynomial<N>; L],
    gamma: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; L]) {
    let leaf = Ct0ChunkLeaf::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K, USER_DATA_ENCRYPTION_CHUNKED_BIT_R1>::new(
        USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
        0,
        N,
        u,
        e0,
        k1,
        r1is,
    );
    let (u_commit, e0_commit, k1_commit, r1_commit) = leaf.commitments();

    let mut r1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        r1i_at_gamma[i] = r1is[i].eval(gamma);
    }

    (u_commit, e0_commit, k1_commit, r1_commit, k1.eval(gamma), e0.eval(gamma), r1i_at_gamma)
}
