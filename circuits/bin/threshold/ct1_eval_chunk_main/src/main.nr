// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round B ct1 leaf: re-supplies the Round A witness, re-derives the identical commitments, and
//! evaluates `e1` and each `p1is[i]` at `gamma`. `u` enters through `ct1_eval_pk_ct`'s kernel.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_E1, USER_DATA_ENCRYPTION_CHUNKED_BIT_P1,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_CT1_CHUNK_CONFIGS,
};
use lib::core::threshold::user_data_encryption_chunk::Ct1ChunkLeaf;
use lib::math::polynomial::Polynomial;

fn main(
    u: Polynomial<N>,
    e1: Polynomial<N>,
    p1is: [Polynomial<N>; L],
    gamma: pub Field,
) -> pub (Field, Field, Field, Field, [Field; L]) {
    let leaf = Ct1ChunkLeaf::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_BIT_E1, USER_DATA_ENCRYPTION_CHUNKED_BIT_P1>::new(
        USER_DATA_ENCRYPTION_CHUNKED_CT1_CHUNK_CONFIGS,
        0,
        N,
        u,
        e1,
        p1is,
    );
    let (u_commit, e1_commit, p1_commit) = leaf.commitments();

    let mut p1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        p1i_at_gamma[i] = p1is[i].eval(gamma);
    }

    (u_commit, e1_commit, p1_commit, e1.eval(gamma), p1i_at_gamma)
}
