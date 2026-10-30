// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! ct1 leaf. Range-checks and commits `u`, `e1` and the reduced quotients `p1is`, derives the
//! challenge from those commitments and the `pk1`/`ct1` commitments, and evaluates the witness at
//! it. See `ct0_chunk_main` for why one circuit can both commit and evaluate.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_E1, USER_DATA_ENCRYPTION_CHUNKED_BIT_P1,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_CT1_CHUNK_CONFIGS,
};
use lib::core::threshold::user_data_encryption_chunk::{ct1_chunk_roots, Ct1ChunkLeaf};
use lib::math::commitments::compute_user_data_encryption_ct1_challenge;
use lib::math::polynomial::Polynomial;

fn main(
    u: Polynomial<N>,
    e1: Polynomial<N>,
    p1is: [Polynomial<N>; L],
    pk1_commitment: Field,
    ct1_commitment: Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; L], Field, [Field; L]) {
    let leaf = Ct1ChunkLeaf::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_BIT_E1, USER_DATA_ENCRYPTION_CHUNKED_BIT_P1>::new(
        USER_DATA_ENCRYPTION_CHUNKED_CT1_CHUNK_CONFIGS,
        0,
        N,
        u,
        e1,
        p1is,
    );
    leaf.check_range_bounds();

    let (u_commit, e1_commit, p1_commit) = leaf.commitments();
    let (u_root, e1_root, p1_root) = ct1_chunk_roots(N, N, [u_commit], [e1_commit], [p1_commit]);

    let payload = [pk1_commitment, ct1_commitment, u_root, e1_root, p1_root].as_vector();
    let challenge = compute_user_data_encryption_ct1_challenge::<L>(payload);
    let gamma = challenge[0];
    let mut batching: [Field; L] = [0; L];
    for i in 0..L {
        batching[i] = challenge[L + i];
    }

    let mut p1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        p1i_at_gamma[i] = p1is[i].eval(gamma);
    }

    (
        pk1_commitment, ct1_commitment, u_root, e1_root, p1_root, gamma, batching, e1.eval(gamma),
        p1i_at_gamma,
    )
}
