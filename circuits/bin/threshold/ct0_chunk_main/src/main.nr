// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! ct0 leaf. Range-checks the whole ct0 witness - `u`, `e0`, `k1` and the reduced quotients `r1is`,
//! all `N` wide - commits each polynomial, derives the Fiat-Shamir challenge from those commitments
//! and the `pk0`/`ct0` commitments, and evaluates the witness at it.
//!
//! The challenge is derived in this circuit, after every witness polynomial is committed, so a
//! second round re-supplying the witness is not needed. `pk0_commitment` and `ct0_commitment` are
//! taken as values and output: `ct0_eval_chunk_identity` equates the first with the hash of the
//! `pk0is` it evaluates, and `user_data_encryption_ct0_chunked` equates the
//! second with the hash of the range-checked `ct0is` that `ct0_pk_ct_commit` evaluates. Both are
//! binding commitments, so `pk0is` and `ct0is` are fixed before the challenge as well.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_R1, USER_DATA_ENCRYPTION_CHUNKED_BIT_U,
    USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
};
use lib::core::threshold::user_data_encryption_chunk::{ct0_chunk_roots, Ct0ChunkLeaf};
use lib::math::commitments::compute_user_data_encryption_ct0_challenge;
use lib::math::polynomial::Polynomial;

fn main(
    u: Polynomial<N>,
    e0: Polynomial<N>,
    k1: Polynomial<N>,
    r1is: [Polynomial<N>; L],
    pk0_commitment: Field,
    ct0_commitment: Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; L], Field, Field, [Field; L]) {
    let leaf = Ct0ChunkLeaf::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K, USER_DATA_ENCRYPTION_CHUNKED_BIT_R1>::new(
        USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
        0,
        N,
        u,
        e0,
        k1,
        r1is,
    );
    leaf.check_range_bounds();

    let (u_commit, e0_commit, k1_commit, r1_commit) = leaf.commitments();
    let (u_root, e0_root, k1_root, r1_root) =
        ct0_chunk_roots(N, N, [u_commit], [e0_commit], [k1_commit], [r1_commit]);

    let payload = [pk0_commitment, ct0_commitment, k1_root, u_root, e0_root, r1_root].as_vector();
    let challenge = compute_user_data_encryption_ct0_challenge::<L>(payload);
    let mut gammas: [Field; L] = [0; L];
    for i in 0..L {
        gammas[i] = challenge[i];
    }
    let gamma = gammas[0];

    let mut r1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        r1i_at_gamma[i] = r1is[i].eval(gamma);
    }

    (
        pk0_commitment, ct0_commitment, k1_root, u_root, e0_root, r1_root, gammas, k1.eval(gamma),
        e0.eval(gamma), r1i_at_gamma,
    )
}
