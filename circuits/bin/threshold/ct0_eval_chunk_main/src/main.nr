// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round B leaf for ct0's merged main+r1 grid. Re-supplies the same
//! `chunk_idx` slice `ct0_chunk_main` checked, re-derives the identical 5 per-chunk commitments for
//! binding, and computes each polynomial's *partial* Horner evaluation for this slice. The ct0
//! identity reads the committed `e0` in every CRT limb: no per-limb split of `e0` is a witness,
//! since one would be chosen after `gamma` and never reach the transcript (IF-006). The per-slice logic
//! lives in `lib::core::threshold::user_data_encryption_chunk` - see `chunk_gamma_pow` for how a
//! Horner evaluation splits across chunks, and why `r1is` is offset against `2N` rather than `N`.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_R1, USER_DATA_ENCRYPTION_CHUNKED_BIT_R2,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
    USER_DATA_ENCRYPTION_CHUNKED_N_CHUNKS as N_CHUNKS,
};
use lib::core::threshold::user_data_encryption_chunk::{chunk_gamma_pow, Ct0ChunkLeaf};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = 2 * CHUNK_SIZE;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e0_chunk: Polynomial<CHUNK_SIZE>,
    k1_chunk: Polynomial<CHUNK_SIZE>,
    r2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    r1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
    gamma: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, [Field; L], [Field; L]) {
    let leaf = Ct0ChunkLeaf::<CHUNK_SIZE, R1_CHUNK_SIZE, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K, USER_DATA_ENCRYPTION_CHUNKED_BIT_R2, USER_DATA_ENCRYPTION_CHUNKED_BIT_R1>::new(
        USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
        chunk_idx,
        N,
        u_chunk,
        e0_chunk,
        k1_chunk,
        r2is_chunk,
        r1is_chunk,
    );
    let (u_commit, e0_commit, k1_commit, r2_commit, r1_commit) = leaf.commitments();

    let gamma_pow = chunk_gamma_pow(N, CHUNK_SIZE, chunk_idx, gamma);

    let u_partial = u_chunk.eval(gamma) * gamma_pow;
    let k1_partial = k1_chunk.eval(gamma) * gamma_pow;
    let e0_partial = e0_chunk.eval(gamma) * gamma_pow;
    let mut r2i_partial: [Field; L] = [0; L];
    for i in 0..L {
        r2i_partial[i] = r2is_chunk[i].eval(gamma) * gamma_pow;
    }

    let r1_gamma_pow = chunk_gamma_pow(2 * N, R1_CHUNK_SIZE, chunk_idx, gamma);
    let mut r1i_partial: [Field; L] = [0; L];
    for i in 0..L {
        r1i_partial[i] = r1is_chunk[i].eval(gamma) * r1_gamma_pow;
    }

    (
        u_commit, e0_commit, k1_commit, r2_commit, r1_commit, u_partial, k1_partial, e0_partial,
        r2i_partial, r1i_partial,
    )
}
