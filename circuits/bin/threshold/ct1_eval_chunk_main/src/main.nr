// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round B leaf for ct1's merged main+p1 grid. Re-supplies the same
//! `chunk_idx` slice `ct1_chunk_main` checked, re-derives the identical 4 per-chunk commitments
//! for binding, and computes each polynomial's *partial* Horner evaluation for this slice. The
//! per-slice logic lives in `lib::core::threshold::user_data_encryption_chunk` - see
//! `chunk_gamma_pow` for how a Horner evaluation splits across chunks, and why `p1is` is offset
//! against `2N` rather than `N`.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_P1, USER_DATA_ENCRYPTION_BIT_P2,
    USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_CT1_CHUNK_CONFIGS,
    USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS,
};
use lib::core::threshold::user_data_encryption_chunk::{chunk_gamma_pow, Ct1ChunkLeaf};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = 2 * CHUNK_SIZE;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e1_chunk: Polynomial<CHUNK_SIZE>,
    p2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    p1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
    gamma: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; L], [Field; L]) {
    let leaf = Ct1ChunkLeaf::<CHUNK_SIZE, R1_CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_P2, USER_DATA_ENCRYPTION_BIT_P1>::new(
        USER_DATA_ENCRYPTION_CT1_CHUNK_CONFIGS,
        chunk_idx,
        N,
        u_chunk,
        e1_chunk,
        p2is_chunk,
        p1is_chunk,
    );
    let (u_commit, e1_commit, p2_commit, p1_commit) = leaf.commitments();

    let gamma_pow = chunk_gamma_pow(N, CHUNK_SIZE, chunk_idx, gamma);

    let u_partial = u_chunk.eval(gamma) * gamma_pow;
    let e1_partial = e1_chunk.eval(gamma) * gamma_pow;
    let mut p2i_partial: [Field; L] = [0; L];
    for i in 0..L {
        p2i_partial[i] = p2is_chunk[i].eval(gamma) * gamma_pow;
    }

    let p1_gamma_pow = chunk_gamma_pow(2 * N, R1_CHUNK_SIZE, chunk_idx, gamma);
    let mut p1i_partial: [Field; L] = [0; L];
    for i in 0..L {
        p1i_partial[i] = p1is_chunk[i].eval(gamma) * p1_gamma_pow;
    }

    (u_commit, e1_commit, p2_commit, p1_commit, u_partial, e1_partial, p2i_partial, p1i_partial)
}
