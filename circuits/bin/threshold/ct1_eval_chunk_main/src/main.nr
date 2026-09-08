// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: Round B leaf for ct1's main grid. Re-supplies the same
//! `chunk_idx` slice `ct1_chunk_main` checked, re-derives the same 3 per-chunk commitments for
//! binding, and computes each polynomial's *partial* Horner evaluation for this slice - see
//! `ct0_eval_chunk_main` for the gamma-offset splitting technique.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_P2, USER_DATA_ENCRYPTION_BIT_U,
    USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS,
};
use lib::math::commitments::{
    compute_ude_chunk_commitment, compute_ude_multi_chunk_commitment, UDE_KIND_CT1_E1,
    UDE_KIND_CT1_P2, UDE_KIND_CT1_U,
};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = N / N_CHUNKS;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e1_chunk: Polynomial<CHUNK_SIZE>,
    p2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    gamma: pub Field,
) -> pub (Field, Field, Field, Field, Field, [Field; L]) {
    let u_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, USER_DATA_ENCRYPTION_BIT_U>(
        UDE_KIND_CT1_U,
        chunk_idx,
        N,
        u_chunk,
    );
    let e1_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, USER_DATA_ENCRYPTION_BIT_E1>(
        UDE_KIND_CT1_E1,
        chunk_idx,
        N,
        e1_chunk,
    );
    let p2_commit = compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_P2>(
        UDE_KIND_CT1_P2,
        chunk_idx,
        N,
        p2is_chunk,
    );

    let offset = N - ((chunk_idx + 1) * CHUNK_SIZE);
    let gamma_pow = gamma.pow_32(offset as Field);

    let u_partial = u_chunk.eval(gamma) * gamma_pow;
    let e1_partial = e1_chunk.eval(gamma) * gamma_pow;
    let mut p2i_partial: [Field; L] = [0; L];
    for i in 0..L {
        p2i_partial[i] = p2is_chunk[i].eval(gamma) * gamma_pow;
    }

    (u_commit, e1_commit, p2_commit, u_partial, e1_partial, p2i_partial)
}
