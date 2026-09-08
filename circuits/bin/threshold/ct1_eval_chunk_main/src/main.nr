// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: Round B leaf for ct1's merged main+p1 grid. Re-supplies the same
//! `chunk_idx` slice `ct1_chunk_main` checked, re-derives the same 4 per-chunk commitments for
//! binding, and computes each polynomial's *partial* Horner evaluation for this slice - see
//! `ct0_eval_chunk_main` for the gamma-offset splitting technique. `p1is` is padded to `2N` (not
//! `N`), so its own offset is computed against `2N`.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_P1, USER_DATA_ENCRYPTION_BIT_P2,
    USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS,
    USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS,
};
use lib::math::commitments::{
    compute_ude_chunk_commitment, compute_ude_multi_chunk_commitment, UDE_KIND_CT1_E1,
    UDE_KIND_CT1_P1, UDE_KIND_CT1_P2, UDE_KIND_CT1_U,
};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e1_chunk: Polynomial<CHUNK_SIZE>,
    p2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    p1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
    gamma: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; L], [Field; L]) {
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
    let p1_commit = compute_ude_multi_chunk_commitment::<R1_CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_P1>(
        UDE_KIND_CT1_P1,
        chunk_idx,
        N,
        p1is_chunk,
    );

    let offset = N - ((chunk_idx + 1) * CHUNK_SIZE);
    let gamma_pow = gamma.pow_32(offset as Field);

    let u_partial = u_chunk.eval(gamma) * gamma_pow;
    let e1_partial = e1_chunk.eval(gamma) * gamma_pow;
    let mut p2i_partial: [Field; L] = [0; L];
    for i in 0..L {
        p2i_partial[i] = p2is_chunk[i].eval(gamma) * gamma_pow;
    }

    let two_n = 2 * N;
    let p1_offset = two_n - ((chunk_idx + 1) * R1_CHUNK_SIZE);
    let p1_gamma_pow = gamma.pow_32(p1_offset as Field);
    let mut p1i_partial: [Field; L] = [0; L];
    for i in 0..L {
        p1i_partial[i] = p1is_chunk[i].eval(gamma) * p1_gamma_pow;
    }

    (u_commit, e1_commit, p2_commit, p1_commit, u_partial, e1_partial, p2i_partial, p1i_partial)
}
