// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: Round B leaf for ct0's main grid. Re-supplies the same
//! `chunk_idx` slice `ct0_chunk_main` checked, redoes the CRT-consistency check (cheap - keeps
//! `e0is` tied to the cross-round-bound `e0`), re-derives the same 4 per-chunk commitments for
//! binding, and computes each polynomial's *partial* Horner evaluation for this slice.
//!
//! Splitting a Horner evaluation across chunks: `Polynomial::eval` treats a `CHUNK_SIZE`-length
//! slice as its own complete (local) polynomial, so a chunk's actual contribution to the full-N
//! evaluation is `local_eval * gamma^offset`, where `offset` is the degree of the chunk's lowest
//! coefficient (`N - (chunk_idx+1)*CHUNK_SIZE` in this descending-coefficient-order layout).
//! Summing every chunk's contribution (done in the combine tree) reconstructs the full
//! evaluation exactly.

use lib::configs::default::threshold::{
    L, N, QIS, USER_DATA_ENCRYPTION_BIT_E0, USER_DATA_ENCRYPTION_BIT_K, USER_DATA_ENCRYPTION_BIT_R2,
    USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS,
};
use lib::math::commitments::{
    compute_ude_chunk_commitment, compute_ude_multi_chunk_commitment, UDE_KIND_CT0_E0,
    UDE_KIND_CT0_K1, UDE_KIND_CT0_R2, UDE_KIND_CT0_U,
};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = N / N_CHUNKS;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e0_chunk: Polynomial<CHUNK_SIZE>,
    k1_chunk: Polynomial<CHUNK_SIZE>,
    e0is_chunk: [Polynomial<CHUNK_SIZE>; L],
    e0_quotients_chunk: [Polynomial<CHUNK_SIZE>; L],
    r2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    gamma: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; L], [Field; L]) {
    for i in 0..L {
        for j in 0..CHUNK_SIZE {
            assert(
                e0_chunk.coefficients[j]
                    == e0is_chunk[i].coefficients[j]
                        + e0_quotients_chunk[i].coefficients[j] * QIS[i],
            );
        }
    }

    let u_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, USER_DATA_ENCRYPTION_BIT_U>(
        UDE_KIND_CT0_U,
        chunk_idx,
        N,
        u_chunk,
    );
    let e0_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, USER_DATA_ENCRYPTION_BIT_E0>(
        UDE_KIND_CT0_E0,
        chunk_idx,
        N,
        e0_chunk,
    );
    let k1_commit = compute_ude_chunk_commitment::<CHUNK_SIZE, USER_DATA_ENCRYPTION_BIT_K>(
        UDE_KIND_CT0_K1,
        chunk_idx,
        N,
        k1_chunk,
    );
    let r2_commit = compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_R2>(
        UDE_KIND_CT0_R2,
        chunk_idx,
        N,
        r2is_chunk,
    );

    let offset = N - ((chunk_idx + 1) * CHUNK_SIZE);
    let gamma_pow = gamma.pow_32(offset as Field);

    let u_partial = u_chunk.eval(gamma) * gamma_pow;
    let k1_partial = k1_chunk.eval(gamma) * gamma_pow;
    let mut e0is_partial: [Field; L] = [0; L];
    let mut r2i_partial: [Field; L] = [0; L];
    for i in 0..L {
        e0is_partial[i] = e0is_chunk[i].eval(gamma) * gamma_pow;
        r2i_partial[i] = r2is_chunk[i].eval(gamma) * gamma_pow;
    }

    (u_commit, e0_commit, k1_commit, r2_commit, u_partial, k1_partial, e0is_partial, r2i_partial)
}
