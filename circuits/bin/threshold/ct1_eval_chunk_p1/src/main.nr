// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: Round B leaf for ct1's p1 grid. Re-supplies the same `chunk_idx`
//! slice `ct1_chunk_p1` checked, re-derives the same per-chunk commitment for binding, and
//! computes `p1is`' partial Horner evaluation for this slice - see `ct0_eval_chunk_main` for the
//! gamma-offset splitting technique. The p1 grid is padded to `2N` (not `N`), so the exponent
//! offset is computed against `2N` here.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_P1, USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS,
};
use lib::math::commitments::{compute_ude_multi_chunk_commitment, UDE_KIND_CT1_P1};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;

fn main(
    chunk_idx: pub u32,
    p1is_chunk: [Polynomial<CHUNK_SIZE>; L],
    gamma: pub Field,
) -> pub (Field, [Field; L]) {
    let p1_commit = compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_P1>(
        UDE_KIND_CT1_P1,
        chunk_idx,
        N,
        p1is_chunk,
    );

    let two_n = 2 * N;
    let offset = two_n - ((chunk_idx + 1) * CHUNK_SIZE);
    let gamma_pow = gamma.pow_32(offset as Field);

    let mut p1i_partial: [Field; L] = [0; L];
    for i in 0..L {
        p1i_partial[i] = p1is_chunk[i].eval(gamma) * gamma_pow;
    }

    (p1_commit, p1i_partial)
}
