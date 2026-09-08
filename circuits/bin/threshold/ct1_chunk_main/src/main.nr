// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: coefficient-level chunk leaf for ct1's main grid (P3). One
//! instance of this circuit is proven once per `chunk_idx` in `0..N_CHUNKS` (2 at this preset -
//! the minimum that's still genuinely "chunking"), each handling a `CHUNK_SIZE = N / N_CHUNKS`
//! slice of `u`/`e1`/`p2is`. No CRT-consistency check here - ct1 has no e1is/e1_quotients
//! equivalent. Emits one chunk commitment per polynomial (not bundled - `u_commitment` must stay
//! independently recoverable: the wrapper cross-checks ct0's and ct1's `u_commitment` directly).
//! At N_CHUNKS=2, exactly 2 of these leaves combine directly into `ct1_chunk_main_root`.
//!
//! `p2is` is padded from its native degree `N-1` to `N` coefficients by one leading zero (see
//! `Polynomial`'s descending-degree convention); the padding slot lives at global index 0, i.e.
//! chunk_idx 0's local offset 0.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_P2, USER_DATA_ENCRYPTION_BIT_U,
    USER_DATA_ENCRYPTION_E1_BOUND, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS,
    USER_DATA_ENCRYPTION_P2_BOUNDS, USER_DATA_ENCRYPTION_U_BOUND,
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
) -> pub (Field, Field, Field) {
    assert(chunk_idx < N_CHUNKS);

    if chunk_idx == 0 {
        for i in 0..L {
            assert(p2is_chunk[i].coefficients[0] == 0, "p2is padding coefficient must be zero");
        }
    }

    u_chunk.range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_U>(
        USER_DATA_ENCRYPTION_U_BOUND,
        USER_DATA_ENCRYPTION_U_BOUND,
    );
    e1_chunk.range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_E1>(
        USER_DATA_ENCRYPTION_E1_BOUND,
        USER_DATA_ENCRYPTION_E1_BOUND,
    );
    for i in 0..L {
        p2is_chunk[i].range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_P2>(
            USER_DATA_ENCRYPTION_P2_BOUNDS[i],
            USER_DATA_ENCRYPTION_P2_BOUNDS[i],
        );
    }

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

    (u_commit, e1_commit, p2_commit)
}
