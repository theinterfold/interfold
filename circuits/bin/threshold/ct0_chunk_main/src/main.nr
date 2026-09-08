// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: coefficient-level chunk leaf for ct0's main grid (P3). One
//! instance of this circuit (same VK) is proven once per `chunk_idx` in `0..N_CHUNKS` (2 at this
//! preset - the minimum that's still genuinely "chunking"), each handling a `CHUNK_SIZE = N /
//! N_CHUNKS` slice of `u`/`e0`/`k1`/`r2is`. Range-checks and CRT-consistency for that slice, then
//! emits one chunk commitment *per polynomial* (not bundled - `u_commitment`/`k1_commitment`
//! must stay independently recoverable: the wrapper cross-checks ct0's and ct1's `u_commitment`
//! directly, and `k1_commitment` survives into ct0's final output tuple unchanged). At
//! N_CHUNKS=2, exactly 2 of these leaves combine directly into `ct0_chunk_main_root` - no
//! intermediate pair/quad level needed.
//!
//! `r2is` is padded from its native degree `N-1` to `N` coefficients by one leading zero (see
//! `Polynomial`'s descending-degree convention); the padding slot lives at global index 0, i.e.
//! chunk_idx 0's local offset 0.

use lib::configs::default::threshold::{
    L, N, QIS, USER_DATA_ENCRYPTION_BIT_E0, USER_DATA_ENCRYPTION_BIT_K, USER_DATA_ENCRYPTION_BIT_R2,
    USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_E0_BOUND, USER_DATA_ENCRYPTION_K1_LOW_BOUND,
    USER_DATA_ENCRYPTION_K1_UP_BOUND, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS,
    USER_DATA_ENCRYPTION_R2_BOUNDS, USER_DATA_ENCRYPTION_U_BOUND,
};

global CHUNK_SIZE: u32 = N / N_CHUNKS;
use lib::math::commitments::{
    compute_ude_chunk_commitment, compute_ude_multi_chunk_commitment, UDE_KIND_CT0_E0,
    UDE_KIND_CT0_K1, UDE_KIND_CT0_R2, UDE_KIND_CT0_U,
};
use lib::math::polynomial::Polynomial;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e0_chunk: Polynomial<CHUNK_SIZE>,
    k1_chunk: Polynomial<CHUNK_SIZE>,
    e0is_chunk: [Polynomial<CHUNK_SIZE>; L],
    e0_quotients_chunk: [Polynomial<CHUNK_SIZE>; L],
    r2is_chunk: [Polynomial<CHUNK_SIZE>; L],
) -> pub (Field, Field, Field, Field) {
    assert(chunk_idx < N_CHUNKS);

    if chunk_idx == 0 {
        for i in 0..L {
            assert(r2is_chunk[i].coefficients[0] == 0, "r2is padding coefficient must be zero");
        }
    }

    u_chunk.range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_U>(
        USER_DATA_ENCRYPTION_U_BOUND,
        USER_DATA_ENCRYPTION_U_BOUND,
    );
    e0_chunk.range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_E0>(
        USER_DATA_ENCRYPTION_E0_BOUND,
        USER_DATA_ENCRYPTION_E0_BOUND,
    );
    k1_chunk.range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_K>(
        USER_DATA_ENCRYPTION_K1_UP_BOUND,
        USER_DATA_ENCRYPTION_K1_LOW_BOUND,
    );
    for i in 0..L {
        r2is_chunk[i].range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_R2>(
            USER_DATA_ENCRYPTION_R2_BOUNDS[i],
            USER_DATA_ENCRYPTION_R2_BOUNDS[i],
        );
    }

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

    (u_commit, e0_commit, k1_commit, r2_commit)
}
