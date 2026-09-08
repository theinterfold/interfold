// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: coefficient-level chunk leaf for ct1's p1 grid (P3). One instance
//! of this circuit is proven once per `chunk_idx` in `0..R1_N_CHUNKS` (2 at this preset), each
//! handling a `CHUNK_SIZE = 2N / R1_N_CHUNKS` slice of `p1is`, padded from degree `2N-1` to `2N`
//! by one leading zero. The padding slot lives at global index 0, i.e. chunk_idx 0's local
//! offset 0. At R1_N_CHUNKS=2, exactly 2 of these leaves combine directly into `ct1_chunk_p1_root`.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_P1, USER_DATA_ENCRYPTION_P1_BOUNDS,
    USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS,
};
use lib::math::commitments::{compute_ude_multi_chunk_commitment, UDE_KIND_CT1_P1};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;

fn main(chunk_idx: pub u32, p1is_chunk: [Polynomial<CHUNK_SIZE>; L]) -> pub Field {
    assert(chunk_idx < R1_N_CHUNKS);

    if chunk_idx == 0 {
        for i in 0..L {
            assert(p1is_chunk[i].coefficients[0] == 0, "p1is padding coefficient must be zero");
        }
    }

    for i in 0..L {
        p1is_chunk[i].range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_P1>(
            USER_DATA_ENCRYPTION_P1_BOUNDS[i],
            USER_DATA_ENCRYPTION_P1_BOUNDS[i],
        );
    }

    compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_P1>(
        UDE_KIND_CT1_P1,
        chunk_idx,
        N,
        p1is_chunk,
    )
}
