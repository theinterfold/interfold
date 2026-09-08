// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: coefficient-level chunk leaf for ct0's r1 grid (P3). One instance
//! of this circuit is proven once per `chunk_idx` in `0..R1_N_CHUNKS` (2 at this preset - the
//! minimum that's still genuinely "chunking"), each handling a `CHUNK_SIZE = 2N / R1_N_CHUNKS`
//! slice of `r1is`, padded from degree `2N-1` to `2N` by one leading zero. The padding slot lives
//! at global index 0, i.e. chunk_idx 0's local offset 0. At R1_N_CHUNKS=2, exactly 2 of these
//! leaves combine directly into `ct0_chunk_r1_root` - no intermediate pair/quad level needed.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_R1, USER_DATA_ENCRYPTION_R1_LOW_BOUNDS,
    USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS, USER_DATA_ENCRYPTION_R1_UP_BOUNDS,
};
use lib::math::commitments::{compute_ude_multi_chunk_commitment, UDE_KIND_CT0_R1};
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;

fn main(chunk_idx: pub u32, r1is_chunk: [Polynomial<CHUNK_SIZE>; L]) -> pub Field {
    assert(chunk_idx < R1_N_CHUNKS);

    if chunk_idx == 0 {
        for i in 0..L {
            assert(r1is_chunk[i].coefficients[0] == 0, "r1is padding coefficient must be zero");
        }
    }

    for i in 0..L {
        r1is_chunk[i].range_check_2bounds::<USER_DATA_ENCRYPTION_BIT_R1>(
            USER_DATA_ENCRYPTION_R1_UP_BOUNDS[i],
            USER_DATA_ENCRYPTION_R1_LOW_BOUNDS[i],
        );
    }

    compute_ude_multi_chunk_commitment::<CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_R1>(
        UDE_KIND_CT0_R1,
        chunk_idx,
        N,
        r1is_chunk,
    )
}
