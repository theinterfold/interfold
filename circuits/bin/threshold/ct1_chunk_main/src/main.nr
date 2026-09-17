// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A leaf for ct1's merged main+p1 grid (P3). One instance of this circuit is proven once
//! per `chunk_idx` in `0..N_CHUNKS` (2 at this preset - the minimum that's still genuinely
//! "chunking"). Range-checks its slice and commits to it; the per-slice logic lives in
//! `lib::core::threshold::user_data_encryption_chunk`.
//!
//! No CRT-consistency check here or in Round B - ct1 has no `e1is`/`e1_quotients` equivalent.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_P1, USER_DATA_ENCRYPTION_BIT_P2,
    USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_CT1_CHUNK_CONFIGS,
    USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS,
};
use lib::core::threshold::user_data_encryption_chunk::Ct1ChunkLeaf;
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = 2 * CHUNK_SIZE;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e1_chunk: Polynomial<CHUNK_SIZE>,
    p2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    p1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
) -> pub (Field, Field, Field, Field) {
    assert(chunk_idx < N_CHUNKS);

    let leaf = Ct1ChunkLeaf::<CHUNK_SIZE, R1_CHUNK_SIZE, L, USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_P2, USER_DATA_ENCRYPTION_BIT_P1>::new(
        USER_DATA_ENCRYPTION_CT1_CHUNK_CONFIGS,
        chunk_idx,
        N,
        u_chunk,
        e1_chunk,
        p2is_chunk,
        p1is_chunk,
    );

    leaf.check_padding();
    leaf.check_range_bounds();

    leaf.commitments()
}
