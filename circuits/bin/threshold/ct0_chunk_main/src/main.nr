// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A leaf for ct0's merged main+r1 grid (P3). One instance of this circuit (same VK) is
//! proven once per `chunk_idx` in `0..N_CHUNKS` (2 at this preset - the minimum that's still
//! genuinely "chunking"). Range-checks its slice and commits to it; the per-slice logic lives in
//! `lib::core::threshold::user_data_encryption_chunk`.
//!
//! The identity reads the committed `e0` directly in every CRT limb, so neither round takes a
//! per-limb split of `e0` as a witness (IF-006).

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_R1, USER_DATA_ENCRYPTION_CHUNKED_BIT_R2,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
    USER_DATA_ENCRYPTION_CHUNKED_N_CHUNKS as N_CHUNKS,
};
use lib::core::threshold::user_data_encryption_chunk::Ct0ChunkLeaf;
use lib::math::polynomial::Polynomial;

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = 2 * CHUNK_SIZE;

fn main(
    chunk_idx: pub u32,
    u_chunk: Polynomial<CHUNK_SIZE>,
    e0_chunk: Polynomial<CHUNK_SIZE>,
    k1_chunk: Polynomial<CHUNK_SIZE>,
    r2is_chunk: [Polynomial<CHUNK_SIZE>; L],
    r1is_chunk: [Polynomial<R1_CHUNK_SIZE>; L],
) -> pub (Field, Field, Field, Field, Field) {
    assert(chunk_idx < N_CHUNKS);

    let leaf = Ct0ChunkLeaf::<CHUNK_SIZE, R1_CHUNK_SIZE, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K, USER_DATA_ENCRYPTION_CHUNKED_BIT_R2, USER_DATA_ENCRYPTION_CHUNKED_BIT_R1>::new(
        USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
        chunk_idx,
        N,
        u_chunk,
        e0_chunk,
        k1_chunk,
        r2is_chunk,
        r1is_chunk,
    );

    leaf.check_padding();
    leaf.check_range_bounds();

    leaf.commitments()
}
