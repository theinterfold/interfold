// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A ct1 leaf: range-checks the whole ct1 witness - `u`, `e1` and the reduced quotients
//! `p1is`, all `N` wide - and commits each polynomial. See `ct0_chunk_main`.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_E1, USER_DATA_ENCRYPTION_CHUNKED_BIT_P1,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_CT1_CHUNK_CONFIGS,
};
use lib::core::threshold::user_data_encryption_chunk::Ct1ChunkLeaf;
use lib::math::polynomial::Polynomial;

fn main(
    u: Polynomial<N>,
    e1: Polynomial<N>,
    p1is: [Polynomial<N>; L],
) -> pub (Field, Field, Field) {
    let leaf = Ct1ChunkLeaf::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_BIT_E1, USER_DATA_ENCRYPTION_CHUNKED_BIT_P1>::new(
        USER_DATA_ENCRYPTION_CHUNKED_CT1_CHUNK_CONFIGS,
        0,
        N,
        u,
        e1,
        p1is,
    );

    leaf.check_range_bounds();

    leaf.commitments()
}
