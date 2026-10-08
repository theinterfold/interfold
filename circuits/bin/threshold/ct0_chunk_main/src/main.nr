// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A ct0 leaf: range-checks the whole ct0 witness - `u`, `e0`, `k1` and the reduced
//! quotients `r1is`, all `N` wide - and commits each polynomial. The reduced identity has no
//! cyclotomic quotient, so the whole witness fits one leaf (`UDE_CT0_N_CHUNKS == 1`) and the
//! commitments are verified directly by `ct0_chunk_gamma`.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K,
    USER_DATA_ENCRYPTION_CHUNKED_BIT_R1, USER_DATA_ENCRYPTION_CHUNKED_BIT_U,
    USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
};
use lib::core::threshold::user_data_encryption_chunk::Ct0ChunkLeaf;
use lib::math::polynomial::Polynomial;

fn main(
    u: Polynomial<N>,
    e0: Polynomial<N>,
    k1: Polynomial<N>,
    r1is: [Polynomial<N>; L],
) -> pub (Field, Field, Field, Field) {
    let leaf = Ct0ChunkLeaf::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_U, USER_DATA_ENCRYPTION_CHUNKED_BIT_E0, USER_DATA_ENCRYPTION_CHUNKED_BIT_K, USER_DATA_ENCRYPTION_CHUNKED_BIT_R1>::new(
        USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS,
        0,
        N,
        u,
        e0,
        k1,
        r1is,
    );

    leaf.check_range_bounds();

    leaf.commitments()
}
