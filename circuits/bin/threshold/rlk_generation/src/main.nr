// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::threshold::{
    G_GADGET_ROWS, GADGET_DIM, L, LBFV_CRS_GADGET_ROWS, LBFV_URS_GADGET_ROWS, N,
    RLK_GENERATION_BIT_D, RLK_GENERATION_BIT_E0, RLK_GENERATION_BIT_E2, RLK_GENERATION_BIT_R,
    RLK_GENERATION_BIT_R1_D0, RLK_GENERATION_BIT_R1_D2, RLK_GENERATION_BIT_R2_D0,
    RLK_GENERATION_BIT_R2_D2, RLK_GENERATION_BIT_SK, RLK_GENERATION_CONFIGS,
};
use lib::core::threshold::rlk_generation::RlkGeneration;
use lib::math::polynomial::Polynomial;

/// l-BFV: this circuit proves one gadget row's RLK `(d0, d2)` contribution. The
/// same compiled circuit is reused for every row `row_index in 0..GADGET_DIM` by
/// selecting that row's URS/CRS/Garner scalar out of `LBFV_URS_GADGET_ROWS`/
/// `LBFV_CRS_GADGET_ROWS`/`G_GADGET_ROWS`. `a` is read from `LBFV_CRS_GADGET_ROWS` - the
/// SAME constant `pk_generation` uses for this row (critical linkage between the
/// public key and the relinearization key for a given row).
fn main(
    row_index: pub u32,
    sk: Polynomial<N>,
    r: Polynomial<N>,
    e0: Polynomial<N>,
    e2: Polynomial<N>,
    r1_d0: [Polynomial<(2 * N) - 1>; L],
    r2_d0: [Polynomial<N - 1>; L],
    r1_d2: [Polynomial<(2 * N) - 1>; L],
    r2_d2: [Polynomial<N - 1>; L],
    d0: [Polynomial<N>; L],
    d2: [Polynomial<N>; L],
) -> pub (Field, Field, Field) {
    assert(row_index < GADGET_DIM, "row_index out of range");
    let d1 = LBFV_URS_GADGET_ROWS[row_index];
    let a = LBFV_CRS_GADGET_ROWS[row_index];
    let g = G_GADGET_ROWS[row_index];

    let rlk_generation: RlkGeneration<N, L, RLK_GENERATION_BIT_R, RLK_GENERATION_BIT_SK, RLK_GENERATION_BIT_E0, RLK_GENERATION_BIT_E2, RLK_GENERATION_BIT_R1_D0, RLK_GENERATION_BIT_R2_D0, RLK_GENERATION_BIT_R1_D2, RLK_GENERATION_BIT_R2_D2, RLK_GENERATION_BIT_D, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> = RlkGeneration::new(
        RLK_GENERATION_CONFIGS,
        d1,
        a,
        g,
        sk,
        r,
        e0,
        e2,
        r1_d0,
        r2_d0,
        r1_d2,
        r2_d2,
        d0,
        d2,
    );
    rlk_generation.execute()
}
