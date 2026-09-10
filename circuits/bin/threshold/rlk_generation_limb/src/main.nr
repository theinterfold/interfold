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
use lib::core::threshold::rlk_generation_limb::RlkGenerationLimb;
use lib::math::polynomial::Polynomial;

/// Prove one CRT limb of one l-BFV RLK gadget row.
fn main(
    row_index: pub u32,
    limb_index: pub u32,
    sk: Polynomial<N>,
    r: Polynomial<N>,
    e0: Polynomial<N>,
    e2: Polynomial<N>,
    r1_d0: Polynomial<(2 * N) - 1>,
    r2_d0: Polynomial<N - 1>,
    r1_d2: Polynomial<(2 * N) - 1>,
    r2_d2: Polynomial<N - 1>,
    d0: Polynomial<N>,
    d2: Polynomial<N>,
) -> pub (Field, Field, Field, Field, Field, Field) {
    assert(row_index < GADGET_DIM, "row_index out of range");
    assert(limb_index < L, "limb_index out of range");

    let circuit: RlkGenerationLimb<N, RLK_GENERATION_BIT_R, RLK_GENERATION_BIT_SK, RLK_GENERATION_BIT_E0, RLK_GENERATION_BIT_E2, RLK_GENERATION_BIT_R1_D0, RLK_GENERATION_BIT_R2_D0, RLK_GENERATION_BIT_R1_D2, RLK_GENERATION_BIT_R2_D2, RLK_GENERATION_BIT_D, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> = RlkGenerationLimb::new(
        RLK_GENERATION_CONFIGS.r_bound,
        RLK_GENERATION_CONFIGS.sk_bound,
        RLK_GENERATION_CONFIGS.e0_bound,
        RLK_GENERATION_CONFIGS.e2_bound,
        RLK_GENERATION_CONFIGS.r1_d0_bounds[limb_index],
        RLK_GENERATION_CONFIGS.r2_d0_bounds[limb_index],
        RLK_GENERATION_CONFIGS.r1_d2_bounds[limb_index],
        RLK_GENERATION_CONFIGS.r2_d2_bounds[limb_index],
        RLK_GENERATION_CONFIGS.qis[limb_index],
        LBFV_URS_GADGET_ROWS[row_index][limb_index],
        LBFV_CRS_GADGET_ROWS[row_index][limb_index],
        G_GADGET_ROWS[row_index],
        row_index,
        limb_index,
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
    circuit.execute()
}
