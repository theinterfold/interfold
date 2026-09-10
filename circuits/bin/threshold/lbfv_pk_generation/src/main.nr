// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY

use lib::configs::default::dkg::{SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::threshold::{
    GADGET_DIM, L, LBFV_CRS_GADGET_ROWS, N, PK_GENERATION_BIT_E_SM, PK_GENERATION_BIT_EEK,
    PK_GENERATION_BIT_PK, PK_GENERATION_BIT_R1, PK_GENERATION_BIT_R2, PK_GENERATION_BIT_SK,
    PK_GENERATION_CONFIGS,
};
use lib::core::threshold::lbfv_pk_generation::LbfvPkGeneration;
use lib::math::polynomial::Polynomial;

/// Prove one row of an l-BFV public-key contribution.
fn main(
    row_index: pub u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    pk0is: [Polynomial<N>; L],
) -> pub (Field, Field) {
    assert(row_index < GADGET_DIM, "row_index out of range");
    let a = LBFV_CRS_GADGET_ROWS[row_index];
    let circuit: LbfvPkGeneration<N, L, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_SK, PK_GENERATION_BIT_E_SM, PK_GENERATION_BIT_R1, PK_GENERATION_BIT_R2, PK_GENERATION_BIT_PK, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> =
        LbfvPkGeneration::new(PK_GENERATION_CONFIGS, a, eek, sk, r1is, r2is, pk0is);
    circuit.execute()
}
