// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::N_PARTIES;
use lib::configs::default::threshold::{
    GADGET_DIM, L, LBFV_CRS_GADGET_ROWS, N, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_PK,
    PK_GENERATION_BIT_R1, PK_GENERATION_BIT_R2, PK_GENERATION_BIT_SK, PK_GENERATION_CONFIGS,
};
use lib::core::threshold::lbfv_pk_generation::LbfvPkGenerationLimb;
use lib::core::threshold::lbfv_proof_domain::{LbfvProofSession, validate_generation_statement};
use lib::math::polynomial::Polynomial;

/// Prove one CRT limb of one l-BFV public-key row.
fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    party_id: pub u32,
    row_index: pub u32,
    limb_index: pub u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1: Polynomial<(2 * N) - 1>,
    r2: Polynomial<N - 1>,
    pk0: Polynomial<N>,
) -> pub (Field, Field, Field) {
    validate_generation_statement::<N_PARTIES, GADGET_DIM>(
        LbfvProofSession { session_id_hi, session_id_lo },
        party_id,
        row_index,
    );
    assert(limb_index < L, "limb_index out of range");

    let circuit: LbfvPkGenerationLimb<N, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_SK, PK_GENERATION_BIT_R1, PK_GENERATION_BIT_R2, PK_GENERATION_BIT_PK, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> = LbfvPkGenerationLimb::new(
        PK_GENERATION_CONFIGS.eek_bound,
        PK_GENERATION_CONFIGS.sk_bound,
        PK_GENERATION_CONFIGS.r1_bounds[limb_index],
        PK_GENERATION_CONFIGS.r2_bounds[limb_index],
        PK_GENERATION_CONFIGS.qis[limb_index],
        LBFV_CRS_GADGET_ROWS[row_index][limb_index],
        row_index,
        limb_index,
        eek,
        sk,
        r1,
        r2,
        pk0,
    );
    circuit.execute()
}
