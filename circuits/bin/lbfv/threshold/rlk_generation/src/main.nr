// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Prove one l-BFV RLK gadget row: both reduced identities of every CRT limb in one proof (see
//! `RlkGenerationRow`). `urs` and `crs` are opened against `LBFV_URS_ROW_COMMITMENTS[row]` and
//! `LBFV_CRS_ROW_COMMITMENTS[row]`.
//!
//! Outputs: `sk_commitment` (the C1 secret root), `r_commitment`, `d0_commitment`,
//! `d2_commitment` (the row commitments that `rlk_aggregation` opens).

use lib::configs::default::dkg::{SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::N_PARTIES;
use lib::configs::default::threshold::{
    GADGET_DIM, L, LBFV_CRS_ROW_COMMITMENTS, LBFV_URS_ROW_COMMITMENTS, N, PK_AGGREGATION_BIT_PK,
    RLK_GENERATION_BIT_D, RLK_GENERATION_BIT_E0, RLK_GENERATION_BIT_E2, RLK_GENERATION_BIT_R,
    RLK_GENERATION_BIT_RD0, RLK_GENERATION_BIT_RD2, RLK_GENERATION_BIT_SK, RLK_GENERATION_CONFIGS,
};
use lib::core::threshold::lbfv_proof_domain::{LbfvProofSession, validate_generation_statement};
use lib::core::threshold::rlk_generation::RlkGenerationRow;
use lib::math::polynomial::Polynomial;

fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    party_id: pub u32,
    row_index: pub u32,
    sk: Polynomial<N>,
    r: Polynomial<N>,
    e0: Polynomial<N>,
    e2: Polynomial<N>,
    rd0: [Polynomial<N>; L],
    rd2: [Polynomial<N>; L],
    d0: [Polynomial<N>; L],
    d2: [Polynomial<N>; L],
    urs: [Polynomial<N>; L],
    crs: [Polynomial<N>; L],
) -> pub (Field, Field, Field, Field) {
    validate_generation_statement::<N_PARTIES, GADGET_DIM>(
        LbfvProofSession { session_id_hi, session_id_lo },
        party_id,
        row_index,
    );

    let circuit: RlkGenerationRow<N, L, RLK_GENERATION_BIT_R, RLK_GENERATION_BIT_SK, RLK_GENERATION_BIT_E0, RLK_GENERATION_BIT_E2, RLK_GENERATION_BIT_RD0, RLK_GENERATION_BIT_RD2, RLK_GENERATION_BIT_D, PK_AGGREGATION_BIT_PK, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> = RlkGenerationRow::new(
        RLK_GENERATION_CONFIGS,
        LBFV_URS_ROW_COMMITMENTS[row_index],
        LBFV_CRS_ROW_COMMITMENTS[row_index],
        row_index,
        sk,
        r,
        e0,
        e2,
        rd0,
        rd2,
        d0,
        d2,
        urs,
        crs,
    );
    circuit.execute()
}
