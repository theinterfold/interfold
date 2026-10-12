// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Prove one l-BFV public-key row: every CRT limb of
//! `pk0is[l] == -(a[l] * sk mod X^N + 1) + eek + q_l * ris[l]`, for the row's public CRS
//! polynomials `a = crs`, in one proof. `crs` is opened against `LBFV_CRS_ROW_COMMITMENTS[row]`.
//!
//! Outputs: `sk_commitment` (the C1 secret root), `pk_commitment` (the row commitment that
//! `lbfv_pk_aggregation` opens).

use lib::configs::default::dkg::{SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::N_PARTIES;
use lib::configs::default::threshold::{
    GADGET_DIM, L, LBFV_CRS_ROW_COMMITMENTS, LBFV_PK_GENERATION_BIT_R, LBFV_PK_GENERATION_R_BOUNDS,
    N, PK_AGGREGATION_BIT_PK, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_PK, PK_GENERATION_BIT_SK,
    PK_GENERATION_CONFIGS,
};
use lib::core::threshold::lbfv_pk_generation::LbfvPkGenerationRow;
use lib::core::threshold::lbfv_proof_domain::{LbfvProofSession, validate_generation_statement};
use lib::math::polynomial::Polynomial;

fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    party_id: pub u32,
    row_index: pub u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    ris: [Polynomial<N>; L],
    pk0is: [Polynomial<N>; L],
    crs: [Polynomial<N>; L],
) -> pub (Field, Field) {
    validate_generation_statement::<N_PARTIES, GADGET_DIM>(
        LbfvProofSession { session_id_hi, session_id_lo },
        party_id,
        row_index,
    );

    let circuit: LbfvPkGenerationRow<N, L, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_SK, LBFV_PK_GENERATION_BIT_R, PK_GENERATION_BIT_PK, PK_AGGREGATION_BIT_PK, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> = LbfvPkGenerationRow::new(
        PK_GENERATION_CONFIGS.eek_bound,
        PK_GENERATION_CONFIGS.sk_bound,
        LBFV_PK_GENERATION_R_BOUNDS,
        PK_GENERATION_CONFIGS.qis,
        LBFV_CRS_ROW_COMMITMENTS[row_index],
        row_index,
        eek,
        sk,
        ris,
        pk0is,
        crs,
    );
    circuit.execute()
}
