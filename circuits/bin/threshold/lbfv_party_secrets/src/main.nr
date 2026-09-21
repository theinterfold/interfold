// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::N_PARTIES;
use lib::configs::default::threshold::{
    L, N, PK_GENERATION_BIT_E_SM, PK_GENERATION_BIT_PK, PK_GENERATION_BIT_SK,
    PK_GENERATION_CONFIGS,
};
use lib::core::threshold::lbfv_party_secrets::LbfvPartySecrets;
use lib::core::threshold::lbfv_proof_domain::{LbfvProofSession, validate_party_statement};
use lib::math::polynomial::Polynomial;

/// Bound and commit one party's l-BFV secrets: the secret key and its smudging noise.
///
/// One proof per party. `row_index` is fixed at 0 because the statement is not row-scoped; it is
/// passed so the session and party checks stay shared with the row circuits.
fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    party_id: pub u32,
    sk: Polynomial<N>,
    e_sm: [Polynomial<N>; L],
) -> pub (Field, Field) {
    validate_party_statement::<N_PARTIES>(
        LbfvProofSession { session_id_hi, session_id_lo },
        party_id,
    );

    let circuit: LbfvPartySecrets<N, L, PK_GENERATION_BIT_SK, PK_GENERATION_BIT_E_SM, PK_GENERATION_BIT_PK, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> =
        LbfvPartySecrets::new(PK_GENERATION_CONFIGS, sk, e_sm);
    circuit.execute()
}
