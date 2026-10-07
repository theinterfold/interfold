// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_E_SM_BIT_SECRET, SHARE_COMPUTATION_N_CHUNKS,
    SHARE_COMPUTATION_SK_BIT_SECRET,
};
use lib::configs::default::threshold::{
    CRP, L, N, PK_GENERATION_BIT_E_SM, PK_GENERATION_BIT_E_SM_LIFTED,
    PK_GENERATION_BIT_E_SM_QUOTIENT, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_PK,
    PK_GENERATION_BIT_R, PK_GENERATION_BIT_SK, PK_GENERATION_CONFIGS,
};
use lib::core::threshold::pk_generation::PkGeneration;
use lib::math::commitments::{
    compute_sc_esm_secret_root_from_polynomial, compute_sc_sk_secret_root_from_polynomial,
};
use lib::math::polynomial::Polynomial;

/// C1 for the l-BFV path: identical to `pk_generation` except that `sk` and `e_sm` are committed
/// as chunk roots, the form the chunked C2 (`sk_share_computation_chunk`,
/// `esm_share_computation_chunk`) opens.
fn main(
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    e_sm: [Polynomial<N>; L],
    e_sm_lifted: Polynomial<N>,
    e_sm_quotients: [Polynomial<N>; L],
    ris: [Polynomial<N>; L],
    pk0is: [Polynomial<N>; L],
) -> pub (Field, Field, Field) {
    // C2 re-opens the sk/e_sm roots built here, so both sides must pack at the same widths.
    assert(PK_GENERATION_BIT_SK == SHARE_COMPUTATION_SK_BIT_SECRET);
    assert(PK_GENERATION_BIT_E_SM == SHARE_COMPUTATION_E_SM_BIT_SECRET);
    let pk_generation: PkGeneration<N, L, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_SK, PK_GENERATION_BIT_E_SM, PK_GENERATION_BIT_E_SM_LIFTED, PK_GENERATION_BIT_E_SM_QUOTIENT, PK_GENERATION_BIT_R, PK_GENERATION_BIT_PK> = PkGeneration::new(
        PK_GENERATION_CONFIGS,
        CRP,
        eek,
        sk,
        e_sm,
        e_sm_lifted,
        e_sm_quotients,
        ris,
        pk0is,
    );
    pk_generation.execute_with(
        |sk| {
            compute_sc_sk_secret_root_from_polynomial::<N, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE, PK_GENERATION_BIT_SK>(
                sk,
            )
        },
        |e_sm| {
            compute_sc_esm_secret_root_from_polynomial::<N, L, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE, PK_GENERATION_BIT_E_SM>(
                e_sm,
            )
        },
    )
}
