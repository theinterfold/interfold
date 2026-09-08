// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::threshold::{
    CRP, L, N, PK_GENERATION_BIT_E_SM, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_PK,
    PK_GENERATION_BIT_R1, PK_GENERATION_BIT_R2, PK_GENERATION_BIT_SK, PK_GENERATION_CONFIGS,
};
use lib::core::threshold::pk_generation::PkGeneration;
use lib::math::polynomial::Polynomial;

fn main(
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    e_sm: [Polynomial<N>; L],
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    pk0is: [Polynomial<N>; L],
) -> pub (Field, Field, Field) {
    let pk_generation: PkGeneration<N, L, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_SK, PK_GENERATION_BIT_E_SM, PK_GENERATION_BIT_R1, PK_GENERATION_BIT_R2, PK_GENERATION_BIT_PK, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> =
        PkGeneration::new(PK_GENERATION_CONFIGS, CRP, eek, sk, e_sm, r1is, r2is, pk0is);
    pk_generation.execute()
}
