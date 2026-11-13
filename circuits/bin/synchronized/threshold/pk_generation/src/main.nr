// SPDX-License-Identifier: LGPL-3.0-only

use lib::configs::synchronized::sync_insecure_64::{
    CRP, L_THRESHOLD, N, N_PARTIES, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_PK,
    PK_GENERATION_BIT_R, PK_GENERATION_BIT_SK, PK_GENERATION_EEK_BOUND, PROFILE_ID, QIS_THRESHOLD,
};
use lib::core::synchronized::pk_generation::execute;
use lib::math::polynomial::Polynomial;

fn main(
    setup_binding: pub [Field; 2],
    dealer_id: pub u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    ris: [Polynomial<N>; L_THRESHOLD],
    pk0is: [Polynomial<N>; L_THRESHOLD],
) -> pub (Field, Field) {
    execute::<N, L_THRESHOLD, N_PARTIES, PK_GENERATION_BIT_EEK, PK_GENERATION_BIT_SK, PK_GENERATION_BIT_R, PK_GENERATION_BIT_PK>(
        PROFILE_ID,
        setup_binding,
        dealer_id,
        QIS_THRESHOLD,
        PK_GENERATION_EEK_BOUND,
        CRP,
        eek,
        sk,
        ris,
        pk0is,
    )
}
