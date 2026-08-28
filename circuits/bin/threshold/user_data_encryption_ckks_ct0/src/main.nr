// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::ckks::{
    CKKS_L, CKKS_N, USER_DATA_ENCRYPTION_CKKS_BIT_CT, USER_DATA_ENCRYPTION_CKKS_BIT_E0,
    USER_DATA_ENCRYPTION_CKKS_BIT_M, USER_DATA_ENCRYPTION_CKKS_BIT_PK,
    USER_DATA_ENCRYPTION_CKKS_BIT_R1, USER_DATA_ENCRYPTION_CKKS_BIT_R2,
    USER_DATA_ENCRYPTION_CKKS_BIT_U, USER_DATA_ENCRYPTION_CKKS_CT0_CONFIGS,
};
use lib::core::threshold::user_data_encryption_ckks_ct0::UserDataEncryptionCkksCt0;
use lib::math::polynomial::Polynomial;

fn main(
    pk0is: [Polynomial<CKKS_N>; CKKS_L],
    ct0is: [Polynomial<CKKS_N>; CKKS_L],
    u: Polynomial<CKKS_N>,
    e0: Polynomial<CKKS_N>,
    e0is: [Polynomial<CKKS_N>; CKKS_L],
    e0_quotients: [Polynomial<CKKS_N>; CKKS_L],
    m: Polynomial<CKKS_N>,
    mis: [Polynomial<CKKS_N>; CKKS_L],
    m_quotients: [Polynomial<CKKS_N>; CKKS_L],
    r1is: [Polynomial<(2 * CKKS_N) - 1>; CKKS_L],
    r2is: [Polynomial<CKKS_N - 1>; CKKS_L],
) -> pub (Field, Field, Field, Field) {
    let circuit: UserDataEncryptionCkksCt0<CKKS_N, CKKS_L, USER_DATA_ENCRYPTION_CKKS_BIT_PK, USER_DATA_ENCRYPTION_CKKS_BIT_CT, USER_DATA_ENCRYPTION_CKKS_BIT_U, USER_DATA_ENCRYPTION_CKKS_BIT_E0, USER_DATA_ENCRYPTION_CKKS_BIT_M, USER_DATA_ENCRYPTION_CKKS_BIT_R1, USER_DATA_ENCRYPTION_CKKS_BIT_R2> = UserDataEncryptionCkksCt0::new(
        USER_DATA_ENCRYPTION_CKKS_CT0_CONFIGS,
        pk0is,
        ct0is,
        u,
        e0,
        e0is,
        e0_quotients,
        m,
        mis,
        m_quotients,
        r1is,
        r2is,
    );

    circuit.execute()
}
