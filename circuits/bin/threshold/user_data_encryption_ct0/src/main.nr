// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_E0,
    USER_DATA_ENCRYPTION_BIT_E0_QUOTIENT, USER_DATA_ENCRYPTION_BIT_E0IS, USER_DATA_ENCRYPTION_BIT_K,
    USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_R1, USER_DATA_ENCRYPTION_BIT_R2,
    USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_CT0_CONFIGS,
};
use lib::core::threshold::user_data_encryption_ct0::UserDataEncryptionCt0;
use lib::math::polynomial::Polynomial;

fn main(
    pk0is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e0is: [Polynomial<N>; L],
    e0_quotients: [Polynomial<N>; L],
    k1: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
) -> pub (Field, Field, Field, Field) {
    let circuit: UserDataEncryptionCt0<N, L, USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_BIT_E0, USER_DATA_ENCRYPTION_BIT_E0IS, USER_DATA_ENCRYPTION_BIT_E0_QUOTIENT, USER_DATA_ENCRYPTION_BIT_K, USER_DATA_ENCRYPTION_BIT_R1, USER_DATA_ENCRYPTION_BIT_R2> = UserDataEncryptionCt0::new(
        USER_DATA_ENCRYPTION_CT0_CONFIGS,
        pk0is,
        ct0is,
        u,
        e0,
        e0is,
        e0_quotients,
        k1,
        r1is,
        r2is,
    );

    circuit.execute()
}
