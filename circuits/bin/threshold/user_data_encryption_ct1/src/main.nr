// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_CT1_BIT_R,
    USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_U,
    USER_DATA_ENCRYPTION_CT1_CONFIGS,
};
use lib::core::threshold::user_data_encryption_ct1::UserDataEncryptionCt1;
use lib::math::polynomial::Polynomial;

fn main(
    pk1is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e1: Polynomial<N>,
    // Named `r_ct1` only because ct0 and ct1 share one generated Prover.toml and each needs its
    // own reduction quotient; the circuit field it feeds is `r`.
    r_ct1: [Polynomial<N>; L],
) -> pub (Field, Field, Field) {
    let circuit: UserDataEncryptionCt1<N, L, USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_CT1_BIT_R> = UserDataEncryptionCt1::new(
        USER_DATA_ENCRYPTION_CT1_CONFIGS,
        pk1is,
        ct1is,
        u,
        e1,
        r_ct1,
    );

    circuit.execute()
}
