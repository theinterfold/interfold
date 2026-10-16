// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::threshold::{
    CRP, L, N, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_E0,
    USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_BIT_K, USER_DATA_ENCRYPTION_BIT_PK,
    USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_CT0_BIT_R, USER_DATA_ENCRYPTION_CT0_CONFIGS,
    USER_DATA_ENCRYPTION_CT1_BIT_R, USER_DATA_ENCRYPTION_CT1_CONFIGS,
};
use lib::core::threshold::user_data_encryption;
use lib::core::threshold::user_data_encryption_ct0::UserDataEncryptionCt0;
use lib::core::threshold::user_data_encryption_ct1::UserDataEncryptionCt1;
use lib::math::polynomial::Polynomial;

/// User-data encryption (P3): proves both legs of one BFV encryption in a single circuit.
///
/// Both legs read the one `u` witness below (see `user_data_encryption::execute`), which replaces
/// the separate ct0 / ct1 proofs and the fold that checked their `u` commitments were equal. `pk1`
/// is the circuit-constant CRS, as in C5. Returns `(pk_commitment, ct_commitment, k1_commitment)`,
/// the values the fold returned.
fn main(
    pk0is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e1: Polynomial<N>,
    k1: Polynomial<N>,
    // ct0's and ct1's reduction quotients.
    r: [Polynomial<N>; L],
    r_ct1: [Polynomial<N>; L],
) -> pub (Field, Field, Field) {
    let ct0: UserDataEncryptionCt0<N, L, USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_BIT_E0, USER_DATA_ENCRYPTION_BIT_K, USER_DATA_ENCRYPTION_CT0_BIT_R> =
        UserDataEncryptionCt0::new(USER_DATA_ENCRYPTION_CT0_CONFIGS, pk0is, ct0is, u, e0, k1, r);

    let ct1: UserDataEncryptionCt1<N, L, USER_DATA_ENCRYPTION_BIT_PK, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_U, USER_DATA_ENCRYPTION_BIT_E1, USER_DATA_ENCRYPTION_CT1_BIT_R> =
        UserDataEncryptionCt1::new(USER_DATA_ENCRYPTION_CT1_CONFIGS, CRP, ct1is, u, e1, r_ct1);

    user_data_encryption::execute(ct0, ct1)
}
