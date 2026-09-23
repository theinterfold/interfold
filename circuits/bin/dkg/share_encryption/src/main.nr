// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L, N, SHARE_ENCRYPTION_BIT_CT, SHARE_ENCRYPTION_BIT_E0, SHARE_ENCRYPTION_BIT_E1,
    SHARE_ENCRYPTION_BIT_MSG, SHARE_ENCRYPTION_BIT_P1, SHARE_ENCRYPTION_BIT_P2,
    SHARE_ENCRYPTION_BIT_PK, SHARE_ENCRYPTION_BIT_R1, SHARE_ENCRYPTION_BIT_R2,
    SHARE_ENCRYPTION_BIT_U, SHARE_ENCRYPTION_CONFIGS,
};
use lib::core::dkg::share_encryption::ShareEncryption;
use lib::math::polynomial::Polynomial;

fn main(
    expected_pk_commitment: pub Field,
    expected_message_commitment: pub Field,
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e1: Polynomial<N>,
    message: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    p1is: [Polynomial<(2 * N) - 1>; L],
    p2is: [Polynomial<N - 1>; L],
) -> pub Field {
    let share_encryption: ShareEncryption<N, L, SHARE_ENCRYPTION_BIT_PK, SHARE_ENCRYPTION_BIT_CT, SHARE_ENCRYPTION_BIT_U, SHARE_ENCRYPTION_BIT_E0, SHARE_ENCRYPTION_BIT_E1, SHARE_ENCRYPTION_BIT_MSG, SHARE_ENCRYPTION_BIT_R1, SHARE_ENCRYPTION_BIT_R2, SHARE_ENCRYPTION_BIT_P1, SHARE_ENCRYPTION_BIT_P2> = ShareEncryption::new(
        SHARE_ENCRYPTION_CONFIGS,
        expected_pk_commitment,
        expected_message_commitment,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e1,
        message,
        r1is,
        r2is,
        p1is,
        p2is,
    );
    share_encryption.execute()
}
