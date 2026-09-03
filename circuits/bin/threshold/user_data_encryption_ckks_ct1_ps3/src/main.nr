// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Greco-style verifiable-encryption proof for CKKS, ct1 leg:
// ct1 = pk1*u + e1 over R_q (per CRT limb), with `u` bound to the ct0
// leg via the shared `u_commitment` public output.
//
// Reuses the scheme-generic `UserDataEncryptionCt1` core (same relation
// as BFV's ct1 leg — no plaintext term) with CKKS moduli and bounds from
// `configs::ckks`.

use lib::configs::ckks_ps3::{
    CKKS_L, CKKS_N, USER_DATA_ENCRYPTION_CKKS_BIT_CT, USER_DATA_ENCRYPTION_CKKS_BIT_E1,
    USER_DATA_ENCRYPTION_CKKS_BIT_P1, USER_DATA_ENCRYPTION_CKKS_BIT_P2,
    USER_DATA_ENCRYPTION_CKKS_BIT_PK, USER_DATA_ENCRYPTION_CKKS_BIT_U,
    USER_DATA_ENCRYPTION_CKKS_CT1_CONFIGS,
};
use lib::core::threshold::user_data_encryption_ct1::UserDataEncryptionCt1;
use lib::math::polynomial::Polynomial;

fn main(
    pk1is: [Polynomial<CKKS_N>; CKKS_L],
    ct1is: [Polynomial<CKKS_N>; CKKS_L],
    u: Polynomial<CKKS_N>,
    e1: Polynomial<CKKS_N>,
    p1is: [Polynomial<(2 * CKKS_N) - 1>; CKKS_L],
    p2is: [Polynomial<CKKS_N - 1>; CKKS_L],
) -> pub (Field, Field, Field) {
    let circuit: UserDataEncryptionCt1<CKKS_N, CKKS_L, USER_DATA_ENCRYPTION_CKKS_BIT_PK, USER_DATA_ENCRYPTION_CKKS_BIT_CT, USER_DATA_ENCRYPTION_CKKS_BIT_U, USER_DATA_ENCRYPTION_CKKS_BIT_E1, USER_DATA_ENCRYPTION_CKKS_BIT_P1, USER_DATA_ENCRYPTION_CKKS_BIT_P2> = UserDataEncryptionCt1::new(
        USER_DATA_ENCRYPTION_CKKS_CT1_CONFIGS,
        pk1is,
        ct1is,
        u,
        e1,
        p1is,
        p2is,
    );

    circuit.execute()
}
