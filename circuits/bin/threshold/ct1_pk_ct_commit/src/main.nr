// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A, ct1 leg: commits both `pk1is` and `ct1is` in one circuit - see `ct0_pk_ct_commit`
//! for why the two groups share a circuit.
//!
//! Each commitment formula MUST stay exactly `compute_multiple_polynomial_commitment` under
//! `DS_PK_AGGREGATION`/`DS_CIPHERTEXT`. The `user_data_encryption` wrapper combines ct0's and
//! ct1's pk/ct commitments the same way `pk_aggregation.nr`'s C5 does, so these hashes are a
//! protocol invariant, not an internal choice.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_PK,
};
use lib::math::commitments::{
    compute_multiple_polynomial_commitment, DS_CIPHERTEXT, DS_PK_AGGREGATION,
};
use lib::math::polynomial::Polynomial;

fn main(pk1is: [Polynomial<N>; L], ct1is: [Polynomial<N>; L]) -> pub (Field, Field) {
    let pk1_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_PK>(
        pk1is,
        DS_PK_AGGREGATION,
    );
    let ct1_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_CT>(
        ct1is,
        DS_CIPHERTEXT,
    );

    (pk1_commitment, ct1_commitment)
}
