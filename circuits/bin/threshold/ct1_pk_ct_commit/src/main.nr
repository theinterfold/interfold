// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A, ct1 leg: commits `ct1is` (pinned to its centered residue) and passes the public-key
//! commitment through - see `ct0_pk_ct_commit` for why the key is not hashed in round A.
//! `ct1_eval_pk_ct` recomputes it from `pk1is` and `user_data_encryption_ct1_chunked` asserts the
//! two rounds agree.
//!
//! The ciphertext commitment MUST stay exactly `compute_multiple_polynomial_commitment_checked`
//! under `DS_CIPHERTEXT`.

use lib::configs::default::threshold::{L, N, QIS, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT};
use lib::core::threshold::user_data_encryption_chunk::assert_centered_ciphertext;
use lib::math::commitments::{compute_multiple_polynomial_commitment_checked, DS_CIPHERTEXT};
use lib::math::polynomial::Polynomial;

fn main(pk1_commitment: Field, ct1is: [Polynomial<N>; L]) -> pub (Field, Field) {
    assert_centered_ciphertext::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(ct1is, QIS);
    let ct1_commitment = compute_multiple_polynomial_commitment_checked::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(
        ct1is,
        DS_CIPHERTEXT,
    );

    (pk1_commitment, ct1_commitment)
}
