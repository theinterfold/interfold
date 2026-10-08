// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! ct1 ciphertext circuit: pins `ct1is` to its centered residues, commits it, and evaluates it at
//! the leaf's challenge. See `ct0_pk_ct_commit`.
//!
//! The commitment MUST stay exactly `compute_multiple_polynomial_commitment_checked` under
//! `DS_CIPHERTEXT`.

use lib::configs::default::threshold::{L, N, QIS, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT};
use lib::core::threshold::user_data_encryption_chunk::assert_centered_ciphertext;
use lib::math::commitments::{compute_multiple_polynomial_commitment_checked, DS_CIPHERTEXT};
use lib::math::polynomial::Polynomial;

fn main(ct1is: [Polynomial<N>; L], gamma: pub Field) -> pub (Field, [Field; L]) {
    assert_centered_ciphertext::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(ct1is, QIS);
    let ct1_commitment = compute_multiple_polynomial_commitment_checked::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(
        ct1is,
        DS_CIPHERTEXT,
    );
    let mut ct1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        ct1is_at_gamma[i] = ct1is[i].eval(gamma);
    }
    (ct1_commitment, ct1is_at_gamma)
}
