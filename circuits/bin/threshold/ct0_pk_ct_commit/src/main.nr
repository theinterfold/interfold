// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! ct0 ciphertext circuit: pins `ct0is` to its centered residues, commits it, and evaluates it at
//! the leaf's challenge. `ct0is` is bound by `ct0_commitment`, which the leaf hashed into that
//! challenge, so evaluating here is sound; `user_data_encryption_ct0_chunked` equates the two
//! commitments and the two challenges.
//!
//! The commitment MUST keep the value of `compute_multiple_polynomial_commitment` under
//! `DS_CIPHERTEXT`, the ciphertext commitment every consumer compares against. This circuit creates
//! it over limbs `assert_centered_ciphertext` has just pinned to their centered residues, so every
//! packed digit is already in its slot and the plain packing is injective; the checked helper
//! computes the same value and would only repeat those bounds.

use lib::configs::default::threshold::{L, N, QIS, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT};
use lib::core::threshold::user_data_encryption_chunk::assert_centered_ciphertext;
use lib::math::commitments::{compute_multiple_polynomial_commitment, DS_CIPHERTEXT};
use lib::math::polynomial::Polynomial;

fn main(ct0is: [Polynomial<N>; L], gamma: pub Field) -> pub (Field, [Field; L]) {
    assert_centered_ciphertext::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(ct0is, QIS);
    let ct0_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(
        ct0is,
        DS_CIPHERTEXT,
    );
    let mut ct0is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        ct0is_at_gamma[i] = ct0is[i].eval(gamma);
    }
    (ct0_commitment, ct0is_at_gamma)
}
