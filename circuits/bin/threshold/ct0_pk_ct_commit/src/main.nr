// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A: commits `ct0is` (pinned to its centered residue) and passes the public-key
//! commitment through, so `ct0_chunk_gamma` reaches both with a single verification - no circuit
//! in this tree can afford more than two.
//!
//! The public key is not hashed here. It is public and fixed per E3, so binding it before the
//! challenge only needs its commitment in the transcript, which this circuit outputs.
//! `ct0_eval_pk_ct` (round B) recomputes the commitment from the `pk0is` it evaluates, and
//! `user_data_encryption_ct0_chunked` asserts the two rounds agree, so the evaluated key is the
//! committed one. Dropping the hash keeps this circuit inside the browser's 2^21 budget now that it
//! range-checks the ciphertext.
//!
//! The ciphertext commitment MUST stay exactly `compute_multiple_polynomial_commitment_checked`
//! under `DS_CIPHERTEXT`.

use lib::configs::default::threshold::{L, N, QIS, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT};
use lib::core::threshold::user_data_encryption_chunk::assert_centered_ciphertext;
use lib::math::commitments::{compute_multiple_polynomial_commitment_checked, DS_CIPHERTEXT};
use lib::math::polynomial::Polynomial;

fn main(pk0_commitment: Field, ct0is: [Polynomial<N>; L]) -> pub (Field, Field) {
    assert_centered_ciphertext::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(ct0is, QIS);
    let ct0_commitment = compute_multiple_polynomial_commitment_checked::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_CT>(
        ct0is,
        DS_CIPHERTEXT,
    );

    (pk0_commitment, ct0_commitment)
}
