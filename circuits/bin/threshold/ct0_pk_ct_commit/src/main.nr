// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A: commits both `pk0is` and `ct0is` in one circuit. Neither commitment involves any
//! recursion, so proving them together costs no more than proving them apart, and it lets
//! `ct0_chunk_gamma` reach both with a single verification - which matters, since no circuit here
//! can afford more than two.
//!
//! Each commitment formula MUST stay exactly `compute_multiple_polynomial_commitment` under
//! `DS_PK_AGGREGATION`/`DS_CIPHERTEXT`. `pk_aggregation.nr`'s C5 independently recomputes the
//! `pk0is` commitment to cross-check the threshold PK, so that hash is a protocol invariant, not
//! an internal choice.

use lib::configs::default::threshold::{
    L, N, USER_DATA_ENCRYPTION_BIT_CT, USER_DATA_ENCRYPTION_BIT_PK,
};
use lib::math::commitments::{
    compute_multiple_polynomial_commitment, DS_CIPHERTEXT, DS_PK_AGGREGATION,
};
use lib::math::polynomial::Polynomial;

fn main(pk0is: [Polynomial<N>; L], ct0is: [Polynomial<N>; L]) -> pub (Field, Field) {
    let pk0_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_PK>(
        pk0is,
        DS_PK_AGGREGATION,
    );
    let ct0_commitment = compute_multiple_polynomial_commitment::<N, L, USER_DATA_ENCRYPTION_BIT_CT>(
        ct0is,
        DS_CIPHERTEXT,
    );

    (pk0_commitment, ct0_commitment)
}
