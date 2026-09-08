// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round A, groups C+D merged (P3): commits both `pk0is` and `ct0is` in one circuit. Each
//! commitment formula MUST stay exactly `compute_multiple_polynomial_commitment` under
//! `DS_PK_AGGREGATION`/`DS_CIPHERTEXT` - unchanged from the two separate circuits this replaces.
//! `pk_aggregation.nr`'s C5 independently recomputes the `pk0is` commitment to cross-check the
//! threshold PK, so that hash is a protocol invariant, not an internal choice.
//!
//! `ct0_pk_commit` and `ct0_ct_commit` used to be proved separately and recombined by
//! `ct0_chunk_pk_ct_combine` purely because `ct0_chunk_gamma` can verify at most two proofs.
//! Merging them into one circuit removes that combine step entirely: both commitments still
//! cost the same to compute (no recursion was ever involved), so `ct0_chunk_gamma` now verifies
//! this circuit directly instead of a three-circuit chain.

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
