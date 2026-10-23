// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bid proof, sparse strategy. See `bid_lib::sparse` for the statement and the bounds.
//! `constants.nr` is generated: it fixes the profile, the variant, `n`, and `B`.

mod constants;

use bid_lib::sparse::{prove, SparseConstants};
use constants::{
    B, BIT_K, CLASS_LEVEL, CLASSES, CTS, N, PLAINTEXT_MODULUS, POSITIONS, QUOTIENT_BITS, S,
    TARGET_AT, TARGET_NEXT, WEIGHTS,
};

/// Private: the bid `b`, and for each bid ciphertext the `S` coefficients of `k1` at `POSITIONS`.
/// Public output: the `k1` commitments, to equate with the `user_data_encryption` outputs.
fn main(b: Field, k1_support: [[Field; S]; CTS]) -> pub [Field; CTS] {
    prove::<N, B, CTS, S, CLASSES, BIT_K, QUOTIENT_BITS>(
        b,
        k1_support,
        SparseConstants {
            t: PLAINTEXT_MODULUS,
            positions: POSITIONS,
            class_level: CLASS_LEVEL,
            weights: WEIGHTS,
            target_at: TARGET_AT,
            target_next: TARGET_NEXT,
        },
    )
}
