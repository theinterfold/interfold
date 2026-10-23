// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bid proof, table strategy. See `bid_lib::table` for the statement and the bounds.
//! `constants.nr` is generated: it fixes the profile, the variant, `n`, and `B`.

mod constants;

use bid_lib::{Polynomial, table::prove};
use constants::{B, BIT_K, COEF_AT, COEF_NEXT, CTS, N, PLAINTEXT_MODULUS, QUOTIENT_BITS, TABLE};

/// Private: the bid `b` and one `k1` polynomial for each bid ciphertext.
/// Public output: the `k1` commitments, to equate with the `user_data_encryption` outputs.
fn main(b: Field, k1s: [Polynomial<N>; CTS]) -> pub [Field; CTS] {
    prove::<N, B, CTS, BIT_K, QUOTIENT_BITS>(b, k1s, PLAINTEXT_MODULUS, COEF_AT, COEF_NEXT, TABLE)
}
