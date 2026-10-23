// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bid proof, NTT strategy. See `bid_lib::ntt` for the statement, the reduction schedule, and
//! the bounds. `constants.nr` is generated: it fixes the profile, the variant, `n`, and `B`.

mod constants;

use bid_lib::{ntt::{NttConstants, prove}, Polynomial};
use constants::{
    B, BIT_K, CTS, LEVEL_OF, LOG_N, N, PLAINTEXT_MODULUS, QUOTIENT_BITS, TARGET_AT, TARGET_NEXT,
    TWIDDLES,
};

/// Private: the bid `b` and one `k1` polynomial for each bid ciphertext.
/// Public output: the `k1` commitments, to equate with the `user_data_encryption` outputs.
fn main(b: Field, k1s: [Polynomial<N>; CTS]) -> pub [Field; CTS] {
    prove::<N, LOG_N, B, CTS, BIT_K, QUOTIENT_BITS>(
        b,
        k1s,
        NttConstants {
            t: PLAINTEXT_MODULUS,
            twiddles: TWIDDLES,
            level_of: LEVEL_OF,
            target_at: TARGET_AT,
            target_next: TARGET_NEXT,
        },
    )
}
