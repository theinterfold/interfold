// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::{MAX_MSG_NON_ZERO_COEFFS, T};
use lib::configs::default::threshold::{
    DECRYPTED_SHARES_AGGREGATION_WIDE_BIT_D_NATIVE, DECRYPTED_SHARES_AGGREGATION_WIDE_BIT_NOISE,
    DECRYPTED_SHARES_AGGREGATION_WIDE_CONFIGS, L,
};
use lib::core::threshold::decrypted_shares_aggregation_wide::DecryptedSharesAggregation;
use lib::math::polynomial::Polynomial;

/// C7 for presets whose ciphertext modulus exceeds what `decrypted_shares_aggregation` supports
/// (secure-16384: Q is about 2^250, so `t * u` passes the field size). Decodes with U384.
///
/// KNOWN UNSOUND: this is the pre-#1999 C7. Its `crt_quotients` carry no range bound, so the CRT
/// consistency equation holds mod p rather than over the integers and a prover can make C7 accept
/// any plaintext (#1999 root cause A). The l-BFV path is not in production; this must be replaced
/// by #1999's bounded construction with wide arithmetic before it is.
fn main(
    expected_d_commitments: pub [Field; T + 1],
    party_ids: pub [Field; T + 1],
    message: pub Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
    u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
) {
    let decrypted_shares_aggregation: DecryptedSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, DECRYPTED_SHARES_AGGREGATION_WIDE_BIT_NOISE, DECRYPTED_SHARES_AGGREGATION_WIDE_BIT_D_NATIVE> = DecryptedSharesAggregation::new(
        DECRYPTED_SHARES_AGGREGATION_WIDE_CONFIGS,
        expected_d_commitments,
        decryption_shares,
        party_ids,
        message,
        u_global,
        crt_quotients,
    );

    decrypted_shares_aggregation.execute();
}
