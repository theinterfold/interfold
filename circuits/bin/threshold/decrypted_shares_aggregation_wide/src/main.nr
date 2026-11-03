// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::{MAX_MSG_NON_ZERO_COEFFS, N_PARTIES, T};
use lib::configs::default::threshold::{
    DECRYPTED_SHARES_AGGREGATION_BIT_D_NATIVE, DECRYPTED_SHARES_AGGREGATION_BIT_K,
    DECRYPTED_SHARES_AGGREGATION_BIT_Q, DECRYPTED_SHARES_AGGREGATION_CONFIGS, L,
};
use lib::core::threshold::decrypted_shares_aggregation_wide::DecryptedSharesAggregation;
use lib::math::polynomial::Polynomial;

/// C7 for ciphertext moduli wider than `decrypted_shares_aggregation` supports (secure-16384: Q is
/// about 2^250, so the decode numerator `t * u` passes the field). Same inputs, constants and
/// statement as `decrypted_shares_aggregation`; Garner runs in mixed radix and the decode in U384.
fn main(
    expected_d_commitments: pub [Field; T + 1],
    party_ids: pub [Field; T + 1],
    message: pub Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
) {
    let decrypted_shares_aggregation: DecryptedSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, N_PARTIES, DECRYPTED_SHARES_AGGREGATION_BIT_D_NATIVE, DECRYPTED_SHARES_AGGREGATION_BIT_Q, DECRYPTED_SHARES_AGGREGATION_BIT_K> = DecryptedSharesAggregation::new(
        DECRYPTED_SHARES_AGGREGATION_CONFIGS,
        expected_d_commitments,
        decryption_shares,
        party_ids,
        message,
    );

    decrypted_shares_aggregation.execute();
}
