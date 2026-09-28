// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::{MAX_MSG_NON_ZERO_COEFFS, T};
use lib::configs::default::threshold::{
    DECRYPTED_SHARES_AGGREGATION_BIT_CRT_QUOTIENT, DECRYPTED_SHARES_AGGREGATION_BIT_D_NATIVE,
    DECRYPTED_SHARES_AGGREGATION_BIT_NOISE, DECRYPTED_SHARES_AGGREGATION_CONFIGS, L,
};
use lib::core::threshold::decrypted_shares_aggregation::DecryptedSharesAggregation;
use lib::math::polynomial::Polynomial;

fn main(
    expected_d_commitments: pub [Field; T + 1],
    party_ids: pub [Field; T + 1],
    message: pub Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
    u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
) {
    let decrypted_shares_aggregation: DecryptedSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, DECRYPTED_SHARES_AGGREGATION_BIT_NOISE, DECRYPTED_SHARES_AGGREGATION_BIT_D_NATIVE, DECRYPTED_SHARES_AGGREGATION_BIT_CRT_QUOTIENT> = DecryptedSharesAggregation::new(
        DECRYPTED_SHARES_AGGREGATION_CONFIGS,
        expected_d_commitments,
        decryption_shares,
        party_ids,
        message,
        u_global,
        crt_quotients,
    );

    decrypted_shares_aggregation.execute();
}
