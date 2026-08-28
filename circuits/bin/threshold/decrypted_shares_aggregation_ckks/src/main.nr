// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::ckks_aggregation::{
    DECRYPTED_SHARES_AGGREGATION_CKKS_BIT_D_NATIVE, DECRYPTED_SHARES_AGGREGATION_CKKS_CONFIGS,
    DECRYPTED_SHARES_AGGREGATION_CKKS_L,
};
use lib::configs::default::{MAX_MSG_NON_ZERO_COEFFS, T};
use lib::core::threshold::decrypted_shares_aggregation_ckks::DecryptedSharesAggregationCkks;
use lib::math::polynomial::Polynomial;

fn main(
    expected_d_commitments: pub [Field; T + 1],
    party_ids: pub [Field; T + 1],
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; DECRYPTED_SHARES_AGGREGATION_CKKS_L]; T + 1],
    u_global: pub Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; DECRYPTED_SHARES_AGGREGATION_CKKS_L],
) {
    let aggregation: DecryptedSharesAggregationCkks<MAX_MSG_NON_ZERO_COEFFS, DECRYPTED_SHARES_AGGREGATION_CKKS_L, T, DECRYPTED_SHARES_AGGREGATION_CKKS_BIT_D_NATIVE> = DecryptedSharesAggregationCkks::new(
        DECRYPTED_SHARES_AGGREGATION_CKKS_CONFIGS,
        expected_d_commitments,
        decryption_shares,
        party_ids,
        u_global,
        crt_quotients,
    );

    aggregation.execute();
}
