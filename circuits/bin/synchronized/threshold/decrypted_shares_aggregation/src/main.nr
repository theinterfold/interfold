// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::protocol::MAX_MSG_NON_ZERO_COEFFS;
use lib::configs::synchronized::sync_insecure_64::{C6_PUBLIC_FIELDS, L_THRESHOLD, N, T};
use lib::core::synchronized::plaintext_aggregation::execute;

fn main(
    rows: pub [[Field; C6_PUBLIC_FIELDS]; T + 1],
    message: pub [u64; MAX_MSG_NON_ZERO_COEFFS],
    c0: [[u64; N]; L_THRESHOLD],
    shares: [[[u64; N]; L_THRESHOLD]; T + 1],
) {
    execute(rows, message, c0, shares);
}
