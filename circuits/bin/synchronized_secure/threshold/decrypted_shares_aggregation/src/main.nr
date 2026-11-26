// SPDX-License-Identifier: LGPL-3.0-only
use lib::configs::protocol::MAX_MSG_NON_ZERO_COEFFS;
use lib::configs::synchronized::sync_secure_8192::{
    AGGREGATE_BIT, C6_PUBLIC_FIELDS, C7_BIT_K, C7_BIT_Q_TOTAL, C7_BIT_T, C7_PLAINTEXT_MODULUS, H,
    L_THRESHOLD as L, N, N_PARTIES, QIS_THRESHOLD as QIS, SHARE_BIT, T,
};
use lib::core::synchronized::plaintext_aggregation::execute_for;

fn main(
    rows: pub [[Field; C6_PUBLIC_FIELDS]; T + 1],
    message: pub [u64; MAX_MSG_NON_ZERO_COEFFS],
    c0: [[u64; N]; L],
    shares: [[[u64; N]; L]; T + 1],
) {
    execute_for::<N, L, T, H, C6_PUBLIC_FIELDS, SHARE_BIT, AGGREGATE_BIT, C7_BIT_K, C7_BIT_T, C7_BIT_Q_TOTAL>(
        rows,
        message,
        c0,
        shares,
        QIS,
        N_PARTIES,
        C7_PLAINTEXT_MODULUS,
    );
}
