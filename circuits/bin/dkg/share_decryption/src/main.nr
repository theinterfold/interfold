// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, QIS_THRESHOLD, SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS,
    SHARE_DECRYPTION_BIT_AGG, SHARE_DECRYPTION_BIT_MSG,
};
use lib::configs::default::H;
use lib::core::dkg::share_decryption::ShareDecryption;
use lib::math::polynomial::Polynomial;

fn main(
    expected_commitments: pub [[Field; L_THRESHOLD]; H],
    decrypted_shares: [[Polynomial<N>; L_THRESHOLD]; H],
    recipient_party_idx: u32,
) -> pub Field {
    let share_decryption: ShareDecryption<N, L_THRESHOLD, H, SHARE_DECRYPTION_BIT_MSG, SHARE_DECRYPTION_BIT_AGG, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE> =
        ShareDecryption::new(expected_commitments, decrypted_shares, recipient_party_idx);

    share_decryption.execute(QIS_THRESHOLD)
}
