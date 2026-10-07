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
use lib::math::commitments::compute_sc_party_share_root_from_polynomial;
use lib::math::polynomial::Polynomial;

/// C4 for the l-BFV path: identical to `share_decryption` except that each received share is
/// opened as the chunk root the chunked C2 committed, keyed by this node's `recipient_party_idx`.
/// The index needs no constraint of its own: a wrong one gives roots that do not match the public
/// `expected_commitments`.
fn main(
    expected_commitments: pub [[Field; L_THRESHOLD]; H],
    decrypted_shares: [[Polynomial<N>; L_THRESHOLD]; H],
    recipient_party_idx: u32,
) -> pub Field {
    let share_decryption: ShareDecryption<N, L_THRESHOLD, H, SHARE_DECRYPTION_BIT_MSG, SHARE_DECRYPTION_BIT_AGG> =
        ShareDecryption::new(expected_commitments, decrypted_shares);
    share_decryption.execute_with(QIS_THRESHOLD, |mod_idx, share| {
        compute_sc_party_share_root_from_polynomial::<N, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE, SHARE_DECRYPTION_BIT_MSG>(
            recipient_party_idx,
            mod_idx,
            share,
        )
    })
}
