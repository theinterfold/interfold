// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L_THRESHOLD, N, QIS_THRESHOLD, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE,
    SHARE_COMPUTATION_N_CHUNKS, SHARE_DECRYPTION_BIT_AGG, SHARE_DECRYPTION_BIT_MSG,
};
use lib::configs::default::H;
use lib::core::dkg::share_decryption::packed_share_decryption;

/// C4 for the l-BFV path. Each received share arrives as the carriers the chunked C2 packed and
/// committed (four coefficients per carrier, reversed order), keyed by this node's
/// `recipient_party_idx`; `packed_share_decryption` hashes them into the C2 chunk roots, sums them
/// while packed and commits to the centred aggregate. The output equals the coefficient-wise C4's.
/// The index needs no constraint of its own: a wrong one gives roots that do not match the public
/// `expected_commitments`.
fn main(
    expected_commitments: pub [[Field; L_THRESHOLD]; H],
    share_carriers: [[[Field; N / 4]; L_THRESHOLD]; H],
    recipient_party_idx: u32,
) -> pub Field {
    // C4 re-opens the chunk roots C2 committed; its bound comes from C2 only at the same width.
    assert(SHARE_DECRYPTION_BIT_MSG == SHARE_COMPUTATION_BIT_SHARE);
    packed_share_decryption::<N, L_THRESHOLD, H, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE, SHARE_DECRYPTION_BIT_MSG, SHARE_DECRYPTION_BIT_AGG>(
        expected_commitments,
        share_carriers,
        recipient_party_idx,
        QIS_THRESHOLD,
    )
}
