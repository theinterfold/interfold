// SPDX-License-Identifier: LGPL-3.0-only

use lib::configs::synchronized::sync_insecure_64::{
    AGGREGATE_BIT, H, L_THRESHOLD, N, N_PARTIES, PRF_KEY_BITS, PROFILE_ID, QIS_THRESHOLD, SHARE_BIT,
    SHARE_ENCRYPTION_BIT_MSG,
};
use lib::core::synchronized::share_decryption::execute;
use lib::math::polynomial::Polynomial;

fn main(
    setup_binding: pub [Field; 2],
    recipient_id: pub u32,
    dealer_ids: pub [u32; H],
    expected_outgoing_root: pub Field,
    expected_commitments: pub [[Field; L_THRESHOLD]; H],
    packed_shares: [[Polynomial<N>; L_THRESHOLD]; H],
    outgoing_keys: [[u8; 32]; N_PARTIES],
    incoming_keys: [[u8; 32]; H],
) -> pub (Field, Field) {
    execute::<N, L_THRESHOLD, N_PARTIES, H, PRF_KEY_BITS, SHARE_BIT, SHARE_ENCRYPTION_BIT_MSG, AGGREGATE_BIT>(
        PROFILE_ID,
        setup_binding,
        recipient_id,
        dealer_ids,
        expected_outgoing_root,
        expected_commitments,
        QIS_THRESHOLD,
        packed_shares,
        outgoing_keys,
        incoming_keys,
    )
}
