// SPDX-License-Identifier: LGPL-3.0-only

use lib::configs::synchronized::sync_insecure_64::{
    L_THRESHOLD, N, N_PARTIES, PK_GENERATION_BIT_SK, PRF_KEY_BITS, PROFILE_ID, QIS_THRESHOLD,
    SHARE_BIT, SHARE_ENCRYPTION_BIT_MSG, T,
};
use lib::core::synchronized::share_computation::execute;
use lib::math::polynomial::Polynomial;

fn main(
    setup_binding: pub [Field; 2],
    dealer_id: pub u32,
    expected_secret_commitment: pub Field,
    sk_secret: Polynomial<N>,
    y: [[[Field; N_PARTIES + 1]; L_THRESHOLD]; N],
    outgoing_keys: [[u8; 32]; N_PARTIES],
) -> pub ([[Field; L_THRESHOLD]; N_PARTIES], Field) {
    execute::<N, L_THRESHOLD, N_PARTIES, T, PRF_KEY_BITS, PK_GENERATION_BIT_SK, SHARE_BIT, SHARE_ENCRYPTION_BIT_MSG>(
        PROFILE_ID,
        setup_binding,
        dealer_id,
        expected_secret_commitment,
        QIS_THRESHOLD,
        sk_secret,
        y,
        outgoing_keys,
    )
}
