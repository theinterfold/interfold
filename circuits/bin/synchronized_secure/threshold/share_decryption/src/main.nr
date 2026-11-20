// SPDX-License-Identifier: LGPL-3.0-only
use lib::configs::synchronized::sync_secure_8192::{
    AGGREGATE_BIT, C6_NOISE_BOUND, H, KEY_BITS, L, N, N_PARTIES, PROFILE_ID, QIS, SHARE_BIT, T,
};
use lib::core::synchronized::threshold_decryption::secure_share;

fn main(
    setup: pub [Field; 2],
    owner: pub u32,
    roster: pub [u32; H],
    domain: pub [u128; 2],
    expected_sk: pub Field,
    expected_bundle: pub Field,
    expected_ct: pub Field,
    outgoing: [[u8; 32]; N_PARTIES],
    incoming: [[u8; 32]; H],
    sk: [[u64; N]; L],
    ct: [[[u64; N]; L]; 2],
    shifted_noise: [Field; N],
    d: [[u64; N]; L],
    product: [[Field; N]; L],
) -> pub (Field, Field) {
    let _ = domain;
    secure_share::<N, L, H, T, N_PARTIES, AGGREGATE_BIT, KEY_BITS, SHARE_BIT>(
        setup,
        owner,
        roster,
        expected_sk,
        expected_bundle,
        expected_ct,
        outgoing,
        incoming,
        sk,
        ct,
        shifted_noise,
        d,
        product,
        QIS,
        PROFILE_ID,
        C6_NOISE_BOUND,
    )
}
