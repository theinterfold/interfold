// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::synchronized::sync_insecure_64::{H, L_THRESHOLD as L, N, N_PARTIES};
use lib::core::synchronized::threshold_decryption::execute;

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
    shifted_noise: [u64; N],
    d: [[u64; N]; L],
) -> pub (Field, Field) {
    // E3 authority is a separate public binding; never absorb it into the upstream PRF.
    let _ = domain;
    execute(
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
    )
}
