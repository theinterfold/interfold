// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk init kernel for C3: verifies the app and appends the app key hash.

use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::chonk::{MegaVerificationKey, PROOF_TYPE_OINK};

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

fn main(
    app_outputs: call_data(1) [Field; 3 * C3_SLOTS + 1],
    app_vk: MegaVerificationKey,
) -> return_data [Field; 3 * C3_SLOTS + 2] {
    std::verify_proof_with_type(app_vk.key, [], [], app_vk.hash, PROOF_TYPE_OINK);
    let mut out = [0; 3 * C3_SLOTS + 2];
    for i in 0..3 * C3_SLOTS + 1 {
        out[i] = app_outputs[i];
    }
    out[3 * C3_SLOTS + 1] = app_vk.hash;
    out
}
