// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk tail kernel for C3: verifies the init kernel and appends its key hash.

use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::chonk::{MegaVerificationKey, PROOF_TYPE_HN_TAIL};

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

fn main(
    prev_outputs: call_data(0) [Field; 3 * C3_SLOTS + 2],
    kernel_vk: MegaVerificationKey,
) -> return_data [Field; 3 * C3_SLOTS + 3] {
    std::verify_proof_with_type(kernel_vk.key, [], [], kernel_vk.hash, PROOF_TYPE_HN_TAIL);
    let mut out = [0; 3 * C3_SLOTS + 3];
    for i in 0..3 * C3_SLOTS + 2 {
        out[i] = prev_outputs[i];
    }
    out[3 * C3_SLOTS + 2] = kernel_vk.hash;
    out
}
