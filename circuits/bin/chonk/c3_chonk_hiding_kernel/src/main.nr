// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk hiding kernel for C3: verifies the tail kernel, appends its key hash and makes the rows
//! and the four key hashes the stack's public outputs.

use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::chonk::{MegaVerificationKey, PROOF_TYPE_HN_FINAL};

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

fn main(
    prev_outputs: call_data(0) [Field; 3 * C3_SLOTS + 3],
    kernel_vk: MegaVerificationKey,
) -> pub [Field; 3 * C3_SLOTS + 4] {
    std::verify_proof_with_type(kernel_vk.key, [], [], kernel_vk.hash, PROOF_TYPE_HN_FINAL);
    let mut out = [0; 3 * C3_SLOTS + 4];
    for i in 0..3 * C3_SLOTS + 3 {
        out[i] = prev_outputs[i];
    }
    out[3 * C3_SLOTS + 3] = kernel_vk.hash;
    out
}
