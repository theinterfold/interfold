// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk hiding kernel for C6: verifies the tail kernel, appends its key hash and ends the stack.

use lib::math::chonk::{C6_CHONK_DATA_LEN, MegaVerificationKey, PROOF_TYPE_HN_FINAL};

fn main(
    prev_outputs: call_data(0) [Field; C6_CHONK_DATA_LEN + 3],
    kernel_vk: MegaVerificationKey,
) -> pub [Field; C6_CHONK_DATA_LEN + 4] {
    std::verify_proof_with_type(kernel_vk.key, [], [], kernel_vk.hash, PROOF_TYPE_HN_FINAL);
    let mut out = [0; C6_CHONK_DATA_LEN + 4];
    for i in 0..C6_CHONK_DATA_LEN + 3 {
        out[i] = prev_outputs[i];
    }
    out[C6_CHONK_DATA_LEN + 3] = kernel_vk.hash;
    out
}
