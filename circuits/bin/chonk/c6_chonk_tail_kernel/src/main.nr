// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk tail kernel for C6: verifies the init kernel and appends its key hash.

use lib::math::chonk::{C6_CHONK_DATA_LEN, KernelVerificationKey, PROOF_TYPE_HN};

fn main(
    prev_outputs: call_data(0) [Field; C6_CHONK_DATA_LEN + 2],
    kernel_vk: KernelVerificationKey,
) -> return_data [Field; C6_CHONK_DATA_LEN + 3] {
    std::verify_proof_with_type(kernel_vk.key, [], [], kernel_vk.hash, PROOF_TYPE_HN);
    let mut out = [0; C6_CHONK_DATA_LEN + 3];
    for i in 0..C6_CHONK_DATA_LEN + 2 {
        out[i] = prev_outputs[i];
    }
    out[C6_CHONK_DATA_LEN + 2] = kernel_vk.hash;
    out
}
