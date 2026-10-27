// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk init kernel for C6: verifies the app and appends the app key hash.

use lib::math::chonk::{AppVerificationKey, C6_CHONK_DATA_LEN, PROOF_TYPE_OINK};

fn main(
    app_outputs: call_data(1) [Field; C6_CHONK_DATA_LEN + 1],
    app_vk: AppVerificationKey,
) -> return_data [Field; C6_CHONK_DATA_LEN + 2] {
    std::verify_proof_with_type(app_vk.key, [], [], app_vk.hash, PROOF_TYPE_OINK);
    let mut out = [0; C6_CHONK_DATA_LEN + 2];
    for i in 0..C6_CHONK_DATA_LEN + 1 {
        out[i] = app_outputs[i];
    }
    out[C6_CHONK_DATA_LEN + 1] = app_vk.hash;
    out
}
