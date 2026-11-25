// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the C6 Chonk stack's proof and exposes its data behind the Chonk key list
//! (`lib::math::chonk`): own key, tube key (the same), Chonk key, then the C6 leaf, app, init and
//! tail key hashes the stack's kernels appended. Proven as a rollup proof carrying an IPA claim.

use lib::math::chonk::{
    C3_CHONK_KEYS, C6_CHONK_DATA_LEN, CHONK_PROOF_LENGTH, CHONK_VK_LENGTH, PROOF_TYPE_CHONK,
};

fn main(
    chonk_vk: [Field; CHONK_VK_LENGTH],
    chonk_key_hash: Field,
    proof: [Field; CHONK_PROOF_LENGTH],
    stack_outputs: [Field; C6_CHONK_DATA_LEN + 4],
    own_key_hash: pub Field,
) -> pub ([Field; C3_CHONK_KEYS - 1], [Field; C6_CHONK_DATA_LEN]) {
    std::verify_proof_with_type(
        chonk_vk,
        proof,
        stack_outputs,
        chonk_key_hash,
        PROOF_TYPE_CHONK,
    );

    // The stack appended the leaf, app, init and tail key hashes after its data.
    let mut keys = [0; C3_CHONK_KEYS - 1];
    keys[0] = own_key_hash;
    keys[1] = chonk_key_hash;
    for k in 0..4 {
        keys[2 + k] = stack_outputs[C6_CHONK_DATA_LEN + k];
    }
    let mut data = [0; C6_CHONK_DATA_LEN];
    for i in 0..C6_CHONK_DATA_LEN {
        data[i] = stack_outputs[i];
    }
    (keys, data)
}
