// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies one C3 Chonk stack's proof and exposes its rows behind the C3 Chonk key list
//! (`lib::math::chonk`): own key, tube key (the same), Chonk key, then the C3 leaf, app, init and
//! tail key hashes the stack's kernels appended. Proven as a rollup proof carrying an IPA claim.

use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::chonk::{C3_CHONK_KEYS, CHONK_PROOF_LENGTH, CHONK_VK_LENGTH, PROOF_TYPE_CHONK};

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

fn main(
    chonk_vk: [Field; CHONK_VK_LENGTH],
    chonk_key_hash: Field,
    proof: [Field; CHONK_PROOF_LENGTH],
    stack_outputs: [Field; 3 * C3_SLOTS + 4],
    own_key_hash: pub Field,
) -> pub ([Field; C3_CHONK_KEYS - 1], [Field; 3 * C3_SLOTS]) {
    std::verify_proof_with_type(
        chonk_vk,
        proof,
        stack_outputs,
        chonk_key_hash,
        PROOF_TYPE_CHONK,
    );

    // The stack appended the leaf, app, init and tail key hashes after its rows.
    let mut keys = [0; C3_CHONK_KEYS - 1];
    keys[0] = own_key_hash;
    keys[1] = chonk_key_hash;
    for k in 0..4 {
        keys[2 + k] = stack_outputs[3 * C3_SLOTS + k];
    }
    let mut rows = [0; 3 * C3_SLOTS];
    for i in 0..3 * C3_SLOTS {
        rows[i] = stack_outputs[i];
    }
    (keys, rows)
}
