// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Accumulates two C3 Chonk rollup proofs into one: the left is a tube or an earlier step of this
//! circuit, the right a tube. Both IPA claims merge into this proof's claim, and `c3ab_fold`
//! closes it. Exposes the C3 Chonk key list (`lib::math::chonk`) and the merged rows.
//!
//! Each child is verified under its own key. A tube's own key is its tube key; this step's own key
//! is a public input, so the step above (or `c3ab_fold`) checks it. Every other key must match on
//! both sides, and `c3ab_fold` pins the list against the anchored VK tree.

use bb_proof_verification::{RollupHonkProof, RollupHonkVerificationKey, verify_rolluphonk_proof};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::chonk::{C3_CHONK_KEYS, C3_CHONK_OWN_KEY, C3_CHONK_TUBE_KEY, merge_rows};

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3_CHONK_PUBLIC_LEN: u32 = C3_CHONK_KEYS + 3 * C3_SLOTS;

fn main(
    left_vk: RollupHonkVerificationKey,
    left_proof: RollupHonkProof,
    left_public: [Field; C3_CHONK_PUBLIC_LEN],
    right_vk: RollupHonkVerificationKey,
    right_proof: RollupHonkProof,
    right_public: [Field; C3_CHONK_PUBLIC_LEN],
    own_key_hash: pub Field,
) -> pub ([Field; C3_CHONK_KEYS - 1], [Field; 3 * C3_SLOTS]) {
    let right_key = right_public[C3_CHONK_OWN_KEY];
    assert(right_key == right_public[C3_CHONK_TUBE_KEY], "the right child must be a tube");
    verify_rolluphonk_proof(right_vk, right_proof, right_public, right_key);

    let left_key = left_public[C3_CHONK_OWN_KEY];
    assert(
        (left_key == left_public[C3_CHONK_TUBE_KEY]) | (left_key == own_key_hash),
        "the left child must be a tube or this accumulator",
    );
    verify_rolluphonk_proof(left_vk, left_proof, left_public, left_key);

    let mut keys = [0; C3_CHONK_KEYS - 1];
    keys[0] = right_public[C3_CHONK_TUBE_KEY];
    for k in 1..C3_CHONK_KEYS {
        assert(left_public[k] == right_public[k], "both children must use the same keys");
        if k > 1 {
            keys[k - 1] = right_public[k];
        }
    }

    let mut left_rows = [0; 3 * C3_SLOTS];
    let mut right_rows = [0; 3 * C3_SLOTS];
    for i in 0..3 * C3_SLOTS {
        left_rows[i] = left_public[C3_CHONK_KEYS + i];
        right_rows[i] = right_public[C3_CHONK_KEYS + i];
    }
    (keys, merge_rows(left_rows, right_rows))
}
