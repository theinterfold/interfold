// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::compute_vk_hash;

/// Keep the leaf, fold, and genesis VK hashes constant throughout a sequential fold.
pub fn predecessor_key_hash(
    inner_key_hash: Field,
    fold_key_hash: Field,
    kernel_key_hash: Field,
    is_first_step: bool,
    prior_keys: [Field; 3],
) -> Field {
    assert(prior_keys == [inner_key_hash, fold_key_hash, kernel_key_hash]);
    if is_first_step {
        kernel_key_hash
    } else {
        fold_key_hash
    }
}

/// Commit to the ordered fold, genesis, and leaf verification keys.
pub fn sequential_fold_vk_hash(
    fold_key_hash: Field,
    kernel_key_hash: Field,
    inner_key_hash: Field,
) -> Field {
    compute_vk_hash([fold_key_hash, kernel_key_hash, inner_key_hash].as_vector())
}

#[test]
fn genesis_and_continuation_select_the_expected_key() {
    assert(predecessor_key_hash(11, 22, 33, true, [11, 22, 33]) == 33);
    assert(predecessor_key_hash(11, 22, 33, false, [11, 22, 33]) == 22);
}

#[test(should_fail)]
fn a_different_leaf_key_is_rejected() {
    let _ = predecessor_key_hash(44, 22, 33, false, [11, 22, 33]);
}

#[test(should_fail)]
fn a_different_fold_key_is_rejected() {
    let _ = predecessor_key_hash(11, 44, 33, false, [11, 22, 33]);
}

#[test(should_fail)]
fn a_different_genesis_key_is_rejected() {
    let _ = predecessor_key_hash(11, 22, 44, false, [11, 22, 33]);
}
