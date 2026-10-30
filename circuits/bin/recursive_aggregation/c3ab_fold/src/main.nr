// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Combines the final C3 Chonk accumulator of the sk C3 chain with that of the e_sm chain and
//! closes both IPA claims (`lib::math::chonk`). Keeps the unchunked `c3ab_fold` output layout.
//!
//! Each chain's key list (accumulator, tube, Chonk, C3 leaf, app, init and tail keys) enters the
//! combined key hash, which `node_fold` binds into the VK tree. A chain built from any other
//! circuits, or ending on a bare tube, gives a different hash and is rejected at the anchor.

use bb_proof_verification::{
    RollupHonkProof, RollupHonkVerificationKey, verify_root_rolluphonk_proof,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::chonk::{C3_CHONK_KEYS, C3_CHONK_OWN_KEY};
use lib::math::commitments::compute_vk_hash;

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

/// A final C3 Chonk accumulator: the key list, then the rows.
pub global C3_CHONK_PUBLIC_LEN: u32 = C3_CHONK_KEYS + 3 * C3_SLOTS;

/// Total public fields for `c3ab_fold` (two key hashes + flattened return tuple).
pub global C3AB_FOLD_PUBLIC_LEN: u32 = 2 + 1 + (6 * C3_SLOTS);

fn chain_key_hash(public: [Field; C3_CHONK_PUBLIC_LEN]) -> Field {
    let mut keys = [0; C3_CHONK_KEYS];
    for k in 0..C3_CHONK_KEYS {
        keys[k] = public[k];
    }
    compute_vk_hash(keys.as_vector())
}

fn main(
    c3a_vk: RollupHonkVerificationKey,
    c3a_proof: RollupHonkProof,
    c3a_public: [Field; C3_CHONK_PUBLIC_LEN],
    c3b_vk: RollupHonkVerificationKey,
    c3b_proof: RollupHonkProof,
    c3b_public: [Field; C3_CHONK_PUBLIC_LEN],
    c3a_key_hash: pub Field,
    c3b_key_hash: pub Field,
    ) -> pub (Field, [Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    assert(c3a_public[C3_CHONK_OWN_KEY] == c3a_key_hash);
    assert(c3b_public[C3_CHONK_OWN_KEY] == c3b_key_hash);
    verify_root_rolluphonk_proof(c3a_vk, c3a_proof, c3a_public, c3a_key_hash);
    verify_root_rolluphonk_proof(c3b_vk, c3b_proof, c3b_public, c3b_key_hash);

    let key_hash = compute_vk_hash([chain_key_hash(c3a_public), chain_key_hash(c3b_public)]
        .as_vector());

    let mut pk_a: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut msg_a: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut ct_a: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut pk_b: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut msg_b: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut ct_b: [Field; C3_SLOTS] = [0; C3_SLOTS];

    for j in 0..C3_SLOTS {
        pk_a[j] = c3a_public[C3_CHONK_KEYS + j];
        msg_a[j] = c3a_public[C3_CHONK_KEYS + C3_SLOTS + j];
        ct_a[j] = c3a_public[C3_CHONK_KEYS + 2 * C3_SLOTS + j];
        pk_b[j] = c3b_public[C3_CHONK_KEYS + j];
        msg_b[j] = c3b_public[C3_CHONK_KEYS + C3_SLOTS + j];
        ct_b[j] = c3b_public[C3_CHONK_KEYS + 2 * C3_SLOTS + j];
    }

    (key_hash, pk_a, msg_a, ct_a, pk_b, msg_b, ct_b)
}
