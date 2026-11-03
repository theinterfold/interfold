// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Closes the C6 Chonk tube's IPA claim as a root rollup and re-exposes its data behind one hash of
//! its seven key hashes (tube, tube, Chonk, C6 leaf, app, init, tail). The decryption aggregator
//! verifies this proof and binds that hash, with this circuit's key, to the anchored C6 tree.

use bb_proof_verification::{
    RollupHonkProof, RollupHonkVerificationKey, verify_root_rolluphonk_proof,
};
use lib::math::chonk::{C3_CHONK_KEYS, C3_CHONK_OWN_KEY, C6_CHONK_DATA_LEN};
use lib::math::commitments::compute_vk_hash;

pub global C6_TUBE_PUBLIC_LEN: u32 = C3_CHONK_KEYS + C6_CHONK_DATA_LEN;

/// A root rollup closes exactly two IPA claims and a C6 column has one tube, so the prover passes
/// the tube twice. Both inputs verify under the tube's own key; only the first gives the statement,
/// and the root's final IPA check fails unless both accumulated claims are valid.
fn main(
    tube_vk: RollupHonkVerificationKey,
    tube_proofs: [RollupHonkProof; 2],
    tube_publics: [[Field; C6_TUBE_PUBLIC_LEN]; 2],
) -> pub (Field, [Field; C6_CHONK_DATA_LEN]) {
    let tube_key = tube_publics[0][C3_CHONK_OWN_KEY];
    assert(tube_publics[1][C3_CHONK_OWN_KEY] == tube_key, "both inputs must be tube proofs");
    for k in 0..2 {
        verify_root_rolluphonk_proof(tube_vk, tube_proofs[k], tube_publics[k], tube_key);
    }
    // The tube's own key opens its public inputs, so the key list hash covers it.
    let mut keys = [0; C3_CHONK_KEYS];
    for k in 0..C3_CHONK_KEYS {
        keys[k] = tube_publics[0][k];
    }
    let mut data = [0; C6_CHONK_DATA_LEN];
    for i in 0..C6_CHONK_DATA_LEN {
        data[i] = tube_publics[0][C3_CHONK_KEYS + i];
    }
    (compute_vk_hash(keys.as_vector()), data)
}
