// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Combines C2a + C2b (two ZK Honk proofs) and surfaces their public inputs for `node_fold`.
//!
//! Each C2 is the final circuit of a chunk chain and exposes the hash of its batch and chunk keys
//! last. That hash enters this fold's key hash next to the C2 key, so the VK tree covers every
//! circuit of the chain. The outputs keep the unchunked C2 layout `node_fold` reads.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::commitments::compute_vk_hash;

/// C2 public IO: `expected_secret_commitment` + `[[Field; L_THRESHOLD]; N_PARTIES]` + the chain's
/// key tree.
pub global C2_PUBLIC_LEN: u32 = 2 + (N_PARTIES * L_THRESHOLD);
pub global C2_KEY_TREE_IDX: u32 = C2_PUBLIC_LEN - 1;

fn main(
    c2a_vk: UltraHonkVerificationKey,
    c2a_proof: UltraHonkZKProof,
    c2a_public: [Field; C2_PUBLIC_LEN],
    c2b_vk: UltraHonkVerificationKey,
    c2b_proof: UltraHonkZKProof,
    c2b_public: [Field; C2_PUBLIC_LEN],
    c2a_key_hash: pub Field,
    c2b_key_hash: pub Field,
    ) -> pub (Field, Field, [[Field; L_THRESHOLD]; N_PARTIES], Field, [[Field; L_THRESHOLD]; N_PARTIES]) {
    verify_honk_proof(c2a_vk, c2a_proof, c2a_public, c2a_key_hash);
    verify_honk_proof(c2b_vk, c2b_proof, c2b_public, c2b_key_hash);

    let vk_hashes = [
        c2a_key_hash,
        c2a_public[C2_KEY_TREE_IDX],
        c2b_key_hash,
        c2b_public[C2_KEY_TREE_IDX],
    ]
        .as_vector();
    let key_hash = compute_vk_hash(vk_hashes);

    let c2a_expected = c2a_public[0];
    let mut c2a_shares: [[Field; L_THRESHOLD]; N_PARTIES] = [[0; L_THRESHOLD]; N_PARTIES];
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            c2a_shares[j][l] = c2a_public[1 + j * L_THRESHOLD + l];
        }
    }

    let c2b_expected = c2b_public[0];
    let mut c2b_shares: [[Field; L_THRESHOLD]; N_PARTIES] = [[0; L_THRESHOLD]; N_PARTIES];
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            c2b_shares[j][l] = c2b_public[1 + j * L_THRESHOLD + l];
        }
    }

    (key_hash, c2a_expected, c2a_shares, c2b_expected, c2b_shares)
}
