// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Combines C2a + C2b (two ZK Honk proofs) and surfaces their public inputs for `node_fold`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::commitments::compute_vk_hash;

/// C2 inner public IO: `expected_secret_commitment` + `[[Field; L_THRESHOLD]; N_PARTIES]`.
pub global C2_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);

/// Two key-hash params + combined key hash + two C2-sized public vectors (a and b).
pub global C2AB_FOLD_PUBLIC_LEN: u32 = 3 + (2 * C2_PUBLIC_LEN);

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

    let mut vk_hashes = [].as_vector();
    vk_hashes = vk_hashes.push_back(c2a_key_hash);
    vk_hashes = vk_hashes.push_back(c2b_key_hash);
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
