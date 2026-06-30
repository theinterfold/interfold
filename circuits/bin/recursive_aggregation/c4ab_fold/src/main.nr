// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Combines C4a + C4b (two ZK Honk proofs using the same C4 binary).

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::H;
use lib::math::commitments::compute_vk_hash;

/// C4 public IO: `expected_commitments` (flattened) + `agg_commit`.
pub global C4_PUBLIC_LEN: u32 = (H * L_THRESHOLD) + 1;

/// Two key-hash params + combined key hash + two C4-sized public vectors (a and b).
pub global C4AB_FOLD_PUBLIC_LEN: u32 = 3 + (2 * C4_PUBLIC_LEN);

fn main(
    c4a_vk: UltraHonkVerificationKey,
    c4a_proof: UltraHonkZKProof,
    c4a_public: [Field; C4_PUBLIC_LEN],
    c4b_vk: UltraHonkVerificationKey,
    c4b_proof: UltraHonkZKProof,
    c4b_public: [Field; C4_PUBLIC_LEN],
    c4a_key_hash: pub Field,
    c4b_key_hash: pub Field,
) -> pub (Field, [[Field; L_THRESHOLD]; H], Field, [[Field; L_THRESHOLD]; H], Field) {
    verify_honk_proof(c4a_vk, c4a_proof, c4a_public, c4a_key_hash);
    verify_honk_proof(c4b_vk, c4b_proof, c4b_public, c4b_key_hash);

    let mut vk_hashes = [].as_vector();
    vk_hashes = vk_hashes.push_back(c4a_key_hash);
    vk_hashes = vk_hashes.push_back(c4b_key_hash);
    let key_hash = compute_vk_hash(vk_hashes);

    let mut c4a_expected: [[Field; L_THRESHOLD]; H] = [[0; L_THRESHOLD]; H];
    for h in 0..H {
        for l in 0..L_THRESHOLD {
            c4a_expected[h][l] = c4a_public[h * L_THRESHOLD + l];
        }
    }
    let sk_agg = c4a_public[H * L_THRESHOLD];

    let mut c4b_expected: [[Field; L_THRESHOLD]; H] = [[0; L_THRESHOLD]; H];
    for h in 0..H {
        for l in 0..L_THRESHOLD {
            c4b_expected[h][l] = c4b_public[h * L_THRESHOLD + l];
        }
    }
    let esm_agg = c4b_public[H * L_THRESHOLD];

    (key_hash, c4a_expected, sk_agg, c4b_expected, esm_agg)
}
