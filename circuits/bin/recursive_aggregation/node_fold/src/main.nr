// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Per-node fold: C0, C1, the C2a finalizer, `c3_fold`, and C4a.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::{H, N_PARTIES};
use lib::math::commitments::compute_vk_hash;

pub global C2_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD) + N_PARTIES;
pub global C2_FINALIZED_PUBLIC_LEN: u32 = C2_PUBLIC_LEN + 2;
pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3_FOLD_PUBLIC_LEN: u32 = 6 + (3 * C3_SLOTS) + N_PARTIES;
pub global C3_MSG_START: u32 = 6 + C3_SLOTS;
pub global C3_KEY_START: u32 = 6 + (3 * C3_SLOTS);
pub global C4_PUBLIC_LEN: u32 = (H * L_THRESHOLD) + H + 1;
pub global C2_SECRET_IDX: u32 = 1;
pub global C2_SHARE_START: u32 = 2;
pub global C2_KEY_START: u32 = 2 + (N_PARTIES * L_THRESHOLD);

/// Six public parameters, then the return tuple.
pub global NODE_FOLD_PUBLIC_LEN: u32 =
    12 + (2 * N_PARTIES) + H + ((N_PARTIES + H) * L_THRESHOLD);
pub global NODE_VK_MANIFEST_IDX: u32 = NODE_FOLD_PUBLIC_LEN - 1;

fn main(
    c0_vk: UltraHonkVerificationKey,
    c0_proof: UltraHonkZKProof,
    c0_public: [Field; 1],
    c1_vk: UltraHonkVerificationKey,
    c1_proof: UltraHonkZKProof,
    c1_public: [Field; 2],
    c2_vk: UltraHonkVerificationKey,
    c2_proof: UltraHonkProof,
    c2_public: [Field; C2_FINALIZED_PUBLIC_LEN],
    c3_vk: UltraHonkVerificationKey,
    c3_proof: UltraHonkProof,
    c3_public: [Field; C3_FOLD_PUBLIC_LEN],
    c4_vk: UltraHonkVerificationKey,
    c4_proof: UltraHonkZKProof,
    c4_public: [Field; C4_PUBLIC_LEN],
    party_id: pub Field,
    c0_key_hash: pub Field,
    c1_key_hash: pub Field,
    c2_key_hash: pub Field,
    c3_key_hash: pub Field,
    c4_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, [Field; N_PARTIES], [[Field; L_THRESHOLD]; N_PARTIES], [[Field; L_THRESHOLD]; H], Field, [Field; N_PARTIES], [Field; H], Field) {
    verify_honk_proof(c0_vk, c0_proof, c0_public, c0_key_hash);
    verify_honk_proof(c1_vk, c1_proof, c1_public, c1_key_hash);
    verify_honk_proof_non_zk(c2_vk, c2_proof, c2_public, c2_key_hash);
    verify_honk_proof_non_zk(c3_vk, c3_proof, c3_public, c3_key_hash);
    verify_honk_proof(c4_vk, c4_proof, c4_public, c4_key_hash);

    let key_hash = compute_vk_hash(
        [
            c0_key_hash,
            c1_key_hash,
            c2_key_hash,
            c3_key_hash,
            c4_key_hash,
            c2_public[0],
            c2_public[C2_FINALIZED_PUBLIC_LEN - 1],
            c3_public[0],
            c3_public[4],
        ]
            .as_vector(),
    );
    let c0_pk = c0_public[0];
    let c1_pk = c1_public[1];
    assert(c1_public[0] == c2_public[C2_SECRET_IDX]);

    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            if party_id != (j as Field) {
                let slot = j * L_THRESHOLD + l;
                assert(c2_public[C2_SHARE_START + slot] == c3_public[C3_MSG_START + slot]);
            }
        }
        if party_id != (j as Field) {
            assert(c2_public[C2_KEY_START + j] == c3_public[C3_KEY_START + j]);
        }
    }

    let mut c3_pk: [Field; N_PARTIES] = [0; N_PARTIES];
    for j in 0..N_PARTIES {
        if party_id == (j as Field) {
            c3_pk[j] = c0_pk;
        } else {
            c3_pk[j] = c3_public[6 + j * L_THRESHOLD];
        }
    }

    let mut c2a: [[Field; L_THRESHOLD]; N_PARTIES] = [[0; L_THRESHOLD]; N_PARTIES];
    let mut c2a_keys: [Field; N_PARTIES] = [0; N_PARTIES];
    for j in 0..N_PARTIES {
        for l in 0..L_THRESHOLD {
            c2a[j][l] = c2_public[C2_SHARE_START + j * L_THRESHOLD + l];
        }
        c2a_keys[j] = c2_public[C2_KEY_START + j];
    }

    let mut c4a: [[Field; L_THRESHOLD]; H] = [[0; L_THRESHOLD]; H];
    let mut c4a_keys: [Field; H] = [0; H];
    for h in 0..H {
        for l in 0..L_THRESHOLD {
            c4a[h][l] = c4_public[h * L_THRESHOLD + l];
        }
        c4a_keys[h] = c4_public[(H * L_THRESHOLD) + h];
    }
    let sk_agg = c4_public[C4_PUBLIC_LEN - 1];
    let vk_manifest = key_hash;

    (
        key_hash, c2_public[C2_FINALIZED_PUBLIC_LEN - 1], c0_pk, c1_pk, c3_pk, c2a, c4a, sk_agg,
        c2a_keys, c4a_keys, vk_manifest,
    )
}
