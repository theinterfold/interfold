// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Top-level ct1 (P3). Same five-proof shape as `user_data_encryption_ct0_chunked`, over ct1's
//! witness (`u`/`e1`/`p1is`): the leaf, `ct1_pk_ct_commit`, `ct1_eval_pk_ct`,
//! `ct1_eval_chunk_identity`, and this circuit, which verifies the identity and ciphertext proofs,
//! requires the ciphertext circuit's commitment and challenge to be the leaf's, checks the batched
//! identity `sum_i b_i * ct1[i](gamma) == rhs`, and folds the leg's key hashes into its VK
//! manifest.
//!
//! Outputs: `vk_manifest`, `pk1_commitment`, `ct1_commitment`, `u_root`.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::threshold::L;
use lib::core::threshold::user_data_encryption_chunk::compute_ude_vk_manifest;

// Identity outputs: leaf and pk key hashes, pk1 and ct1 commitments, u/e1/p1 roots, gamma,
// batching[L], the batched right-hand side.
global IDENTITY_LEN: u32 = 9 + L;
global LEAF_KEY_HASH: u32 = 0;
global PK_KEY_HASH: u32 = 1;
global PK1: u32 = 2;
global CT1: u32 = 3;
global U: u32 = 4;
global GAMMA: u32 = 7;
global BATCHING: u32 = 8;
global RHS: u32 = 8 + L;
// Ciphertext circuit public inputs: gamma, ct1 commitment, ct1(gamma)[L].
global CT_LEN: u32 = 2 + L;

fn main(
    identity_vk: UltraHonkVerificationKey,
    identity_key_hash: Field,
    identity_proof: UltraHonkProof,
    identity_public_inputs: [Field; IDENTITY_LEN],
    ct_vk: UltraHonkVerificationKey,
    ct_key_hash: Field,
    ct_proof: UltraHonkZKProof,
    ct_public_inputs: [Field; CT_LEN],
) -> pub (Field, Field, Field, Field) {
    verify_honk_proof_non_zk(
        identity_vk,
        identity_proof,
        identity_public_inputs,
        identity_key_hash,
    );
    verify_honk_proof(ct_vk, ct_proof, ct_public_inputs, ct_key_hash);

    let id = identity_public_inputs;
    assert(ct_public_inputs[0] == id[GAMMA], "gamma mismatch between leaf and ciphertext");
    assert(ct_public_inputs[1] == id[CT1], "ct1_commitment mismatch between leaf and ciphertext");

    let mut lhs = 0;
    for i in 0..L {
        lhs += ct_public_inputs[2 + i] * id[BATCHING + i];
    }
    assert(lhs == id[RHS], "ct1 encryption check failed");

    let vk_manifest = compute_ude_vk_manifest(
        identity_key_hash,
        id[LEAF_KEY_HASH],
        id[PK_KEY_HASH],
        ct_key_hash,
    );

    (vk_manifest, id[PK1], id[CT1], id[U])
}
