// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Top-level ct1 (P3). Same two-round shape as `user_data_encryption_ct0_chunked`, over ct1's
//! witness (`u`/`e1`/`p1is`): `ct1_chunk_main` and `ct1_pk_ct_commit` feed `ct1_chunk_gamma`;
//! `ct1_eval_chunk_main` and `ct1_eval_pk_ct` feed `ct1_eval_chunk_identity`, which checks the
//! identity reduced modulo `X^N + 1`.
//!
//! This circuit verifies both round proofs, checks their commitments, gamma and batching
//! coefficients agree, and folds the four child key hashes and its own two into the leg's VK
//! manifest (see `user_data_encryption_ct0_chunked`).
//!
//! Outputs: `vk_manifest`, `pk1_commitment`, `ct1_commitment`, `u_root`.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;
use lib::core::threshold::user_data_encryption_chunk::{
    compute_ude_vk_manifest, UDE_ROUND_CHILD_KEY_HASHES,
};

// Both rounds share one output layout: leaf and pk/ct key hashes, pk1 and ct1 commitments, u/e1/p1 roots, gamma, then
// the batching coefficients.
global ROUND_LEN: u32 = 8 + L;
global PK1: u32 = 2;
global CT1: u32 = 3;
global U: u32 = 4;
global E1: u32 = 5;
global P1: u32 = 6;
global GAMMA: u32 = 7;
global BATCHING: u32 = 8;

fn main(
    a_vk: UltraHonkVerificationKey,
    a_key_hash: Field,
    a_proof: UltraHonkProof,
    a_public_inputs: [Field; ROUND_LEN],
    b_vk: UltraHonkVerificationKey,
    b_key_hash: Field,
    b_proof: UltraHonkProof,
    b_public_inputs: [Field; ROUND_LEN],
) -> pub (Field, Field, Field, Field) {
    verify_honk_proof_non_zk(a_vk, a_proof, a_public_inputs, a_key_hash);
    verify_honk_proof_non_zk(b_vk, b_proof, b_public_inputs, b_key_hash);

    let a = a_public_inputs;
    let b = b_public_inputs;

    assert(a[PK1] == b[PK1], "pk1_commitment mismatch between rounds");
    assert(a[CT1] == b[CT1], "ct1_commitment mismatch between rounds");
    assert(a[U] == b[U], "u root mismatch between rounds");
    assert(a[E1] == b[E1], "e1 root mismatch between rounds");
    assert(a[P1] == b[P1], "p1 root mismatch between rounds");
    assert(a[GAMMA] == b[GAMMA], "gamma mismatch between rounds");
    for i in 0..L {
        assert(a[BATCHING + i] == b[BATCHING + i], "batching-coefficient mismatch between rounds");
    }

    let mut a_children: [Field; UDE_ROUND_CHILD_KEY_HASHES] = [0; UDE_ROUND_CHILD_KEY_HASHES];
    let mut b_children: [Field; UDE_ROUND_CHILD_KEY_HASHES] = [0; UDE_ROUND_CHILD_KEY_HASHES];
    for i in 0..UDE_ROUND_CHILD_KEY_HASHES {
        a_children[i] = a[i];
        b_children[i] = b[i];
    }
    let vk_manifest = compute_ude_vk_manifest(a_key_hash, a_children, b_key_hash, b_children);

    (vk_manifest, a[PK1], a[CT1], a[U])
}
