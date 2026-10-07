// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Top-level ct1 (P3), mirroring ct0's split. Proving ct1 in a single circuit does not fit the
//! browser's ~2M gate ceiling at N=16384, L=5, so its work is split by coefficient-level chunking
//! into one merged grid - `u`/`e1`/`p2is`/`p1is` together, 2 chunks - each chunk range-checked
//! independently and combined directly into a root (N_CHUNKS=2 needs no intermediate pair level):
//! `ct1_chunk_main` (leaves, 2 instances) -> `ct1_chunk_main_root` (verifies both leaves
//! directly) + separate `ct1_pk_ct_commit` (commits `pk1is` and `ct1is` together) ->
//! `ct1_chunk_gamma` (verifies `ct1_chunk_main_root` and `ct1_pk_ct_commit`, derives gamma).
//! Round B (`ct1_eval_chunk_*`) mirrors this shape to evaluate every chunk at gamma and sum the
//! partial evaluations, converging on `ct1_eval_chunk_identity` (the actual Schwartz-Zippel
//! identity check).
//!
//! This circuit verifies both final proofs and checks every commitment and batching coefficient
//! they produced agree. It also folds every key hash below it into the VK manifest and outputs
//! the manifest first - see `user_data_encryption_ct0` for why.
//!
//! Outputs: `vk_manifest`, `pk1_commitment`, `ct1_commitment`, `u_root`.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;
use lib::core::threshold::user_data_encryption_chunk::{
    compute_ude_vk_manifest, UDE_ROUND_CHILD_KEY_HASHES,
};

// Both rounds share one output layout: 3 key hashes (root, leaf, pk/ct), `pk1`, `ct1`, `u`, `e1`,
// `p2`, `p1`, `gamma`, then the L batching coefficients.
global ROUND_LEN: u32 = 10 + L;
global PK1: u32 = 3;
global CT1: u32 = 4;
global U: u32 = 5;
global E1: u32 = 6;
global P2: u32 = 7;
global P1: u32 = 8;
global GAMMA: u32 = 9;
global BATCHING: u32 = 10;

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
    assert(a[P2] == b[P2], "p2 root mismatch between rounds");
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
