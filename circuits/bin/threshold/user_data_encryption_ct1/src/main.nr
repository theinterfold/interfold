// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Top-level ct1 (P3), chunking-comparison branch: mirrors ct0's split - the monolithic
//! `UserDataEncryptionCt1` circuit no longer fits a single browser-side proof at N=16384, L=5,
//! so its work is split by coefficient-level chunking - `u`/`e1`/`p2is` (main grid, 2 chunks)
//! and `p1is` (p1 grid, 2 chunks), each chunk range-checked independently and combined directly
//! into a root (N_CHUNKS=2 needs no intermediate pair/quad level): `ct1_chunk_main`/`ct1_chunk_p1`
//! (leaves) -> `ct1_chunk_main_root`/`ct1_chunk_p1_root` -> `ct1_chunk_combine_roots` +
//! `ct1_chunk_pk_ct_combine` -> `ct1_chunk_gamma` (derives gamma). Round B (`ct1_eval_chunk_*`)
//! mirrors this shape to evaluate every chunk at gamma and sum the partial evaluations,
//! converging on `ct1_eval_chunk_identity` (the actual Schwartz-Zippel identity check).
//!
//! This circuit verifies both final proofs and checks every commitment and batching coefficient
//! they produced agree. Output shape matches the witness-group-split branch's top-level circuit
//! exactly, so the `user_data_encryption` wrapper needs no changes either way.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;

global ROUND_LEN: u32 = 9 + L;

fn main(
    a_vk: UltraHonkVerificationKey,
    a_proof: UltraHonkProof,
    a_public_inputs: [Field; ROUND_LEN],
    a_key_hash: pub Field,
    b_vk: UltraHonkVerificationKey,
    b_proof: UltraHonkProof,
    b_public_inputs: [Field; ROUND_LEN],
    b_key_hash: pub Field,
) -> pub (Field, Field, Field) {
    verify_honk_proof_non_zk(a_vk, a_proof, a_public_inputs, a_key_hash);
    verify_honk_proof_non_zk(b_vk, b_proof, b_public_inputs, b_key_hash);

    // Round A (`ct1_chunk_gamma`): 2 key-hash params, then 6 commitments/roots + gamma + batching[L].
    let a_pk1_commitment = a_public_inputs[2];
    let a_ct1_commitment = a_public_inputs[3];
    let a_u_root = a_public_inputs[4];
    let a_e1_root = a_public_inputs[5];
    let a_p2_root = a_public_inputs[6];
    let a_p1_root = a_public_inputs[7];
    let a_gamma = a_public_inputs[8];
    let mut a_batching: [Field; L] = [0; L];
    for i in 0..L {
        a_batching[i] = a_public_inputs[9 + i];
    }

    // Round B (`ct1_eval_chunk_identity`): 2 key-hash params + batching[L] param, then 7 outputs.
    let mut b_batching: [Field; L] = [0; L];
    for i in 0..L {
        b_batching[i] = b_public_inputs[2 + i];
    }
    let b_ret_start = 2 + L;
    let b_pk1_commitment = b_public_inputs[b_ret_start];
    let b_ct1_commitment = b_public_inputs[b_ret_start + 1];
    let b_u_root = b_public_inputs[b_ret_start + 2];
    let b_e1_root = b_public_inputs[b_ret_start + 3];
    let b_p2_root = b_public_inputs[b_ret_start + 4];
    let b_p1_root = b_public_inputs[b_ret_start + 5];
    let b_gamma = b_public_inputs[b_ret_start + 6];

    assert(a_pk1_commitment == b_pk1_commitment, "pk1_commitment mismatch between rounds");
    assert(a_ct1_commitment == b_ct1_commitment, "ct1_commitment mismatch between rounds");
    assert(a_u_root == b_u_root, "u root mismatch between rounds");
    assert(a_e1_root == b_e1_root, "e1 root mismatch between rounds");
    assert(a_p2_root == b_p2_root, "p2 root mismatch between rounds");
    assert(a_p1_root == b_p1_root, "p1 root mismatch between rounds");
    assert(a_gamma == b_gamma, "gamma mismatch between rounds");
    for i in 0..L {
        assert(a_batching[i] == b_batching[i], "batching-coefficient mismatch between rounds");
    }

    (a_pk1_commitment, a_ct1_commitment, a_u_root)
}
