// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Top-level ct0 (P3), chunking-comparison branch: the monolithic `UserDataEncryptionCt0`
//! circuit no longer fits a single browser-side proof at N=16384, L=5, so its work is split by
//! coefficient-level chunking into one merged grid - `u`/`e0`/`k1`/`r2is`/`r1is` together, 2
//! chunks - each chunk range-checked independently and combined through a two-level tree (max 2
//! recursive verifications per circuit): `ct0_chunk_main` (leaves, 2 instances) ->
//! `ct0_chunk_main_root` (verifies both leaves directly, no intermediate pair level) + separate
//! `ct0_pk_ct_commit` (commits `pk0is` and `ct0is` together - never recursive, so no combine
//! step is needed) -> `ct0_chunk_gamma` (verifies `ct0_chunk_main_root` and `ct0_pk_ct_commit`,
//! derives gamma). Round B (`ct0_eval_chunk_*`) mirrors this shape to evaluate every chunk at
//! gamma and sum the partial evaluations, converging on `ct0_eval_chunk_identity` (the actual
//! Schwartz-Zippel identity check).
//!
//! This circuit verifies both final proofs and checks every commitment and batching coefficient
//! they produced agree - closing the binding that stops a prover from range-checking one witness
//! in Round A and evaluating a different, unconstrained one in Round B. Output shape matches the
//! witness-group-split branch's top-level circuit exactly, so the `user_data_encryption` wrapper
//! needs no changes either way.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;

global ROUND_A_LEN: u32 = 9 + L;
global ROUND_B_LEN: u32 = 10 + L;

fn main(
    a_vk: UltraHonkVerificationKey,
    a_proof: UltraHonkProof,
    a_public_inputs: [Field; ROUND_A_LEN],
    a_key_hash: pub Field,
    b_vk: UltraHonkVerificationKey,
    b_proof: UltraHonkProof,
    b_public_inputs: [Field; ROUND_B_LEN],
    b_key_hash: pub Field,
) -> pub (Field, Field, Field, Field) {
    verify_honk_proof_non_zk(a_vk, a_proof, a_public_inputs, a_key_hash);
    verify_honk_proof_non_zk(b_vk, b_proof, b_public_inputs, b_key_hash);

    // Round A (`ct0_chunk_gamma`): 2 key-hash params, then 7 commitments/roots + ct0_gammas[L].
    let a_pk0_commitment = a_public_inputs[2];
    let a_ct0_commitment = a_public_inputs[3];
    let a_k1_root = a_public_inputs[4];
    let a_u_root = a_public_inputs[5];
    let a_e0_root = a_public_inputs[6];
    let a_r2_root = a_public_inputs[7];
    let a_r1_root = a_public_inputs[8];
    let mut a_gammas: [Field; L] = [0; L];
    for i in 0..L {
        a_gammas[i] = a_public_inputs[9 + i];
    }

    // Round B (`ct0_eval_chunk_identity`): 2 key-hash params + batching[L] param, then 8 outputs.
    let mut b_gammas: [Field; L] = [0; L];
    for i in 0..L {
        b_gammas[i] = b_public_inputs[2 + i];
    }
    let b_ret_start = 2 + L;
    let b_pk0_commitment = b_public_inputs[b_ret_start];
    let b_ct0_commitment = b_public_inputs[b_ret_start + 1];
    let b_k1_root = b_public_inputs[b_ret_start + 2];
    let b_u_root = b_public_inputs[b_ret_start + 3];
    let b_e0_root = b_public_inputs[b_ret_start + 4];
    let b_r2_root = b_public_inputs[b_ret_start + 5];
    let b_r1_root = b_public_inputs[b_ret_start + 6];
    let b_gamma = b_public_inputs[b_ret_start + 7];

    assert(a_pk0_commitment == b_pk0_commitment, "pk0_commitment mismatch between rounds");
    assert(a_ct0_commitment == b_ct0_commitment, "ct0_commitment mismatch between rounds");
    assert(a_k1_root == b_k1_root, "k1 root mismatch between rounds");
    assert(a_u_root == b_u_root, "u root mismatch between rounds");
    assert(a_e0_root == b_e0_root, "e0 root mismatch between rounds");
    assert(a_r2_root == b_r2_root, "r2 root mismatch between rounds");
    assert(a_r1_root == b_r1_root, "r1 root mismatch between rounds");
    assert(a_gammas[0] == b_gamma, "gamma mismatch between rounds");
    for i in 0..L {
        assert(a_gammas[i] == b_gammas[i], "batching-coefficient mismatch between rounds");
    }

    (a_pk0_commitment, a_ct0_commitment, a_k1_root, a_u_root)
}
