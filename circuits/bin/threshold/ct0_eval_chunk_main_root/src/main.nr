// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the two `ct0_eval_chunk_main` leaf proofs directly - at N_CHUNKS=2 no intermediate
//! pair level is needed. Both leaves hold raw sensitive witness data, so both are ZK-verified.
//! Checks they agree on `gamma`, computes the five root commitments (for binding against Round
//! A's `ct0_chunk_main_root`), and sums the two chunks' partial evaluations into the full
//! `u_at_gamma`/`k1_at_gamma`/`e0is_at_gamma`/`r2i_at_gamma`/`r1i_at_gamma`. This output feeds
//! directly into `ct0_eval_chunk_identity`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, N, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS};
use lib::core::threshold::user_data_encryption_chunk::ct0_chunk_roots;

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = 2 * CHUNK_SIZE;
global LEAF_LEN: u32 = 9 + (3 * L);

fn main(
    leaf0_vk: UltraHonkVerificationKey,
    leaf0_proof: UltraHonkZKProof,
    leaf0_gamma: Field,
    leaf0_u: Field,
    leaf0_e0: Field,
    leaf0_k1: Field,
    leaf0_r2: Field,
    leaf0_r1: Field,
    leaf0_u_partial: Field,
    leaf0_k1_partial: Field,
    leaf0_e0is_partial: [Field; L],
    leaf0_r2i_partial: [Field; L],
    leaf0_r1i_partial: [Field; L],
    leaf0_key_hash: pub Field,
    leaf1_vk: UltraHonkVerificationKey,
    leaf1_proof: UltraHonkZKProof,
    leaf1_gamma: Field,
    leaf1_u: Field,
    leaf1_e0: Field,
    leaf1_k1: Field,
    leaf1_r2: Field,
    leaf1_r1: Field,
    leaf1_u_partial: Field,
    leaf1_k1_partial: Field,
    leaf1_e0is_partial: [Field; L],
    leaf1_r2i_partial: [Field; L],
    leaf1_r1i_partial: [Field; L],
    leaf1_key_hash: pub Field,
    ) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, [Field; L], [Field; L], [Field; L]) {
    let mut leaf0_inputs: [Field; LEAF_LEN] = [0; LEAF_LEN];
    leaf0_inputs[0] = 0;
    leaf0_inputs[1] = leaf0_gamma;
    leaf0_inputs[2] = leaf0_u;
    leaf0_inputs[3] = leaf0_e0;
    leaf0_inputs[4] = leaf0_k1;
    leaf0_inputs[5] = leaf0_r2;
    leaf0_inputs[6] = leaf0_r1;
    leaf0_inputs[7] = leaf0_u_partial;
    leaf0_inputs[8] = leaf0_k1_partial;
    for i in 0..L {
        leaf0_inputs[9 + i] = leaf0_e0is_partial[i];
        leaf0_inputs[9 + L + i] = leaf0_r2i_partial[i];
        leaf0_inputs[9 + (2 * L) + i] = leaf0_r1i_partial[i];
    }
    verify_honk_proof(leaf0_vk, leaf0_proof, leaf0_inputs, leaf0_key_hash);

    let mut leaf1_inputs: [Field; LEAF_LEN] = [0; LEAF_LEN];
    leaf1_inputs[0] = 1;
    leaf1_inputs[1] = leaf1_gamma;
    leaf1_inputs[2] = leaf1_u;
    leaf1_inputs[3] = leaf1_e0;
    leaf1_inputs[4] = leaf1_k1;
    leaf1_inputs[5] = leaf1_r2;
    leaf1_inputs[6] = leaf1_r1;
    leaf1_inputs[7] = leaf1_u_partial;
    leaf1_inputs[8] = leaf1_k1_partial;
    for i in 0..L {
        leaf1_inputs[9 + i] = leaf1_e0is_partial[i];
        leaf1_inputs[9 + L + i] = leaf1_r2i_partial[i];
        leaf1_inputs[9 + (2 * L) + i] = leaf1_r1i_partial[i];
    }
    verify_honk_proof(leaf1_vk, leaf1_proof, leaf1_inputs, leaf1_key_hash);

    assert(leaf0_gamma == leaf1_gamma, "gamma mismatch");

    let (u_root, e0_root, k1_root, r2_root, r1_root) = ct0_chunk_roots(
        N,
        CHUNK_SIZE,
        R1_CHUNK_SIZE,
        [leaf0_u, leaf1_u],
        [leaf0_e0, leaf1_e0],
        [leaf0_k1, leaf1_k1],
        [leaf0_r2, leaf1_r2],
        [leaf0_r1, leaf1_r1],
    );

    let u_at_gamma = leaf0_u_partial + leaf1_u_partial;
    let k1_at_gamma = leaf0_k1_partial + leaf1_k1_partial;
    let mut e0is_at_gamma: [Field; L] = [0; L];
    let mut r2i_at_gamma: [Field; L] = [0; L];
    let mut r1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        e0is_at_gamma[i] = leaf0_e0is_partial[i] + leaf1_e0is_partial[i];
        r2i_at_gamma[i] = leaf0_r2i_partial[i] + leaf1_r2i_partial[i];
        r1i_at_gamma[i] = leaf0_r1i_partial[i] + leaf1_r1i_partial[i];
    }

    (
        leaf0_gamma, u_root, e0_root, k1_root, r2_root, r1_root, u_at_gamma, k1_at_gamma,
        e0is_at_gamma, r2i_at_gamma, r1i_at_gamma,
    )
}
