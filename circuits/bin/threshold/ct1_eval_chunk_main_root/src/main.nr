// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies the two `ct1_eval_chunk_main` leaf proofs directly
//! (N_CHUNKS=2 - no intermediate pair level needed). Both leaves hold raw sensitive witness data,
//! so both are ZK-verified. Checks they agree on `gamma`, computes the three root commitments
//! (for binding against Round A's `ct1_chunk_main_root`), and sums the two chunks' partial
//! evaluations into the full `u_at_gamma`/`e1_at_gamma`/`p2i_at_gamma`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, N, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS};
use lib::math::commitments::{
    compute_ude_chunk_root_commitment, UDE_KIND_CT1_E1, UDE_KIND_CT1_P2, UDE_KIND_CT1_U,
};

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global LEAF_LEN: u32 = 7 + L;

fn main(
    leaf0_vk: UltraHonkVerificationKey,
    leaf0_proof: UltraHonkZKProof,
    leaf0_gamma: Field,
    leaf0_u: Field,
    leaf0_e1: Field,
    leaf0_p2: Field,
    leaf0_u_partial: Field,
    leaf0_e1_partial: Field,
    leaf0_p2i_partial: [Field; L],
    leaf0_key_hash: pub Field,
    leaf1_vk: UltraHonkVerificationKey,
    leaf1_proof: UltraHonkZKProof,
    leaf1_gamma: Field,
    leaf1_u: Field,
    leaf1_e1: Field,
    leaf1_p2: Field,
    leaf1_u_partial: Field,
    leaf1_e1_partial: Field,
    leaf1_p2i_partial: [Field; L],
    leaf1_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; L]) {
    let mut leaf0_inputs: [Field; LEAF_LEN] = [0; LEAF_LEN];
    leaf0_inputs[0] = 0;
    leaf0_inputs[1] = leaf0_gamma;
    leaf0_inputs[2] = leaf0_u;
    leaf0_inputs[3] = leaf0_e1;
    leaf0_inputs[4] = leaf0_p2;
    leaf0_inputs[5] = leaf0_u_partial;
    leaf0_inputs[6] = leaf0_e1_partial;
    for i in 0..L {
        leaf0_inputs[7 + i] = leaf0_p2i_partial[i];
    }
    verify_honk_proof(leaf0_vk, leaf0_proof, leaf0_inputs, leaf0_key_hash);

    let mut leaf1_inputs: [Field; LEAF_LEN] = [0; LEAF_LEN];
    leaf1_inputs[0] = 1;
    leaf1_inputs[1] = leaf1_gamma;
    leaf1_inputs[2] = leaf1_u;
    leaf1_inputs[3] = leaf1_e1;
    leaf1_inputs[4] = leaf1_p2;
    leaf1_inputs[5] = leaf1_u_partial;
    leaf1_inputs[6] = leaf1_e1_partial;
    for i in 0..L {
        leaf1_inputs[7 + i] = leaf1_p2i_partial[i];
    }
    verify_honk_proof(leaf1_vk, leaf1_proof, leaf1_inputs, leaf1_key_hash);

    assert(leaf0_gamma == leaf1_gamma, "gamma mismatch");

    let u_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT1_U, N, CHUNK_SIZE, [leaf0_u, leaf1_u]);
    let e1_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT1_E1, N, CHUNK_SIZE, [leaf0_e1, leaf1_e1]);
    let p2_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT1_P2, N, CHUNK_SIZE, [leaf0_p2, leaf1_p2]);

    let u_at_gamma = leaf0_u_partial + leaf1_u_partial;
    let e1_at_gamma = leaf0_e1_partial + leaf1_e1_partial;
    let mut p2i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        p2i_at_gamma[i] = leaf0_p2i_partial[i] + leaf1_p2i_partial[i];
    }

    (leaf0_gamma, u_root, e1_root, p2_root, u_at_gamma, e1_at_gamma, p2i_at_gamma)
}
