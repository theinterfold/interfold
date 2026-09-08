// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies the two `ct0_eval_chunk_r1` leaf proofs directly
//! (R1_N_CHUNKS=2 - no intermediate pair/quad level needed). Both leaves hold raw sensitive
//! witness data, so both are ZK-verified. Checks they agree on `gamma`, computes the r1 grid's
//! root commitment (for binding against Round A's `ct0_chunk_r1_root`), and sums the two chunks'
//! partial evaluations into the full `r1i_at_gamma`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, N, USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS};
use lib::math::commitments::{compute_ude_chunk_root_commitment, UDE_KIND_CT0_R1};

global CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;
global LEAF_LEN: u32 = 3 + L;

fn main(
    leaf0_vk: UltraHonkVerificationKey,
    leaf0_proof: UltraHonkZKProof,
    leaf0_gamma: Field,
    leaf0_commit: Field,
    leaf0_partial: [Field; L],
    leaf0_key_hash: pub Field,
    leaf1_vk: UltraHonkVerificationKey,
    leaf1_proof: UltraHonkZKProof,
    leaf1_gamma: Field,
    leaf1_commit: Field,
    leaf1_partial: [Field; L],
    leaf1_key_hash: pub Field,
) -> pub (Field, Field, [Field; L]) {
    let mut leaf0_inputs: [Field; LEAF_LEN] = [0; LEAF_LEN];
    leaf0_inputs[0] = 0;
    leaf0_inputs[1] = leaf0_gamma;
    leaf0_inputs[2] = leaf0_commit;
    for i in 0..L {
        leaf0_inputs[3 + i] = leaf0_partial[i];
    }
    verify_honk_proof(leaf0_vk, leaf0_proof, leaf0_inputs, leaf0_key_hash);

    let mut leaf1_inputs: [Field; LEAF_LEN] = [0; LEAF_LEN];
    leaf1_inputs[0] = 1;
    leaf1_inputs[1] = leaf1_gamma;
    leaf1_inputs[2] = leaf1_commit;
    for i in 0..L {
        leaf1_inputs[3 + i] = leaf1_partial[i];
    }
    verify_honk_proof(leaf1_vk, leaf1_proof, leaf1_inputs, leaf1_key_hash);

    assert(leaf0_gamma == leaf1_gamma, "gamma mismatch");

    let r1_root = compute_ude_chunk_root_commitment(
        UDE_KIND_CT0_R1,
        N,
        CHUNK_SIZE,
        [leaf0_commit, leaf1_commit],
    );

    let mut r1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        r1i_at_gamma[i] = leaf0_partial[i] + leaf1_partial[i];
    }

    (leaf0_gamma, r1_root, r1i_at_gamma)
}
