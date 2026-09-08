// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies the two `ct0_chunk_r1` leaf proofs directly
//! (R1_N_CHUNKS=2 - no intermediate pair/quad level needed). Both leaves hold raw sensitive
//! witness data, so both are ZK-verified. Computes the r1 grid's root commitment over both
//! chunks.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{N, USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS};
use lib::math::commitments::{compute_ude_chunk_root_commitment, UDE_KIND_CT0_R1};

global CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;

fn main(
    leaf0_vk: UltraHonkVerificationKey,
    leaf0_proof: UltraHonkZKProof,
    leaf0_commit: Field,
    leaf0_key_hash: pub Field,
    leaf1_vk: UltraHonkVerificationKey,
    leaf1_proof: UltraHonkZKProof,
    leaf1_commit: Field,
    leaf1_key_hash: pub Field,
) -> pub Field {
    assert(R1_N_CHUNKS == 2, "root circuit is sized for exactly 2 chunks");

    verify_honk_proof(leaf0_vk, leaf0_proof, [0, leaf0_commit], leaf0_key_hash);
    verify_honk_proof(leaf1_vk, leaf1_proof, [1, leaf1_commit], leaf1_key_hash);

    compute_ude_chunk_root_commitment(UDE_KIND_CT0_R1, N, CHUNK_SIZE, [leaf0_commit, leaf1_commit])
}
