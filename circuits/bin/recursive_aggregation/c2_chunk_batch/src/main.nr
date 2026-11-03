// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies a fixed batch of independent C2 chunk proofs.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::dkg::{
    L_THRESHOLD, SHARE_COMPUTATION_CHUNKS_PER_BATCH as CHUNKS_PER_BATCH,
    SHARE_COMPUTATION_N_CHUNKS as N_CHUNKS,
};
use lib::configs::default::N_PARTIES;

pub global CHUNK_COMMITMENT_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);
pub global CHUNK_PUBLIC_LEN: u32 = 1 + CHUNK_COMMITMENT_LEN;
pub global BATCH_RETURN_LEN: u32 = CHUNKS_PER_BATCH * CHUNK_COMMITMENT_LEN;

fn main(
    chunk_vk: UltraHonkVerificationKey,
    chunk_proofs: [UltraHonkZKProof; CHUNKS_PER_BATCH],
    chunk_public_inputs: [[Field; CHUNK_PUBLIC_LEN]; CHUNKS_PER_BATCH],
    chunk_key_hash: pub Field,
    batch_idx: pub u32,
) -> pub [Field; BATCH_RETURN_LEN] {
    // The finalize step reads `batch_idx` from the public inputs and each chunk's commitments
    // from the return; nothing else is exported, so no batch-level hash is needed.
    let mut output: [Field; BATCH_RETURN_LEN] = [0; BATCH_RETURN_LEN];

    for i in 0..CHUNKS_PER_BATCH {
        let expected_chunk_idx = batch_idx * CHUNKS_PER_BATCH + i;
        assert(expected_chunk_idx < N_CHUNKS);
        verify_honk_proof(
            chunk_vk,
            chunk_proofs[i],
            chunk_public_inputs[i],
            chunk_key_hash,
        );
        assert(chunk_public_inputs[i][0] == expected_chunk_idx as Field);

        for j in 1..CHUNK_PUBLIC_LEN {
            output[i * CHUNK_COMMITMENT_LEN + (j - 1)] = chunk_public_inputs[i][j];
        }
    }

    output
}
