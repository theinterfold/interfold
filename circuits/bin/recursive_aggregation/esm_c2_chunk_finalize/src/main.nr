// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies C2 chunk batches and reconstructs the existing ESM C2 public layout.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::{
    L_THRESHOLD, N, SHARE_COMPUTATION_CHUNK_SIZE as CHUNK_SIZE,
    SHARE_COMPUTATION_CHUNKS_PER_BATCH as CHUNKS_PER_BATCH,
    SHARE_COMPUTATION_N_BATCHES as N_BATCHES, SHARE_COMPUTATION_N_CHUNKS as N_CHUNKS,
};
use lib::configs::default::N_PARTIES;
use lib::math::commitments::{
    compute_sc_party_share_chunk_root_commitment, compute_sc_secret_chunk_root_commitment,
};

pub global CHUNK_COMMITMENT_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);
pub global BATCH_RETURN_LEN: u32 = 2 + (CHUNKS_PER_BATCH * CHUNK_COMMITMENT_LEN);
pub global BATCH_PUBLIC_LEN: u32 = 2 + BATCH_RETURN_LEN;
pub global C2_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);
pub global C2_FINALIZED_PUBLIC_LEN: u32 = C2_PUBLIC_LEN + 2;

fn main(
    batch_vk: UltraHonkVerificationKey,
    batch_proofs: [UltraHonkProof; N_BATCHES],
    batch_public_inputs: [[Field; BATCH_PUBLIC_LEN]; N_BATCHES],
    batch_key_hash: Field,
) -> pub [Field; C2_FINALIZED_PUBLIC_LEN] {
    assert(N_BATCHES * CHUNKS_PER_BATCH == N_CHUNKS);

    let mut secret_chunks: [Field; N_CHUNKS] = [0; N_CHUNKS];
    let mut share_chunks: [[Field; N_CHUNKS]; N_PARTIES * L_THRESHOLD] =
        [[0; N_CHUNKS]; N_PARTIES * L_THRESHOLD];

    for batch_idx in 0..N_BATCHES {
        verify_honk_proof_non_zk(
            batch_vk,
            batch_proofs[batch_idx],
            batch_public_inputs[batch_idx],
            batch_key_hash,
        );
        assert(batch_public_inputs[batch_idx][1] == batch_idx as Field);
        assert(batch_public_inputs[batch_idx][2] == batch_idx as Field);
        assert(batch_public_inputs[batch_idx][0] == batch_public_inputs[0][0]);

        for chunk_in_batch in 0..CHUNKS_PER_BATCH {
            let chunk_idx = batch_idx * CHUNKS_PER_BATCH + chunk_in_batch;
            let start = 4 + chunk_in_batch * CHUNK_COMMITMENT_LEN;
            secret_chunks[chunk_idx] = batch_public_inputs[batch_idx][start];
            for slot in 0..(N_PARTIES * L_THRESHOLD) {
                share_chunks[slot][chunk_idx] = batch_public_inputs[batch_idx][start + 1 + slot];
            }
        }
    }

    let mut output: [Field; C2_FINALIZED_PUBLIC_LEN] = [0; C2_FINALIZED_PUBLIC_LEN];
    output[0] = batch_public_inputs[0][0];
    output[1] = compute_sc_secret_chunk_root_commitment(1, N, CHUNK_SIZE, secret_chunks);
    for party_idx in 0..N_PARTIES {
        for mod_idx in 0..L_THRESHOLD {
            let slot = party_idx * L_THRESHOLD + mod_idx;
            output[2 + slot] = compute_sc_party_share_chunk_root_commitment(
                party_idx,
                mod_idx,
                N,
                CHUNK_SIZE,
                share_chunks[slot],
            );
        }
    }
    // Preserve the batch VK hash in the terminal statement. This lets the
    // parent C2AB fold bind the complete batch -> finalizer chain.
    output[C2_FINALIZED_PUBLIC_LEN - 1] = batch_key_hash;
    output
}
