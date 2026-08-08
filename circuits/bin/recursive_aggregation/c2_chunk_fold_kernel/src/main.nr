// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Genesis kernel for `c2_chunk_fold`. It verifies the base proof and the first
//! chunk proof, then initializes the accumulator state without verifying a prior fold.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
};
use lib::configs::default::dkg::{L_THRESHOLD, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::N_PARTIES;

pub global C2_BASE_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD) + SHARE_COMPUTATION_N_CHUNKS;
pub global C2_CHUNK_PUBLIC_LEN: u32 = 2;
pub global C2_CHUNK_FOLD_PREFIX_LEN: u32 = 6;
pub global C2_CHUNK_FOLD_STATE_LEN: u32 =
    1 + (N_PARTIES * L_THRESHOLD) + (2 * SHARE_COMPUTATION_N_CHUNKS);
pub global C2_CHUNK_FOLD_PUBLIC_LEN: u32 = C2_CHUNK_FOLD_PREFIX_LEN + C2_CHUNK_FOLD_STATE_LEN;

fn main(
    base_vk: UltraHonkVerificationKey,
    base_proof: UltraHonkZKProof,
    base_public_inputs: [Field; C2_BASE_PUBLIC_LEN],
    chunk_vk: UltraHonkVerificationKey,
    chunk_proof: UltraHonkZKProof,
    chunk_public_inputs: [Field; C2_CHUNK_PUBLIC_LEN],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C2_CHUNK_FOLD_PUBLIC_LEN],
    base_key_hash: pub Field,
    chunk_key_hash: pub Field,
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    is_last_step: pub bool,
    chunk_idx: pub u32,
    ) -> pub ([Field; SHARE_COMPUTATION_N_CHUNKS], [Field; SHARE_COMPUTATION_N_CHUNKS], Field, [[Field; L_THRESHOLD]; N_PARTIES]) {
    assert(is_first_step);
    assert(chunk_idx < SHARE_COMPUTATION_N_CHUNKS);
    assert(chunk_public_inputs[1] == chunk_idx as Field);

    verify_honk_proof(base_vk, base_proof, base_public_inputs, base_key_hash);
    verify_honk_proof(chunk_vk, chunk_proof, chunk_public_inputs, chunk_key_hash);

    let _ = (acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let mut base_chunks: [Field; SHARE_COMPUTATION_N_CHUNKS] = [0; SHARE_COMPUTATION_N_CHUNKS];
    let mut flags: [Field; SHARE_COMPUTATION_N_CHUNKS] = [0; SHARE_COMPUTATION_N_CHUNKS];
    for chunk in 0..SHARE_COMPUTATION_N_CHUNKS {
        base_chunks[chunk] = base_public_inputs[1 + chunk];
    }

    assert(chunk_public_inputs[0] == base_chunks[chunk_idx]);
    flags[chunk_idx] = 1;

    if is_last_step {
        for chunk in 0..SHARE_COMPUTATION_N_CHUNKS {
            assert(flags[chunk] == 1);
        }
    }

    let mut party_commitments: [[Field; L_THRESHOLD]; N_PARTIES] = [[0; L_THRESHOLD]; N_PARTIES];
    for party_idx in 0..N_PARTIES {
        for mod_idx in 0..L_THRESHOLD {
            party_commitments[party_idx][mod_idx] = base_public_inputs[1
                + SHARE_COMPUTATION_N_CHUNKS
                + party_idx * L_THRESHOLD
                + mod_idx];
        }
    }

    (base_chunks, flags, base_public_inputs[0], party_commitments)
}
