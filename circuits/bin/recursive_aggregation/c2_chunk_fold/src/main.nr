// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C2 chunk fold. The first step binds the base proof and all chunk
//! commitments. Each step adds one chunk proof and the last step requires full coverage.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::dkg::{L_THRESHOLD, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::N_PARTIES;

/// Existing C2 public fields: secret commitment plus party share commitments.
pub global C2_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);

/// Base C2 public fields: secret commitment, chunk commitments, and party commitments.
pub global C2_BASE_PUBLIC_LEN: u32 = C2_PUBLIC_LEN + SHARE_COMPUTATION_N_CHUNKS;

/// Chunk public fields: commitment and public chunk index.
pub global C2_CHUNK_PUBLIC_LEN: u32 = 2;

/// Public parameters exposed by each fold step.
pub global C2_CHUNK_FOLD_PREFIX_LEN: u32 = 6;

/// Accumulator state: base commitments, coverage flags, and the final C2 fields.
pub global C2_CHUNK_FOLD_STATE_LEN: u32 = C2_PUBLIC_LEN + (2 * SHARE_COMPUTATION_N_CHUNKS);

/// Full public signal length for a fold proof.
pub global C2_CHUNK_FOLD_PUBLIC_LEN: u32 = C2_CHUNK_FOLD_PREFIX_LEN + C2_CHUNK_FOLD_STATE_LEN;

pub global C2_CHUNK_FOLD_BASE_OFFSET: u32 = 0;
pub global C2_CHUNK_FOLD_FLAGS_OFFSET: u32 = SHARE_COMPUTATION_N_CHUNKS;
pub global C2_CHUNK_FOLD_C2_OFFSET: u32 = 2 * SHARE_COMPUTATION_N_CHUNKS;

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
    assert(chunk_idx < SHARE_COMPUTATION_N_CHUNKS);
    assert(chunk_public_inputs[1] == chunk_idx as Field);

    if is_first_step {
        verify_honk_proof(base_vk, base_proof, base_public_inputs, base_key_hash);
    }
    verify_honk_proof(chunk_vk, chunk_proof, chunk_public_inputs, chunk_key_hash);
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let mut base_chunks: [Field; SHARE_COMPUTATION_N_CHUNKS] = [0; SHARE_COMPUTATION_N_CHUNKS];
    let mut flags: [Field; SHARE_COMPUTATION_N_CHUNKS] = [0; SHARE_COMPUTATION_N_CHUNKS];
    let mut expected_secret_commitment: Field = 0;
    let mut party_commitments: [[Field; L_THRESHOLD]; N_PARTIES] = [[0; L_THRESHOLD]; N_PARTIES];

    if is_first_step {
        expected_secret_commitment = base_public_inputs[0];
        for chunk in 0..SHARE_COMPUTATION_N_CHUNKS {
            base_chunks[chunk] = base_public_inputs[1 + chunk];
        }
        for party_idx in 0..N_PARTIES {
            for mod_idx in 0..L_THRESHOLD {
                party_commitments[party_idx][mod_idx] = base_public_inputs[1
                    + SHARE_COMPUTATION_N_CHUNKS
                    + party_idx * L_THRESHOLD
                    + mod_idx];
            }
        }
    } else {
        for chunk in 0..SHARE_COMPUTATION_N_CHUNKS {
            base_chunks[chunk] =
                acc_public_inputs[C2_CHUNK_FOLD_PREFIX_LEN + C2_CHUNK_FOLD_BASE_OFFSET + chunk];
            flags[chunk] =
                acc_public_inputs[C2_CHUNK_FOLD_PREFIX_LEN + C2_CHUNK_FOLD_FLAGS_OFFSET + chunk];
        }
        expected_secret_commitment =
            acc_public_inputs[C2_CHUNK_FOLD_PREFIX_LEN + C2_CHUNK_FOLD_C2_OFFSET];
        for party_idx in 0..N_PARTIES {
            for mod_idx in 0..L_THRESHOLD {
                party_commitments[party_idx][mod_idx] = acc_public_inputs[C2_CHUNK_FOLD_PREFIX_LEN
                    + C2_CHUNK_FOLD_C2_OFFSET
                    + 1
                    + party_idx * L_THRESHOLD
                    + mod_idx];
            }
        }
    }

    assert(chunk_public_inputs[0] == base_chunks[chunk_idx]);
    assert(flags[chunk_idx] == 0);
    flags[chunk_idx] = 1;

    if is_last_step {
        for chunk in 0..SHARE_COMPUTATION_N_CHUNKS {
            assert(flags[chunk] == 1);
        }
    }

    (base_chunks, flags, expected_secret_commitment, party_commitments)
}
