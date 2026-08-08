// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Projects a complete C2 chunk accumulator back to the existing C2 public layout.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::{L_THRESHOLD, SHARE_COMPUTATION_N_CHUNKS};
use lib::configs::default::N_PARTIES;

pub global C2_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);
pub global C2_CHUNK_FOLD_PREFIX_LEN: u32 = 6;
pub global C2_CHUNK_FOLD_STATE_LEN: u32 = C2_PUBLIC_LEN + (2 * SHARE_COMPUTATION_N_CHUNKS);
pub global C2_CHUNK_FOLD_PUBLIC_LEN: u32 = C2_CHUNK_FOLD_PREFIX_LEN + C2_CHUNK_FOLD_STATE_LEN;
pub global C2_CHUNK_FOLD_C2_OFFSET: u32 =
    C2_CHUNK_FOLD_PREFIX_LEN + (2 * SHARE_COMPUTATION_N_CHUNKS);

fn main(
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C2_CHUNK_FOLD_PUBLIC_LEN],
    acc_key_hash: Field,
) -> pub (Field, [[Field; L_THRESHOLD]; N_PARTIES]) {
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    for chunk in 0..SHARE_COMPUTATION_N_CHUNKS {
        assert(
            acc_public_inputs[C2_CHUNK_FOLD_PREFIX_LEN + SHARE_COMPUTATION_N_CHUNKS + chunk] == 1,
        );
    }

    let expected_secret_commitment = acc_public_inputs[C2_CHUNK_FOLD_C2_OFFSET];
    let mut party_commitments: [[Field; L_THRESHOLD]; N_PARTIES] = [[0; L_THRESHOLD]; N_PARTIES];
    for party_idx in 0..N_PARTIES {
        for mod_idx in 0..L_THRESHOLD {
            party_commitments[party_idx][mod_idx] =
                acc_public_inputs[C2_CHUNK_FOLD_C2_OFFSET + 1 + party_idx * L_THRESHOLD + mod_idx];
        }
    }

    (expected_secret_commitment, party_commitments)
}
