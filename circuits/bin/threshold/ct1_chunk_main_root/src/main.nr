// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the two `ct1_chunk_main` leaf proofs directly - at N_CHUNKS=2 no intermediate pair
//! level is needed. Both leaves hold raw sensitive witness data, so both are ZK-verified.
//! Computes four separate root commitments, one per polynomial (u/e1/p2/p1) rather than one
//! bundled root, so `u_root` stays independently usable downstream: the `user_data_encryption`
//! wrapper cross-checks it against ct0's. This output feeds directly into `ct1_chunk_gamma`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{N, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS};
use lib::core::threshold::user_data_encryption_chunk::ct1_chunk_roots;

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = 2 * CHUNK_SIZE;

fn main(
    leaf0_vk: UltraHonkVerificationKey,
    leaf0_proof: UltraHonkZKProof,
    leaf0_u: Field,
    leaf0_e1: Field,
    leaf0_p2: Field,
    leaf0_p1: Field,
    leaf0_key_hash: pub Field,
    leaf1_vk: UltraHonkVerificationKey,
    leaf1_proof: UltraHonkZKProof,
    leaf1_u: Field,
    leaf1_e1: Field,
    leaf1_p2: Field,
    leaf1_p1: Field,
    leaf1_key_hash: pub Field,
) -> pub (Field, Field, Field, Field) {
    assert(N_CHUNKS == 2, "root circuit is sized for exactly 2 chunks");

    verify_honk_proof(
        leaf0_vk,
        leaf0_proof,
        [0, leaf0_u, leaf0_e1, leaf0_p2, leaf0_p1],
        leaf0_key_hash,
    );
    verify_honk_proof(
        leaf1_vk,
        leaf1_proof,
        [1, leaf1_u, leaf1_e1, leaf1_p2, leaf1_p1],
        leaf1_key_hash,
    );

    ct1_chunk_roots(
        N,
        CHUNK_SIZE,
        R1_CHUNK_SIZE,
        [leaf0_u, leaf1_u],
        [leaf0_e1, leaf1_e1],
        [leaf0_p2, leaf1_p2],
        [leaf0_p1, leaf1_p1],
    )
}
