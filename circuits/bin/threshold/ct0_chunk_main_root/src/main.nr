// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the two `ct0_chunk_main` leaf proofs directly - at N_CHUNKS=2 no intermediate pair
//! level is needed. Both leaves hold raw sensitive witness data, so both are ZK-verified.
//! Computes five separate root commitments, one per polynomial (u/e0/k1/r2/r1) rather than one
//! bundled root, so `u_root` and `k1_root` stay independently usable downstream: the
//! `user_data_encryption` wrapper cross-checks `u` against ct1's, and `k1` survives into ct0's
//! final output tuple. This output feeds directly into `ct0_chunk_gamma`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{N, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS};
use lib::core::threshold::user_data_encryption_chunk::ct0_chunk_roots;

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = 2 * CHUNK_SIZE;

fn main(
    leaf0_vk: UltraHonkVerificationKey,
    leaf0_proof: UltraHonkZKProof,
    leaf0_u: Field,
    leaf0_e0: Field,
    leaf0_k1: Field,
    leaf0_r2: Field,
    leaf0_r1: Field,
    leaf0_key_hash: pub Field,
    leaf1_vk: UltraHonkVerificationKey,
    leaf1_proof: UltraHonkZKProof,
    leaf1_u: Field,
    leaf1_e0: Field,
    leaf1_k1: Field,
    leaf1_r2: Field,
    leaf1_r1: Field,
    leaf1_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, Field) {
    assert(N_CHUNKS == 2, "root circuit is sized for exactly 2 chunks");

    verify_honk_proof(
        leaf0_vk,
        leaf0_proof,
        [0, leaf0_u, leaf0_e0, leaf0_k1, leaf0_r2, leaf0_r1],
        leaf0_key_hash,
    );
    verify_honk_proof(
        leaf1_vk,
        leaf1_proof,
        [1, leaf1_u, leaf1_e0, leaf1_k1, leaf1_r2, leaf1_r1],
        leaf1_key_hash,
    );

    ct0_chunk_roots(
        N,
        CHUNK_SIZE,
        R1_CHUNK_SIZE,
        [leaf0_u, leaf1_u],
        [leaf0_e0, leaf1_e0],
        [leaf0_k1, leaf1_k1],
        [leaf0_r2, leaf1_r2],
        [leaf0_r1, leaf1_r1],
    )
}
