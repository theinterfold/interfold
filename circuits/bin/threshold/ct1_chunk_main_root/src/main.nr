// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies the two `ct1_chunk_main` leaf proofs directly (N_CHUNKS=2
//! - no intermediate pair level needed). Both leaves hold raw sensitive witness data, so both are
//! ZK-verified. Computes four separate root commitments - one per polynomial (u/e1/p2/p1), not
//! one bundled root - so `u_root` stays independently usable downstream. This output feeds
//! directly into `ct1_chunk_gamma` - p1 no longer has its own root/combine circuits.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{
    N, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS, USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS,
};
use lib::math::commitments::{
    compute_ude_chunk_root_commitment, UDE_KIND_CT1_E1, UDE_KIND_CT1_P1, UDE_KIND_CT1_P2,
    UDE_KIND_U,
};

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;

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

    let u_root = compute_ude_chunk_root_commitment(UDE_KIND_U, N, CHUNK_SIZE, [leaf0_u, leaf1_u]);
    let e1_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT1_E1, N, CHUNK_SIZE, [leaf0_e1, leaf1_e1]);
    let p2_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT1_P2, N, CHUNK_SIZE, [leaf0_p2, leaf1_p2]);
    let p1_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT1_P1, N, R1_CHUNK_SIZE, [leaf0_p1, leaf1_p1]);

    (u_root, e1_root, p2_root, p1_root)
}
