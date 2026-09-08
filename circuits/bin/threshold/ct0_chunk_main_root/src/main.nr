// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies the two `ct0_chunk_main` leaf proofs directly (N_CHUNKS=2
//! - no intermediate pair level needed). Both leaves hold raw sensitive witness data, so both are
//! ZK-verified. Computes five separate root commitments - one per polynomial (u/e0/k1/r2/r1), not
//! one bundled root - so `u_root`/`k1_root` stay independently usable downstream, the same way
//! `u_commitment`/`k1_commitment` are on the witness-group-split branch. This output feeds
//! directly into `ct0_chunk_gamma` - r1 no longer has its own root/combine circuits.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{
    N, USER_DATA_ENCRYPTION_N_CHUNKS as N_CHUNKS, USER_DATA_ENCRYPTION_R1_N_CHUNKS as R1_N_CHUNKS,
};
use lib::math::commitments::{
    compute_ude_chunk_root_commitment, UDE_KIND_CT0_E0, UDE_KIND_CT0_K1, UDE_KIND_CT0_R1,
    UDE_KIND_CT0_R2, UDE_KIND_CT0_U,
};

global CHUNK_SIZE: u32 = N / N_CHUNKS;
global R1_CHUNK_SIZE: u32 = (2 * N) / R1_N_CHUNKS;

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

    let u_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT0_U, N, CHUNK_SIZE, [leaf0_u, leaf1_u]);
    let e0_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT0_E0, N, CHUNK_SIZE, [leaf0_e0, leaf1_e0]);
    let k1_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT0_K1, N, CHUNK_SIZE, [leaf0_k1, leaf1_k1]);
    let r2_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT0_R2, N, CHUNK_SIZE, [leaf0_r2, leaf1_r2]);
    let r1_root =
        compute_ude_chunk_root_commitment(UDE_KIND_CT0_R1, N, R1_CHUNK_SIZE, [leaf0_r1, leaf1_r1]);

    (u_root, e0_root, k1_root, r2_root, r1_root)
}
