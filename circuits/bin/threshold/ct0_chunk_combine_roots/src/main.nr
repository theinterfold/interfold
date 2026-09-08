// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct0_chunk_main_root` (4 separate roots: u/e0/k1/r2) and
//! `ct0_chunk_r1_root` (1 root) - both non-ZK, already aggregated - and passes all 5 through.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};

fn main(
    main_vk: UltraHonkVerificationKey,
    main_proof: UltraHonkProof,
    u_root: Field,
    e0_root: Field,
    k1_root: Field,
    r2_root: Field,
    main_key_hash: pub Field,
    r1_vk: UltraHonkVerificationKey,
    r1_proof: UltraHonkProof,
    r1_root: Field,
    r1_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, Field) {
    verify_honk_proof_non_zk(
        main_vk,
        main_proof,
        [u_root, e0_root, k1_root, r2_root],
        main_key_hash,
    );
    verify_honk_proof_non_zk(r1_vk, r1_proof, [r1_root], r1_key_hash);

    (u_root, e0_root, k1_root, r2_root, r1_root)
}
