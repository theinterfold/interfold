// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct1_chunk_main_root` (3 separate roots: u/e1/p2) and
//! `ct1_chunk_p1_root` (1 root) - both non-ZK, already aggregated - and passes all 4 through.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};

fn main(
    main_vk: UltraHonkVerificationKey,
    main_proof: UltraHonkProof,
    u_root: Field,
    e1_root: Field,
    p2_root: Field,
    main_key_hash: pub Field,
    p1_vk: UltraHonkVerificationKey,
    p1_proof: UltraHonkProof,
    p1_root: Field,
    p1_key_hash: pub Field,
) -> pub (Field, Field, Field, Field) {
    verify_honk_proof_non_zk(
        main_vk,
        main_proof,
        [u_root, e1_root, p2_root],
        main_key_hash,
    );
    verify_honk_proof_non_zk(p1_vk, p1_proof, [p1_root], p1_key_hash);

    (u_root, e1_root, p2_root, p1_root)
}
