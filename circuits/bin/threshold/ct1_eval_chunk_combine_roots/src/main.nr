// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct1_eval_chunk_main_root` and `ct1_eval_chunk_p1_root`
//! (both non-ZK), checks they agree on `gamma`, and passes everything through.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;

global MAIN_LEN: u32 = 8 + L;
global P1_LEN: u32 = 4 + L;

fn main(
    main_vk: UltraHonkVerificationKey,
    main_proof: UltraHonkProof,
    main_public_inputs: [Field; MAIN_LEN],
    main_key_hash: pub Field,
    p1_vk: UltraHonkVerificationKey,
    p1_proof: UltraHonkProof,
    p1_public_inputs: [Field; P1_LEN],
    p1_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; L], Field, [Field; L]) {
    verify_honk_proof_non_zk(main_vk, main_proof, main_public_inputs, main_key_hash);
    verify_honk_proof_non_zk(p1_vk, p1_proof, p1_public_inputs, p1_key_hash);

    let gamma = main_public_inputs[2];
    assert(gamma == p1_public_inputs[2], "gamma mismatch");

    let u_root = main_public_inputs[3];
    let e1_root = main_public_inputs[4];
    let p2_root = main_public_inputs[5];
    let u_at_gamma = main_public_inputs[6];
    let e1_at_gamma = main_public_inputs[7];
    let mut p2i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        p2i_at_gamma[i] = main_public_inputs[8 + i];
    }

    let p1_root = p1_public_inputs[3];
    let mut p1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        p1i_at_gamma[i] = p1_public_inputs[4 + i];
    }

    (gamma, u_root, e1_root, p2_root, u_at_gamma, e1_at_gamma, p2i_at_gamma, p1_root, p1i_at_gamma)
}
