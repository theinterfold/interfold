// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct0_eval_chunk_main_root` and `ct0_eval_chunk_r1_root`
//! (both non-ZK), checks they agree on `gamma`, and passes everything through.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;

global MAIN_LEN: u32 = 9 + (2 * L);
global R1_LEN: u32 = 4 + L;

fn main(
    main_vk: UltraHonkVerificationKey,
    main_proof: UltraHonkProof,
    main_public_inputs: [Field; MAIN_LEN],
    main_key_hash: pub Field,
    r1_vk: UltraHonkVerificationKey,
    r1_proof: UltraHonkProof,
    r1_public_inputs: [Field; R1_LEN],
    r1_key_hash: pub Field,
    ) -> pub (Field, Field, Field, Field, Field, Field, Field, [Field; L], [Field; L], Field, [Field; L]) {
    verify_honk_proof_non_zk(main_vk, main_proof, main_public_inputs, main_key_hash);
    verify_honk_proof_non_zk(r1_vk, r1_proof, r1_public_inputs, r1_key_hash);

    let gamma = main_public_inputs[2];
    assert(gamma == r1_public_inputs[2], "gamma mismatch");

    let u_root = main_public_inputs[3];
    let e0_root = main_public_inputs[4];
    let k1_root = main_public_inputs[5];
    let r2_root = main_public_inputs[6];
    let u_at_gamma = main_public_inputs[7];
    let k1_at_gamma = main_public_inputs[8];
    let mut e0is_at_gamma: [Field; L] = [0; L];
    let mut r2i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        e0is_at_gamma[i] = main_public_inputs[9 + i];
        r2i_at_gamma[i] = main_public_inputs[9 + L + i];
    }

    let r1_root = r1_public_inputs[3];
    let mut r1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        r1i_at_gamma[i] = r1_public_inputs[4 + i];
    }

    (
        gamma, u_root, e0_root, k1_root, r2_root, u_at_gamma, k1_at_gamma, e0is_at_gamma,
        r2i_at_gamma, r1_root, r1i_at_gamma,
    )
}
