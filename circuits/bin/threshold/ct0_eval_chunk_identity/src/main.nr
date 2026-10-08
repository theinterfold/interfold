// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the ct0 leaf and `ct0_eval_pk_ct` (both ZK - each holds raw witness), binds the public
//! key and `u` the second one used to the first one's challenge, and evaluates the right-hand side
//! of the reduced ct0 identity, batched with the leaf's coefficients:
//!   `sum_i gamma_i * ((pk0[i] * u mod X^N + 1) + e0 + k0[i] * k1 + q_i * r1[i])` at `gamma`.
//! `user_data_encryption_ct0_chunked` compares it with the batched ciphertext evaluation.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, QIS, USER_DATA_ENCRYPTION_CHUNKED_K0IS};

// Leaf outputs: pk0 and ct0 commitments, k1/u/e0/r1 roots, gammas[L], k1(gamma), e0(gamma),
// r1i(gamma)[L].
global LEAF_LEN: u32 = 8 + (2 * L);
global LEAF_PK0: u32 = 0;
global LEAF_CT0: u32 = 1;
global LEAF_U_ROOT: u32 = 3;
global LEAF_GAMMAS: u32 = 6;
global LEAF_K1_AT: u32 = 6 + L;
global LEAF_E0_AT: u32 = 7 + L;
global LEAF_R1_AT: u32 = 8 + L;
// pk circuit public inputs: gamma, pk0 commitment, pk0u(gamma)[L], u root.
global PK_LEN: u32 = 3 + L;

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    leaf_proof: UltraHonkZKProof,
    leaf_public_inputs: [Field; LEAF_LEN],
    pk_vk: UltraHonkVerificationKey,
    pk_key_hash: Field,
    pk_proof: UltraHonkZKProof,
    pk_public_inputs: [Field; PK_LEN],
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, [Field; L], Field) {
    verify_honk_proof(leaf_vk, leaf_proof, leaf_public_inputs, leaf_key_hash);
    verify_honk_proof(pk_vk, pk_proof, pk_public_inputs, pk_key_hash);

    let leaf = leaf_public_inputs;
    let gamma = leaf[LEAF_GAMMAS];
    assert(pk_public_inputs[0] == gamma, "gamma mismatch");
    assert(pk_public_inputs[1] == leaf[LEAF_PK0], "pk0 commitment mismatch");
    assert(pk_public_inputs[2 + L] == leaf[LEAF_U_ROOT], "u root mismatch");

    let mut gammas: [Field; L] = [0; L];
    let mut rhs = 0;
    for i in 0..L {
        gammas[i] = leaf[LEAF_GAMMAS + i];
        let mut ct0_rhs = pk_public_inputs[2 + i] + leaf[LEAF_E0_AT];
        ct0_rhs += leaf[LEAF_K1_AT] * USER_DATA_ENCRYPTION_CHUNKED_K0IS[i];
        ct0_rhs += leaf[LEAF_R1_AT + i] * QIS[i];
        let gamma_i = if i == 0 { 1 } else { gammas[i] };
        rhs += ct0_rhs * gamma_i;
    }

    (
        leaf_key_hash, pk_key_hash, leaf[LEAF_PK0], leaf[LEAF_CT0], leaf[2], leaf[LEAF_U_ROOT],
        leaf[4], leaf[5], gammas, rhs,
    )
}
