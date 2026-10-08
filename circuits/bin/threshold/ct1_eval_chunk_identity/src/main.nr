// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the ct1 leaf and `ct1_eval_pk_ct` (both ZK), binds the public key and `u` the second
//! one used to the first one's challenge, and evaluates the batched right-hand side of the reduced
//! ct1 identity: `sum_i b_i * ((pk1[i] * u mod X^N + 1) + e1 + q_i * p1[i])` at `gamma`.
//! `user_data_encryption_ct1_chunked` compares it with the batched ciphertext evaluation.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, QIS};

// Leaf outputs: pk1 and ct1 commitments, u/e1/p1 roots, gamma, batching[L], e1(gamma),
// p1i(gamma)[L].
global LEAF_LEN: u32 = 7 + (2 * L);
global LEAF_PK1: u32 = 0;
global LEAF_CT1: u32 = 1;
global LEAF_U_ROOT: u32 = 2;
global LEAF_GAMMA: u32 = 5;
global LEAF_BATCHING: u32 = 6;
global LEAF_E1_AT: u32 = 6 + L;
global LEAF_P1_AT: u32 = 7 + L;
// pk circuit public inputs: gamma, pk1 commitment, pk1u(gamma)[L], u root.
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
    let gamma = leaf[LEAF_GAMMA];
    assert(pk_public_inputs[0] == gamma, "gamma mismatch");
    assert(pk_public_inputs[1] == leaf[LEAF_PK1], "pk1 commitment mismatch");
    assert(pk_public_inputs[2 + L] == leaf[LEAF_U_ROOT], "u root mismatch");

    let mut batching: [Field; L] = [0; L];
    let mut rhs = 0;
    for i in 0..L {
        batching[i] = leaf[LEAF_BATCHING + i];
        let ct1_rhs = pk_public_inputs[2 + i] + leaf[LEAF_E1_AT] + leaf[LEAF_P1_AT + i] * QIS[i];
        rhs += ct1_rhs * batching[i];
    }

    (
        leaf_key_hash, pk_key_hash, leaf[LEAF_PK1], leaf[LEAF_CT1], leaf[LEAF_U_ROOT], leaf[3],
        leaf[4], gamma, batching, rhs,
    )
}
