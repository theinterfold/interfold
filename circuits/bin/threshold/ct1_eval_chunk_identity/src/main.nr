// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the ct1 leaf (ZK), opens `pk1is` against the leaf's `pk1_commitment` and `u` against
//! its `u` root, and evaluates the right-hand side of the reduced ct1 identity, batched with the
//! leaf's coefficients:
//!   `sum_i b_i * ((pk1[i] * u mod X^N + 1) + e1 + q_i * p1[i])` at `gamma`.
//! `user_data_encryption_ct1_chunked` compares it with the batched ciphertext evaluation. See
//! `ct0_eval_chunk_identity` for the openings. Prove this circuit with the ZK recursive target
//! because its witness contains `u`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{
    L, N, QIS, USER_DATA_ENCRYPTION_CHUNKED_BIT_PK, USER_DATA_ENCRYPTION_CHUNKED_BIT_U,
};
use lib::core::threshold::user_data_encryption_chunk::{
    UDE_N_CHUNKS, ude_single_root_from_polynomial,
};
use lib::math::commitments::{
    compute_multiple_polynomial_commitment_checked, DS_PK_AGGREGATION, UDE_KIND_U,
};
use lib::math::polynomial::{negacyclic_kernel, Polynomial};

global LEAF_LEN: u32 = 7 + (2 * L);
global LEAF_PK1: u32 = 0;
global LEAF_CT1: u32 = 1;
global LEAF_U_ROOT: u32 = 2;
global LEAF_GAMMA: u32 = 5;
global LEAF_BATCHING: u32 = 6;
global LEAF_E1_AT: u32 = 6 + L;
global LEAF_P1_AT: u32 = 7 + L;

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    leaf_proof: UltraHonkZKProof,
    leaf_public_inputs: [Field; LEAF_LEN],
    pk1is: [Polynomial<N>; L],
    u: Polynomial<N>,
) -> pub (Field, Field, Field, Field, Field, Field, Field, [Field; L], Field) {
    verify_honk_proof(leaf_vk, leaf_proof, leaf_public_inputs, leaf_key_hash);

    let leaf = leaf_public_inputs;
    let gamma = leaf[LEAF_GAMMA];
    let pk1_commitment = compute_multiple_polynomial_commitment_checked::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_PK>(
        pk1is,
        DS_PK_AGGREGATION,
    );
    assert(pk1_commitment == leaf[LEAF_PK1], "pk1 commitment mismatch");
    let u_root = ude_single_root_from_polynomial::<N, UDE_N_CHUNKS, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_U>(
        UDE_KIND_U,
        u,
    );
    assert(u_root == leaf[LEAF_U_ROOT], "u root mismatch");

    let kernel = negacyclic_kernel(u, gamma);
    let mut batching: [Field; L] = [0; L];
    let mut rhs = 0;
    for i in 0..L {
        batching[i] = leaf[LEAF_BATCHING + i];
        let ct1_rhs = pk1is[i].dot(kernel) + leaf[LEAF_E1_AT] + leaf[LEAF_P1_AT + i] * QIS[i];
        rhs += ct1_rhs * batching[i];
    }

    (
        leaf_key_hash, leaf[LEAF_PK1], leaf[LEAF_CT1], leaf[LEAF_U_ROOT], leaf[3], leaf[4], gamma,
        batching, rhs,
    )
}
