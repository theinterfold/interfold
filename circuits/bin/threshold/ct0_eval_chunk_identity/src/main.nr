// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the ct0 leaf (ZK), opens `pk0is` against the leaf's `pk0_commitment` and `u` against
//! its `u` root, and evaluates the right-hand side of the reduced ct0 identity, batched with the
//! leaf's coefficients:
//!   `sum_i gamma_i * ((pk0[i] * u mod X^N + 1) + e0 + k0[i] * k1 + q_i * r1[i])` at `gamma`.
//! `user_data_encryption_ct0_chunked` compares it with the batched ciphertext evaluation.
//!
//! Both openings use checked packing, so the `pk0is` and `u` evaluated here are the ones the leaf
//! committed before deriving `gamma`. The product `pk0 * u mod X^N + 1` is evaluated through
//! `negacyclic_kernel` and never enters a witness. Prove this circuit with the ZK recursive target
//! because its witness contains `u`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{
    L, N, QIS, USER_DATA_ENCRYPTION_CHUNKED_BIT_PK, USER_DATA_ENCRYPTION_CHUNKED_BIT_U,
    USER_DATA_ENCRYPTION_CHUNKED_K0IS,
};
use lib::core::threshold::user_data_encryption_chunk::{
    UDE_N_CHUNKS, ude_single_root_from_polynomial,
};
use lib::math::commitments::{
    compute_multiple_polynomial_commitment_checked, DS_PK_AGGREGATION, UDE_KIND_U,
};
use lib::math::polynomial::{negacyclic_kernel, Polynomial};

global LEAF_LEN: u32 = 8 + (2 * L);
global LEAF_PK0: u32 = 0;
global LEAF_CT0: u32 = 1;
global LEAF_U_ROOT: u32 = 3;
global LEAF_GAMMAS: u32 = 6;
global LEAF_K1_AT: u32 = 6 + L;
global LEAF_E0_AT: u32 = 7 + L;
global LEAF_R1_AT: u32 = 8 + L;

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    leaf_proof: UltraHonkZKProof,
    leaf_public_inputs: [Field; LEAF_LEN],
    pk0is: [Polynomial<N>; L],
    u: Polynomial<N>,
) -> pub (Field, Field, Field, Field, Field, Field, Field, [Field; L], Field) {
    verify_honk_proof(leaf_vk, leaf_proof, leaf_public_inputs, leaf_key_hash);

    let leaf = leaf_public_inputs;
    let gamma = leaf[LEAF_GAMMAS];
    let pk0_commitment = compute_multiple_polynomial_commitment_checked::<N, L, USER_DATA_ENCRYPTION_CHUNKED_BIT_PK>(
        pk0is,
        DS_PK_AGGREGATION,
    );
    assert(pk0_commitment == leaf[LEAF_PK0], "pk0 commitment mismatch");
    let u_root = ude_single_root_from_polynomial::<N, UDE_N_CHUNKS, N, USER_DATA_ENCRYPTION_CHUNKED_BIT_U>(
        UDE_KIND_U,
        u,
    );
    assert(u_root == leaf[LEAF_U_ROOT], "u root mismatch");

    let kernel = negacyclic_kernel(u, gamma);
    let mut gammas: [Field; L] = [0; L];
    let mut rhs = 0;
    for i in 0..L {
        gammas[i] = leaf[LEAF_GAMMAS + i];
        let mut ct0_rhs = pk0is[i].dot(kernel) + leaf[LEAF_E0_AT];
        ct0_rhs += leaf[LEAF_K1_AT] * USER_DATA_ENCRYPTION_CHUNKED_K0IS[i];
        ct0_rhs += leaf[LEAF_R1_AT + i] * QIS[i];
        let gamma_i = if i == 0 { 1 } else { gammas[i] };
        rhs += ct0_rhs * gamma_i;
    }

    (
        leaf_key_hash, leaf[LEAF_PK0], leaf[LEAF_CT0], leaf[2], leaf[LEAF_U_ROOT], leaf[4], leaf[5],
        gammas, rhs,
    )
}
