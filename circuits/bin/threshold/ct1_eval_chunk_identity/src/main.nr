// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the Round B ct1 leaf and `ct1_eval_pk_ct` (both ZK), then checks the reduced ct1
//! identity at `gamma` for every CRT limb, batched with the Round A coefficients:
//!   `ct1[i] == (pk1[i] * u mod X^N + 1) + e1 + q_i * p1[i]`.
//! Every term has `N` coefficients and is bounded; see `ct0_eval_chunk_identity`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, N, QIS};
use lib::core::threshold::user_data_encryption_chunk::ct1_chunk_roots;

global LEAF_LEN: u32 = 5 + L;
global PK_CT_LEN: u32 = 4 + (2 * L);

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    leaf_proof: UltraHonkZKProof,
    leaf_public_inputs: [Field; LEAF_LEN],
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_key_hash: Field,
    pk_ct_proof: UltraHonkZKProof,
    pk_ct_public_inputs: [Field; PK_CT_LEN],
    ct1_batching_coeffs: [Field; L],
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof(leaf_vk, leaf_proof, leaf_public_inputs, leaf_key_hash);
    verify_honk_proof(pk_ct_vk, pk_ct_proof, pk_ct_public_inputs, pk_ct_key_hash);

    // Leaf public inputs: gamma, then (u, e1, p1) commitments, e1(gamma), p1i(gamma).
    let gamma = leaf_public_inputs[0];
    assert(gamma == pk_ct_public_inputs[0], "gamma mismatch");

    let (u_root, e1_root, p1_root) = ct1_chunk_roots(
        N,
        N,
        [leaf_public_inputs[1]],
        [leaf_public_inputs[2]],
        [leaf_public_inputs[3]],
    );
    let e1_at_gamma = leaf_public_inputs[4];

    // pk/ct public inputs: gamma, pk1 commitment, pk1u(gamma)[L], ct1 commitment, ct1(gamma)[L],
    // u root. The `u` that `ct1_eval_pk_ct` reduced against must be the leaf's.
    let pk1_commitment = pk_ct_public_inputs[1];
    let ct1_commitment = pk_ct_public_inputs[2 + L];
    assert(pk_ct_public_inputs[3 + (2 * L)] == u_root, "u root mismatch");

    let mut sum = (0, 0);
    for i in 0..L {
        let mut ct1_rhs = pk_ct_public_inputs[2 + i] + e1_at_gamma;
        ct1_rhs += leaf_public_inputs[5 + i] * QIS[i];

        let ct1_lhs = pk_ct_public_inputs[3 + L + i];
        let gamma_i = ct1_batching_coeffs[i];

        sum = (sum.0 + ct1_lhs * gamma_i, sum.1 + ct1_rhs * gamma_i);
    }
    assert(sum.0 == sum.1, "ct1 encryption check failed");

    (
        leaf_key_hash, pk_ct_key_hash, pk1_commitment, ct1_commitment, u_root, e1_root, p1_root,
        gamma, ct1_batching_coeffs,
    )
}
