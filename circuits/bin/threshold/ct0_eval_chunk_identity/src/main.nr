// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the Round B ct0 leaf and `ct0_eval_pk_ct` (both ZK - each holds raw witness), then
//! checks the reduced ct0 identity at `gamma` for every CRT limb, batched with the Round A
//! coefficients:
//!   `ct0[i] == (pk0[i] * u mod X^N + 1) + e0 + k0[i] * k1 + q_i * r1[i]`.
//! Every term has `N` coefficients, so the difference has degree below `N` and Schwartz-Zippel
//! applies. Every term is bounded (ct0 and pk0 centered, u trinary, e0 and k1 by their leaf bounds,
//! r1 by its reduced bound), so the field equality implies the integer one.
//!
//! `ct0_batching_coeffs` (`gammas[0..L]` from `ct0_chunk_gamma`) is a private input here. The
//! top-level circuit binds it by asserting it equals Round A's output.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, N, QIS, USER_DATA_ENCRYPTION_CHUNKED_K0IS};
use lib::core::threshold::user_data_encryption_chunk::ct0_chunk_roots;

global LEAF_LEN: u32 = 7 + L;
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
    ct0_batching_coeffs: [Field; L],
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof(leaf_vk, leaf_proof, leaf_public_inputs, leaf_key_hash);
    verify_honk_proof(pk_ct_vk, pk_ct_proof, pk_ct_public_inputs, pk_ct_key_hash);

    // Leaf public inputs: gamma, then (u, e0, k1, r1) commitments, k1(gamma), e0(gamma), r1i(gamma).
    let gamma = leaf_public_inputs[0];
    assert(gamma == pk_ct_public_inputs[0], "gamma mismatch");
    assert(gamma == ct0_batching_coeffs[0], "gamma mismatch with batching coefficients");

    let (u_root, e0_root, k1_root, r1_root) = ct0_chunk_roots(
        N,
        N,
        [leaf_public_inputs[1]],
        [leaf_public_inputs[2]],
        [leaf_public_inputs[3]],
        [leaf_public_inputs[4]],
    );
    let k1_at_gamma = leaf_public_inputs[5];
    // The committed, lifted `e0` serves every CRT limb; `r1` absorbs its multiple of `q_i`.
    let e0_at_gamma = leaf_public_inputs[6];

    // pk/ct public inputs: gamma, pk0 commitment, pk0u(gamma)[L], ct0 commitment, ct0(gamma)[L],
    // u root. The `u` that `ct0_eval_pk_ct` reduced against must be the leaf's.
    let pk0_commitment = pk_ct_public_inputs[1];
    let ct0_commitment = pk_ct_public_inputs[2 + L];
    assert(pk_ct_public_inputs[3 + (2 * L)] == u_root, "u root mismatch");

    let mut sum = (0, 0);
    for i in 0..L {
        let mut ct0_rhs = pk_ct_public_inputs[2 + i] + e0_at_gamma;
        ct0_rhs += k1_at_gamma * USER_DATA_ENCRYPTION_CHUNKED_K0IS[i];
        ct0_rhs += leaf_public_inputs[7 + i] * QIS[i];

        let ct0_lhs = pk_ct_public_inputs[3 + L + i];
        let gamma_i = if i == 0 { 1 } else { ct0_batching_coeffs[i] };

        sum = (sum.0 + ct0_lhs * gamma_i, sum.1 + ct0_rhs * gamma_i);
    }
    assert(sum.0 == sum.1, "ct0 encryption check failed");

    (
        leaf_key_hash, pk_ct_key_hash, pk0_commitment, ct0_commitment, k1_root, u_root, e0_root,
        r1_root, ct0_batching_coeffs,
    )
}
