// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies `ct1_eval_chunk_main_root` (non-ZK - it covers all four witness groups directly) and
//! `ct1_eval_pk_ct` (ZK - it holds raw `pk1is`/`ct1is` witness directly), then performs the ct1
//! Schwartz-Zippel identity check - the one place all four witness groups' evaluations are
//! simultaneously available, and so the only circuit that can run it. Note ct1's difference from
//! ct0: the batching coefficient is `ct1_batching_coeffs[i]` for every limb `i`, with no
//! `i == 0` special-case.
//!
//! `ct1_batching_coeffs` (`gammas[L..2L]` from `ct1_chunk_gamma`) is a private input here. This
//! circuit outputs it, and `user_data_encryption_ct1` checks it against Round A's value.
//!
//! Key hashes: the root's public inputs start with its leaf key hash. This circuit outputs it
//! with the root and pk/ct key hashes, in the order root, leaf, pk/ct - see `ct0_chunk_gamma` for
//! how they reach the deployment anchor.
//!
//! Outputs: 3 key hashes, then `pk1`, `ct1`, `u`, `e1`, `p2`, `p1`, `gamma`, then
//! `ct1_batching_coeffs[L]` - the same layout as `ct1_chunk_gamma`.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::threshold::{L, N, QIS};

// `ct1_eval_chunk_main_root` public inputs: leaf key hash, gamma, 4 roots, u_at_gamma,
// e1_at_gamma, then p2i/p1i evaluations (L each).
global ROOTS_LEN: u32 = 8 + (2 * L);
// `ct1_eval_pk_ct` public inputs: gamma, pk1 commitment, pk1is evaluations (L), ct1 commitment,
// ct1is evaluations (L).
global PK_CT_LEN: u32 = 3 + (2 * L);

fn main(
    roots_vk: UltraHonkVerificationKey,
    roots_key_hash: Field,
    roots_proof: UltraHonkProof,
    roots_public_inputs: [Field; ROOTS_LEN],
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_key_hash: Field,
    pk_ct_proof: UltraHonkZKProof,
    pk_ct_public_inputs: [Field; PK_CT_LEN],
    ct1_batching_coeffs: [Field; L],
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof_non_zk(roots_vk, roots_proof, roots_public_inputs, roots_key_hash);
    verify_honk_proof(pk_ct_vk, pk_ct_proof, pk_ct_public_inputs, pk_ct_key_hash);

    let leaf_key_hash = roots_public_inputs[0];
    let gamma = roots_public_inputs[1];
    assert(gamma == pk_ct_public_inputs[0], "gamma mismatch");

    let u_root = roots_public_inputs[2];
    let e1_root = roots_public_inputs[3];
    let p2_root = roots_public_inputs[4];
    let p1_root = roots_public_inputs[5];
    let u_at_gamma = roots_public_inputs[6];
    let e1_at_gamma = roots_public_inputs[7];
    let mut p2i_at_gamma: [Field; L] = [0; L];
    let mut p1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        p2i_at_gamma[i] = roots_public_inputs[8 + i];
        p1i_at_gamma[i] = roots_public_inputs[8 + L + i];
    }

    let pk1_commitment = pk_ct_public_inputs[1];
    let mut pk1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        pk1is_at_gamma[i] = pk_ct_public_inputs[2 + i];
    }
    let ct1_commitment = pk_ct_public_inputs[2 + L];
    let mut ct1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        ct1is_at_gamma[i] = pk_ct_public_inputs[3 + L + i];
    }

    let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
    let mut sum = (0, 0);
    for i in 0..L {
        let mut ct1_rhs = pk1is_at_gamma[i] * u_at_gamma + e1_at_gamma;
        ct1_rhs += p1i_at_gamma[i] * QIS[i];
        ct1_rhs += p2i_at_gamma[i] * cyclo_at_gamma;

        let ct1_lhs = ct1is_at_gamma[i];
        let gamma_i = ct1_batching_coeffs[i];

        sum = (sum.0 + ct1_lhs * gamma_i, sum.1 + ct1_rhs * gamma_i);
    }
    assert(sum.0 == sum.1, "ct1 encryption check failed");

    (
        roots_key_hash, leaf_key_hash, pk_ct_key_hash, pk1_commitment, ct1_commitment, u_root,
        e1_root, p2_root, p1_root, gamma, ct1_batching_coeffs,
    )
}
