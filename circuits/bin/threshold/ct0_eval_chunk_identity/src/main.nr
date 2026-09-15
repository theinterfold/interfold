// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies `ct0_eval_chunk_main_root` (non-ZK - it covers all five witness groups directly) and
//! `ct0_eval_pk_ct` (ZK - it holds raw `pk0is`/`ct0is` witness directly), then performs the ct0
//! Schwartz-Zippel identity check - the one place all five witness groups' evaluations are
//! simultaneously available, and so the only circuit that can run it.
//!
//! `ct0_batching_coeffs` (`gammas[0..L]` from `ct0_chunk_gamma`) is a private input here. This
//! circuit outputs it, and `user_data_encryption_ct0` checks it against Round A's value. The
//! circuit asserts `ct0_batching_coeffs[0] == gamma`, so that output also carries `gamma`.
//!
//! Key hashes: the root's public inputs start with its leaf key hash. This circuit outputs it
//! with the root and pk/ct key hashes, in the order root, leaf, pk/ct - see `ct0_chunk_gamma` for
//! how they reach the deployment anchor.
//!
//! Outputs: 3 key hashes, then `pk0`, `ct0`, `k1`, `u`, `e0`, `r2`, `r1`, then
//! `ct0_batching_coeffs[L]` - the same layout as `ct0_chunk_gamma`.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::threshold::{L, N, QIS, USER_DATA_ENCRYPTION_K0IS};

// `ct0_eval_chunk_main_root` public inputs: leaf key hash, gamma, 5 roots, u_at_gamma,
// k1_at_gamma, then e0is/r2i/r1i evaluations (L each).
global ROOTS_LEN: u32 = 9 + (3 * L);
// `ct0_eval_pk_ct` public inputs: gamma, pk0 commitment, pk0is evaluations (L), ct0 commitment,
// ct0is evaluations (L).
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
    ct0_batching_coeffs: [Field; L],
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof_non_zk(roots_vk, roots_proof, roots_public_inputs, roots_key_hash);
    verify_honk_proof(pk_ct_vk, pk_ct_proof, pk_ct_public_inputs, pk_ct_key_hash);

    let leaf_key_hash = roots_public_inputs[0];
    let gamma = roots_public_inputs[1];
    assert(gamma == pk_ct_public_inputs[0], "gamma mismatch");
    assert(gamma == ct0_batching_coeffs[0], "gamma mismatch with batching coefficients");

    let u_root = roots_public_inputs[2];
    let e0_root = roots_public_inputs[3];
    let k1_root = roots_public_inputs[4];
    let r2_root = roots_public_inputs[5];
    let r1_root = roots_public_inputs[6];
    let u_at_gamma = roots_public_inputs[7];
    let k1_at_gamma = roots_public_inputs[8];
    let mut e0is_at_gamma: [Field; L] = [0; L];
    let mut r2i_at_gamma: [Field; L] = [0; L];
    let mut r1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        e0is_at_gamma[i] = roots_public_inputs[9 + i];
        r2i_at_gamma[i] = roots_public_inputs[9 + L + i];
        r1i_at_gamma[i] = roots_public_inputs[9 + (2 * L) + i];
    }

    let pk0_commitment = pk_ct_public_inputs[1];
    let mut pk0is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        pk0is_at_gamma[i] = pk_ct_public_inputs[2 + i];
    }
    let ct0_commitment = pk_ct_public_inputs[2 + L];
    let mut ct0is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        ct0is_at_gamma[i] = pk_ct_public_inputs[3 + L + i];
    }

    let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
    let mut sum = (0, 0);
    for i in 0..L {
        let mut ct0_rhs = pk0is_at_gamma[i] * u_at_gamma + e0is_at_gamma[i];
        ct0_rhs += k1_at_gamma * USER_DATA_ENCRYPTION_K0IS[i];
        ct0_rhs += r1i_at_gamma[i] * QIS[i];
        ct0_rhs += r2i_at_gamma[i] * cyclo_at_gamma;

        let ct0_lhs = ct0is_at_gamma[i];
        let gamma_i = if i == 0 { 1 } else { ct0_batching_coeffs[i] };

        sum = (sum.0 + ct0_lhs * gamma_i, sum.1 + ct0_rhs * gamma_i);
    }
    assert(sum.0 == sum.1, "ct0 encryption check failed");

    (
        roots_key_hash, leaf_key_hash, pk_ct_key_hash, pk0_commitment, ct0_commitment, k1_root,
        u_root, e0_root, r2_root, r1_root, ct0_batching_coeffs,
    )
}
