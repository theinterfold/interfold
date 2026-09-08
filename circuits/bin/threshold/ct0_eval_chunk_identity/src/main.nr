// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct0_eval_chunk_main_root` (non-ZK - covers all five
//! witness groups directly) and `ct0_eval_pk_ct` (ZK - holds raw `pk0is`/`ct0is` witness
//! directly, no combine step needed), then performs the actual ct0 Schwartz-Zippel identity
//! check - the one place all five witness groups' evaluations are simultaneously available.
//! Replicates the monolithic circuit's `verify_evaluations` exactly (same as the
//! witness-group-split branch's `ct0_eval_abcde_combine`).
//!
//! `ct0_batching_coeffs` (`gammas[0..L]` from `ct0_chunk_gamma`) is taken as a plain input, not
//! verified against Round A within this circuit - the top-level `user_data_encryption_ct0`
//! circuit verifies both this proof and Round A's `ct0_chunk_gamma` and checks they agree.
//!
//! `ct0_eval_chunk_main_root` itself recursively verifies two leaf proofs, so it declares its own
//! `pub leaf0_key_hash`/`leaf1_key_hash` parameters ahead of its return tuple in its public
//! inputs - `ROOTS_LEN` and the indices below account for those 2 leading fields.
//! `ct0_eval_pk_ct` has only one such param, `gamma` (needed to derive its own per-limb
//! evaluations), ahead of its four-element return tuple.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::threshold::{L, N, QIS, USER_DATA_ENCRYPTION_K0IS};

global ROOTS_LEN: u32 = 10 + (3 * L);
global PK_CT_LEN: u32 = 3 + (2 * L);

fn main(
    roots_vk: UltraHonkVerificationKey,
    roots_proof: UltraHonkProof,
    roots_public_inputs: [Field; ROOTS_LEN],
    roots_key_hash: pub Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_proof: UltraHonkZKProof,
    pk_ct_public_inputs: [Field; PK_CT_LEN],
    pk_ct_key_hash: pub Field,
    ct0_batching_coeffs: pub [Field; L],
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field) {
    verify_honk_proof_non_zk(roots_vk, roots_proof, roots_public_inputs, roots_key_hash);
    verify_honk_proof(pk_ct_vk, pk_ct_proof, pk_ct_public_inputs, pk_ct_key_hash);

    let gamma = roots_public_inputs[2];
    assert(gamma == pk_ct_public_inputs[0], "gamma mismatch");
    assert(gamma == ct0_batching_coeffs[0], "gamma mismatch with batching coefficients");

    let u_root = roots_public_inputs[3];
    let e0_root = roots_public_inputs[4];
    let k1_root = roots_public_inputs[5];
    let r2_root = roots_public_inputs[6];
    let r1_root = roots_public_inputs[7];
    let u_at_gamma = roots_public_inputs[8];
    let k1_at_gamma = roots_public_inputs[9];
    let mut e0is_at_gamma: [Field; L] = [0; L];
    let mut r2i_at_gamma: [Field; L] = [0; L];
    let mut r1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        e0is_at_gamma[i] = roots_public_inputs[10 + i];
        r2i_at_gamma[i] = roots_public_inputs[10 + L + i];
        r1i_at_gamma[i] = roots_public_inputs[10 + (2 * L) + i];
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

    (pk0_commitment, ct0_commitment, k1_root, u_root, e0_root, r2_root, r1_root, gamma)
}
