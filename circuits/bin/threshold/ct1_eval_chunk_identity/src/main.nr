// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct1_eval_chunk_main_root` (now covers all four witness
//! groups directly - no separate combine-roots step) and `ct1_eval_chunk_pk_ct_combine` (both
//! non-ZK), then performs the actual ct1 Schwartz-Zippel identity check - the one place all four
//! witness groups' evaluations are simultaneously available. Replicates the monolithic circuit's
//! `verify_evaluations` for ct1 exactly, including its difference from ct0: the batching
//! coefficient is `ct1_batching_coeffs[i]` for every limb `i`, with no `i == 0` special-case.
//!
//! `ct1_batching_coeffs` (`gammas[L..2L]` from `ct1_chunk_gamma`) is taken as a plain input, not
//! verified against Round A here - the top-level `user_data_encryption_ct1` circuit verifies
//! both this proof and Round A's `ct1_chunk_gamma` and checks they agree.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::{L, N, QIS};

global ROOTS_LEN: u32 = 7 + (2 * L);
global PK_CT_LEN: u32 = 5 + (2 * L);

fn main(
    roots_vk: UltraHonkVerificationKey,
    roots_proof: UltraHonkProof,
    roots_public_inputs: [Field; ROOTS_LEN],
    roots_key_hash: pub Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_proof: UltraHonkProof,
    pk_ct_public_inputs: [Field; PK_CT_LEN],
    pk_ct_key_hash: pub Field,
    ct1_batching_coeffs: pub [Field; L],
) -> pub (Field, Field, Field, Field, Field, Field, Field) {
    verify_honk_proof_non_zk(roots_vk, roots_proof, roots_public_inputs, roots_key_hash);
    verify_honk_proof_non_zk(pk_ct_vk, pk_ct_proof, pk_ct_public_inputs, pk_ct_key_hash);

    let gamma = roots_public_inputs[0];
    assert(gamma == pk_ct_public_inputs[2], "gamma mismatch");

    let u_root = roots_public_inputs[1];
    let e1_root = roots_public_inputs[2];
    let p2_root = roots_public_inputs[3];
    let p1_root = roots_public_inputs[4];
    let u_at_gamma = roots_public_inputs[5];
    let e1_at_gamma = roots_public_inputs[6];
    let mut p2i_at_gamma: [Field; L] = [0; L];
    let mut p1i_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        p2i_at_gamma[i] = roots_public_inputs[7 + i];
        p1i_at_gamma[i] = roots_public_inputs[7 + L + i];
    }

    let pk1_commitment = pk_ct_public_inputs[3];
    let mut pk1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        pk1is_at_gamma[i] = pk_ct_public_inputs[4 + i];
    }
    let ct1_commitment = pk_ct_public_inputs[4 + L];
    let mut ct1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        ct1is_at_gamma[i] = pk_ct_public_inputs[5 + L + i];
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

    (pk1_commitment, ct1_commitment, u_root, e1_root, p2_root, p1_root, gamma)
}
