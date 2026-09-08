// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct1_chunk_main_root` (now covers all four witness
//! groups - u/e1/p2/p1 merged into one grid, so there's no separate combine-roots step) and
//! `ct1_chunk_pk_ct_combine` (both non-ZK), gathering every commitment the ct1 challenge depends
//! on, then derives `gamma`. Same replacement the witness-group-split branch's
//! `ct1_abcd_combine` makes: the transcript hashes commitments/roots instead of raw
//! coefficients.
//!
//! Unlike ct0, ct1's batching coefficients are `gammas[L..2L]` for every limb (no `i == 0`
//! special-case) - see `verify_evaluations` in the original `UserDataEncryptionCt1`.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;
use lib::math::commitments::compute_user_data_encryption_ct1_challenge;

fn main(
    roots_vk: UltraHonkVerificationKey,
    roots_proof: UltraHonkProof,
    u_root: Field,
    e1_root: Field,
    p2_root: Field,
    p1_root: Field,
    roots_key_hash: pub Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_proof: UltraHonkProof,
    pk1_commitment: Field,
    ct1_commitment: Field,
    pk_ct_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof_non_zk(
        roots_vk,
        roots_proof,
        [u_root, e1_root, p2_root, p1_root],
        roots_key_hash,
    );
    verify_honk_proof_non_zk(
        pk_ct_vk,
        pk_ct_proof,
        [pk1_commitment, ct1_commitment],
        pk_ct_key_hash,
    );

    let payload = [pk1_commitment, ct1_commitment, u_root, e1_root, p1_root, p2_root].as_vector();
    let gammas = compute_user_data_encryption_ct1_challenge::<L>(payload);

    let gamma = gammas[0];
    let mut ct1_batching_coeffs: [Field; L] = [0; L];
    for i in 0..L {
        ct1_batching_coeffs[i] = gammas[L + i];
    }

    (pk1_commitment, ct1_commitment, u_root, e1_root, p2_root, p1_root, gamma, ct1_batching_coeffs)
}
