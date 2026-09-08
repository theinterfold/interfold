// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct1_chunk_main_root` (non-ZK - covers all four witness
//! groups, u/e1/p2/p1 merged into one grid) and `ct1_pk_ct_commit` (ZK - holds raw
//! `pk1is`/`ct1is` witness directly, no combine step needed since it was never recursive to
//! begin with), gathering every commitment the ct1 challenge depends on, then derives `gamma`.
//! Same replacement the witness-group-split branch's `ct1_abcd_combine` makes: the transcript
//! hashes commitments/roots instead of raw coefficients.
//!
//! Unlike ct0, ct1's batching coefficients are `gammas[L..2L]` for every limb (no `i == 0`
//! special-case) - see `verify_evaluations` in the original `UserDataEncryptionCt1`.
//!
//! `ct1_chunk_main_root` itself recursively verifies two inner proofs, so it declares its own
//! `pub leaf0_key_hash`/`leaf1_key_hash` parameters ahead of its return tuple in its public
//! inputs - `roots_leaf0_key_hash`/`roots_leaf1_key_hash` below account for those 2 leading
//! fields. `ct1_pk_ct_commit` has no such params (it doesn't itself verify anything), so its
//! public inputs are exactly its two-commitment return tuple.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::threshold::L;
use lib::math::commitments::compute_user_data_encryption_ct1_challenge;

fn main(
    roots_vk: UltraHonkVerificationKey,
    roots_proof: UltraHonkProof,
    roots_leaf0_key_hash: Field,
    roots_leaf1_key_hash: Field,
    u_root: Field,
    e1_root: Field,
    p2_root: Field,
    p1_root: Field,
    roots_key_hash: pub Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_proof: UltraHonkZKProof,
    pk1_commitment: Field,
    ct1_commitment: Field,
    pk_ct_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof_non_zk(
        roots_vk,
        roots_proof,
        [roots_leaf0_key_hash, roots_leaf1_key_hash, u_root, e1_root, p2_root, p1_root],
        roots_key_hash,
    );
    verify_honk_proof(
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
