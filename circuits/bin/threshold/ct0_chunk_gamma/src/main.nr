// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct0_chunk_main_root` (now covers all five witness
//! groups - u/e0/k1/r2/r1 merged into one grid, so there's no separate combine-roots step) and
//! `ct0_chunk_pk_ct_combine` (both non-ZK), gathering every commitment the ct0 challenge depends
//! on, then derives `gamma`. Same replacement the witness-group-split branch's
//! `ct0_abcde_combine` makes: the transcript hashes commitments/roots instead of raw
//! coefficients.
//!
//! Both verified circuits themselves recursively verify two inner proofs, so each declares its
//! own `pub` key-hash parameters (`leaf0_key_hash`/`leaf1_key_hash` on `ct0_chunk_main_root`,
//! `pk_key_hash`/`ct_key_hash` on `ct0_chunk_pk_ct_combine`) - those are part of *their* real
//! public inputs, not an internal detail, so this circuit must reconstruct the full public-input
//! vector including them, not just the return tuple.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::threshold::L;
use lib::math::commitments::compute_user_data_encryption_ct0_challenge;

fn main(
    roots_vk: UltraHonkVerificationKey,
    roots_proof: UltraHonkProof,
    roots_leaf0_key_hash: Field,
    roots_leaf1_key_hash: Field,
    u_root: Field,
    e0_root: Field,
    k1_root: Field,
    r2_root: Field,
    r1_root: Field,
    roots_key_hash: pub Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_proof: UltraHonkProof,
    pk_key_hash_pub: Field,
    ct_key_hash_pub: Field,
    pk0_commitment: Field,
    ct0_commitment: Field,
    pk_ct_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof_non_zk(
        roots_vk,
        roots_proof,
        [roots_leaf0_key_hash, roots_leaf1_key_hash, u_root, e0_root, k1_root, r2_root, r1_root],
        roots_key_hash,
    );
    verify_honk_proof_non_zk(
        pk_ct_vk,
        pk_ct_proof,
        [pk_key_hash_pub, ct_key_hash_pub, pk0_commitment, ct0_commitment],
        pk_ct_key_hash,
    );

    let payload =
        [pk0_commitment, ct0_commitment, k1_root, u_root, e0_root, r2_root, r1_root].as_vector();
    let gammas = compute_user_data_encryption_ct0_challenge::<L>(payload);

    let mut ct0_gammas: [Field; L] = [0; L];
    for i in 0..L {
        ct0_gammas[i] = gammas[i];
    }

    (pk0_commitment, ct0_commitment, k1_root, u_root, e0_root, r2_root, r1_root, ct0_gammas)
}
