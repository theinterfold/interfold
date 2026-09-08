// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct0_chunk_main_root` (non-ZK - covers all five witness
//! groups, u/e0/k1/r2/r1 merged into one grid) and `ct0_pk_ct_commit` (ZK - holds raw
//! `pk0is`/`ct0is` witness directly, no combine step needed since it was never recursive to
//! begin with), gathering every commitment the ct0 challenge depends on, then derives `gamma`.
//! Same replacement the witness-group-split branch's `ct0_abcde_combine` makes: the transcript
//! hashes commitments/roots instead of raw coefficients.
//!
//! `ct0_chunk_main_root` itself recursively verifies two inner proofs, so it declares its own
//! `pub leaf0_key_hash`/`leaf1_key_hash` parameters ahead of its return tuple in its public
//! inputs - `roots_leaf0_key_hash`/`roots_leaf1_key_hash` below account for those 2 leading
//! fields. `ct0_pk_ct_commit` has no such params (it doesn't itself verify anything), so its
//! public inputs are exactly its two-commitment return tuple.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
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
    pk_ct_proof: UltraHonkZKProof,
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
    verify_honk_proof(
        pk_ct_vk,
        pk_ct_proof,
        [pk0_commitment, ct0_commitment],
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
