// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies `ct0_chunk_main_root` (non-ZK - it covers all five witness groups, u/e0/k1/r2/r1
//! merged into one grid) and `ct0_pk_ct_commit` (ZK - it holds raw `pk0is`/`ct0is` witness
//! directly), gathering every commitment the ct0 challenge depends on, then derives `gamma`. The
//! transcript hashes commitments and roots rather than raw coefficients, which is what keeps this
//! circuit inside the gate budget.
//!
//! The root's public inputs start with its leaf key hash. This circuit reads that value and
//! outputs it with the root and pk/ct key hashes, in the order root, leaf, pk/ct. It does not
//! compare them to expected values: `user_data_encryption_ct0` folds them into the VK manifest,
//! and the verifier checks the manifest against a deployment anchor.
//!
//! Outputs: 3 key hashes, then `pk0`, `ct0`, `k1`, `u`, `e0`, `r2`, `r1`, then `ct0_gammas[L]`.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::threshold::L;
use lib::math::commitments::compute_user_data_encryption_ct0_challenge;

fn main(
    roots_vk: UltraHonkVerificationKey,
    roots_key_hash: Field,
    roots_proof: UltraHonkProof,
    leaf_key_hash: Field,
    u_root: Field,
    e0_root: Field,
    k1_root: Field,
    r2_root: Field,
    r1_root: Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_key_hash: Field,
    pk_ct_proof: UltraHonkZKProof,
    pk0_commitment: Field,
    ct0_commitment: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof_non_zk(
        roots_vk,
        roots_proof,
        [leaf_key_hash, u_root, e0_root, k1_root, r2_root, r1_root],
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

    (
        roots_key_hash, leaf_key_hash, pk_ct_key_hash, pk0_commitment, ct0_commitment, k1_root,
        u_root, e0_root, r2_root, r1_root, ct0_gammas,
    )
}
