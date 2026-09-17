// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies `ct1_chunk_main_root` (non-ZK - it covers all four witness groups, u/e1/p2/p1 merged
//! into one grid) and `ct1_pk_ct_commit` (ZK - it holds raw `pk1is`/`ct1is` witness directly),
//! gathering every commitment the ct1 challenge depends on, then derives `gamma`. The transcript
//! hashes commitments and roots rather than raw coefficients, which is what keeps this circuit
//! inside the gate budget.
//!
//! Unlike ct0, ct1's batching coefficients are `gammas[L..2L]` for every limb, with no `i == 0`
//! special-case - see `ct1_eval_chunk_identity`, where they are applied.
//!
//! The root's public inputs start with its leaf key hash. This circuit outputs it with the root
//! and pk/ct key hashes, in the order root, leaf, pk/ct - see `ct0_chunk_gamma` for how they reach
//! the deployment anchor.
//!
//! Outputs: 3 key hashes, then `pk1`, `ct1`, `u`, `e1`, `p2`, `p1`, `gamma`, then
//! `ct1_batching_coeffs[L]`.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::threshold::L;
use lib::math::commitments::compute_user_data_encryption_ct1_challenge;

fn main(
    roots_vk: UltraHonkVerificationKey,
    roots_key_hash: Field,
    roots_proof: UltraHonkProof,
    leaf_key_hash: Field,
    u_root: Field,
    e1_root: Field,
    p2_root: Field,
    p1_root: Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_key_hash: Field,
    pk_ct_proof: UltraHonkZKProof,
    pk1_commitment: Field,
    ct1_commitment: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof_non_zk(
        roots_vk,
        roots_proof,
        [leaf_key_hash, u_root, e1_root, p2_root, p1_root],
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

    (
        roots_key_hash, leaf_key_hash, pk_ct_key_hash, pk1_commitment, ct1_commitment, u_root,
        e1_root, p2_root, p1_root, gamma, ct1_batching_coeffs,
    )
}
