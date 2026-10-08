// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the Round A ct1 leaf and `ct1_pk_ct_commit` (both ZK), rebuilds the single-chunk roots
//! and derives `gamma` and the ct1 batching coefficients. See `ct0_chunk_gamma`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, N};
use lib::core::threshold::user_data_encryption_chunk::ct1_chunk_roots;
use lib::math::commitments::compute_user_data_encryption_ct1_challenge;

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    leaf_proof: UltraHonkZKProof,
    u_commit: Field,
    e1_commit: Field,
    p1_commit: Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_key_hash: Field,
    pk_ct_proof: UltraHonkZKProof,
    pk1_commitment: Field,
    ct1_commitment: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof(
        leaf_vk,
        leaf_proof,
        [u_commit, e1_commit, p1_commit],
        leaf_key_hash,
    );
    verify_honk_proof(
        pk_ct_vk,
        pk_ct_proof,
        [pk1_commitment, ct1_commitment],
        pk_ct_key_hash,
    );

    let (u_root, e1_root, p1_root) = ct1_chunk_roots(N, N, [u_commit], [e1_commit], [p1_commit]);

    let payload = [pk1_commitment, ct1_commitment, u_root, e1_root, p1_root].as_vector();
    let gammas = compute_user_data_encryption_ct1_challenge::<L>(payload);

    let gamma = gammas[0];
    let mut ct1_batching_coeffs: [Field; L] = [0; L];
    for i in 0..L {
        ct1_batching_coeffs[i] = gammas[L + i];
    }

    (
        leaf_key_hash, pk_ct_key_hash, pk1_commitment, ct1_commitment, u_root, e1_root, p1_root,
        gamma, ct1_batching_coeffs,
    )
}
