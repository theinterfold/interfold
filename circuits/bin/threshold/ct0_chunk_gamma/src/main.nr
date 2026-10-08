// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies the Round A ct0 leaf and `ct0_pk_ct_commit` (both ZK - each holds raw witness),
//! rebuilds the single-chunk roots from the leaf's commitments, and derives `gamma` from every
//! commitment the ct0 challenge depends on. The transcript hashes commitments and roots rather than
//! raw coefficients, which is what keeps this circuit inside the gate budget.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::{L, N};
use lib::core::threshold::user_data_encryption_chunk::ct0_chunk_roots;
use lib::math::commitments::compute_user_data_encryption_ct0_challenge;

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    leaf_proof: UltraHonkZKProof,
    u_commit: Field,
    e0_commit: Field,
    k1_commit: Field,
    r1_commit: Field,
    pk_ct_vk: UltraHonkVerificationKey,
    pk_ct_key_hash: Field,
    pk_ct_proof: UltraHonkZKProof,
    pk0_commitment: Field,
    ct0_commitment: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field, [Field; L]) {
    verify_honk_proof(
        leaf_vk,
        leaf_proof,
        [u_commit, e0_commit, k1_commit, r1_commit],
        leaf_key_hash,
    );
    verify_honk_proof(
        pk_ct_vk,
        pk_ct_proof,
        [pk0_commitment, ct0_commitment],
        pk_ct_key_hash,
    );

    let (u_root, e0_root, k1_root, r1_root) =
        ct0_chunk_roots(N, N, [u_commit], [e0_commit], [k1_commit], [r1_commit]);

    let payload = [pk0_commitment, ct0_commitment, k1_root, u_root, e0_root, r1_root].as_vector();
    let gammas = compute_user_data_encryption_ct0_challenge::<L>(payload);

    let mut ct0_gammas: [Field; L] = [0; L];
    for i in 0..L {
        ct0_gammas[i] = gammas[i];
    }

    (
        leaf_key_hash, pk_ct_key_hash, pk0_commitment, ct0_commitment, k1_root, u_root, e0_root,
        r1_root, ct0_gammas,
    )
}
