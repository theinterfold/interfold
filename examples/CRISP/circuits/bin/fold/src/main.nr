// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use interfold_lib::math::commitments::compute_vk_hash;

/// Binds the `user_data_encryption` and `crisp` key hashes and both complete VK chains.
/// Run `pnpm compute:vk-hash` in `examples/CRISP` after a circuit or preset change.
/// Each preset has a different circuit tree and must have a different anchor.
pub global CRISP_FOLD_EXPECTED_KEY_HASH_INSECURE: Field =
    0x1d5318009917208068c6d38d7b6ac2b8245318e843526a47fae1a619387804ea;
pub global CRISP_FOLD_EXPECTED_KEY_HASH_SECURE_8192: Field =
    0x070a6127ee18e551064f96d4cd43afa7d2c71dbc6c69d2833a38e9415eda2fc4;
pub global CRISP_FOLD_EXPECTED_KEY_HASH_SECURE_16384: Field =
    0x11da3be958709d22a9a31ec4adfd89ff2fe5d384e1578f494ecb67ee4437a3b3;

fn main(
    // User Data Encryption Section.
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    user_data_encryption_proof: UltraHonkProof,
    user_data_encryption_public_inputs: [Field; 5], // ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_key_hash: Field,
    // Crisp Section.
    crisp_verification_key: UltraHonkVerificationKey,
    crisp_proof: UltraHonkProof,
    crisp_key_hash: Field,
    prev_ct_commitment: pub Field,
    digest_hi: pub Field,
    digest_lo: pub Field,
    slot_address: pub Field,
    merkle_root: pub Field,
    is_first_vote: pub bool,
    num_options: pub u32,
    final_ct_commitment: pub Field,
    ct_commitment: Field,
    k1_commitment: Field,
) -> pub Field {
    verify_honk_proof_non_zk(
        user_data_encryption_verification_key,
        user_data_encryption_proof,
        user_data_encryption_public_inputs,
        user_data_encryption_key_hash,
    );
    verify_honk_proof_non_zk(
        crisp_verification_key,
        crisp_proof,
        [
            prev_ct_commitment,
            digest_hi,
            digest_lo,
            slot_address,
            merkle_root,
            if is_first_vote { 1 } else { 0 },
            num_options as Field,
            final_ct_commitment,
            ct_commitment,
            k1_commitment,
        ],
        crisp_key_hash,
    );

    // Verify that the ct_commitment from the crisp proof matches the one computed from user data encryption.
    assert(ct_commitment == user_data_encryption_public_inputs[3]);

    // Verify that the k1_commitment from the crisp proof matches the one computed from user data encryption.
    assert(k1_commitment == user_data_encryption_public_inputs[4]);

    let vk_hashes = [
        user_data_encryption_key_hash,
        crisp_key_hash,
        // Each chain binds the VK of every circuit in that leg's chunk tree, not only the
        // top-level circuit - see `compute_ude_vk_chain`.
        user_data_encryption_public_inputs[0], // ct0_vk_chain
        user_data_encryption_public_inputs[1], // ct1_vk_chain
    ]
        .as_vector();

    let chain_key_hash = compute_vk_hash(vk_hashes);
    assert(
        (chain_key_hash == CRISP_FOLD_EXPECTED_KEY_HASH_INSECURE)
            | (chain_key_hash == CRISP_FOLD_EXPECTED_KEY_HASH_SECURE_8192)
            | (chain_key_hash == CRISP_FOLD_EXPECTED_KEY_HASH_SECURE_16384),
    );

    user_data_encryption_public_inputs[2]
}
