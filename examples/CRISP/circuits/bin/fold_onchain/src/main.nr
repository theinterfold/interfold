// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use interfold_lib::math::commitments::compute_vk_hash;

/// Binds the `user_data_encryption` and `crisp_onchain` key hashes and both complete VK chains.
/// Run `pnpm compute:vk-hash` in `examples/CRISP` after a circuit or preset change.
/// Each preset has a different circuit tree and must have a different anchor.
pub global CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_INSECURE: Field =
    0x21159078343ee16ef426fd872bb932707bf0d38fb535eb08536a6b3eb8bb20cc;
pub global CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_SECURE_8192: Field =
    0x04bbfc5d61e22e8034eef60274df17048375c80b54bce71570a8835c65d8f447;
pub global CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_SECURE_16384: Field =
    0x29ef5fc0b104605ead5b7d55cbb4144f11206771213ee248ea8b9f9618c4674b;

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
    voting_power: pub Field,
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
            voting_power,
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
        (chain_key_hash == CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_INSECURE)
            | (chain_key_hash == CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_SECURE_8192)
            | (chain_key_hash == CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_SECURE_16384),
    );

    user_data_encryption_public_inputs[2]
}
