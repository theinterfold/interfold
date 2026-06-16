// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use interfold_lib::math::commitments::compute_vk_hash;

/// Binds the four inner `vk_hash` witnesses. Regenerate with `pnpm compute:vk-hash` in
/// `examples/CRISP` after changing ct0 / ct1 / user_data_encryption / crisp (or the lib preset).
/// Insecure: `lib::configs::default` uses `insecure::*`; secure: uses `secure::*`.
pub global CRISP_FOLD_EXPECTED_KEY_HASH_INSECURE: Field =
    0x2e53e3285d47eebd65eb932cf6a57ecaa5e43f90b1673165715c92b78e493a9c;
pub global CRISP_FOLD_EXPECTED_KEY_HASH_SECURE: Field =
    0x15c663ca84d55d8c794cda86add7073873eec66cbf798e94998f0056b125ba69;

fn main(
    // User Data Encryption Section.
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    user_data_encryption_proof: UltraHonkProof,
    user_data_encryption_public_inputs: [Field; 5], // ct0_key_hash, ct1_key_hash, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_key_hash: Field,
    // Crisp Section.
    crisp_verification_key: UltraHonkVerificationKey,
    crisp_proof: UltraHonkProof,
    crisp_key_hash: Field,
    prev_ct_commitment: pub Field,
    merkle_root: pub Field,
    slot_address: pub Field,
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
            merkle_root,
            slot_address,
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

    let mut vk_hashes = Vec::new();
    vk_hashes.push(user_data_encryption_key_hash);
    vk_hashes.push(crisp_key_hash);
    vk_hashes.push(user_data_encryption_public_inputs[0]); // ct0_key_hash
    vk_hashes.push(user_data_encryption_public_inputs[1]); // ct1_key_hash

    let chain_key_hash = compute_vk_hash(vk_hashes);
    assert(
        (chain_key_hash == CRISP_FOLD_EXPECTED_KEY_HASH_INSECURE)
            | (chain_key_hash == CRISP_FOLD_EXPECTED_KEY_HASH_SECURE),
    );

    user_data_encryption_public_inputs[2]
}
