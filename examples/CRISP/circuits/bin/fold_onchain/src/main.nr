// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use interfold_lib::math::commitments::compute_vk_hash;

/// Binds the four inner `vk_hash` witnesses. Regenerate with `pnpm compute:vk-hash` in
/// `examples/CRISP` after changing ct0 / ct1 / user_data_encryption / crisp_onchain (or the lib
/// preset). Insecure: `lib::configs::default` uses `insecure::*`; secure: uses `secure::*`.
pub global CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_INSECURE: Field =
    0x162ff416a5cc1839dbb7cd6e2b1b7db320bd6c3416fb4a502f08c27c1dce7ec2;
pub global CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_SECURE: Field =
    0x1fc4d9bb421b22ba11e115c6bb79d3d85fcc17e8be7e224866c81fde055ed3fe;

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
        user_data_encryption_public_inputs[0], // ct0_key_hash
        user_data_encryption_public_inputs[1], // ct1_key_hash
    ]
        .as_vector();

    let chain_key_hash = compute_vk_hash(vk_hashes);
    assert(
        (chain_key_hash == CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_INSECURE)
            | (chain_key_hash == CRISP_ONCHAIN_FOLD_EXPECTED_KEY_HASH_SECURE),
    );

    user_data_encryption_public_inputs[2]
}
