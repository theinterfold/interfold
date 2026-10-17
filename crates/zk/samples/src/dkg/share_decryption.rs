// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the share-decryption circuit: honest ciphertexts, sum ciphertexts, secret key, and message.

use e3_committee::CiphernodesCommittee;
use e3_fhe_params::BfvPreset;
use e3_zk_config::{dkg::share_decryption::Configs, DkgInputType};
use e3_zk_witness::dkg::share_decryption::ShareDecryptionCircuitData;
use e3_zk_witness::WitnessError;
use fhe::bfv::Ciphertext;
use fhe::bfv::Encoding;
use fhe::bfv::Plaintext;
use fhe::bfv::{PublicKey, SecretKey};
use fhe::trbfv::ShareManager;
use fhe_traits::FheEncoder;
use fhe_traits::FheEncrypter;

/// Generates sample data for the share-decryption circuit (decrypts a sum of honest ciphertexts under DKG secret key).
pub fn generate(
    config: &Configs,
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    dkg_input_type: DkgInputType,
) -> Result<ShareDecryptionCircuitData, WitnessError> {
    let threshold_params = &config.threshold_params;
    let dkg_params = &config.params;

    let mut rng = rand::rng();

    let dkg_secret_key = SecretKey::random(dkg_params, &mut rng);
    let dkg_public_key = PublicKey::new(&dkg_secret_key, &mut rng);

    let mut share_manager =
        ShareManager::new(committee.n, committee.threshold, threshold_params.clone())
            .map_err(|e| WitnessError::Sample(format!("Failed to create ShareManager: {:?}", e)))?;
    let noise = match dkg_input_type {
        DkgInputType::SecretKey => None,
        DkgInputType::SmudgingNoise => {
            let defaults = preset
                .search_defaults()
                .ok_or_else(|| WitnessError::Sample("Preset has no search defaults".into()))?;
            Some(crate::smudging::generator(
                threshold_params,
                committee.n,
                usize::try_from(defaults.z).map_err(|e| WitnessError::Sample(e.to_string()))?,
                preset,
            )?)
        }
    };

    let mut honest_ciphertexts: Vec<Option<Vec<Ciphertext>>> = Vec::new();
    let num_honest = committee.h;
    // Midpoint own slot exercises both the None (own plaintext) and Some (BFV-decrypt) branches.
    let own_slot_idx = num_honest / 2;
    let mut own_plaintext_share: Vec<Vec<u64>> =
        Vec::with_capacity(threshold_params.moduli().len());

    for slot_idx in 0..num_honest {
        let mut party_cts = Vec::new();
        let mut own_share_for_slot: Vec<Vec<u64>> = Vec::new();
        for _ in 0..threshold_params.moduli().len() {
            // Each modulus keeps its fresh draw and selects first-modulus receiver zero.
            let share_row = super::share_row(&mut share_manager, noise.as_ref(), &mut rng)?;

            if slot_idx == own_slot_idx {
                own_share_for_slot.push(share_row);
                continue;
            }

            let pt =
                Plaintext::try_encode(&share_row, Encoding::poly(), dkg_params).map_err(|e| {
                    WitnessError::Sample(format!("Failed to encode plaintext: {:?}", e))
                })?;

            let ct = dkg_public_key.try_encrypt(&pt, &mut rng).map_err(|e| {
                WitnessError::Sample(format!("Failed to encrypt plaintext: {:?}", e))
            })?;

            party_cts.push(ct);
        }

        if slot_idx == own_slot_idx {
            own_plaintext_share = own_share_for_slot;
            honest_ciphertexts.push(None);
        } else {
            honest_ciphertexts.push(Some(party_cts));
        }
    }

    Ok(ShareDecryptionCircuitData {
        honest_ciphertexts,
        own_plaintext_share,
        secret_key: dkg_secret_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvPreset;
    use e3_zk_config::DkgInputType;

    #[test]
    fn test_recipient_outside_dealer_set_decrypts_every_row() {
        use e3_zk_witness::dkg::share_decryption::Inputs;
        let committee = CiphernodesCommitteeSize::Small.values();
        let preset = BfvPreset::InsecureThreshold64;
        let config = Configs::for_preset(preset).unwrap();
        let mut sample = generate(&config, preset, committee, DkgInputType::SecretKey).unwrap();
        let dkg_params = &config.params;
        let expected = Inputs::compute(&config, &sample).unwrap();
        let mut rng = rand::rng();
        let public_key = PublicKey::new(&sample.secret_key, &mut rng);
        let own_idx = sample
            .honest_ciphertexts
            .iter()
            .position(Option::is_none)
            .unwrap();
        let encrypted_row = sample
            .own_plaintext_share
            .iter()
            .map(|row| {
                let plaintext = Plaintext::try_encode(row, Encoding::poly(), dkg_params).unwrap();
                public_key.try_encrypt(&plaintext, &mut rng).unwrap()
            })
            .collect();
        sample.honest_ciphertexts[own_idx] = Some(encrypted_row);
        sample.own_plaintext_share.clear();

        let inputs = Inputs::compute(&config, &sample).unwrap();
        assert_eq!(inputs.decrypted_shares, expected.decrypted_shares);
        assert_eq!(inputs.expected_commitments, expected.expected_commitments);
    }

    #[test]
    fn test_generate_secret_key_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let config = Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap();
        let sample = generate(
            &config,
            BfvPreset::InsecureThreshold64,
            committee.clone(),
            DkgInputType::SecretKey,
        )
        .unwrap();

        assert_eq!(sample.honest_ciphertexts.len(), committee.h);
        assert_eq!(
            sample.secret_key.coeffs.len(),
            BfvPreset::InsecureThreshold64.metadata().degree
        );
    }

    #[test]
    fn test_generate_smudging_noise_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let config = Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap();
        let sample = generate(
            &config,
            BfvPreset::InsecureThreshold64,
            committee.clone(),
            DkgInputType::SmudgingNoise,
        )
        .unwrap();

        assert_eq!(sample.honest_ciphertexts.len(), committee.h);
        assert_eq!(
            sample.secret_key.coeffs.len(),
            BfvPreset::InsecureThreshold64.metadata().degree
        );
    }
}
