// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the share-encryption circuit: DKG public key, plaintext,
//! ciphertext, and encryption randomness (u_rns, e0_rns, e1_rns) for testing and codegen.

use e3_committee::CiphernodesCommittee;
use e3_fhe_params::BfvPreset;
use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_encryption::ShareEncryptionCircuitData;
use e3_zk_witness::WitnessError;
use fhe::bfv::Encoding;
use fhe::bfv::Plaintext;
use fhe::bfv::{BfvParameters, PublicKey, SecretKey};
use fhe::trbfv::ShareManager;
use fhe_traits::FheEncoder;
use std::sync::Arc;

/// Generates sample data for the share-encryption circuit (encrypts a share row under DKG pk).
pub fn generate(
    threshold_params: &Arc<BfvParameters>,
    dkg_params: &Arc<BfvParameters>,
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    dkg_input_type: DkgInputType,
    num_ciphertexts: u128, // z in the search defaults
) -> Result<ShareEncryptionCircuitData, WitnessError> {
    let mut rng = rand::rng();

    let dkg_secret_key = SecretKey::random(dkg_params, &mut rng);
    let dkg_public_key = PublicKey::new(&dkg_secret_key, &mut rng);

    let mut share_manager =
        ShareManager::new(committee.n, committee.threshold, threshold_params.clone())
            .map_err(|e| WitnessError::Sample(format!("Failed to create ShareManager: {:?}", e)))?;

    let noise = match dkg_input_type {
        DkgInputType::SecretKey => None,
        DkgInputType::SmudgingNoise => Some(crate::smudging::generator(
            threshold_params,
            committee.n,
            usize::try_from(num_ciphertexts).map_err(|e| WitnessError::Sample(e.to_string()))?,
            preset,
        )?),
    };
    let share_row = super::share_row(&mut share_manager, noise.as_ref(), &mut rng)?;

    let pt = Plaintext::try_encode(&share_row, Encoding::poly(), dkg_params)
        .map_err(|e| WitnessError::Sample(format!("Failed to encode plaintext: {:?}", e)))?;

    let (ct, intermediates) = dkg_public_key
        .try_encrypt_with_intermediates(&pt, &mut rng)
        .map_err(|e| WitnessError::Sample(format!("Failed to encrypt extended: {:?}", e)))?;

    Ok(ShareEncryptionCircuitData {
        plaintext: pt,
        ciphertext: ct,
        public_key: dkg_public_key,
        u_rns: intermediates.randomness().clone(),
        e0_rns: intermediates.error_0().clone(),
        e1_rns: intermediates.error_1().clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvPreset;
    use e3_zk_config::DkgInputType;
    use fhe_traits::FheDecoder;

    #[test]
    fn test_generate_secret_key_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold64.search_defaults().unwrap();
        let (threshold_params, dkg_params) = BfvPreset::InsecureThreshold64.build_pair().unwrap();
        let sample = generate(
            &threshold_params,
            &dkg_params,
            BfvPreset::InsecureThreshold64,
            committee.clone(),
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
        assert_eq!(
            Vec::<u64>::try_decode(&sample.plaintext, Encoding::poly())
                .unwrap()
                .len(),
            BfvPreset::InsecureThreshold64.metadata().degree
        );
        assert_eq!(sample.ciphertext.len(), 2);
        assert_eq!(
            sample.u_rns.coefficients().len(),
            BfvPreset::InsecureThreshold64.metadata().degree
                * e3_fhe_params::constants::insecure_64::dkg::MODULI.len()
        );
        assert_eq!(
            sample.e0_rns.coefficients().len(),
            BfvPreset::InsecureThreshold64.metadata().degree
                * e3_fhe_params::constants::insecure_64::dkg::MODULI.len()
        );
        assert_eq!(
            sample.e1_rns.coefficients().len(),
            BfvPreset::InsecureThreshold64.metadata().degree
                * e3_fhe_params::constants::insecure_64::dkg::MODULI.len()
        );
    }

    #[test]
    fn test_generate_smudging_noise_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold64.search_defaults().unwrap();
        let (threshold_params, dkg_params) = BfvPreset::InsecureThreshold64.build_pair().unwrap();
        let sample = generate(
            &threshold_params,
            &dkg_params,
            BfvPreset::InsecureThreshold64,
            committee,
            DkgInputType::SmudgingNoise,
            sd.z,
        )
        .unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
        assert_eq!(sample.ciphertext.len(), 2);
        assert_eq!(
            sample.u_rns.coefficients().len(),
            BfvPreset::InsecureThreshold64.metadata().degree
                * e3_fhe_params::constants::insecure_64::dkg::MODULI.len()
        );
        assert_eq!(
            sample.e0_rns.coefficients().len(),
            BfvPreset::InsecureThreshold64.metadata().degree
                * e3_fhe_params::constants::insecure_64::dkg::MODULI.len()
        );
        assert_eq!(
            sample.e1_rns.coefficients().len(),
            BfvPreset::InsecureThreshold64.metadata().degree
                * e3_fhe_params::constants::insecure_64::dkg::MODULI.len()
        );
    }
}
