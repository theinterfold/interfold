// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the share-encryption circuit: DKG public key, plaintext,
//! ciphertext, and encryption randomness (u_rns, e0_rns, e1_rns) for testing and codegen.

use crate::circuits::dkg::share_encryption::circuit::ShareEncryptionCircuitData;
use crate::computation::DkgInputType;
use crate::CiphernodesCommittee;
use crate::CircuitsErrors;
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use fhe::bfv::Encoding;
use fhe::bfv::Plaintext;
use fhe::bfv::{PublicKey, SecretKey};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_traits::FheEncoder;

impl ShareEncryptionCircuitData {
    /// Generates sample data for the share-encryption circuit (encrypts a share row under DKG pk).
    pub fn generate_sample(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
        dkg_input_type: DkgInputType,
        num_ciphertexts: u128, // z in the search defaults
    ) -> Result<Self, CircuitsErrors> {
        let (threshold_params, dkg_params) = build_pair_for_preset(preset).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e))
        })?;

        let mut rng = rand::rng();

        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = preset
            .lambda()
            .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let dkg_secret_key = SecretKey::random(&dkg_params, &mut rng);
        let dkg_public_key = PublicKey::new(&dkg_secret_key, &mut rng);

        let trbfv = TRBFV::new(committee.n, committee.threshold, threshold_params.clone())
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to create TRBFV: {:?}", e)))?;
        let mut share_manager =
            ShareManager::new(committee.n, committee.threshold, threshold_params.clone()).map_err(
                |e| CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e)),
            )?;

        let share_row = match dkg_input_type {
            DkgInputType::SecretKey => {
                let threshold_secret_key = SecretKey::random(&threshold_params, &mut rng);

                let sk_poly = share_manager
                    .coeffs_to_poly_level0(threshold_secret_key.coeffs.clone().as_ref())
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!(
                            "Failed to convert secret key to poly: {:?}",
                            e
                        ))
                    })?;

                let sk_sss_u64 = share_manager
                    .generate_secret_shares_from_poly(sk_poly.clone(), &mut rng)
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to generate secret shares: {:?}", e))
                    })?;

                sk_sss_u64[0].row(0).to_vec()
            }
            DkgInputType::SmudgingNoise => {
                let esi_coeffs = trbfv
                    .generate_smudging_error(num_ciphertexts as usize, lambda, &mut rng)
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!(
                            "Failed to generate smudging error: {:?}",
                            e
                        ))
                    })
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!(
                            "Failed to generate smudging error: {:?}",
                            e
                        ))
                    })?;
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to convert error to poly: {:?}", e))
                })?;
                let esi_sss_u64 = share_manager
                    .generate_secret_shares_from_poly(esi_poly.clone(), &mut rng.clone())
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to generate error shares: {:?}", e))
                    })?;

                esi_sss_u64[0].row(0).to_vec()
            }
        };

        let pt = Plaintext::try_encode(&share_row, Encoding::poly(), &dkg_params)
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to encode plaintext: {:?}", e)))?;

        let (_ct, u_rns, e0_rns, e1_rns) = dkg_public_key
            .try_encrypt_extended(&pt, &mut rng)
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to encrypt extended: {:?}", e)))?;

        Ok(ShareEncryptionCircuitData {
            plaintext: pt,
            ciphertext: _ct,
            public_key: dkg_public_key,
            secret_key: dkg_secret_key,
            u_rns,
            e0_rns,
            e1_rns,
            dkg_input_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{computation::DkgInputType, CiphernodesCommitteeSize};
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_secret_key_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold512.search_defaults().unwrap();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee.clone(),
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
        assert_eq!(
            crate::math::plaintext_poly_u64(&sample.plaintext)
                .unwrap()
                .len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
        assert_eq!(sample.ciphertext.len(), 2);
        assert_eq!(
            sample.u_rns.coefficients().len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
        assert_eq!(
            sample.e0_rns.coefficients().len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
        assert_eq!(
            sample.e1_rns.coefficients().len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
    }

    #[test]
    fn test_generate_smudging_noise_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold512.search_defaults().unwrap();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SmudgingNoise,
            sd.z,
        )
        .unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
        assert_eq!(sample.ciphertext.len(), 2);
        assert_eq!(
            sample.u_rns.coefficients().len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
        assert_eq!(
            sample.e0_rns.coefficients().len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
        assert_eq!(
            sample.e1_rns.coefficients().len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
    }
}
