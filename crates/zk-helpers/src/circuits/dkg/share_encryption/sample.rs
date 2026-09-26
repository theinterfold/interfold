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
use e3_fhe_params::{build_pair_for_preset, generate_smudging_error, BfvPreset};
use fhe::bfv::Encoding;
use fhe::bfv::Plaintext;
use fhe::bfv::{PublicKey, SecretKey};
use fhe::trbfv::ShareManager;
use fhe_math::rq::Poly;
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

        let share_manager =
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
                    .generate_secret_key_shares(sk_poly.clone(), &mut rng)
                    .map(|shares| shares.into_transport())
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to generate secret shares: {:?}", e))
                    })?;

                sk_sss_u64[0].row(0).to_vec()
            }
            DkgInputType::SmudgingNoise => {
                let sd = preset.search_defaults().ok_or_else(|| {
                    CircuitsErrors::Sample("Preset has no search defaults".into())
                })?;
                let esi_coeffs = generate_smudging_error(
                    threshold_params.clone(),
                    committee.n,
                    num_ciphertexts as usize,
                    sd.mult_depth,
                    lambda,
                    &mut rng,
                )
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to generate smudging error: {:?}", e))
                })
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to generate smudging error: {:?}", e))
                })?;
                let esi_poly = Poly::from_bigints(
                    &esi_coeffs,
                    threshold_params.context_at_level(0).map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to get BFV context: {:?}", e))
                    })?,
                )
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to convert error to poly: {:?}", e))
                })?;
                let esi_sss_u64 = share_manager
                    .generate_secret_key_shares(esi_poly.clone(), &mut rng.clone())
                    .map(|shares| shares.into_transport())
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
            party_idx: 0,
            mod_idx: 0,
            chunk_size: dkg_params.degree().min(512) as u32,
            committee,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{computation::DkgInputType, CiphernodesCommitteeSize};
    use e3_fhe_params::{build_pair_for_preset, BfvPreset};

    #[test]
    fn test_generate_secret_key_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold.search_defaults().unwrap();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold,
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
            BfvPreset::InsecureThreshold.metadata().degree
        );
        assert_eq!(sample.ciphertext.len(), 2);
        let (_, dkg_params) = build_pair_for_preset(BfvPreset::InsecureThreshold).unwrap();
        assert_eq!(
            sample.u_rns.coefficients().len(),
            dkg_params.degree() * dkg_params.moduli().len()
        );
        assert_eq!(
            sample.e0_rns.coefficients().len(),
            dkg_params.degree() * dkg_params.moduli().len()
        );
        assert_eq!(
            sample.e1_rns.coefficients().len(),
            dkg_params.degree() * dkg_params.moduli().len()
        );
    }

    #[test]
    fn test_generate_smudging_noise_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold.search_defaults().unwrap();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold,
            committee,
            DkgInputType::SmudgingNoise,
            sd.z,
        )
        .unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
        assert_eq!(sample.ciphertext.len(), 2);
        let (_, dkg_params) = build_pair_for_preset(BfvPreset::InsecureThreshold).unwrap();
        assert_eq!(
            sample.u_rns.coefficients().len(),
            dkg_params.degree() * dkg_params.moduli().len()
        );
        assert_eq!(
            sample.e0_rns.coefficients().len(),
            dkg_params.degree() * dkg_params.moduli().len()
        );
        assert_eq!(
            sample.e1_rns.coefficients().len(),
            dkg_params.degree() * dkg_params.moduli().len()
        );
    }
}
