// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the share-encryption circuit: DKG public key, plaintext,
//! ciphertext, and encryption randomness (u_rns, e0_rns, e1_rns) for testing and codegen.

use e3_committee::CiphernodesCommittee;
use e3_fhe_params::{generate_smudging_error, BfvPreset};
use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_encryption::ShareEncryptionCircuitData;
use e3_zk_witness::WitnessError;
use fhe::bfv::Encoding;
use fhe::bfv::Plaintext;
use fhe::bfv::{PublicKey, SecretKey};
use fhe::trbfv::ShareManager;
use fhe_math::rq::Poly;
use fhe_traits::FheEncoder;

use fhe::bfv::BfvParameters;
use std::sync::Arc;
pub fn generate(
    threshold_params: &Arc<BfvParameters>,
    dkg_params: &Arc<BfvParameters>,
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    dkg_input_type: DkgInputType,
    num_ciphertexts: u128, // z in the search defaults
) -> Result<ShareEncryptionCircuitData, WitnessError> {
    let mut rng = rand::rng();

    // Lambda is secure or insecure depending on the preset's security tier.
    let lambda = preset
        .lambda()
        .map_err(|e| WitnessError::Sample(e.to_string()))?;

    let dkg_secret_key = SecretKey::random(&dkg_params, &mut rng);
    let dkg_public_key = PublicKey::new(&dkg_secret_key, &mut rng);

    let share_manager =
        ShareManager::new(committee.n, committee.threshold, threshold_params.clone())
            .map_err(|e| WitnessError::Sample(format!("Failed to create ShareManager: {:?}", e)))?;

    let share_row = match dkg_input_type {
        DkgInputType::SecretKey => {
            let threshold_secret_key = SecretKey::random(&threshold_params, &mut rng);

            let sk_poly = share_manager
                .coeffs_to_poly_level0(threshold_secret_key.coeffs.clone().as_ref())
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to convert secret key to poly: {:?}", e))
                })?;

            let sk_sss_u64 = share_manager
                .generate_secret_key_shares(sk_poly.clone(), &mut rng)
                .map(|shares| shares.into_transport())
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to generate secret shares: {:?}", e))
                })?;

            sk_sss_u64[0].row(0).to_vec()
        }
        DkgInputType::SmudgingNoise => {
            let sd = preset
                .search_defaults()
                .ok_or_else(|| WitnessError::Sample("Preset has no search defaults".into()))?;
            let esi_coeffs = generate_smudging_error(
                threshold_params.clone(),
                committee.n,
                num_ciphertexts as usize,
                sd.mult_depth,
                lambda,
                &mut rng,
            )
            .map_err(|e| {
                WitnessError::Sample(format!("Failed to generate smudging error: {:?}", e))
            })
            .map_err(|e| {
                WitnessError::Sample(format!("Failed to generate smudging error: {:?}", e))
            })?;
            let esi_poly = Poly::from_bigints(
                &esi_coeffs,
                threshold_params.context_at_level(0).map_err(|e| {
                    WitnessError::Sample(format!("Failed to get BFV context: {:?}", e))
                })?,
            )
            .map_err(|e| {
                WitnessError::Sample(format!("Failed to convert error to poly: {:?}", e))
            })?;
            let esi_sss_u64 = share_manager
                .generate_secret_key_shares(esi_poly.clone(), &mut rng.clone())
                .map(|shares| shares.into_transport())
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to generate error shares: {:?}", e))
                })?;

            esi_sss_u64[0].row(0).to_vec()
        }
    };

    let pt = Plaintext::try_encode(&share_row, Encoding::poly(), &dkg_params)
        .map_err(|e| WitnessError::Sample(format!("Failed to encode plaintext: {:?}", e)))?;

    let (ct, intermediates) =
        e3_zk_witness::encrypt_with_intermediates(&dkg_public_key, &pt, &mut rng)
            .map_err(|e| WitnessError::Sample(format!("Failed to encrypt extended: {:?}", e)))?;

    Ok(ShareEncryptionCircuitData {
        dkg_input_type,
        plaintext: pt,
        ciphertext: ct,
        public_key: dkg_public_key,

        u_rns: intermediates.randomness().clone(),
        e0_rns: intermediates.error_0().clone(),
        e1_rns: intermediates.error_1().clone(),

        party_idx: 0,
        mod_idx: 0,
        chunk_size: e3_zk_config::chunks::c2_chunk_size(dkg_params.degree(), committee.n) as u32,
        committee,
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
        let sd = BfvPreset::InsecureThreshold.search_defaults().unwrap();
        let (threshold_params, dkg_params) = BfvPreset::InsecureThreshold.build_pair().unwrap();
        let sample = generate(
            &threshold_params,
            &dkg_params,
            BfvPreset::InsecureThreshold,
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
            BfvPreset::InsecureThreshold.metadata().degree
        );
        assert_eq!(sample.ciphertext.len(), 2);
        assert_eq!(
            sample.u_rns.coefficients().len(),
            BfvPreset::InsecureThreshold.metadata().degree
                * e3_fhe_params::constants::insecure::dkg::MODULI.len()
        );
        assert_eq!(
            sample.e0_rns.coefficients().len(),
            BfvPreset::InsecureThreshold.metadata().degree
                * e3_fhe_params::constants::insecure::dkg::MODULI.len()
        );
        assert_eq!(
            sample.e1_rns.coefficients().len(),
            BfvPreset::InsecureThreshold.metadata().degree
                * e3_fhe_params::constants::insecure::dkg::MODULI.len()
        );
    }

    #[test]
    fn test_generate_smudging_noise_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold.search_defaults().unwrap();
        let (threshold_params, dkg_params) = BfvPreset::InsecureThreshold.build_pair().unwrap();
        let sample = generate(
            &threshold_params,
            &dkg_params,
            BfvPreset::InsecureThreshold,
            committee,
            DkgInputType::SmudgingNoise,
            sd.z,
        )
        .unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
        assert_eq!(sample.ciphertext.len(), 2);
        assert_eq!(
            sample.u_rns.coefficients().len(),
            BfvPreset::InsecureThreshold.metadata().degree
                * e3_fhe_params::constants::insecure::dkg::MODULI.len()
        );
        assert_eq!(
            sample.e0_rns.coefficients().len(),
            BfvPreset::InsecureThreshold.metadata().degree
                * e3_fhe_params::constants::insecure::dkg::MODULI.len()
        );
        assert_eq!(
            sample.e1_rns.coefficients().len(),
            BfvPreset::InsecureThreshold.metadata().degree
                * e3_fhe_params::constants::insecure::dkg::MODULI.len()
        );
    }
}
