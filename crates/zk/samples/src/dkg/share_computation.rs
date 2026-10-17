// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the share-computation circuit: committee, DKG public key,
//! secret (SK or smudging noise) in CRT form and Shamir shares.

use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use e3_zk_config::{dkg::share_computation::Configs, DkgInputType};
use e3_zk_witness::dkg::share_computation::ShareComputationCircuitData;
use e3_zk_witness::WitnessError;
use fhe::bfv::SecretKey;
use fhe::trbfv::ShareManager;
use num_bigint::BigInt;

/// Generates sample data for the share-computation circuit.
pub fn generate(
    config: &Configs,
    preset: BfvPreset,
    dkg_input_type: DkgInputType,
) -> Result<ShareComputationCircuitData, WitnessError> {
    let threshold_params = &config.params;
    let committee = config.committee.values();
    let mut rng = rand::rng();

    let mut share_manager =
        ShareManager::new(committee.n, committee.threshold, threshold_params.clone())
            .map_err(|e| WitnessError::Sample(format!("Failed to create ShareManager: {:?}", e)))?;

    let (secret, secret_sss) = match dkg_input_type {
        DkgInputType::SecretKey => {
            let threshold_secret_key = SecretKey::random(&threshold_params, &mut rng);

            let sk_poly = share_manager
                .coeffs_to_poly_level0(threshold_secret_key.coeffs.as_ref())
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to convert secret key to poly: {:?}", e))
                })?;

            let sk_sss_u64 = share_manager
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to generate secret shares: {:?}", e))
                })?;

            let secret_sss = sk_sss_u64
                .into_iter()
                .map(|arr| arr.mapv(BigInt::from))
                .collect();

            let sk_coeffs: Vec<BigInt> = threshold_secret_key
                .coeffs
                .iter()
                .map(|&c| BigInt::from(c))
                .collect();
            let mut secret_crt =
                CrtPolynomial::from_mod_q_polynomial(&sk_coeffs, threshold_params.moduli());
            secret_crt.center(threshold_params.moduli()).map_err(|e| {
                WitnessError::Sample(format!("Failed to center secret CRT: {:?}", e))
            })?;

            (secret_crt, secret_sss)
        }
        DkgInputType::SmudgingNoise => {
            // C2 samples with committee.n ciphertexts, not the other families' default z.
            let noise =
                crate::smudging::generator(threshold_params, committee.n, committee.n, preset)?;
            let esi_coeffs = noise.generate_smudging_error(&mut rng).map_err(|e| {
                WitnessError::Sample(format!("Failed to generate smudging error: {:?}", e))
            })?;
            let esi_poly = share_manager.bigints_to_poly(&esi_coeffs)?;
            let esi_sss_u64 = share_manager
                .generate_secret_shares_from_poly(esi_poly, &mut rng)
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to generate error shares: {:?}", e))
                })?;
            let secret_sss = esi_sss_u64
                .into_iter()
                .map(|arr| arr.mapv(BigInt::from))
                .collect();

            let mut secret_crt =
                CrtPolynomial::from_mod_q_polynomial(&esi_coeffs, threshold_params.moduli());
            secret_crt.center(threshold_params.moduli())?;

            (secret_crt, secret_sss)
        }
    };

    Ok(ShareComputationCircuitData {
        dkg_input_type,
        secret,
        secret_sss,
    })
}

#[cfg(test)]
mod tests {
    use super::generate;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvPreset;
    use e3_zk_config::DkgInputType;

    #[test]
    fn test_generate_secret_key_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let config = e3_zk_config::dkg::share_computation::Configs::for_preset(
            BfvPreset::InsecureThreshold64,
            CiphernodesCommitteeSize::Small,
        )
        .unwrap();
        let sample = generate(
            &config,
            BfvPreset::InsecureThreshold64,
            DkgInputType::SecretKey,
        )
        .unwrap();
        assert_eq!(sample.secret_sss[0].nrows(), committee.n);
        assert_eq!(sample.dkg_input_type, DkgInputType::SecretKey);
        assert_eq!(
            sample.secret_sss.len(),
            e3_fhe_params::constants::insecure_64::threshold::MODULI.len()
        );
        assert_eq!(
            sample.secret.limbs.len(),
            e3_fhe_params::constants::insecure_64::threshold::MODULI.len()
        );
    }

    #[test]
    fn test_generate_smudging_noise_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let config = e3_zk_config::dkg::share_computation::Configs::for_preset(
            BfvPreset::InsecureThreshold64,
            CiphernodesCommitteeSize::Small,
        )
        .unwrap();
        let sample = generate(
            &config,
            BfvPreset::InsecureThreshold64,
            DkgInputType::SmudgingNoise,
        )
        .unwrap();
        assert_eq!(sample.secret_sss[0].nrows(), committee.n);
        assert_eq!(sample.dkg_input_type, DkgInputType::SmudgingNoise);
        assert_eq!(
            sample.secret_sss.len(),
            e3_fhe_params::constants::insecure_64::threshold::MODULI.len()
        );
        assert_eq!(
            sample.secret.limbs.len(),
            e3_fhe_params::constants::insecure_64::threshold::MODULI.len()
        );
    }
}
