// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the share-computation circuit: committee, DKG public key,
//! secret (SK or smudging noise) in CRT form, Shamir shares, and parity matrices.

type SecretShares = Vec<ndarray::Array2<BigInt>>;
use e3_fhe_params::{generate_smudging_error, BfvPreset};
use e3_polynomial::CrtPolynomial;
use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_computation::ShareComputationCircuitData;
use e3_zk_witness::WitnessError;
use fhe::bfv::SecretKey;
use fhe::trbfv::ShareManager;
use fhe_math::rq::Poly;
use num_bigint::BigInt;

use e3_zk_config::dkg::share_computation::Configs;
pub fn generate(
    config: &Configs,
    preset: BfvPreset,
    dkg_input_type: DkgInputType,
) -> Result<ShareComputationCircuitData, WitnessError> {
    let threshold_params = &config.params;
    let committee = config.committee.values();

    let mut rng = rand::rng();

    let share_manager =
        ShareManager::new(committee.n, committee.threshold, threshold_params.clone())
            .map_err(|e| WitnessError::Sample(format!("Failed to create ShareManager: {:?}", e)))?;

    let (secret, secret_sss) = match dkg_input_type {
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

            let secret_sss: SecretShares = sk_sss_u64
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
            let lambda = preset
                .lambda()
                .map_err(|e| WitnessError::Sample(e.to_string()))?;
            let sd = preset
                .search_defaults()
                .ok_or_else(|| WitnessError::Sample("Preset has no search defaults".into()))?;
            let esi_coeffs = generate_smudging_error(
                threshold_params.clone(),
                committee.n,
                sd.z as usize,
                sd.mult_depth,
                lambda,
                &mut rng,
            )
            .map_err(|e| {
                WitnessError::Sample(format!("Failed to generate smudging error: {:?}", e))
            })
            .unwrap();
            let esi_poly =
                Poly::from_bigints(&esi_coeffs, threshold_params.context_at_level(0).unwrap())
                    .unwrap();
            let esi_sss_u64 = share_manager
                .generate_secret_key_shares(esi_poly.clone(), &mut rng)
                .map(|shares| shares.into_transport())
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to generate error shares: {:?}", e))
                })
                .unwrap();
            let secret_sss: SecretShares = esi_sss_u64
                .into_iter()
                .map(|arr| arr.mapv(BigInt::from))
                .collect();

            let mut secret_crt =
                CrtPolynomial::from_mod_q_polynomial(&esi_coeffs, threshold_params.moduli());
            secret_crt.center(threshold_params.moduli()).unwrap();

            (secret_crt, secret_sss)
        }
    };

    Ok(ShareComputationCircuitData {
        parity_matrix: e3_zk_config::dkg::share_computation::parity::compute_parity_matrix(
            threshold_params.moduli(),
            committee.n,
            committee.threshold,
        )
        .map_err(WitnessError::Sample)?,
        n_parties: committee.n as u32,
        threshold: committee.threshold as u32,
        chunk_size: config.chunk_size as u32,
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
            e3_fhe_params::constants::insecure::threshold::MODULI.len()
        );
        assert_eq!(
            sample.secret.limbs.len(),
            e3_fhe_params::constants::insecure::threshold::MODULI.len()
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
            e3_fhe_params::constants::insecure::threshold::MODULI.len()
        );
        assert_eq!(
            sample.secret.limbs.len(),
            e3_fhe_params::constants::insecure::threshold::MODULI.len()
        );
    }
}
#[cfg(test)]
mod chunk_tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_zk_witness::dkg::share_computation::{prepare_chunk, Inputs};

    #[test]
    fn chunk_leaves_preserve_every_coefficient_and_lift() {
        let preset = BfvPreset::InsecureThresholdLbfv;
        let config = Configs::for_preset(preset, CiphernodesCommitteeSize::Minimum)
            .unwrap()
            .with_chunk_size(64)
            .unwrap();
        for kind in [DkgInputType::SecretKey, DkgInputType::SmudgingNoise] {
            let data = generate(&config, preset, kind).unwrap();
            let inputs = Inputs::compute(&config, &data).unwrap();
            let whole = inputs.to_json();
            let mut y = Vec::new();
            let mut lift = Vec::new();
            for index in 0..2 {
                let chunk = prepare_chunk(&config, &data, index).unwrap();
                assert_eq!(chunk["chunk_idx"], index);
                y.extend(chunk["y_chunk"].as_array().unwrap().iter().cloned());
                if kind == DkgInputType::SmudgingNoise {
                    lift.extend(
                        chunk["e_sm_lifted_chunk"]["coefficients"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .cloned(),
                    );
                    for limb in chunk["e_sm_quotients_chunk"].as_array().unwrap() {
                        assert_eq!(limb["coefficients"].as_array().unwrap().len(), 64);
                    }
                } else {
                    assert_eq!(
                        chunk["secret_chunk"]["coefficients"]
                            .as_array()
                            .unwrap()
                            .len(),
                        64
                    );
                }
            }
            assert_eq!(serde_json::Value::Array(y), whole["y"]);
            if kind == DkgInputType::SmudgingNoise {
                assert_eq!(
                    serde_json::Value::Array(lift),
                    whole["e_sm_lifted"]["coefficients"]
                );
            }
            assert!(prepare_chunk(&config, &data, 2).is_err());
        }
    }
}
