// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the share-computation circuit: committee, DKG public key,
//! secret (SK or smudging noise) in CRT form, Shamir shares, and parity matrices.

use crate::circuits::dkg::share_computation::utils::compute_parity_matrix;
use crate::computation::DkgInputType;
use crate::dkg::share_computation::ShareComputationCircuitData;
use crate::math::array2_u64_to_bigint;
use crate::CiphernodesCommittee;
use crate::CircuitsErrors;
use e3_fhe_params::{build_pair_for_preset, generate_smudging_error, BfvPreset};
use e3_polynomial::CrtPolynomial;
use fhe::bfv::SecretKey;
use fhe::trbfv::ShareManager;
use fhe_math::rq::Poly;
use num_bigint::BigInt;

pub type SecretShares = Vec<ndarray::Array2<BigInt>>;

impl ShareComputationCircuitData {
    /// Generates sample data for the share-computation circuit.
    pub fn generate_sample(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
        dkg_input_type: DkgInputType,
    ) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) = build_pair_for_preset(preset).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e))
        })?;
        let mut rng = rand::rng();

        let share_manager =
            ShareManager::new(committee.n, committee.threshold, threshold_params.clone()).map_err(
                |e| CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e)),
            )?;

        let parity_matrix =
            compute_parity_matrix(threshold_params.moduli(), committee.n, committee.threshold)
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to compute parity matrix: {:?}", e))
                })?;

        let (secret, secret_sss) = match dkg_input_type {
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

                let secret_sss: SecretShares = sk_sss_u64
                    .into_iter()
                    .map(|arr| array2_u64_to_bigint(&arr))
                    .collect();

                let sk_coeffs: Vec<BigInt> = threshold_secret_key
                    .coeffs
                    .iter()
                    .map(|&c| BigInt::from(c))
                    .collect();
                let mut secret_crt =
                    CrtPolynomial::from_mod_q_polynomial(&sk_coeffs, threshold_params.moduli());
                secret_crt.center(threshold_params.moduli()).map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to center secret CRT: {:?}", e))
                })?;

                (secret_crt, secret_sss)
            }
            DkgInputType::SmudgingNoise => {
                let lambda = preset
                    .lambda()
                    .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
                let sd = preset.search_defaults().ok_or_else(|| {
                    CircuitsErrors::Sample("Preset has no search defaults".into())
                })?;
                let esi_coeffs = generate_smudging_error(
                    threshold_params.clone(),
                    committee.n,
                    sd.z as usize,
                    sd.mult_depth,
                    lambda,
                    &mut rng,
                )
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to generate smudging error: {:?}", e))
                })
                .unwrap();
                let esi_poly =
                    Poly::from_bigints(&esi_coeffs, threshold_params.context_at_level(0).unwrap())
                        .unwrap();
                let esi_sss_u64 = share_manager
                    .generate_secret_key_shares(esi_poly.clone(), &mut rng)
                    .map(|shares| shares.into_transport())
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to generate error shares: {:?}", e))
                    })
                    .unwrap();
                let secret_sss: SecretShares = esi_sss_u64
                    .into_iter()
                    .map(|arr| array2_u64_to_bigint(&arr))
                    .collect();

                let mut secret_crt =
                    CrtPolynomial::from_mod_q_polynomial(&esi_coeffs, threshold_params.moduli());
                secret_crt.center(threshold_params.moduli()).unwrap();

                (secret_crt, secret_sss)
            }
        };

        Ok(Self {
            dkg_input_type,
            n_parties: committee.n as u32,
            threshold: committee.threshold as u32,
            chunk_size: threshold_params.degree().min(512) as u32,
            secret,
            secret_sss,
            parity_matrix,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphernodes_committee::CiphernodesCommitteeSize;
    use crate::computation::DkgInputType;
    use crate::dkg::share_computation::ShareComputationCircuitData;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_secret_key_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold,
            committee.clone(),
            DkgInputType::SecretKey,
        )
        .unwrap();
        assert_eq!(sample.n_parties, committee.n as u32);
        assert_eq!(sample.threshold, committee.threshold as u32);
        assert_eq!(sample.dkg_input_type, DkgInputType::SecretKey);
        assert_eq!(sample.secret_sss.len(), 3);
        assert_eq!(sample.secret.limbs.len(), 3);
    }

    #[test]
    fn test_generate_smudging_noise_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold,
            committee.clone(),
            DkgInputType::SmudgingNoise,
        )
        .unwrap();
        assert_eq!(sample.n_parties, committee.n as u32);
        assert_eq!(sample.threshold, committee.threshold as u32);
        assert_eq!(sample.dkg_input_type, DkgInputType::SmudgingNoise);
        assert_eq!(sample.secret_sss.len(), 3);
        assert_eq!(sample.secret.limbs.len(), 3);
    }
}
