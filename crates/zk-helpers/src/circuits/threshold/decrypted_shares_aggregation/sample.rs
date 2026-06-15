// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for decrypted shares aggregation circuit.
//!
//! Produces TRBFV parties with secret/public key shares, collects and aggregates shares,
//! encrypts a message, computes T+1 decryption shares, and decrypts to obtain the message.
//! The result is used as inputs for computation and codegen.

use crate::circuits::computation::Computation;
use crate::threshold::decrypted_shares_aggregation::computation::Configs;
use crate::CircuitsErrors;
use crate::{
    threshold::decrypted_shares_aggregation::DecryptedSharesAggregationCircuitData,
    CiphernodesCommittee,
};
use e3_fhe_params::{build_pair_for_preset, create_deterministic_crp_from_default_seed, BfvPreset};
use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe::mbfv::{AggregateIter, PublicKeyShare};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::FheDecoder;
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::Array2;
use std::sync::Arc;

struct Party {
    pk_share: PublicKeyShare,
    sk_sss: Vec<Array2<u64>>,
    esi_sss: Vec<Array2<u64>>,
    sk_sss_collected: Vec<Array2<u64>>,
    es_sss_collected: Vec<Array2<u64>>,
    sk_poly_sum: Poly<PowerBasis>,
    es_poly_sum: Poly<PowerBasis>,
}

impl DecryptedSharesAggregationCircuitData {
    /// Generates sample data for the decrypted shares aggregation circuit:
    /// TRBFV setup, parties with sk/pk shares and smudging error shares, share collection
    /// and aggregation, encryption of a message, T+1 decryption shares, and threshold decrypt.
    pub fn generate_sample(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
    ) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) = build_pair_for_preset(preset).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e))
        })?;

        let sd = preset
            .search_defaults()
            .ok_or_else(|| CircuitsErrors::Sample("Preset has no search defaults".into()))?;
        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = preset
            .lambda()
            .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let num_parties = committee.n;
        let threshold = committee.threshold;
        let degree = threshold_params.degree();
        let num_moduli = threshold_params.moduli().len();

        let trbfv = TRBFV::new(num_parties, threshold, threshold_params.clone())
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to create TRBFV: {:?}", e)))?;
        let mut rng = rand::rng();

        let crp = create_deterministic_crp_from_default_seed(&threshold_params);

        let ctx = threshold_params.context_at_level(0).unwrap();

        let mut parties: Vec<Party> = (0..num_parties)
            .map(|_| -> Result<Party, CircuitsErrors> {
                let sk_share = SecretKey::random(&threshold_params, &mut rng);
                let pk_share =
                    PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).map_err(|e| {
                        CircuitsErrors::Sample(format!(
                            "Failed to create public key share: {:?}",
                            e
                        ))
                    })?;

                let mut share_manager = ShareManager::new(
                    num_parties,
                    threshold,
                    threshold_params.clone(),
                )
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e))
                })?;
                let sk_poly = share_manager
                    .coeffs_to_poly_level0(sk_share.coeffs.as_ref())
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!(
                            "Failed to convert secret key to poly: {:?}",
                            e
                        ))
                    })?;

                let sk_sss = share_manager
                    .generate_secret_shares_from_poly(sk_poly, &mut rng)
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to generate secret shares: {:?}", e))
                    })?;

                let esi_coeffs = trbfv
                    .generate_smudging_error(sd.z as usize, lambda, &mut rng)
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!(
                            "Failed to generate smudging error: {:?}",
                            e
                        ))
                    })?;
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to convert error to poly: {:?}", e))
                })?;
                let esi_sss = share_manager
                    .generate_secret_shares_from_poly(esi_poly, &mut rng)
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to generate error shares: {:?}", e))
                    })?;

                let sk_sss_collected = Vec::with_capacity(num_parties);
                let es_sss_collected = Vec::with_capacity(num_parties);
                let sk_poly_sum = Poly::<PowerBasis>::zero(ctx);
                let es_poly_sum = Poly::<PowerBasis>::zero(ctx);

                Ok(Party {
                    pk_share,
                    sk_sss,
                    esi_sss,
                    sk_sss_collected,
                    es_sss_collected,
                    sk_poly_sum,
                    es_poly_sum,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Collect shares: for each party i, sk_sss_collected is one Array2 per sender j
        // (same as Vec<ShamirShare>). Each Array2 has shape (num_moduli, degree): row m = share from j for modulus m.
        for i in 0..num_parties {
            parties[i].sk_sss_collected = (0..num_parties)
                .map(|j| {
                    let data: Vec<u64> = (0..num_moduli)
                        .flat_map(|m| {
                            parties[j].sk_sss[m]
                                .row(i)
                                .iter()
                                .copied()
                                .collect::<Vec<_>>()
                        })
                        .collect();
                    Array2::from_shape_vec((num_moduli, degree), data).map_err(|e| {
                        CircuitsErrors::Sample(format!("sk_sss_collected shape: {:?}", e))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to collect sk_sss_collected: {:?}", e))
                })?;
            parties[i].es_sss_collected = (0..num_parties)
                .map(|j| {
                    let data: Vec<u64> = (0..num_moduli)
                        .flat_map(|m| {
                            parties[j].esi_sss[m]
                                .row(i)
                                .iter()
                                .copied()
                                .collect::<Vec<_>>()
                        })
                        .collect();
                    Array2::from_shape_vec((num_moduli, degree), data).map_err(|e| {
                        CircuitsErrors::Sample(format!("es_sss_collected shape: {:?}", e))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to collect es_sss_collected: {:?}", e))
                })?;
        }

        // Aggregate collected shares to get sk_poly_sum and es_poly_sum per party
        for party in parties.iter_mut() {
            let share_manager = ShareManager::new(num_parties, threshold, threshold_params.clone())
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e))
                })?;
            party.sk_poly_sum = share_manager
                .aggregate_collected_shares(&party.sk_sss_collected)
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to aggregate collected shares: {:?}", e))
                })?;
            party.es_poly_sum = share_manager
                .aggregate_collected_shares(&party.es_sss_collected)
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to aggregate collected shares: {:?}", e))
                })?;
        }

        // Aggregate public key
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .collect::<Vec<_>>()
            .iter()
            .cloned()
            .aggregate()
            .map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to aggregate public key: {:?}", e))
            })?;

        // Build message: max_msg_non_zero_coeffs from config, tiled from CRISP-style pattern, pad to degree
        let configs = Configs::compute(preset, &())
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to compute configs: {:?}", e)))?;
        let n = configs.max_msg_non_zero_coeffs;
        let pattern: Vec<u64> = vec![
            2, 1, 5, 2, 1, 2, 3, 2, 4, 3, 3, 3, 2, 3, 3, 1, 2, 3, 4, 6, 1, 5, 1, 1, 2, 1, 2,
        ];
        let mut message: Vec<u64> = (0..n).map(|i| pattern[i % pattern.len()]).collect();
        message.resize(degree, 0);

        let pt = Plaintext::try_encode(&message, Encoding::poly(), &threshold_params)
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to encode plaintext: {:?}", e)))?;
        let ciphertext = public_key
            .try_encrypt(&pt, &mut rng)
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to encrypt: {:?}", e)))?;

        let ciphertext = Arc::new(ciphertext);

        // Decryption shares from T+1 parties (1-based party IDs)
        let honest_parties = threshold + 1;
        let mut d_share_polys: Vec<Poly<PowerBasis>> = Vec::with_capacity(honest_parties);

        for party in parties.iter().take(honest_parties) {
            let share_manager = ShareManager::new(num_parties, threshold, threshold_params.clone())
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e))
                })?;
            // For a single ciphertext, es_poly_sum is one Poly per party
            let d_share = share_manager
                .decryption_share(
                    Arc::clone(&ciphertext),
                    party.sk_poly_sum.clone().into_ntt(),
                    party.es_poly_sum.clone(),
                )
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to compute decryption share: {:?}", e))
                })?;
            d_share_polys.push(d_share);
        }

        let reconstructing_parties: Vec<usize> = (1..=honest_parties).collect();

        // Threshold decrypt to obtain message (verify)
        let share_manager = ShareManager::new(num_parties, threshold, threshold_params.clone())
            .map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e))
            })?;
        let plaintext = share_manager
            .decrypt_from_shares(
                d_share_polys.clone(),
                reconstructing_parties.clone(),
                Arc::clone(&ciphertext),
            )
            .map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to decrypt from shares: {:?}", e))
            })?;

        let message_vec = Vec::<u64>::try_decode(&plaintext, Encoding::poly())
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to decode plaintext: {:?}", e)))?;

        Ok(DecryptedSharesAggregationCircuitData {
            committee,
            d_share_polys,
            reconstructing_parties,
            message_vec,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        computation::Computation,
        threshold::decrypted_shares_aggregation::{DecryptedSharesAggregationCircuitData, Inputs},
        CiphernodesCommitteeSize,
    };
    use e3_fhe_params::BfvPreset;
    use num_bigint::BigInt;

    /// Sample generation and input computation: output shapes match circuit expectations.
    #[test]
    fn test_generate_sample() {
        let preset = BfvPreset::InsecureThreshold512;
        let committee = CiphernodesCommitteeSize::Small.values();

        let sample =
            DecryptedSharesAggregationCircuitData::generate_sample(preset, committee).unwrap();
        let inputs = Inputs::compute(preset, &sample).unwrap();

        assert_eq!(
            inputs.decryption_shares.len(),
            sample.committee.threshold + 1
        );
        assert_eq!(inputs.party_ids.len(), sample.reconstructing_parties.len());
        let configs =
            crate::threshold::decrypted_shares_aggregation::computation::Configs::compute(
                preset,
                &(),
            )
            .unwrap();
        assert_eq!(
            inputs.message.coefficients().len(),
            configs.max_msg_non_zero_coeffs
        );
    }

    /// Input message matches sample (ascending order: index 0 = constant term).
    #[test]
    fn test_input_message_matches_sample() {
        use crate::threshold::decrypted_shares_aggregation::computation::Configs;
        let preset = BfvPreset::InsecureThreshold512;
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample =
            DecryptedSharesAggregationCircuitData::generate_sample(preset, committee).unwrap();
        let inputs = Inputs::compute(preset, &sample).unwrap();
        let configs = Configs::compute(preset, &()).unwrap();
        let n = configs.max_msg_non_zero_coeffs;
        for i in 0..n {
            let expected = sample.message_vec.get(i).copied().unwrap_or(0);
            let w = &inputs.message.coefficients()[i];
            let exp = BigInt::from(expected);
            assert_eq!(w, &exp, "message coeff {} mismatch", i);
        }
    }
}
