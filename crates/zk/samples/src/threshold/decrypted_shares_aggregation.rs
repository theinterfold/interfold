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

use e3_fhe_params::{create_deterministic_crp_from_default_seed, BfvPreset};
use e3_zk_config::threshold::decrypted_shares_aggregation::Configs;
use e3_zk_witness::threshold::decrypted_shares_aggregation::DecryptedSharesAggregationCircuitData;
use e3_zk_witness::WitnessError;
use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe::mbfv::{AggregateIter, PublicKeyShare};
use fhe::trbfv::ShareManager;
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::FheDecoder;
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::Array2;
use std::sync::Arc;

struct Party {
    sk_sss: Vec<Array2<u64>>,
    esi_sss: Vec<Array2<u64>>,
}

/// Generates sample data for the decrypted shares aggregation circuit:
/// TRBFV setup, parties with sk/pk shares and smudging error shares, share collection
/// and aggregation, encryption of a message, T+1 decryption shares, and threshold decrypt.
pub fn generate(
    config: &Configs,
    preset: BfvPreset,
) -> Result<DecryptedSharesAggregationCircuitData, WitnessError> {
    let threshold_params = &config.params;
    let committee = config.committee.values();

    let sd = preset
        .search_defaults()
        .ok_or_else(|| WitnessError::Sample("Preset has no search defaults".into()))?;
    let num_parties = committee.n;
    let threshold = committee.threshold;
    let degree = threshold_params.degree();
    let width = config.max_msg_non_zero_coeffs;
    if width > degree {
        return Err(WitnessError::Sample(
            "sample message width exceeds the BFV degree".into(),
        ));
    }
    let mut share_manager = ShareManager::new(num_parties, threshold, threshold_params.clone())?;
    let noise = crate::smudging::generator(
        threshold_params,
        num_parties,
        usize::try_from(sd.z).map_err(|e| WitnessError::Sample(e.to_string()))?,
        preset,
    )?;
    let mut rng = rand::rng();

    let crp = create_deterministic_crp_from_default_seed(threshold_params);
    let mut pk_shares = Vec::with_capacity(num_parties);

    let parties: Vec<Party> = (0..num_parties)
        .map(|_| -> Result<Party, WitnessError> {
            let sk_share = SecretKey::random(threshold_params, &mut rng);
            let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).map_err(|e| {
                WitnessError::Sample(format!("Failed to create public key share: {:?}", e))
            })?;

            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk_share.coeffs.as_ref())
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to convert secret key to poly: {:?}", e))
                })?;

            let sk_sss = share_manager
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to generate secret shares: {:?}", e))
                })?;

            let esi_coeffs = noise.generate_smudging_error(&mut rng).map_err(|e| {
                WitnessError::Sample(format!("Failed to generate smudging error: {:?}", e))
            })?;
            let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).map_err(|e| {
                WitnessError::Sample(format!("Failed to convert error to poly: {:?}", e))
            })?;
            let esi_sss = share_manager
                .generate_secret_shares_from_poly(esi_poly, &mut rng)
                .map_err(|e| {
                    WitnessError::Sample(format!("Failed to generate error shares: {:?}", e))
                })?;

            pk_shares.push(pk_share);
            Ok(Party { sk_sss, esi_sss })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Aggregate public key
    let public_key: PublicKey = pk_shares
        .into_iter()
        .aggregate()
        .map_err(|e| WitnessError::Sample(format!("Failed to aggregate public key: {:?}", e)))?;

    // Use the supplied message prefix width, then pad the plaintext to the BFV degree.
    let pattern = [
        2, 1, 5, 2, 1, 2, 3, 2, 4, 3, 3, 3, 2, 3, 3, 1, 2, 3, 4, 6, 1, 5, 1, 1, 2, 1, 2,
    ];
    let mut message: Vec<u64> = (0..width).map(|i| pattern[i % pattern.len()]).collect();
    message.resize(degree, 0);

    let pt = Plaintext::try_encode(&message, Encoding::poly(), threshold_params)
        .map_err(|e| WitnessError::Sample(format!("Failed to encode plaintext: {:?}", e)))?;
    let ciphertext = public_key
        .try_encrypt(&pt, &mut rng)
        .map_err(|e| WitnessError::Sample(format!("Failed to encrypt: {:?}", e)))?;

    let ciphertext = Arc::new(ciphertext);

    // Decryption shares from T+1 parties (1-based party IDs)
    let reconstructing_count = threshold + 1;
    let mut d_share_polys: Vec<Poly<PowerBasis>> = Vec::with_capacity(reconstructing_count);

    for receiver in 0..reconstructing_count {
        // Keep every dealer contribution, but only collect the recipients used for reconstruction.
        // Each temporary contribution set is dropped after aggregation.
        let sk_poly_sum = share_manager.aggregate_collected_shares(
            &parties
                .iter()
                .map(|party| super::receiver_shares(&party.sk_sss, receiver, threshold_params))
                .collect::<Vec<_>>(),
        )?;
        let es_poly_sum = share_manager.aggregate_collected_shares(
            &parties
                .iter()
                .map(|party| super::receiver_shares(&party.esi_sss, receiver, threshold_params))
                .collect::<Vec<_>>(),
        )?;
        let d_share = share_manager
            .decryption_share(Arc::clone(&ciphertext), sk_poly_sum.into_ntt(), es_poly_sum)
            .map_err(|e| {
                WitnessError::Sample(format!("Failed to compute decryption share: {:?}", e))
            })?;
        d_share_polys.push(d_share);
    }

    let reconstructing_parties: Vec<usize> = (1..=reconstructing_count).collect();

    // Threshold decrypt to obtain message (verify)
    let plaintext = share_manager
        .decrypt_from_shares(
            d_share_polys.clone(),
            reconstructing_parties.clone(),
            Arc::clone(&ciphertext),
        )
        .map_err(|e| WitnessError::Sample(format!("Failed to decrypt from shares: {:?}", e)))?;

    let message_vec = Vec::<u64>::try_decode(&plaintext, Encoding::poly())
        .map_err(|e| WitnessError::Sample(format!("Failed to decode plaintext: {:?}", e)))?;
    if message_vec != message {
        return Err(WitnessError::Sample(
            "threshold decryption did not recover the sample message".into(),
        ));
    }

    Ok(DecryptedSharesAggregationCircuitData {
        d_share_polys,
        reconstructing_parties,
        message_vec,
    })
}

#[cfg(test)]
mod tests {
    use super::generate;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvPreset;
    use e3_zk_witness::threshold::decrypted_shares_aggregation::Inputs;
    use num_bigint::BigInt;

    /// Input message matches sample (ascending order: index 0 = constant term).
    #[test]
    fn test_input_message_matches_sample() {
        use e3_zk_config::threshold::decrypted_shares_aggregation::Configs;
        for (preset, committee, width) in [
            (
                BfvPreset::InsecureThreshold64,
                CiphernodesCommitteeSize::Small,
                50,
            ),
            (
                BfvPreset::SecureThreshold8192,
                CiphernodesCommitteeSize::Minimum,
                7,
            ),
        ] {
            let mut configs = Configs::for_preset(preset, committee).unwrap();
            configs.max_msg_non_zero_coeffs = width;
            let sample = generate(&configs, preset).unwrap();
            assert_eq!(sample.message_vec.len(), configs.params.degree());
            assert!(sample.message_vec[..width]
                .iter()
                .any(|&coefficient| coefficient != 0));
            assert!(
                sample.message_vec[width..]
                    .iter()
                    .all(|&coefficient| coefficient == 0),
                "sample ignored the supplied message prefix width"
            );
            let inputs = Inputs::compute(&configs, &sample).unwrap();
            let n = configs.max_msg_non_zero_coeffs;
            for i in 0..n {
                let expected = sample.message_vec.get(i).copied().unwrap_or(0);
                let w = &inputs.message.coefficients()[i];
                let exp = BigInt::from(expected);
                assert_eq!(w, &exp, "message coeff {} mismatch", i);
            }
        }
    }
}
