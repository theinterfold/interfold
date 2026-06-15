// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the share-decryption circuit: honest ciphertexts, sum ciphertexts, secret key, and message.

use crate::circuits::dkg::share_decryption::circuit::ShareDecryptionCircuitData;
use crate::computation::DkgInputType;
use crate::CiphernodesCommittee;
use crate::CircuitsErrors;
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use fhe::bfv::Ciphertext;
use fhe::bfv::Encoding;
use fhe::bfv::Plaintext;
use fhe::bfv::{PublicKey, SecretKey};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_traits::FheEncoder;
use fhe_traits::FheEncrypter;

impl ShareDecryptionCircuitData {
    /// Generates sample data for the share-decryption circuit (decrypts a sum of honest ciphertexts under DKG secret key).
    pub fn generate_sample(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
        dkg_input_type: DkgInputType,
    ) -> Result<Self, CircuitsErrors> {
        let (threshold_params, dkg_params) = build_pair_for_preset(preset).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e))
        })?;
        let sd = preset
            .search_defaults()
            .ok_or_else(|| CircuitsErrors::Sample("Preset has no search defaults".into()))?;

        let mut rng = rand::rng();

        let dkg_secret_key = SecretKey::random(&dkg_params, &mut rng);
        let dkg_public_key = PublicKey::new(&dkg_secret_key, &mut rng);

        let trbfv = TRBFV::new(committee.n, committee.threshold, threshold_params.clone())
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to create TRBFV: {:?}", e)))?;
        let mut share_manager =
            ShareManager::new(committee.n, committee.threshold, threshold_params.clone()).map_err(
                |e| CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e)),
            )?;
        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = preset
            .lambda()
            .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

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
                let share_row = match dkg_input_type {
                    DkgInputType::SecretKey => {
                        let threshold_secret_key = SecretKey::random(&threshold_params, &mut rng);

                        let sk_poly = share_manager
                            .coeffs_to_poly_level0(threshold_secret_key.coeffs.clone().as_ref())
                            .map_err(|e| {
                                CircuitsErrors::Sample(format!(
                                    "Failed to convert secret key to polynomial: {:?}",
                                    e
                                ))
                            })?;

                        let sk_sss_u64 = share_manager
                            .generate_secret_shares_from_poly(sk_poly.clone(), &mut rng)
                            .map_err(|e| {
                                CircuitsErrors::Sample(format!(
                                    "Failed to generate secret shares: {:?}",
                                    e
                                ))
                            })?;

                        sk_sss_u64[0].row(0).to_vec()
                    }
                    DkgInputType::SmudgingNoise => {
                        let esi_coeffs = trbfv
                            .generate_smudging_error(sd.z as usize, lambda, &mut rng)
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
                            CircuitsErrors::Sample(format!(
                                "Failed to convert error to poly: {:?}",
                                e
                            ))
                        })?;
                        let esi_sss_u64 = share_manager
                            .generate_secret_shares_from_poly(esi_poly.clone(), &mut rng.clone())
                            .map_err(|e| {
                                CircuitsErrors::Sample(format!(
                                    "Failed to generate error shares: {:?}",
                                    e
                                ))
                            })
                            .map_err(|e| {
                                CircuitsErrors::Sample(format!(
                                    "Failed to generate error shares: {:?}",
                                    e
                                ))
                            })?;

                        esi_sss_u64[0].row(0).to_vec()
                    }
                };

                if slot_idx == own_slot_idx {
                    own_share_for_slot.push(share_row);
                    continue;
                }

                let pt = Plaintext::try_encode(&share_row, Encoding::poly(), &dkg_params).map_err(
                    |e| CircuitsErrors::Sample(format!("Failed to encode plaintext: {:?}", e)),
                )?;

                let ct = dkg_public_key.try_encrypt(&pt, &mut rng).map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to encrypt plaintext: {:?}", e))
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
            dkg_input_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphernodes_committee::CiphernodesCommitteeSize;
    use crate::computation::DkgInputType;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_secret_key_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareDecryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee.clone(),
            DkgInputType::SecretKey,
        )
        .unwrap();

        assert_eq!(sample.honest_ciphertexts.len(), committee.h);
        assert_eq!(
            sample.secret_key.coeffs.len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
    }

    #[test]
    fn test_generate_smudging_noise_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareDecryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee.clone(),
            DkgInputType::SmudgingNoise,
        )
        .unwrap();

        assert_eq!(sample.honest_ciphertexts.len(), committee.h);
        assert_eq!(
            sample.secret_key.coeffs.len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
    }
}
