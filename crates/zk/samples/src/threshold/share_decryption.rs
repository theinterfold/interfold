// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the threshold share decryption circuit.
//!
//! Produces a random BFV ciphertext, aggregated secret and smudging-error shares (s, e),
//! and the corresponding decryption share (d_share) for use in codegen and tests.

use std::sync::Arc;

use e3_committee::CiphernodesCommittee;
use e3_fhe_params::{create_deterministic_crp_from_default_seed, BfvPreset};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_witness::{threshold::share_decryption::ShareDecryptionCircuitData, WitnessError};
use fhe::{
    bfv::{BfvParameters, Encoding, Plaintext, PublicKey},
    mbfv::{AggregateIter, PublicKeyShare},
    trbfv::ShareManager,
};
use fhe_traits::{FheEncoder, FheEncrypter};

/// Sample all N public-key contributions and recipient zero's selected T+1 decryption contributions.
pub fn generate(
    threshold_params: &Arc<BfvParameters>,
    preset: BfvPreset,
    committee: CiphernodesCommittee,
) -> Result<ShareDecryptionCircuitData, WitnessError> {
    let sd = preset
        .search_defaults()
        .ok_or_else(|| WitnessError::Sample("Preset has no search defaults".into()))?;

    let mut rng = rand::rng();

    let num_parties = committee.n;
    let threshold = committee.threshold;
    let num_ciphertexts = usize::try_from(sd.z).map_err(|e| WitnessError::Sample(e.to_string()))?;
    let mut share_manager = ShareManager::new(num_parties, threshold, threshold_params.clone())?;
    let noise = crate::smudging::generator(threshold_params, num_parties, num_ciphertexts, preset)?;

    let crp = create_deterministic_crp_from_default_seed(threshold_params);

    // Every dealer contributes a fresh secret key to the public key.
    let mut party_secret_keys = Vec::with_capacity(num_parties);
    let mut pk_shares = Vec::with_capacity(num_parties);

    for _ in 0..num_parties {
        let sk = fhe::bfv::SecretKey::random(threshold_params, &mut rng);
        let pk_share = PublicKeyShare::new(&sk, crp.clone(), &mut rng).map_err(|e| {
            WitnessError::Sample(format!("Failed to create public key share: {:?}", e))
        })?;
        party_secret_keys.push(sk);
        pk_shares.push(pk_share);
    }

    let public_key: PublicKey = pk_shares
        .into_iter()
        .aggregate()
        .map_err(|e| WitnessError::Sample(format!("Failed to aggregate public key: {:?}", e)))?;

    let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), threshold_params)
        .map_err(|e| WitnessError::Sample(format!("Failed to encode plaintext: {:?}", e)))?;
    let ciphertext = public_key.try_encrypt(&pt, &mut rng)?;

    // C6 selects the first T+1 dealers, while its public key still includes all N dealers.
    let selected_dealers = threshold + 1;
    let mut sk_collected = Vec::with_capacity(selected_dealers);
    let mut es_collected = Vec::with_capacity(selected_dealers);

    for (dealer, sk) in party_secret_keys.into_iter().enumerate() {
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.as_ref())
            .map_err(|e| {
                WitnessError::Sample(format!("Failed to convert SK coeffs to poly: {:?}", e))
            })?;

        let sk_sss = share_manager
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .map_err(|e| WitnessError::Sample(format!("Failed to generate SK shares: {:?}", e)))?;

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
        // Generate every dealer's fresh material, retaining only receiver zero's selected contributions.
        if dealer < selected_dealers {
            sk_collected.push(super::receiver_shares(&sk_sss, 0, threshold_params));
            es_collected.push(super::receiver_shares(&esi_sss, 0, threshold_params));
        }
    }

    // The FHE owner validates and sums canonical contribution matrices once.
    let sk_poly_sum = share_manager
        .aggregate_collected_shares(&sk_collected)
        .map_err(|e| WitnessError::Sample(format!("Failed to aggregate SK shares: {:?}", e)))?;

    let es_poly_sum = share_manager
        .aggregate_collected_shares(&es_collected)
        .map_err(|e| WitnessError::Sample(format!("Failed to aggregate ES shares: {:?}", e)))?;

    let s = CrtPolynomial::from_fhe_polynomial(&sk_poly_sum);
    let e = CrtPolynomial::from_fhe_polynomial(&es_poly_sum);
    let d_share_rns = share_manager
        .decryption_share(
            Arc::new(ciphertext.clone()),
            sk_poly_sum.into_ntt(),
            es_poly_sum,
        )
        .map_err(|e| {
            WitnessError::Sample(format!("Failed to compute decryption share: {:?}", e))
        })?;

    Ok(ShareDecryptionCircuitData {
        ciphertext,
        s,
        e,
        d_share: CrtPolynomial::from_fhe_polynomial(&d_share_rns),
        domain_hi: 1,
        domain_lo: 2,
    })
}

#[cfg(test)]
mod tests {
    use e3_committee::CiphernodesCommitteeSize;

    use super::*;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_template_succeeds_and_has_correct_structure() {
        for (preset, committee) in [
            (
                BfvPreset::InsecureThreshold64,
                CiphernodesCommitteeSize::Small,
            ),
            (
                BfvPreset::SecureThreshold8192,
                CiphernodesCommitteeSize::Minimum,
            ),
        ] {
            let config =
                e3_zk_config::threshold::share_decryption::Configs::for_preset(preset).unwrap();
            let sample = generate(&config.params, preset, committee.values()).unwrap();
            let inputs =
                e3_zk_witness::threshold::share_decryption::Inputs::compute(&config, &sample)
                    .unwrap();

            let degree = config.params.degree();
            let num_moduli = config.params.moduli().len();

            assert_eq!(
                sample.ciphertext.len(),
                2,
                "BFV ciphertext has two components"
            );

            assert_eq!(
                sample.s.limbs.len(),
                num_moduli,
                "s polynomial has one limb per modulus"
            );
            assert_eq!(
                sample.e.limbs.len(),
                num_moduli,
                "e polynomial has one limb per modulus"
            );
            assert_eq!(
                sample.d_share.limbs.len(),
                num_moduli,
                "d_share polynomial has one limb per modulus"
            );

            assert_eq!(
                sample.s.limb(0).coefficients().len(),
                degree,
                "each limb has degree coefficients"
            );
            for (limb, bound) in inputs.r.limbs.iter().zip(&config.bounds.r_bounds) {
                assert!(
                    limb.coefficients()
                        .iter()
                        .all(|coefficient| coefficient.magnitude() <= bound),
                    "C6 quotient exceeds its configured bound"
                );
            }
        }
    }
}
