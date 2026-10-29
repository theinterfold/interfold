// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the threshold share decryption circuit.
//!
//! Produces a random BFV ciphertext, the aggregated secret share (s), fresh smudging noise
//! (e, e_signed), and the corresponding decryption share (d_share) for use in codegen and tests.

use std::sync::Arc;

use e3_committee::CiphernodesCommittee;
use e3_fhe_params::{BfvPreset, create_deterministic_crp_from_default_seed};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_witness::{WitnessError, threshold::share_decryption::ShareDecryptionCircuitData};
use fhe::{
    bfv::{BfvParameters, Encoding, Plaintext, PublicKey},
    mbfv::{AggregateIter, PublicKeyShare},
    trbfv::ShareManager,
};
use fhe_traits::{FheEncoder, FheEncrypter};

use crate::smudging::SmudgingDrawer;

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
    let noise = SmudgingDrawer::new(threshold_params, num_parties, num_ciphertexts, preset);

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

    for (dealer, sk) in party_secret_keys.into_iter().enumerate() {
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.as_ref())
            .map_err(|e| {
                WitnessError::Sample(format!("Failed to convert SK coeffs to poly: {:?}", e))
            })?;

        let sk_sss = share_manager
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .map_err(|e| WitnessError::Sample(format!("Failed to generate SK shares: {:?}", e)))?;

        // Generate every dealer's fresh material, retaining only receiver zero's selected contributions.
        if dealer < selected_dealers {
            sk_collected.push(super::receiver_shares(&sk_sss, 0, threshold_params));
        }
    }

    // The FHE owner validates and sums canonical contribution matrices once.
    let sk_poly_sum = share_manager
        .aggregate_collected_shares(&sk_collected)
        .map_err(|e| WitnessError::Sample(format!("Failed to aggregate SK shares: {:?}", e)))?;

    let s = CrtPolynomial::from_fhe_polynomial(&sk_poly_sum);
    // One fresh draw is shared by every output index in this sample.
    let e_signed = noise.draw(&mut rng)?;
    let e = CrtPolynomial::from_mod_q_polynomial(&e_signed, threshold_params.moduli());
    let decryptors: Vec<u32> = (1..=(threshold as u32 + 1)).collect();
    // Outgoing `k_{1,j}` and incoming `k_{j,1}` differ, so this party's mask is nonzero.
    let directed_key = |from: u8, to: u8, label: u8| {
        let mut key = vec![label; 32];
        key[0] = from;
        key[1] = to;
        key
    };
    let outgoing_prf_keys = (0..num_parties)
        .map(|peer| directed_key(1, u8::try_from(peer + 1).unwrap_or(0), 1))
        .collect();
    let incoming_prf_keys = (0..num_parties)
        .map(|peer| directed_key(u8::try_from(peer + 1).unwrap_or(0), 1, 2))
        .collect();
    let mut data = ShareDecryptionCircuitData {
        ciphertext,
        public_key,
        s,
        e,
        e_signed,
        d_share: CrtPolynomial::new(vec![]),
        domain_hi: 1,
        domain_lo: 2,
        committee,
        party_idx: 0,
        decryptors,
        outgoing_prf_keys,
        incoming_prf_keys,
    };
    data.d_share = synchronized_decryption_share(&data, threshold_params, preset)?;
    Ok(data)
}

/// Construct a real synchronized partial decryption for a sample's exact keys and noise.
pub fn synchronized_decryption_share(
    data: &ShareDecryptionCircuitData,
    params: &Arc<BfvParameters>,
    preset: BfvPreset,
) -> Result<CrtPolynomial, WitnessError> {
    use fhe::trbfv::SynchronizedDecryptor;
    use fhe_math::rq::{Poly, PowerBasis};
    let inputs = e3_fhe_params::fresh_smudging_inputs(preset, data.committee.n)
        .map_err(WitnessError::Other)?;
    let noise = e3_fhe_params::smudging_noise_from_signed_coefficients(
        params.clone(),
        inputs.num_parties,
        inputs.num_ciphertexts,
        inputs.mult_depth,
        inputs.lambda,
        &data.e_signed,
    )?;
    let mut coefficients = ndarray::Array2::zeros((params.moduli().len(), params.degree()));
    for (row, limb) in data.s.limbs.iter().enumerate() {
        for (col, coefficient) in limb.coefficients().iter().enumerate() {
            coefficients[(row, col)] = u64::try_from(coefficient)
                .map_err(|_| WitnessError::Sample("non-native secret share".into()))?;
        }
    }
    let mut sk = Poly::<PowerBasis>::zero(params.context_at_level(0)?);
    sk.set_coefficients(coefficients);
    let keys = e3_zk_witness::prf::party_keys(
        data.party_idx,
        data.committee.n,
        &data.outgoing_prf_keys,
        &data.incoming_prf_keys,
    )?;
    let share =
        SynchronizedDecryptor::new(data.committee.n, data.committee.threshold, params.clone())?
            .decryption_share(
                &data.ciphertext,
                &sk.into_ntt(),
                data.party_idx as usize + 1,
                &data
                    .decryptors
                    .iter()
                    .map(|id| *id as usize)
                    .collect::<Vec<_>>(),
                noise,
                &keys,
            )?;
    Ok(CrtPolynomial::from_fhe_polynomial(&share.into_parts().0))
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

            assert_ne!(
                sample.outgoing_prf_keys, sample.incoming_prf_keys,
                "identical PRF directions make the mask zero for every implementation"
            );
            if preset == BfvPreset::InsecureThreshold64 {
                let mask = e3_zk_witness::prf::mask(
                    sample.party_idx,
                    &sample.decryptors,
                    &sample.outgoing_prf_keys,
                    &sample.incoming_prf_keys,
                    &sample.ciphertext,
                    sample.committee.n,
                )
                .unwrap();
                assert!(
                    mask.coefficients()
                        .iter()
                        .any(|coefficient| *coefficient != 0),
                    "the acceptance sample mask is zero"
                );
            }

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
