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

use crate::{
    threshold::share_decryption::ShareDecryptionCircuitData, CiphernodesCommittee, CircuitsErrors,
};
use e3_fhe_params::{build_pair_for_preset, create_deterministic_crp_from_default_seed, BfvPreset};
use e3_polynomial::CrtPolynomial;
use fhe::{
    bfv::{Encoding, Plaintext, PublicKey},
    mbfv::{AggregateIter, PublicKeyShare},
    trbfv::{ShareManager, TRBFV},
};
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::ArrayView;
impl ShareDecryptionCircuitData {
    /// Generates a random secret key, public key, and plaintext for the given BFV parameters.
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

        let mut rng = rand::rng();

        let num_parties = committee.n;
        let threshold = committee.threshold;
        let num_ciphertexts = sd.z as usize;
        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = preset
            .lambda()
            .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        // Create TRBFV instance for share generation
        let trbfv = TRBFV::new(num_parties, threshold, threshold_params.clone())
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to create TRBFV: {:?}", e)))?;

        // Generate a random secret key and create public key shares
        let crp = create_deterministic_crp_from_default_seed(&threshold_params);

        // Generate secret keys for each party (each party has their own secret key)
        // Each party splits their secret key into shares and sends them to others
        let mut party_secret_keys = Vec::new();
        let mut pk_shares = Vec::new();

        for _ in 0..num_parties {
            let sk = fhe::bfv::SecretKey::random(&threshold_params, &mut rng);
            let pk_share = PublicKeyShare::new(&sk, crp.clone(), &mut rng).map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to create public key share: {:?}", e))
            })?;
            party_secret_keys.push(sk);
            pk_shares.push(pk_share);
        }

        // Aggregate public key shares to get the full public key
        let public_key: PublicKey = pk_shares.iter().cloned().aggregate().map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to aggregate public key: {:?}", e))
        })?;

        // Encrypt a sample message (e.g., 1) to create a ciphertext
        let message = 1u64;
        let pt = Plaintext::try_encode(&[message], Encoding::poly(), &threshold_params)
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to encode plaintext: {:?}", e)))?;
        let ciphertext = public_key.try_encrypt(&pt, &mut rng)?;

        // Simulate party 0's perspective:
        // - Each party has their own secret key
        // - Each party splits their secret key into shares and sends them to others
        // - Party 0 collects shares from other parties (including themselves)
        // - When party 0 computes a decryption share, they aggregate all collected shares

        let mut share_manager = ShareManager::new(num_parties, threshold, threshold_params.clone())
            .map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e))
            })?;

        // Generate shares for each party's secret key
        // In reality, each party would do this independently
        let mut all_party_sk_shares = Vec::new(); // [party][modulus][receiver][coefficient]
        let mut all_party_esi_shares = Vec::new(); // [party][modulus][receiver][coefficient]

        for party_sk in party_secret_keys.iter().take(num_parties) {
            let sk = &party_sk;
            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk.coeffs.clone().as_ref())
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to convert SK coeffs to poly: {:?}", e))
                })?;

            let temp_trbfv = trbfv.clone();
            let sk_sss = temp_trbfv
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to generate SK shares: {:?}", e))
                })?;

            all_party_sk_shares.push(sk_sss);

            let esi_coeffs = trbfv
                .generate_smudging_error(num_ciphertexts, lambda, &mut rng)
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to generate smudging error: {:?}", e))
                })?;
            let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to convert error to poly: {:?}", e))
            })?;
            let esi_sss = share_manager
                .generate_secret_shares_from_poly(esi_poly, &mut rng)
                .map_err(|e| {
                    CircuitsErrors::Sample(format!("Failed to generate error shares: {:?}", e))
                })?;
            all_party_esi_shares.push(esi_sss);
        }

        // Simulate party 0 collecting shares from other parties
        let honest_parties = threshold + 1;
        let mut sk_sss_collected = Vec::new();
        let mut es_sss_collected = Vec::new();

        for modulus_idx in 0..threshold_params.moduli().len() {
            let mut sk_collected = ndarray::Array2::<u64>::zeros((0, threshold_params.degree()));
            let mut es_collected = ndarray::Array2::<u64>::zeros((0, threshold_params.degree()));

            // Party 0 collects shares from honest parties
            // For each party i, party 0 collects the share that party i sent to party 0
            // This is all_party_sk_shares[i][modulus_idx].row(0) (share for party 0)
            for party_idx in 0..honest_parties {
                // Check bounds before accessing
                if modulus_idx >= all_party_sk_shares[party_idx].len() {
                    return Err(CircuitsErrors::Sample(format!(
                        "Modulus index {} out of bounds for party {} (has {} moduli)",
                        modulus_idx,
                        party_idx,
                        all_party_sk_shares[party_idx].len()
                    )));
                }
                if modulus_idx >= all_party_esi_shares[party_idx].len() {
                    return Err(CircuitsErrors::Sample(format!(
                        "Modulus index {} out of bounds for party {} error shares (has {} moduli)",
                        modulus_idx,
                        party_idx,
                        all_party_esi_shares[party_idx].len()
                    )));
                }

                // Collect the share that party_idx sent to party 0
                let sk_share_row = all_party_sk_shares[party_idx][modulus_idx].row(0);
                let sk_share_vec = sk_share_row.to_vec();
                sk_collected
                    .push_row(ArrayView::from(&sk_share_vec))
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to push SK share row: {:?}", e))
                    })?;

                let es_share_row = all_party_esi_shares[party_idx][modulus_idx].row(0);
                let es_share_vec = es_share_row.to_vec();
                es_collected
                    .push_row(ArrayView::from(&es_share_vec))
                    .map_err(|e| {
                        CircuitsErrors::Sample(format!("Failed to push ES share row: {:?}", e))
                    })?;
            }

            sk_sss_collected.push(sk_collected);
            es_sss_collected.push(es_collected);
        }

        // Aggregate collected shares to get s and e polynomials
        // First, sum across parties for each modulus, then restructure to match
        // the format expected by aggregate_collected_shares: one Array2 of shape [num_moduli, degree]
        let ctx = threshold_params.context_at_level(0)?;
        let num_moduli = sk_sss_collected.len();

        // Sum across parties for each modulus to create [num_moduli, degree] matrices
        let mut sk_sum_matrix =
            ndarray::Array2::<u64>::zeros((num_moduli, threshold_params.degree()));
        let mut es_sum_matrix =
            ndarray::Array2::<u64>::zeros((num_moduli, threshold_params.degree()));

        for modulus_idx in 0..num_moduli {
            // Sum across parties (rows) for this modulus
            for party_idx in 0..sk_sss_collected[modulus_idx].nrows() {
                for coeff_idx in 0..threshold_params.degree() {
                    sk_sum_matrix[[modulus_idx, coeff_idx]] = (sk_sum_matrix
                        [[modulus_idx, coeff_idx]]
                        + sk_sss_collected[modulus_idx][[party_idx, coeff_idx]])
                        % ctx.moduli()[modulus_idx];
                    es_sum_matrix[[modulus_idx, coeff_idx]] = (es_sum_matrix
                        [[modulus_idx, coeff_idx]]
                        + es_sss_collected[modulus_idx][[party_idx, coeff_idx]])
                        % ctx.moduli()[modulus_idx];
                }
            }
        }

        // Use aggregate_collected_shares with the correctly formatted data
        // It expects a slice with one Array2 of shape [num_moduli, degree]
        let sk_poly_sum = trbfv
            .aggregate_collected_shares(&[sk_sum_matrix])
            .map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to aggregate SK shares: {:?}", e))
            })?;

        let es_poly_sum = trbfv
            .aggregate_collected_shares(&[es_sum_matrix])
            .map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to aggregate ES shares: {:?}", e))
            })?;

        // Compute the decryption share using TRBFV
        let d_share_rns = trbfv
            .clone()
            .decryption_share(
                Arc::new(ciphertext.clone()),
                sk_poly_sum.clone().into_ntt(),
                es_poly_sum.clone(),
            )
            .map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to compute decryption share: {:?}", e))
            })?;

        Ok(Self {
            ciphertext,
            public_key,
            s: CrtPolynomial::from_fhe_polynomial(&sk_poly_sum),
            e: CrtPolynomial::from_fhe_polynomial(&es_poly_sum),
            d_share: CrtPolynomial::from_fhe_polynomial(&d_share_rns),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::CiphernodesCommitteeSize;

    use super::*;
    use e3_fhe_params::BfvPreset;

    const PRESET: BfvPreset = BfvPreset::InsecureThreshold512;

    #[test]
    fn test_generate_template_succeeds_and_has_correct_structure() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareDecryptionCircuitData::generate_sample(PRESET, committee).unwrap();

        let degree = PRESET.metadata().degree;
        let num_moduli = PRESET.metadata().num_moduli;

        assert_eq!(
            sample.public_key.c.len(),
            2,
            "BFV public key has two components"
        );
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
    }

    #[test]
    fn test_generate_template_polynomials_consistent() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareDecryptionCircuitData::generate_sample(PRESET, committee).unwrap();

        let n = sample.s.limbs.len();
        assert_eq!(sample.e.limbs.len(), n, "e must have same limb count as s");
        assert_eq!(
            sample.d_share.limbs.len(),
            n,
            "d_share must have same limb count as s"
        );
    }

    #[test]
    fn test_generate_template_repeatable() {
        let committee = CiphernodesCommitteeSize::Small.values();

        let a = ShareDecryptionCircuitData::generate_sample(PRESET, committee.clone()).unwrap();
        let b = ShareDecryptionCircuitData::generate_sample(PRESET, committee).unwrap();

        assert_eq!(a.public_key.c.len(), b.public_key.c.len());
        assert_eq!(a.s.limbs.len(), b.s.limbs.len());
        assert_eq!(a.e.limbs.len(), b.e.limbs.len());
        assert_eq!(a.d_share.limbs.len(), b.d_share.limbs.len());
    }
}
