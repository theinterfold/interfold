// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for pk generation circuit.
//!
//! [`Sample`] produces a random BFV key pair and plaintext; the public key and plaintext are used as input
//! for codegen and tests.

use crate::{
    threshold::pk_generation::PkGenerationCircuitData, CiphernodesCommittee, CircuitsErrors,
};
use e3_fhe_params::{build_pair_for_preset, create_deterministic_crp_from_default_seed, BfvPreset};
use e3_polynomial::CrtPolynomial;
use fhe::mbfv::PublicKeyShare;
use fhe::{
    bfv::SecretKey,
    trbfv::{ShareManager, TRBFV},
};
use std::ops::Deref;

impl PkGenerationCircuitData {
    pub fn generate_sample(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
    ) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) = build_pair_for_preset(preset).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e))
        })?;

        let mut rng = rand::rng();

        let secret_key = SecretKey::random(&threshold_params, &mut rng);
        let crp = create_deterministic_crp_from_default_seed(&threshold_params);

        let (pk0_share, _, sk, e) =
            PublicKeyShare::new_extended(&secret_key, crp.clone(), &mut rng).map_err(|e| {
                CircuitsErrors::Sample(format!("Failed to create public key share: {:?}", e))
            })?;

        let num_parties = committee.n;
        let threshold = committee.threshold;

        let defaults = preset
            .search_defaults()
            .ok_or_else(|| CircuitsErrors::Sample("missing search defaults".to_string()))?;
        let num_ciphertexts = defaults.z;
        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = preset
            .lambda()
            .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let trbfv = TRBFV::new(num_parties, threshold, threshold_params.clone())?;
        let share_manager = ShareManager::new(num_parties, threshold, threshold_params)?;

        // Generate smudging error coefficients
        let esi_coeffs =
            trbfv.generate_smudging_error(num_ciphertexts as usize, lambda, &mut rng)?;

        // Convert to polynomial in RNS representation
        // bigints_to_poly returns Zeroizing<Poly>, we need to clone the inner Poly
        let e_sm_rns_zeroizing = share_manager.bigints_to_poly(&esi_coeffs)?;

        let e_sm = e_sm_rns_zeroizing.deref().clone();

        Ok(PkGenerationCircuitData {
            committee,
            pk0_share: CrtPolynomial::from_fhe_polynomial(&pk0_share),
            eek: CrtPolynomial::from_fhe_polynomial(&e),
            e_sm: CrtPolynomial::from_fhe_polynomial(&e_sm),
            sk: CrtPolynomial::from_fhe_polynomial(&sk),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        computation::Computation,
        threshold::pk_generation::{Inputs, PkGenerationCircuitData},
        CiphernodesCommitteeSize,
    };

    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_sample() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample =
            PkGenerationCircuitData::generate_sample(BfvPreset::InsecureThreshold512, committee)
                .unwrap();
        let inputs = Inputs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();

        assert_eq!(inputs.pk0is.limbs.len(), 2);
        assert_eq!(inputs.e_sm.limbs.len(), 2);
        assert_eq!(inputs.r1is.limbs.len(), 2);
        assert_eq!(inputs.r2is.limbs.len(), 2);
    }
}
