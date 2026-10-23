// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for pk generation circuit.
//!
//! The sample contains one public-key share and its matching secret and smudging material.

use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::threshold::pk_generation::Configs;
use e3_zk_witness::{threshold::pk_generation::PkGenerationCircuitData, WitnessError};
use fhe::mbfv::PublicKeyShare;
use fhe::{
    bfv::SecretKey,
    trbfv::{smudging::SmudgingNoiseGenerator, ShareManager},
};

pub fn generate(config: &Configs) -> Result<PkGenerationCircuitData, WitnessError> {
    let threshold_params = &config.params;
    let mut rng = rand::rng();

    let secret_key = SecretKey::random(threshold_params, &mut rng);
    let crp = create_deterministic_crp_from_default_seed(threshold_params);

    let (pk_share, intermediates) =
        PublicKeyShare::new_with_intermediates(&secret_key, crp, &mut rng).map_err(|e| {
            WitnessError::Sample(format!("Failed to create public key share: {:?}", e))
        })?;

    let committee = config.committee.values();
    let share_manager =
        ShareManager::new(committee.n, committee.threshold, threshold_params.clone())?;
    // C1 supplies the same additive, all-N-participant bound as the sample noise setup.
    let noise =
        SmudgingNoiseGenerator::new(threshold_params.clone(), config.bounds.e_sm_bound.clone());
    let e_sm = share_manager.bigints_to_poly(&noise.generate_smudging_error(&mut rng)?)?;

    Ok(PkGenerationCircuitData {
        pk0_share: CrtPolynomial::from_fhe_polynomial(pk_share.p0_share()),
        eek: CrtPolynomial::from_fhe_polynomial(intermediates.error()),
        e_sm: CrtPolynomial::from_fhe_polynomial(&*e_sm),
        e_sm_lifted: Polynomial::from_fhe_polynomial(&*e_sm),
        sk: CrtPolynomial::from_fhe_polynomial(intermediates.secret_key()),
    })
}

#[cfg(test)]
mod tests {
    use super::generate;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_zk_config::threshold::pk_generation::Configs;
    use e3_zk_witness::threshold::pk_generation::Inputs;

    use e3_fhe_params::BfvPreset;
    use num_bigint::BigInt;
    use num_traits::Signed;

    #[test]
    fn test_generate_sample() {
        for preset in BfvPreset::PAIR_PRESETS {
            let committee = CiphernodesCommitteeSize::Small;
            let config = Configs::for_preset(preset, committee).unwrap();
            let sample = generate(&config).unwrap();
            let inputs = Inputs::compute(&config, &sample).unwrap();
            let bounds = &config.bounds;

            let num_moduli = config.params.moduli().len();
            assert_eq!(inputs.pk0is.limbs.len(), num_moduli);
            assert_eq!(inputs.e_sm.limbs.len(), num_moduli);
            assert_eq!(inputs.ris.limbs.len(), num_moduli);
            for coefficient in inputs.e_sm_lifted.coefficients() {
                assert!(
                    coefficient.abs() <= BigInt::from(bounds.e_sm_bound.clone()),
                    "lifted smudging error exceeds the C1 bound"
                );
            }
            for coefficient in inputs.eek.coefficients() {
                assert!(
                    coefficient.abs() <= BigInt::from(bounds.eek_bound.clone()),
                    "key-generation error exceeds the C1 bound"
                );
            }
            for coefficient in inputs.sk.coefficients() {
                assert!(
                    coefficient.abs() <= BigInt::from(bounds.sk_bound.clone()),
                    "secret key exceeds the C1 bound"
                );
            }
            for limb in &inputs.e_sm.limbs {
                for coefficient in limb.coefficients() {
                    assert!(
                        coefficient.abs() <= BigInt::from(bounds.e_sm_bound.clone()),
                        "smudging error exceeds the C1 bound"
                    );
                }
            }
            // One quotient replaces the `r1` / `r2` pair now that the identity is checked reduced
            // modulo X^N + 1. This is the check that would catch a bound derived from the wrong terms:
            // the reduced `r` is a different polynomial from `r1`, so it needs its own bound to hold.
            for (limb, bound) in inputs.ris.limbs.iter().zip(&bounds.r_bounds) {
                for coefficient in limb.coefficients() {
                    assert!(
                        coefficient.abs() <= BigInt::from(bound.clone()),
                        "reduced quotient exceeds the C1 bound"
                    );
                }
            }
        }
    }
}
