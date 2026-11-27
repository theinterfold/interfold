// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Artificial l-BFV row material.
use crate::lbfv_proof_domain::sample_lbfv_proof_domain;
use e3_committee::CiphernodesCommittee;
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, BfvPreset};
use e3_zk_witness::threshold::pk_generation::*;
use e3_zk_witness::WitnessError;
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::PublicKeyShare;

/// Generate one valid l-BFV public-key row 0, for codegen and prover tests.
pub fn generate_sample(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
) -> Result<LbfvPkGenerationCircuitData, WitnessError> {
    generate_sample_for_row(preset, committee, 0)
}

/// Generate one valid l-BFV public-key row for codegen and prover tests.
pub fn generate_sample_for_row(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    row_index: u32,
) -> Result<LbfvPkGenerationCircuitData, WitnessError> {
    let (params, _) =
        build_pair_for_preset(preset).map_err(|error| WitnessError::Sample(error.to_string()))?;
    let crs_seed = lbfv_crs_seed(preset)
        .ok_or_else(|| WitnessError::Sample(format!("l-BFV CRS is not enabled for {preset:?}")))?;
    let crp = CommonRandomPolyVec::from_seed(&params, crs_seed)?;
    let mut rng = rand::rng();
    let secret_key = SecretKey::random(&params, &mut rng);
    let public_key = PublicKeyShare::contribute_with_crp(&secret_key, &crp, &mut rng)?;
    let adapter = LbfvPkGenerationAdapter::from_crp(&params, &crp)?;
    adapter.row_data(
        committee,
        sample_lbfv_proof_domain(),
        0,
        row_index,
        &secret_key,
        &public_key,
    )
}

#[cfg(test)]
mod row_tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;

    use e3_zk_witness::WitnessError;
    use num_bigint::BigInt;
    use num_traits::Signed;

    #[test]
    fn sample_quotients_fit_the_limb_bounds() -> Result<(), WitnessError> {
        let preset = BfvPreset::InsecureThresholdLbfv;
        let config = e3_zk_config::threshold::pk_generation::Configs::for_preset(
            preset,
            CiphernodesCommitteeSize::Minimum,
        )?;
        let row = generate_sample(preset, CiphernodesCommitteeSize::Minimum.values())?;

        let inputs = LbfvPkGenerationInputs::compute(&config, &row)?;
        for (r, bound) in inputs.ris.limbs.iter().zip(&config.bounds.r_bounds) {
            let bound = BigInt::from(bound.clone());
            assert!(r.coefficients().iter().all(|c| c.abs() <= bound));
        }
        Ok(())
    }
}
