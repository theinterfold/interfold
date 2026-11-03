// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Artificial l-BFV row material.
use crate::lbfv_proof_domain::sample_lbfv_proof_domain;
use e3_committee::CiphernodesCommittee;
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_zk_witness::threshold::rlk_generation::*;
use e3_zk_witness::WitnessError;
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::RelinKeyShare;
pub fn generate_sample(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
) -> Result<RlkGenerationCircuitData, WitnessError> {
    generate_sample_for_row(preset, committee, 0)
}

/// Generate one valid RLK row for codegen and prover tests.
pub fn generate_sample_for_row(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    row_index: u32,
) -> Result<RlkGenerationCircuitData, WitnessError> {
    let (params, _) =
        build_pair_for_preset(preset).map_err(|error| WitnessError::Sample(error.to_string()))?;
    let crs_seed = lbfv_crs_seed(preset)
        .ok_or_else(|| WitnessError::Sample(format!("l-BFV CRS is not enabled for {preset:?}")))?;
    let urs_seed = lbfv_urs_seed(preset)
        .ok_or_else(|| WitnessError::Sample(format!("l-BFV URS is not enabled for {preset:?}")))?;
    let crp_d1 = CommonRandomPolyVec::from_seed(&params, urs_seed)?;
    let crp_a = CommonRandomPolyVec::from_seed(&params, crs_seed)?;
    let mut rng = rand::rng();
    let sk = SecretKey::random(&params, &mut rng);
    let (share, witness) =
        RelinKeyShare::contribution_with_crp_extended(&sk, &crp_d1, &crp_a, 0, 0, &mut rng)?;
    let adapter = RlkGenerationAdapter::from_rows(&params, &crp_d1, &crp_a)?;
    let witness = RlkWitnessGuard::new(witness);
    adapter.row_data(
        committee,
        sample_lbfv_proof_domain(),
        0,
        row_index,
        &sk,
        &share,
        witness.as_ref(),
    )
}

#[cfg(test)]
mod row_tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs;

    use e3_polynomial::Polynomial;

    use e3_zk_witness::WitnessError;
    use num_bigint::{BigInt, BigUint};
    use num_traits::Signed;
    fn size(c: &e3_committee::CiphernodesCommittee) -> CiphernodesCommitteeSize {
        CiphernodesCommitteeSize::from_threshold(c.threshold, c.n).unwrap()
    }
    fn generate_toml(inputs: RlkGenerationInputs) -> Result<String, WitnessError> {
        toml::to_string(
            &inputs
                .to_json()
                .map_err(|e| WitnessError::Other(e.to_string()))?,
        )
        .map_err(|e| WitnessError::Other(e.to_string()))
    }

    #[test]
    fn sample_quotients_fit_the_limb_bounds() -> Result<(), WitnessError> {
        let preset = BfvPreset::InsecureThresholdLbfv;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let bounds =
            RlkGenerationConfigs::for_preset(preset, size(&committee)).map(|c| c.bounds)?;
        let row = crate::threshold::rlk_generation::generate_sample(preset, committee)?;
        let fits = |polynomial: &Polynomial, bound: &BigUint| {
            let bound = BigInt::from(bound.clone());
            polynomial.coefficients().iter().all(|c| c.abs() <= bound)
        };

        let inputs = RlkGenerationInputs::compute(
            &e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs::for_preset(
                preset,
                size(&row.committee),
            )?,
            &row,
        )?;
        for (limb_index, (rd0, rd2)) in inputs.rd0.limbs.iter().zip(&inputs.rd2.limbs).enumerate() {
            assert!(fits(rd0, &bounds.rd0_bounds[limb_index]));
            assert!(fits(rd2, &bounds.rd2_bounds[limb_index]));
        }
        Ok(())
    }

    #[test]
    fn row_inputs_carry_the_fixed_urs_and_crs_rows() -> Result<(), WitnessError> {
        let preset = BfvPreset::InsecureThresholdLbfv;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let adapter = RlkGenerationAdapter::from_config(
            &e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs::for_preset(
                preset,
                CiphernodesCommitteeSize::Minimum,
            )?,
        )?;
        let config = RlkGenerationConfigs::for_preset(preset, size(&committee))?;
        let row_index = 1;
        let mut row = crate::threshold::rlk_generation::generate_sample_for_row(
            preset, committee, row_index,
        )?;
        let inputs = adapter.row_inputs(&row)?;

        assert_eq!(inputs.row_index, row_index);
        assert_eq!(
            inputs.urs,
            e3_zk_witness::encoding::fhe_poly_to_crt_centered(
                &CommonRandomPolyVec::from_seed(&config.params, lbfv_urs_seed(preset).unwrap())?
                    .to_polys()[row_index as usize],
                config.params.moduli()
            )?
        );
        assert_eq!(
            inputs.crs,
            e3_zk_witness::encoding::fhe_poly_to_crt_centered(
                &CommonRandomPolyVec::from_seed(&config.params, lbfv_crs_seed(preset).unwrap())?
                    .to_polys()[row_index as usize],
                config.params.moduli()
            )?
        );
        assert_eq!(inputs.d0, row.d0);
        let toml = generate_toml(inputs)?;
        for key in ["rd0", "rd2", "d0", "d2", "urs", "crs"] {
            assert!(toml.contains(&format!("[[{key}]]")), "missing {key}");
        }

        row.row_index = adapter.row_count() as u32;
        assert!(adapter.row_inputs(&row).is_err());
        Ok(())
    }
}
