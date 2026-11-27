// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Artificial l-BFV row material.
use crate::lbfv_proof_domain::sample_lbfv_proof_domain;
use e3_committee::CiphernodesCommittee;
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_zk_witness::threshold::rlk_aggregation::*;
use e3_zk_witness::WitnessError;
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::RelinKeyShare;

/// Generate `H` valid RLK shares for one aggregation row and component, for codegen and prover
/// tests.
pub fn generate_sample_for_row(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    row_index: u32,
    component: RlkAggregationComponent,
) -> Result<RlkAggregationCircuitData, WitnessError> {
    let canonical = e3_zk_config::committee::canonical_committee_for_circuit(&committee)
        .map_err(|error| WitnessError::Sample(error.to_string()))?;
    let (params, _) =
        build_pair_for_preset(preset).map_err(|error| WitnessError::Sample(error.to_string()))?;
    if row_index as usize >= params.moduli().len() {
        return Err(WitnessError::Sample(format!(
            "RLK row index {row_index} is out of range for {} rows",
            params.moduli().len()
        )));
    }
    let crp_d1 = CommonRandomPolyVec::from_seed(
        &params,
        lbfv_urs_seed(preset).ok_or_else(|| {
            WitnessError::Sample(format!("l-BFV URS is not enabled for {preset:?}"))
        })?,
    )?;
    let crp_a = CommonRandomPolyVec::from_seed(
        &params,
        lbfv_crs_seed(preset).ok_or_else(|| {
            WitnessError::Sample(format!("l-BFV CRS is not enabled for {preset:?}"))
        })?,
    )?;
    let mut rng = rand::rng();
    let mut shares = Vec::with_capacity(canonical.h);
    for _ in 0..canonical.h {
        let secret_key = SecretKey::random(&params, &mut rng);
        shares.push(RelinKeyShare::contribute_with_crp(
            &secret_key,
            &crp_d1,
            &crp_a,
            0,
            0,
            &mut rng,
        )?);
    }

    Ok(RlkAggregationCircuitData {
        committee,
        proof_domain: sample_lbfv_proof_domain(),
        aggregator_party_id: 0,
        party_ids: (0..canonical.h).map(|party_id| party_id as u32).collect(),
        row_index,
        component,
        shares,
    })
}

#[cfg(test)]
mod row_tests {
    use super::*;
    use crate::threshold::aggregate_rows;
    use e3_committee::CiphernodesCommitteeSize;

    use e3_zk_config::threshold::rlk_aggregation::*;

    use e3_zk_witness::{commitments::*, WitnessError};

    fn generate_toml(inputs: RlkAggregationInputs) -> Result<String, WitnessError> {
        toml::to_string(&inputs.to_json()).map_err(|e| WitnessError::Other(e.to_string()))
    }

    #[test]
    fn secure_sample_builds_component_inputs_and_rejects_wrong_multiplicity(
    ) -> Result<(), WitnessError> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let configs = RlkAggregationConfigs::for_preset(preset, CiphernodesCommitteeSize::Minimum)?;
        let mut sample =
            generate_sample_for_row(preset, committee.clone(), 4, RlkAggregationComponent::D0)?;
        let adapter = e3_zk_witness::threshold::rlk_generation::RlkGenerationAdapter::from_config(
            &e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs::for_preset(
                preset,
                CiphernodesCommitteeSize::Minimum,
            )?,
        )?;

        let mut aggregates = Vec::new();
        for component in RlkAggregationComponent::ALL {
            sample.component = component;
            let inputs = RlkAggregationInputs::compute(&configs, &sample)?;
            assert_eq!(inputs.row_index, 4);
            assert_eq!(inputs.component, component.index());
            assert_eq!(inputs.values.len(), committee.h);
            for (party, share) in sample.shares.iter().enumerate() {
                let (d0, d2) = adapter.share_row_components(4, share)?;
                let expected = match component {
                    RlkAggregationComponent::D0 => d0,
                    RlkAggregationComponent::D2 => d2,
                };
                assert_eq!(inputs.values[party], expected);
                assert_eq!(
                    inputs.expected_commitments[party],
                    component.generation_commitment(4, &expected, configs.bits.d_bit)
                );
            }
            assert_eq!(
                inputs.agg,
                aggregate_rows(&inputs.values, &configs.moduli, configs.n)?
            );
            aggregates.push(compute_rlk_aggregation_commitment(
                &inputs.agg,
                configs.bits.d_bit,
            ));
            let toml = generate_toml(inputs)?;
            assert!(toml.contains("expected_commitments"));
            // The circuit takes packed rows and derives the aggregate itself.
            assert!(toml.contains("value_carriers"));
            assert!(!toml.contains("[[agg]]"));
        }
        assert_ne!(aggregates[0], aggregates[1]);
        assert!(configs.render()?.contains("RLK_AGGREGATION_CONFIGS"));

        let removed = sample.shares.pop().expect("sample has H shares");
        assert!(RlkAggregationInputs::compute(&configs, &sample).is_err());
        sample.shares.push(removed);
        sample.shares.push(sample.shares[0].clone());
        assert!(RlkAggregationInputs::compute(&configs, &sample).is_err());
        Ok(())
    }
}
