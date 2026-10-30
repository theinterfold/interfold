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
pub fn generate_sample_for_row(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    row_index: u32,
    component: RlkAggregationComponent,
) -> Result<RlkAggregationCircuitData, WitnessError> {
    ensure_supported(preset)?;
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
            WitnessError::Sample("supported preset has no RLK URS seed".to_string())
        })?,
    )?;
    let crp_a = CommonRandomPolyVec::from_seed(
        &params,
        lbfv_crs_seed(preset).ok_or_else(|| {
            WitnessError::Sample("supported preset has no RLK CRS seed".to_string())
        })?,
    )?;
    let mut rng = rand::rng();
    let mut shares = Vec::with_capacity(canonical.h);
    for _ in 0..canonical.h {
        let secret_key = SecretKey::random(&params, &mut rng);
        shares.push(RelinKeyShare::contribution_with_crp(
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
fn ensure_supported(preset: BfvPreset) -> Result<(), WitnessError> {
    if lbfv_crs_seed(preset).is_none() || lbfv_urs_seed(preset).is_none() {
        return Err(WitnessError::Other(format!(
            "l-BFV RLK aggregation is not enabled for {preset:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod row_tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;

    use e3_polynomial::{CrtPolynomial, Polynomial};
    use e3_zk_config::threshold::rlk_aggregation::*;

    use e3_zk_witness::{commitments::*, WitnessError};
    use num_bigint::BigInt;

    fn size(c: &e3_committee::CiphernodesCommittee) -> CiphernodesCommitteeSize {
        CiphernodesCommitteeSize::from_threshold(c.threshold, c.n).unwrap()
    }
    fn generate_toml(inputs: RlkAggregationInputs) -> Result<String, WitnessError> {
        toml::to_string(
            &inputs
                .to_json()
                .map_err(|e| WitnessError::Other(e.to_string()))?,
        )
        .map_err(|e| WitnessError::Other(e.to_string()))
    }
    fn aggregate_rows(
        rows: &[CrtPolynomial],
        moduli: &[u64],
        degree: usize,
    ) -> Result<CrtPolynomial, WitnessError> {
        let limbs = (0..moduli.len())
            .map(|l| {
                rows.iter().fold(
                    Polynomial::new(vec![BigInt::from(0); degree]),
                    |sum, row| sum.add(row.limb(l)),
                )
            })
            .collect();
        let mut sum = CrtPolynomial::new(limbs);
        sum.reduce(moduli)?;
        sum.center(moduli)?;
        Ok(sum)
    }

    #[test]
    fn secure_sample_builds_component_inputs_and_rejects_wrong_multiplicity(
    ) -> Result<(), WitnessError> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let configs = RlkAggregationConfigs::for_preset(preset, size(&committee))?;
        let mut sample = crate::threshold::rlk_aggregation::generate_sample_for_row(
            preset,
            committee.clone(),
            4,
            RlkAggregationComponent::D0,
        )?;
        let adapter = e3_zk_witness::threshold::rlk_generation::RlkGenerationAdapter::from_config(
            &e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs::for_preset(
                preset,
                CiphernodesCommitteeSize::Minimum,
            )?,
        )?;

        let mut aggregates = Vec::new();
        for component in RlkAggregationComponent::ALL {
            sample.component = component;
            let inputs = RlkAggregationInputs::compute(
                &e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs::for_preset(
                    preset,
                    size(&sample.committee),
                )?,
                &sample,
            )?;
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
        assert!(RlkAggregationInputs::compute(
            &e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs::for_preset(
                preset,
                size(&sample.committee)
            )?,
            &sample
        )
        .is_err());
        sample.shares.push(removed);
        sample.shares.push(sample.shares[0].clone());
        assert!(RlkAggregationInputs::compute(
            &e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs::for_preset(
                preset,
                size(&sample.committee)
            )?,
            &sample
        )
        .is_err());
        Ok(())
    }
}
