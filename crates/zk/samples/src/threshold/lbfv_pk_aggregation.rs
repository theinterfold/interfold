// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Artificial l-BFV row material.
use crate::lbfv_proof_domain::sample_lbfv_proof_domain;
use e3_committee::CiphernodesCommittee;
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, BfvPreset};
use e3_zk_witness::threshold::lbfv_pk_aggregation::*;
use e3_zk_witness::WitnessError;
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::PublicKeyShare;

/// Generate `H` valid public-key shares for one aggregation row, for codegen and prover tests.
pub fn generate_sample_for_row(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    row_index: u32,
) -> Result<LbfvPkAggregationCircuitData, WitnessError> {
    let canonical = e3_zk_config::committee::canonical_committee_for_circuit(&committee)
        .map_err(|error| WitnessError::Sample(error.to_string()))?;
    let (params, _) =
        build_pair_for_preset(preset).map_err(|error| WitnessError::Sample(error.to_string()))?;
    if row_index as usize >= params.moduli().len() {
        return Err(WitnessError::Sample(format!(
            "l-BFV row index {row_index} is out of range for {} rows",
            params.moduli().len()
        )));
    }
    let crp = CommonRandomPolyVec::from_seed(
        &params,
        lbfv_crs_seed(preset).ok_or_else(|| {
            WitnessError::Sample(format!("l-BFV CRS is not enabled for {preset:?}"))
        })?,
    )?;
    let mut rng = rand::rng();
    let mut shares = Vec::with_capacity(canonical.h);
    for _ in 0..canonical.h {
        let secret_key = SecretKey::random(&params, &mut rng);
        shares.push(PublicKeyShare::contribute_with_crp(
            &secret_key,
            &crp,
            &mut rng,
        )?);
    }

    Ok(LbfvPkAggregationCircuitData {
        committee,
        proof_domain: sample_lbfv_proof_domain(),
        aggregator_party_id: 0,
        party_ids: (0..canonical.h).map(|party_id| party_id as u32).collect(),
        row_index,
        shares,
    })
}

#[cfg(test)]
mod row_tests {
    use super::*;
    use crate::threshold::aggregate_rows;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_zk_config::threshold::lbfv_pk_aggregation::*;

    use e3_zk_witness::{commitments::*, WitnessError};
    use num_bigint::BigInt;

    fn configs(preset: BfvPreset) -> Result<LbfvPkAggregationConfigs, WitnessError> {
        Ok(LbfvPkAggregationConfigs::for_preset(
            preset,
            CiphernodesCommitteeSize::Minimum,
        )?)
    }

    fn generate_toml(inputs: LbfvPkAggregationInputs) -> Result<String, WitnessError> {
        toml::to_string(&inputs.to_json()).map_err(|e| WitnessError::Other(e.to_string()))
    }

    #[test]
    fn secure_nonzero_row_builds_commitments_and_exact_aggregate() -> Result<(), WitnessError> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let mut sample = generate_sample_for_row(preset, committee.clone(), 4)?;
        let configs = configs(preset)?;
        let inputs = LbfvPkAggregationInputs::compute(&configs, &sample)?;
        let adapter =
            e3_zk_witness::threshold::pk_generation::LbfvPkGenerationAdapter::from_config(
                &e3_zk_config::threshold::pk_generation::Configs::for_preset(
                    preset,
                    CiphernodesCommitteeSize::Minimum,
                )?,
            )?;

        assert_eq!(inputs.row_index, 4);
        assert_eq!(inputs.pk0.len(), committee.h);
        assert_eq!(
            inputs.pk0_agg,
            aggregate_rows(&inputs.pk0, &configs.moduli, configs.n)?
        );
        for party in 0..committee.h {
            assert_eq!(
                inputs.expected_pk_generation_commitments[party],
                compute_lbfv_pk_row_commitment(
                    inputs.row_index,
                    &inputs.pk0[party],
                    configs.bits.pk_bit
                )
            );
        }
        assert_ne!(
            compute_pk_aggregation_commitment(
                &inputs.pk0_agg,
                &adapter.crs_row(4)?,
                configs.bits.pk_bit,
            ),
            BigInt::from(0u8)
        );
        let toml = generate_toml(inputs)?;
        assert!(toml.contains("expected_pk_generation_commitments"));
        // The circuit takes packed rows and derives the aggregate itself.
        assert!(toml.contains("pk0_carriers"));
        assert!(!toml.contains("pk0_agg"));
        assert!(configs.render()?.contains("PK_AGGREGATION_CONFIGS"));

        let removed = sample.shares.pop().expect("sample has H shares");
        assert!(LbfvPkAggregationInputs::compute(&configs, &sample).is_err());
        sample.shares.push(removed);
        sample.shares.push(sample.shares[0].clone());
        assert!(LbfvPkAggregationInputs::compute(&configs, &sample).is_err());
        Ok(())
    }

    #[test]
    fn wrong_crs_and_row_bounds_fail_closed() -> Result<(), WitnessError> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let mut sample = generate_sample_for_row(preset, committee.clone(), 0)?;
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| WitnessError::Other(error.to_string()))?;
        let mut rng = rand::rng();
        let other_crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        sample.shares[0] = PublicKeyShare::contribute_with_crp(&secret_key, &other_crp, &mut rng)?;
        assert!(LbfvPkAggregationInputs::compute(&configs(preset)?, &sample).is_err());

        let out_of_range = generate_sample_for_row(preset, committee, params.moduli().len() as u32);
        assert!(out_of_range.is_err());
        Ok(())
    }
}
