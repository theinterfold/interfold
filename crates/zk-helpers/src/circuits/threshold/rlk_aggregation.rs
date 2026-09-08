// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion and aggregation of l-BFV relinearization-key share rows.

use crate::{
    bigint_1d_to_json_values, compute_modulus_bit, compute_rlk_d0_commitment,
    compute_rlk_d2_commitment, crt_polynomial_to_toml_json, Artifacts, CiphernodesCommittee,
    Circuit, CircuitCodegen, CircuitComputation, CircuitsErrors, CodegenConfigs, CodegenToml,
    Computation,
};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::RelinKeyShare;
use num_bigint::BigInt;

/// Row-level l-BFV relinearization-key aggregation circuit.
#[derive(Debug)]
pub struct RlkAggregationCircuit;

impl Circuit for RlkAggregationCircuit {
    const NAME: &'static str = "rlk-aggregation";
    const PREFIX: &'static str = "RLK_AGGREGATION";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

/// Selected RLK shares for one gadget row, in canonical party order.
pub struct RlkAggregationCircuitData {
    pub committee: CiphernodesCommittee,
    pub row_index: u32,
    pub shares: Vec<RelinKeyShare>,
}

/// Complete RLK aggregation computation output.
pub struct RlkAggregationComputationOutput {
    pub configs: RlkAggregationConfigs,
    pub inputs: RlkAggregationInputs,
}

/// Constants for one RLK aggregation circuit configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RlkAggregationConfigs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: RlkAggregationBits,
}

/// Coefficient bit width used by the RLK aggregation circuit.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RlkAggregationBits {
    pub d_bit: u32,
}

/// Prover inputs for one aggregated RLK gadget row.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RlkAggregationInputs {
    pub row_index: u32,
    pub expected_d0_commitments: Vec<BigInt>,
    pub expected_d2_commitments: Vec<BigInt>,
    pub d0: Vec<CrtPolynomial>,
    pub d2: Vec<CrtPolynomial>,
    pub d0_agg: CrtPolynomial,
    pub d2_agg: CrtPolynomial,
}

impl CircuitComputation for RlkAggregationCircuit {
    type Preset = BfvPreset;
    type Data = RlkAggregationCircuitData;
    type Output = RlkAggregationComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        Ok(Self::Output {
            configs: RlkAggregationConfigs::compute(preset, &data.committee)?,
            inputs: RlkAggregationInputs::compute(preset, data)?,
        })
    }
}

impl Computation for RlkAggregationBits {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        ensure_supported(preset)?;
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        Ok(Self {
            d_bit: compute_modulus_bit(&params),
        })
    }
}

impl Computation for RlkAggregationConfigs {
    type Preset = BfvPreset;
    type Data = CiphernodesCommittee;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, committee: &Self::Data) -> Result<Self, Self::Error> {
        ensure_supported(preset)?;
        crate::ciphernodes_committee::canonical_committee_for_circuit(committee)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        Ok(Self {
            n: params.degree(),
            l: params.moduli().len(),
            moduli: params.moduli().to_vec(),
            bits: RlkAggregationBits::compute(preset, &())?,
        })
    }
}

impl Computation for RlkAggregationInputs {
    type Preset = BfvPreset;
    type Data = RlkAggregationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        ensure_supported(preset)?;
        let canonical =
            crate::ciphernodes_committee::canonical_committee_for_circuit(&data.committee)
                .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        if data.shares.len() != canonical.h {
            return Err(CircuitsErrors::Other(format!(
                "RLK aggregation requires exactly {} shares; received {}",
                canonical.h,
                data.shares.len()
            )));
        }

        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let adapter = super::rlk_generation::RlkGenerationAdapter::new(preset)?;
        let bit_d = compute_modulus_bit(&params);
        let mut d0 = Vec::with_capacity(canonical.h);
        let mut d2 = Vec::with_capacity(canonical.h);
        let mut expected_d0_commitments = Vec::with_capacity(canonical.h);
        let mut expected_d2_commitments = Vec::with_capacity(canonical.h);

        for share in &data.shares {
            let (d0_row, d2_row) = adapter.share_row_components(data.row_index, share)?;
            expected_d0_commitments.push(compute_rlk_d0_commitment(&d0_row, bit_d));
            expected_d2_commitments.push(compute_rlk_d2_commitment(&d2_row, bit_d));
            d0.push(d0_row);
            d2.push(d2_row);
        }

        let d0_agg = aggregate_rows(&d0, params.moduli(), params.degree())?;
        let d2_agg = aggregate_rows(&d2, params.moduli(), params.degree())?;

        Ok(Self {
            row_index: data.row_index,
            expected_d0_commitments,
            expected_d2_commitments,
            d0,
            d2,
            d0_agg,
            d2_agg,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let d0 = self
            .d0
            .iter()
            .map(crt_polynomial_to_toml_json)
            .collect::<Vec<_>>();
        let d2 = self
            .d2
            .iter()
            .map(crt_polynomial_to_toml_json)
            .collect::<Vec<_>>();
        Ok(serde_json::json!({
            "row_index": self.row_index,
            "expected_d0_commitments": bigint_1d_to_json_values(&self.expected_d0_commitments),
            "expected_d2_commitments": bigint_1d_to_json_values(&self.expected_d2_commitments),
            "d0": d0,
            "d2": d2,
            "d0_agg": crt_polynomial_to_toml_json(&self.d0_agg),
            "d2_agg": crt_polynomial_to_toml_json(&self.d2_agg),
        }))
    }
}

impl CircuitCodegen for RlkAggregationCircuit {
    type Preset = BfvPreset;
    type Data = RlkAggregationCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let output = Self::compute(preset, data)?;
        Ok(Artifacts {
            toml: generate_toml(output.inputs)?,
            configs: generate_configs(&output.configs),
        })
    }
}

/// Serialize one RLK aggregation row as `Prover.toml`.
pub fn generate_toml(inputs: RlkAggregationInputs) -> Result<CodegenToml, CircuitsErrors> {
    Ok(toml::to_string(&inputs.to_json()?)?)
}

/// Generate standalone Noir constants for RLK aggregation.
pub fn generate_configs(configs: &RlkAggregationConfigs) -> CodegenConfigs {
    let prefix = <RlkAggregationCircuit as Circuit>::PREFIX;
    let moduli = crate::utils::join_display(&configs.moduli, ", ");
    format!(
        r#"use crate::core::threshold::rlk_aggregation::Configs as RlkAggregationConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

pub global {}_BIT_D: u32 = {};
pub global {}_CONFIGS: RlkAggregationConfigs<L> = RlkAggregationConfigs::new(QIS);
"#,
        configs.n, configs.l, moduli, prefix, configs.bits.d_bit, prefix,
    )
}

impl RlkAggregationCircuitData {
    /// Generate one valid RLK aggregation row for codegen and prover tests.
    pub fn generate_sample_for_row(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
        row_index: u32,
    ) -> Result<Self, CircuitsErrors> {
        ensure_supported(preset)?;
        let canonical = crate::ciphernodes_committee::canonical_committee_for_circuit(&committee)
            .map_err(|error| CircuitsErrors::Sample(error.to_string()))?;
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Sample(error.to_string()))?;
        if row_index as usize >= params.moduli().len() {
            return Err(CircuitsErrors::Sample(format!(
                "RLK row index {row_index} is out of range for {} rows",
                params.moduli().len()
            )));
        }
        let crp_d1 = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_urs_seed(preset).ok_or_else(|| {
                CircuitsErrors::Sample("supported preset has no RLK URS seed".to_string())
            })?,
        )?;
        let crp_a = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_crs_seed(preset).ok_or_else(|| {
                CircuitsErrors::Sample("supported preset has no RLK CRS seed".to_string())
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

        Ok(Self {
            committee,
            row_index,
            shares,
        })
    }
}

fn ensure_supported(preset: BfvPreset) -> Result<(), CircuitsErrors> {
    if lbfv_crs_seed(preset).is_none() || lbfv_urs_seed(preset).is_none() {
        return Err(CircuitsErrors::Other(format!(
            "l-BFV RLK aggregation is not enabled for {preset:?}"
        )));
    }
    Ok(())
}

fn aggregate_rows(
    rows: &[CrtPolynomial],
    moduli: &[u64],
    degree: usize,
) -> Result<CrtPolynomial, CircuitsErrors> {
    if rows.is_empty() {
        return Err(CircuitsErrors::Other(
            "RLK aggregation requires at least one share".to_string(),
        ));
    }
    crate::utils::verify_crt_shapes(&rows.iter().collect::<Vec<_>>(), moduli.len(), degree)
        .map_err(|error| CircuitsErrors::Other(format!("RLK CRT shape mismatch: {error}")))?;

    let limbs = (0..moduli.len())
        .map(|limb_index| {
            let mut coefficients = vec![BigInt::from(0u8); degree];
            for row in rows {
                for (sum, coefficient) in coefficients
                    .iter_mut()
                    .zip(row.limb(limb_index).coefficients())
                {
                    *sum += coefficient;
                }
            }
            Polynomial::new(coefficients)
        })
        .collect();
    let mut aggregate = CrtPolynomial::new(limbs);
    aggregate.reduce(moduli)?;
    aggregate.center(moduli)?;
    Ok(aggregate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compute_rlk_aggregation_commitment, CiphernodesCommitteeSize};

    #[test]
    fn unsupported_presets_fail_closed() {
        let committee = CiphernodesCommitteeSize::Minimum.values();
        assert!(
            RlkAggregationConfigs::compute(BfvPreset::InsecureThreshold512, &committee).is_err()
        );
        assert!(
            RlkAggregationConfigs::compute(BfvPreset::SecureThreshold8192, &committee).is_err()
        );
    }

    #[test]
    fn aggregation_reduces_and_centers_each_limb() -> Result<(), CircuitsErrors> {
        let rows = vec![
            CrtPolynomial::from_bigint_vectors(vec![
                vec![4.into(), (-4).into()],
                vec![6.into(), 1.into()],
            ]),
            CrtPolynomial::from_bigint_vectors(vec![
                vec![4.into(), 3.into()],
                vec![6.into(), 6.into()],
            ]),
        ];
        let aggregate = aggregate_rows(&rows, &[7, 11], 2)?;

        assert_eq!(aggregate.limb(0).coefficients(), &[1.into(), (-1).into()]);
        assert_eq!(aggregate.limb(1).coefficients(), &[1.into(), (-4).into()]);
        Ok(())
    }

    #[test]
    fn secure_sample_builds_row_inputs_and_rejects_wrong_multiplicity() -> Result<(), CircuitsErrors>
    {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let mut sample =
            RlkAggregationCircuitData::generate_sample_for_row(preset, committee.clone(), 4)?;
        let inputs = RlkAggregationInputs::compute(preset, &sample)?;
        let configs = RlkAggregationConfigs::compute(preset, &committee)?;

        assert_eq!(inputs.row_index, 4);
        assert_eq!(inputs.d0.len(), committee.h);
        assert_eq!(inputs.d2.len(), committee.h);
        assert_eq!(
            inputs.d0_agg,
            aggregate_rows(&inputs.d0, &configs.moduli, configs.n)?
        );
        assert_eq!(
            inputs.d2_agg,
            aggregate_rows(&inputs.d2, &configs.moduli, configs.n)?
        );
        for party in 0..committee.h {
            assert_eq!(
                inputs.expected_d0_commitments[party],
                compute_rlk_d0_commitment(&inputs.d0[party], configs.bits.d_bit)
            );
            assert_eq!(
                inputs.expected_d2_commitments[party],
                compute_rlk_d2_commitment(&inputs.d2[party], configs.bits.d_bit)
            );
        }
        assert_ne!(
            compute_rlk_aggregation_commitment(&inputs.d0_agg, configs.bits.d_bit),
            compute_rlk_aggregation_commitment(&inputs.d2_agg, configs.bits.d_bit)
        );
        let toml = generate_toml(inputs)?;
        assert!(toml.contains("expected_d0_commitments"));
        assert!(toml.contains("[[d0_agg]]"));
        assert!(generate_configs(&configs).contains("RLK_AGGREGATION_CONFIGS"));

        let removed = sample.shares.pop().expect("sample has H shares");
        assert!(RlkAggregationInputs::compute(preset, &sample).is_err());
        sample.shares.push(removed);
        sample.shares.push(sample.shares[0].clone());
        assert!(RlkAggregationInputs::compute(preset, &sample).is_err());
        Ok(())
    }
}
