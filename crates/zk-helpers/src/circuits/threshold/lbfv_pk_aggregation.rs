// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion and aggregation of threshold l-BFV public-key share rows.

use crate::{
    bigint_1d_to_json_values, compute_modulus_bit, compute_threshold_pk_commitment,
    crt_polynomial_to_toml_json, Artifacts, CiphernodesCommittee, Circuit, CircuitCodegen,
    CircuitComputation, CircuitsErrors, CodegenConfigs, CodegenToml, Computation,
};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::PublicKeyShare;
use num_bigint::BigInt;

/// Row-level threshold l-BFV public-key aggregation circuit.
#[derive(Debug)]
pub struct LbfvPkAggregationCircuit;

impl Circuit for LbfvPkAggregationCircuit {
    const NAME: &'static str = "lbfv-pk-aggregation";
    const PREFIX: &'static str = "LBFV_PK_AGGREGATION";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

/// Selected public-key shares for one gadget row, in canonical party order.
pub struct LbfvPkAggregationCircuitData {
    pub committee: CiphernodesCommittee,
    pub row_index: u32,
    pub shares: Vec<PublicKeyShare>,
}

/// Complete l-BFV public-key aggregation computation output.
pub struct LbfvPkAggregationComputationOutput {
    pub configs: LbfvPkAggregationConfigs,
    pub inputs: LbfvPkAggregationInputs,
}

/// Constants for one l-BFV public-key aggregation configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LbfvPkAggregationConfigs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: LbfvPkAggregationBits,
}

/// Coefficient bit width used by the l-BFV public-key aggregation circuit.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LbfvPkAggregationBits {
    pub pk_bit: u32,
}

/// Prover inputs for one aggregated l-BFV public-key gadget row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LbfvPkAggregationInputs {
    pub row_index: u32,
    pub expected_pk_generation_commitments: Vec<BigInt>,
    pub pk0: Vec<CrtPolynomial>,
    pub pk0_agg: CrtPolynomial,
}

impl CircuitComputation for LbfvPkAggregationCircuit {
    type Preset = BfvPreset;
    type Data = LbfvPkAggregationCircuitData;
    type Output = LbfvPkAggregationComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        Ok(Self::Output {
            configs: LbfvPkAggregationConfigs::compute(preset, &data.committee)?,
            inputs: LbfvPkAggregationInputs::compute(preset, data)?,
        })
    }
}

impl Computation for LbfvPkAggregationBits {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        ensure_supported(preset)?;
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        Ok(Self {
            pk_bit: compute_modulus_bit(&params),
        })
    }
}

impl Computation for LbfvPkAggregationConfigs {
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
            bits: LbfvPkAggregationBits::compute(preset, &())?,
        })
    }
}

impl Computation for LbfvPkAggregationInputs {
    type Preset = BfvPreset;
    type Data = LbfvPkAggregationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        ensure_supported(preset)?;
        let canonical =
            crate::ciphernodes_committee::canonical_committee_for_circuit(&data.committee)
                .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        if data.shares.len() != canonical.h {
            return Err(CircuitsErrors::Other(format!(
                "l-BFV public-key aggregation requires exactly {} shares; received {}",
                canonical.h,
                data.shares.len()
            )));
        }

        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let adapter = super::pk_generation::LbfvPkGenerationAdapter::new(preset)?;
        let bit_pk = compute_modulus_bit(&params);
        let mut pk0 = Vec::with_capacity(canonical.h);
        let mut expected_pk_generation_commitments = Vec::with_capacity(canonical.h);

        for share in &data.shares {
            let (_, pk0_row) = adapter.share_row_components(data.row_index, share)?;
            expected_pk_generation_commitments
                .push(compute_threshold_pk_commitment(&pk0_row, bit_pk));
            pk0.push(pk0_row);
        }
        let pk0_agg = aggregate_rows(&pk0, params.moduli(), params.degree())?;

        Ok(Self {
            row_index: data.row_index,
            expected_pk_generation_commitments,
            pk0,
            pk0_agg,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let pk0 = self
            .pk0
            .iter()
            .map(crt_polynomial_to_toml_json)
            .collect::<Vec<_>>();
        Ok(serde_json::json!({
            "row_index": self.row_index,
            "expected_pk_generation_commitments": bigint_1d_to_json_values(
                &self.expected_pk_generation_commitments,
            ),
            "pk0": pk0,
            "pk0_agg": crt_polynomial_to_toml_json(&self.pk0_agg),
        }))
    }
}

impl CircuitCodegen for LbfvPkAggregationCircuit {
    type Preset = BfvPreset;
    type Data = LbfvPkAggregationCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let output = Self::compute(preset, data)?;
        Ok(Artifacts {
            toml: generate_toml(output.inputs)?,
            configs: generate_configs(&output.configs),
        })
    }
}

/// Serialize one l-BFV public-key aggregation row as `Prover.toml`.
pub fn generate_toml(inputs: LbfvPkAggregationInputs) -> Result<CodegenToml, CircuitsErrors> {
    Ok(toml::to_string(&inputs.to_json()?)?)
}

/// Generate standalone Noir constants for l-BFV public-key aggregation.
pub fn generate_configs(configs: &LbfvPkAggregationConfigs) -> CodegenConfigs {
    let moduli = crate::utils::join_display(&configs.moduli, ", ");
    format!(
        r#"use crate::core::threshold::pk_aggregation::Configs as PkAggregationConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

pub global PK_AGGREGATION_BIT_PK: u32 = {};
pub global PK_AGGREGATION_CONFIGS: PkAggregationConfigs<L> = PkAggregationConfigs::new(QIS);
"#,
        configs.n, configs.l, moduli, configs.bits.pk_bit,
    )
}

impl LbfvPkAggregationCircuitData {
    /// Generate one valid aggregation row for codegen and prover tests.
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
        let adapter = super::pk_generation::LbfvPkGenerationAdapter::new(preset)?;
        adapter.crs_row(row_index)?;
        let crp = CommonRandomPolyVec::from_seed(
            &params,
            lbfv_crs_seed(preset).ok_or_else(|| {
                CircuitsErrors::Sample("supported preset has no l-BFV CRS seed".to_string())
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

        Ok(Self {
            committee,
            row_index,
            shares,
        })
    }
}

fn ensure_supported(preset: BfvPreset) -> Result<(), CircuitsErrors> {
    if lbfv_crs_seed(preset).is_none() {
        return Err(CircuitsErrors::Other(format!(
            "l-BFV public-key aggregation is not enabled for {preset:?}"
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
            "l-BFV public-key aggregation requires at least one share".to_string(),
        ));
    }
    crate::utils::verify_crt_shapes(&rows.iter().collect::<Vec<_>>(), moduli.len(), degree)
        .map_err(|error| CircuitsErrors::Other(format!("l-BFV CRT shape mismatch: {error}")))?;

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
    use crate::{compute_pk_aggregation_commitment, CiphernodesCommitteeSize};

    #[test]
    fn unsupported_presets_fail_closed() {
        let committee = CiphernodesCommitteeSize::Minimum.values();
        assert!(
            LbfvPkAggregationConfigs::compute(BfvPreset::InsecureThreshold512, &committee).is_err()
        );
        assert!(
            LbfvPkAggregationConfigs::compute(BfvPreset::SecureThreshold8192, &committee).is_err()
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
    fn secure_nonzero_row_builds_commitments_and_exact_aggregate() -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let mut sample =
            LbfvPkAggregationCircuitData::generate_sample_for_row(preset, committee.clone(), 4)?;
        let inputs = LbfvPkAggregationInputs::compute(preset, &sample)?;
        let configs = LbfvPkAggregationConfigs::compute(preset, &committee)?;
        let adapter = super::super::pk_generation::LbfvPkGenerationAdapter::new(preset)?;

        assert_eq!(inputs.row_index, 4);
        assert_eq!(inputs.pk0.len(), committee.h);
        assert_eq!(
            inputs.pk0_agg,
            aggregate_rows(&inputs.pk0, &configs.moduli, configs.n)?
        );
        for party in 0..committee.h {
            assert_eq!(
                inputs.expected_pk_generation_commitments[party],
                compute_threshold_pk_commitment(&inputs.pk0[party], configs.bits.pk_bit)
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
        assert!(toml.contains("[[pk0_agg]]"));
        assert!(generate_configs(&configs).contains("PK_AGGREGATION_CONFIGS"));

        let removed = sample.shares.pop().expect("sample has H shares");
        assert!(LbfvPkAggregationInputs::compute(preset, &sample).is_err());
        sample.shares.push(removed);
        sample.shares.push(sample.shares[0].clone());
        assert!(LbfvPkAggregationInputs::compute(preset, &sample).is_err());
        Ok(())
    }

    #[test]
    fn wrong_crs_and_row_bounds_fail_closed() -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let mut sample =
            LbfvPkAggregationCircuitData::generate_sample_for_row(preset, committee.clone(), 0)?;
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let mut rng = rand::rng();
        let other_crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        sample.shares[0] = PublicKeyShare::contribute_with_crp(&secret_key, &other_crp, &mut rng)?;
        assert!(LbfvPkAggregationInputs::compute(preset, &sample).is_err());

        let out_of_range = LbfvPkAggregationCircuitData::generate_sample_for_row(
            preset,
            committee,
            params.moduli().len() as u32,
        );
        assert!(out_of_range.is_err());
        Ok(())
    }
}
