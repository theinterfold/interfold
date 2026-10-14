// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion and aggregation of l-BFV relinearization-key share rows. Each gadget row is proved
//! once per component: `d0` and `d2` are independent sums, and `lbfv_aggregation_fold` binds the
//! two proofs of a row to components 0 and 1.

use crate::threshold::lbfv_proof_domain::{
    lbfv_accepted_party_set, lbfv_proof_session, sample_lbfv_proof_domain,
    validate_lbfv_generation_party_id,
};
use crate::{
    bigint_1d_to_json_values, compute_modulus_bit, compute_rlk_d0_commitment,
    compute_rlk_d2_commitment, crt_polynomial_to_toml_json, Artifacts, CiphernodesCommittee,
    Circuit, CircuitCodegen, CircuitComputation, CircuitsErrors, CodegenConfigs, CodegenToml,
    Computation,
};
use e3_committee_hash::LbfvProofDomainContext;
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::RelinKeyShare;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

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

/// The RLK row component that one aggregation proof sums. The discriminant is the circuit's
/// public `component` input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RlkAggregationComponent {
    D0 = 0,
    D2 = 1,
}

impl RlkAggregationComponent {
    /// Both components, in public-input order.
    pub const ALL: [Self; 2] = [Self::D0, Self::D2];

    /// The circuit's public `component` value.
    pub fn index(self) -> u32 {
        self as u32
    }

    /// The component at public `component` value `index`, if any.
    pub fn from_index(index: u32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|component| component.index() == index)
    }

    /// The RLK generation commitment that the circuit opens for this component's row.
    pub fn generation_commitment(self, row_index: u32, row: &CrtPolynomial, bit_d: u32) -> BigInt {
        match self {
            Self::D0 => compute_rlk_d0_commitment(row_index, row, bit_d),
            Self::D2 => compute_rlk_d2_commitment(row_index, row, bit_d),
        }
    }
}

/// Selected RLK shares for one component of one gadget row, in canonical party order.
pub struct RlkAggregationCircuitData {
    pub committee: CiphernodesCommittee,
    pub proof_domain: LbfvProofDomainContext,
    pub aggregator_party_id: u32,
    pub party_ids: Vec<u32>,
    pub row_index: u32,
    pub component: RlkAggregationComponent,
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

/// Prover inputs for one component of one aggregated RLK gadget row.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RlkAggregationInputs {
    pub session_id_hi: u128,
    pub session_id_lo: u128,
    pub aggregator_party_id: u32,
    pub accepted_party_set_hash_hi: u128,
    pub accepted_party_set_hash_lo: u128,
    pub row_index: u32,
    pub component: u32,
    pub expected_commitments: Vec<BigInt>,
    pub values: Vec<CrtPolynomial>,
    pub agg: CrtPolynomial,
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
        let session = lbfv_proof_session(data.proof_domain)?;
        validate_lbfv_generation_party_id(data.aggregator_party_id, &data.committee)?;
        let accepted = lbfv_accepted_party_set(&data.party_ids, &data.committee)?;
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
        let mut values = Vec::with_capacity(canonical.h);
        let mut expected_commitments = Vec::with_capacity(canonical.h);

        for share in &data.shares {
            let (d0_row, d2_row) = adapter.share_row_components(data.row_index, share)?;
            let row = match data.component {
                RlkAggregationComponent::D0 => d0_row,
                RlkAggregationComponent::D2 => d2_row,
            };
            expected_commitments.push(data.component.generation_commitment(
                data.row_index,
                &row,
                bit_d,
            ));
            values.push(row);
        }

        let agg = aggregate_rows(&values, params.moduli(), params.degree())?;

        Ok(Self {
            session_id_hi: session.session_id_hi,
            session_id_lo: session.session_id_lo,
            aggregator_party_id: data.aggregator_party_id,
            accepted_party_set_hash_hi: accepted.accepted_party_set_hash_hi,
            accepted_party_set_hash_lo: accepted.accepted_party_set_hash_lo,
            row_index: data.row_index,
            component: data.component.index(),
            expected_commitments,
            values,
            agg,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let values = self
            .values
            .iter()
            .map(crt_polynomial_to_toml_json)
            .collect::<Vec<_>>();
        Ok(serde_json::json!({
            "session_id_hi": self.session_id_hi.to_string(),
            "session_id_lo": self.session_id_lo.to_string(),
            "aggregator_party_id": self.aggregator_party_id,
            "accepted_party_set_hash_hi": self.accepted_party_set_hash_hi.to_string(),
            "accepted_party_set_hash_lo": self.accepted_party_set_hash_lo.to_string(),
            "row_index": self.row_index,
            "component": self.component,
            "expected_commitments": bigint_1d_to_json_values(&self.expected_commitments),
            "values": values,
            "agg": crt_polynomial_to_toml_json(&self.agg),
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

/// Serialize one RLK aggregation statement as `Prover.toml`.
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
    /// Generate one valid RLK aggregation statement for codegen and prover tests.
    pub fn generate_sample_for_row(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
        row_index: u32,
        component: RlkAggregationComponent,
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
            proof_domain: sample_lbfv_proof_domain(),
            aggregator_party_id: 0,
            party_ids: (0..canonical.h).map(|party_id| party_id as u32).collect(),
            row_index,
            component,
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
    fn secure_sample_builds_component_inputs_and_rejects_wrong_multiplicity(
    ) -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let configs = RlkAggregationConfigs::compute(preset, &committee)?;
        let mut sample = RlkAggregationCircuitData::generate_sample_for_row(
            preset,
            committee.clone(),
            4,
            RlkAggregationComponent::D0,
        )?;
        let adapter = crate::threshold::rlk_generation::RlkGenerationAdapter::new(preset)?;

        let mut aggregates = Vec::new();
        for component in RlkAggregationComponent::ALL {
            sample.component = component;
            let inputs = RlkAggregationInputs::compute(preset, &sample)?;
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
            assert!(toml.contains("[[agg]]"));
        }
        assert_ne!(aggregates[0], aggregates[1]);
        assert!(generate_configs(&configs).contains("RLK_AGGREGATION_CONFIGS"));

        let removed = sample.shares.pop().expect("sample has H shares");
        assert!(RlkAggregationInputs::compute(preset, &sample).is_err());
        sample.shares.push(removed);
        sample.shares.push(sample.shares[0].clone());
        assert!(RlkAggregationInputs::compute(preset, &sample).is_err());
        Ok(())
    }
}
