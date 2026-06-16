// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the public key aggregation circuit: constants, bounds, bit widths, and input.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) public key shares and aggregated public key. They implement [`Computation`] and are used by codegen.

use crate::bigint_1d_to_json_values;
use crate::compute_modulus_bit;
use crate::compute_threshold_pk_commitment;
use crate::crt_polynomial_to_toml_json;
use crate::threshold::pk_aggregation::circuit::PkAggregationCircuit;
use crate::threshold::pk_aggregation::circuit::PkAggregationCircuitData;
use crate::threshold::pk_generation::utils::deterministic_crp_crt_polynomial;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use num_bigint::BigInt;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// Output of [`CircuitComputation::compute`] for [`PkAggregationCircuit`]: bounds, bit widths, and input.
#[derive(Debug)]
pub struct PkAggregationComputationOutput {
    pub bounds: Bounds,
    pub bits: Bits,
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`PkAggregationCircuit`].
impl CircuitComputation for PkAggregationCircuit {
    type Preset = BfvPreset;
    type Data = PkAggregationCircuitData;
    type Output = PkAggregationComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &())?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(PkAggregationComputationOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub pk_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub pk_bound: BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub expected_threshold_pk_commitments: Vec<BigInt>,
    pub pk0: Vec<CrtPolynomial>,
    pub pk0_agg: CrtPolynomial,
    pub crp: CrtPolynomial,
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let moduli = threshold_params.moduli().to_vec();

        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &())?;

        Ok(Configs {
            n: threshold_params.degree(),
            l: moduli.len(),
            moduli,
            bits,
            bounds,
        })
    }
}

impl Computation for Bits {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let pk_bit = compute_modulus_bit(&threshold_params);

        Ok(Bits { pk_bit })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let mut pk_bound_max = BigUint::from(0u32);

        for &qi in threshold_params.moduli() {
            let qi_bound: BigUint = (BigUint::from(qi) - 1u32) / 2u32;

            if qi_bound > pk_bound_max {
                pk_bound_max = qi_bound;
            }
        }

        let bounds = Bounds {
            pk_bound: pk_bound_max,
        };

        Ok(bounds)
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = PkAggregationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let bit_pk = compute_modulus_bit(&threshold_params);

        let mut pk0: Vec<CrtPolynomial> = data.pk0_shares.clone();
        let mut pk0_agg = CrtPolynomial::from_fhe_polynomial(&data.public_key.c[0]);
        let crp = deterministic_crp_crt_polynomial(&threshold_params)?;

        pk0_agg.reverse();
        pk0_agg.center(threshold_params.moduli())?;

        let mut expected_threshold_pk_commitments = Vec::new();

        for pk in pk0.iter_mut().take(data.committee.h) {
            pk.reverse();
            pk.center(threshold_params.moduli())?;

            let commitment = compute_threshold_pk_commitment(pk, bit_pk);

            expected_threshold_pk_commitments.push(commitment);
        }

        Ok(Inputs {
            expected_threshold_pk_commitments,
            pk0,
            pk0_agg,
            crp,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let pk0: Vec<Vec<serde_json::Value>> =
            self.pk0.iter().map(crt_polynomial_to_toml_json).collect();
        let pk0_agg = crt_polynomial_to_toml_json(&self.pk0_agg);
        let expected_threshold_pk_commitments =
            bigint_1d_to_json_values(&self.expected_threshold_pk_commitments);

        let json = serde_json::json!({
            "expected_threshold_pk_commitments": expected_threshold_pk_commitments,
            "pk0": pk0,
            "pk0_agg": pk0_agg,
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let preset = BfvPreset::InsecureThreshold512;
        let (threshold_params, _) = build_pair_for_preset(preset).unwrap();

        let bounds = Bounds::compute(preset, &()).unwrap();
        let bits = Bits::compute(preset, &()).unwrap();

        let expected_bits = compute_modulus_bit(&threshold_params);

        assert_eq!(bounds.pk_bound, BigUint::from(34359701504u128));
        assert_eq!(bits.pk_bit, expected_bits);
    }
}
