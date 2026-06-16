// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the pk circuit: constants, bounds, bit widths, and input.
//!
//! [`Constants`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) a public key. They implement [`Computation`] and are used by codegen.

use crate::circuits::dkg::pk::circuit::PkCircuit;
use crate::circuits::dkg::pk::circuit::PkCircuitData;
use crate::compute_max_modulus;
use crate::crt_polynomial_to_toml_json;
use crate::utils::compute_modulus_bit;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// Output of [`CircuitComputation::compute`] for [`PkCircuit`]: bounds, bit widths, and input.
#[derive(Debug)]
pub struct PkComputationOutput {
    pub bounds: Bounds,
    pub bits: Bits,
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`PkCircuit`].
impl CircuitComputation for PkCircuit {
    type Preset = BfvPreset;
    type Data = PkCircuitData;
    type Output = PkComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &())?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(PkComputationOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

/// BFV parameters extracted for the circuit: degree, number of moduli, and modulus values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
}

/// Bit widths used by the Noir prover (e.g. for packing coefficients).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub pk_bit: u32,
}

/// Coefficient bounds for public key polynomials (used to derive bit widths).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub pk_bound: BigUint,
}

/// Input for the pk circuit: public key polynomials in CRT form for the prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Public key polynomials (pk0, pk1) for each CRT basis.
    pub pk0is: CrtPolynomial,
    pub pk1is: CrtPolynomial,
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let moduli = dkg_params.moduli().to_vec();
        let l = moduli.len();
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &())?;

        Ok(Configs {
            n: dkg_params.degree(),
            l,
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
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        Ok(Bits {
            pk_bit: compute_modulus_bit(&dkg_params),
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let moduli = dkg_params.moduli();
        let max_mod = compute_max_modulus(moduli);
        let pk_bound = (BigUint::from(max_mod) - 1u32) / 2u32;

        Ok(Bounds { pk_bound })
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = PkCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
        let moduli = dkg_params.moduli();

        let pk0is = crate::math::fhe_poly_to_crt_centered(&data.public_key.c[0], moduli)?;
        let pk1is = crate::math::fhe_poly_to_crt_centered(&data.public_key.c[1], moduli)?;

        Ok(Inputs { pk0is, pk1is })
    }

    // Used as inputs for Nargo execution.
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let pk0is = crt_polynomial_to_toml_json(&self.pk0is);
        let pk1is = crt_polynomial_to_toml_json(&self.pk1is);

        let json = serde_json::json!({
            "pk0is": pk0is,
            "pk1is": pk1is,
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let (_, dkg_params) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();

        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &()).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &()).unwrap();
        let expected_bits = compute_modulus_bit(&dkg_params);

        assert_eq!(bounds.pk_bound, BigUint::from(1125899906777088u128));
        assert_eq!(bits.pk_bit, expected_bits);
    }

    #[test]
    fn test_constants_json_roundtrip() {
        let constants = Configs::compute(BfvPreset::InsecureThreshold512, &()).unwrap();

        let json = constants.to_json().unwrap();
        let decoded: Configs = serde_json::from_value(json).unwrap();

        assert_eq!(decoded.n, constants.n);
        assert_eq!(decoded.l, constants.l);
        assert_eq!(decoded.moduli, constants.moduli);
        assert_eq!(decoded.bits, constants.bits);
        assert_eq!(decoded.bounds, constants.bounds);
    }
}
