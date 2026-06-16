// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the share-computation circuit: constants, bounds, bit widths, and input.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) secret plus shares. Input values are normalized to [0, q_j) per modulus
//! and then to the ZKP field modulus so the Noir circuit's range check and parity check succeed.

use crate::bigint_3d_to_json_values;
use crate::circuits::commitments::{
    compute_share_computation_e_sm_commitment, compute_share_computation_sk_commitment,
};
use crate::computation::DkgInputType;
use crate::dkg::share_computation::ShareComputationCircuit;
use crate::dkg::share_computation::ShareComputationCircuitData;
use crate::CircuitsErrors;
use crate::{calculate_bit_width, crt_polynomial_to_toml_json, poly_coefficients_to_toml_json};
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::{reduce, CrtPolynomial};
use fhe::bfv::SecretKey;
use fhe::trbfv::{SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use num_bigint::{BigInt, BigUint};
use serde::{Deserialize, Serialize};

/// Output of [`CircuitComputation::compute`] for [`ShareComputationCircuit`]: bounds, bit widths, and input.
#[derive(Debug)]
pub struct ShareComputationOutput {
    pub bounds: Bounds,
    pub bits: Bits,
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`ShareComputationCircuit`].
impl CircuitComputation for ShareComputationCircuit {
    type Preset = BfvPreset;
    type Data = ShareComputationCircuitData;
    type Output = ShareComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(ShareComputationOutput {
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

/// Bit widths used by the Noir prover (e.g. for packing coefficients).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub bit_sk_secret: u32,
    pub bit_e_sm_secret: u32,
    pub bit_share: u32,
}

/// Coefficient bounds for public key polynomials (used to derive bit widths).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub sk_bound: BigUint,
    pub e_sm_bound: BigUint,
}

/// Input for the share-computation circuit: secret in CRT form, y (secret + shares per coeff/modulus), and commitment.
///
/// All coefficients are reduced to the ZKP field modulus for serialization. Before that,
/// secret_crt and y are normalized so that per modulus j: secret and shares are in [0, q_j),
/// ensuring the circuit's secret consistency (y[i][j][0] == e_sm_secret[j][i]), range check, and parity check pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Secret polynomial in CRT form (SK or smudging noise). Coefficients in [0, zkp_modulus) for serialization.
    pub secret_crt: CrtPolynomial,
    /// y[coeff_idx][mod_idx][0] = secret at (mod_idx, coeff_idx); y[coeff_idx][mod_idx][1 + party] = share for party. Values in [0, zkp_modulus).
    pub y: Vec<Vec<Vec<BigInt>>>,
    /// Expected secret commitment (matches C1's compute_secret_commitment).
    pub expected_secret_commitment: BigInt,
    /// Which secret type this witness is for (determines which circuit to run).
    pub dkg_input_type: DkgInputType,
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ShareComputationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let moduli = threshold_params.moduli().to_vec();
        let l = moduli.len();
        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;

        Ok(Configs {
            n: threshold_params.degree(),
            l,
            moduli,
            bits,
            bounds,
        })
    }
}

impl Computation for Bits {
    type Preset = BfvPreset;
    type Data = Bounds;
    type Error = crate::utils::ZkHelpersUtilsError;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) = build_pair_for_preset(preset)
            .map_err(|e| crate::utils::ZkHelpersUtilsError::ParseBound(e.to_string()))?;

        let mut bit_share = 0;
        for &qi in threshold_params.moduli() {
            let share_bound = BigUint::from(qi - 1);
            let bit_width = calculate_bit_width(BigInt::from(share_bound));
            bit_share = bit_share.max(bit_width);
        }

        Ok(Bits {
            bit_sk_secret: calculate_bit_width(BigInt::from(data.sk_bound.clone())),
            bit_e_sm_secret: calculate_bit_width(BigInt::from(data.e_sm_bound.clone())),
            bit_share,
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ShareComputationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
        let defaults = preset
            .search_defaults()
            .ok_or_else(|| CircuitsErrors::Sample("missing search defaults".to_string()))?;
        let num_ciphertexts = defaults.z;
        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = preset
            .lambda()
            .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        // Use the same committee size as C1 (pk_generation) so smudging bounds and
        // bit widths match PK_GENERATION_BIT_E_SM / SHARE_COMPUTATION_E_SM_BIT_SECRET.
        let e_sm_config = SmudgingBoundCalculatorConfig::new(
            threshold_params,
            data.n_parties as usize,
            num_ciphertexts as usize,
            lambda,
        );

        let e_sm_calculator = SmudgingBoundCalculator::new(e_sm_config);

        let e_sm_bound = e_sm_calculator.calculate_sm_bound()?;

        Ok(Bounds {
            sk_bound: BigUint::from(SecretKey::sk_bound() as u128),
            e_sm_bound,
        })
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = ShareComputationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
        let moduli = threshold_params.moduli();
        let degree = threshold_params.degree();
        let num_moduli = moduli.len();
        let n_parties = data.n_parties as usize;

        let mut secret_crt = data.secret.clone();
        let sss = &data.secret_sss;

        if data.dkg_input_type == DkgInputType::SmudgingNoise {
            // Normalize secret_crt to [0, q_j) per limb so it matches what we put in y and what the circuit expects (e_sm_secret[j][i] == y[i][j][0]).
            secret_crt
                .reduce(moduli)
                .map_err(|e| CircuitsErrors::Sample(format!("secret_crt reduce: {:?}", e)))?;
        }

        // y[coeff_idx][mod_idx][0] = secret_crt[mod_idx][coeff_idx] (already in [0, q_j)); y[coeff_idx][mod_idx][1+party] = share in [0, q_j).
        let mut y: Vec<Vec<Vec<BigInt>>> = Vec::with_capacity(degree);
        for coeff_idx in 0..degree {
            let mut y_coeff: Vec<Vec<BigInt>> = Vec::with_capacity(num_moduli);
            for mod_idx in 0..num_moduli {
                let q_j = BigInt::from(moduli[mod_idx]);
                let mut y_mod: Vec<BigInt> = Vec::with_capacity(1 + n_parties);
                y_mod.push(secret_crt.limb(mod_idx).coefficients()[coeff_idx].clone());
                for party_idx in 0..n_parties {
                    let share_value = &sss[mod_idx][[party_idx, coeff_idx]];
                    y_mod.push(reduce(share_value, &q_j));
                }
                y_coeff.push(y_mod);
            }
            y.push(y_coeff);
        }

        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;
        // Reverse+center before committing to match C1 (PkGeneration)'s convention:
        // C1 applies reverse then center to sk/e_sm before computing the commitment.
        // For SK the values are already centered ({-1,0,1}) so centering is a no-op.
        // For e_sm values are in [0,q) here, so we must center to [-(q-1)/2, (q-1)/2].
        let expected_secret_commitment = match data.dkg_input_type {
            DkgInputType::SecretKey => {
                let mut reversed = secret_crt.limb(0).clone();
                reversed.reverse();
                compute_share_computation_sk_commitment(&reversed, bits.bit_sk_secret)
            }
            DkgInputType::SmudgingNoise => {
                let centered_reversed_crt = e3_polynomial::CrtPolynomial::new(
                    secret_crt
                        .limbs
                        .iter()
                        .zip(moduli.iter())
                        .map(|(l, &qi)| {
                            let q = num_bigint::BigInt::from(qi);
                            let mut r = l.clone();
                            r.reverse();
                            r.center(&q);
                            r
                        })
                        .collect(),
                );
                compute_share_computation_e_sm_commitment(
                    &centered_reversed_crt,
                    bits.bit_e_sm_secret,
                )
            }
        };

        Ok(Inputs {
            secret_crt,
            y,
            expected_secret_commitment,
            dkg_input_type: data.dkg_input_type,
        })
    }

    // Used as input for Nargo execution.
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let y = bigint_3d_to_json_values(&self.y);
        let expected_secret_commitment = self.expected_secret_commitment.to_string();

        let (key, value) = match self.dkg_input_type {
            DkgInputType::SecretKey => (
                "sk_secret",
                poly_coefficients_to_toml_json(self.secret_crt.limb(0).coefficients()),
            ),
            DkgInputType::SmudgingNoise => (
                "e_sm_secret",
                serde_json::Value::Array(crt_polynomial_to_toml_json(&self.secret_crt)),
            ),
        };

        let mut json = serde_json::json!({
            "y": y,
            "expected_secret_commitment": expected_secret_commitment,
        });

        json.as_object_mut().unwrap().insert(key.to_string(), value);

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ciphernodes_committee::CiphernodesCommitteeSize;
    use crate::computation::DkgInputType;
    use crate::dkg::share_computation::ShareComputationCircuitData;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();
        let expected_sk_bits = calculate_bit_width(BigInt::from(bounds.sk_bound.clone()));

        assert_eq!(bits.bit_sk_secret, expected_sk_bits);
    }

    #[test]
    fn test_input_smudging_noise_secret_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SmudgingNoise,
        )
        .unwrap();
        let inputs = Inputs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let degree = inputs.secret_crt.limb(0).coefficients().len();
        let num_moduli = inputs.secret_crt.limbs.len();
        for coeff_idx in 0..degree {
            for mod_idx in 0..num_moduli {
                let secret_coeff =
                    inputs.secret_crt.limb(mod_idx).coefficients()[coeff_idx].clone();
                let y_secret = inputs.y[coeff_idx][mod_idx][0].clone();
                assert_eq!(
                    secret_coeff, y_secret,
                    "secret consistency: secret_crt[{mod_idx}][{coeff_idx}] must equal y[{coeff_idx}][{mod_idx}][0]"
                );
            }
        }
    }

    #[test]
    fn test_constants_json_roundtrip() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();

        let constants = Configs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();

        let json = constants.to_json().unwrap();
        let decoded: Configs = serde_json::from_value(json).unwrap();

        assert_eq!(decoded.n, constants.n);
        assert_eq!(decoded.l, constants.l);
        assert_eq!(decoded.moduli, constants.moduli);
        assert_eq!(decoded.bits, constants.bits);
        assert_eq!(decoded.bounds, constants.bounds);
    }
}
