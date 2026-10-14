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
    compute_sc_esm_secret_root_commitment, compute_sc_sk_secret_root_commitment,
    compute_share_computation_e_sm_commitment, compute_share_computation_sk_commitment,
};
use crate::computation::DkgInputType;
use crate::dkg::share_computation::ShareComputationCircuit;
use crate::dkg::share_computation::ShareComputationCircuitData;
use crate::CircuitsErrors;
use crate::{calculate_bit_width, crt_polynomial_to_toml_json, poly_coefficients_to_toml_json};
use crate::{CircuitComputation, Computation};
use e3_fhe_params::BfvPreset;
use e3_fhe_params::{build_pair_for_preset, calculate_smudging_bound};
use e3_polynomial::{reduce, CrtPolynomial};
use fhe::bfv::SecretKey;
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
    /// l-BFV smudging noise only: the lifted noise and its CRT quotients (see [`e_sm_crt_lift`]),
    /// which the C2b chunk leaves range-check. `None` for the secret key and on the trBFV path,
    /// whose single C2 proof takes no such inputs.
    #[serde(default)]
    pub e_sm_lift: Option<(Vec<BigInt>, Vec<Vec<BigInt>>)>,
}

/// The smudging noise lifted to one integer per coefficient, and the CRT quotient that ties it to
/// each centered residue: `lifted[i] == center(residue_l[i], q_l) + quotients[l][i] * q_l`.
///
/// The l-BFV C2b chunk leaves range-check `lifted` against `e_sm_bound`, the check C1 carries on
/// the trBFV path. Coefficients are in natural order, the order of `y`. The noise is bounded far
/// below `Q / 2`, so the centered CRT reconstruction recovers it exactly.
pub fn e_sm_crt_lift(
    secret_crt: &CrtPolynomial,
    moduli: &[u64],
) -> Result<(Vec<BigInt>, Vec<Vec<BigInt>>), CircuitsErrors> {
    if secret_crt.limbs.len() != moduli.len() {
        return Err(CircuitsErrors::Sample(format!(
            "e_sm has {} CRT limbs; expected {}",
            secret_crt.limbs.len(),
            moduli.len()
        )));
    }
    let q_product: BigUint = moduli.iter().map(|&q| BigUint::from(q)).product();
    let mut basis = Vec::with_capacity(moduli.len());
    for &q in moduli {
        let q = BigUint::from(q);
        let cofactor = &q_product / &q;
        let inverse = (&cofactor % &q)
            .modinv(&q)
            .ok_or_else(|| CircuitsErrors::Sample(format!("CRT moduli are not coprime at {q}")))?;
        basis.push(BigInt::from(cofactor * inverse));
    }
    let q_product = BigInt::from(q_product);

    let degree = secret_crt.limb(0).coefficients().len();
    let mut lifted = Vec::with_capacity(degree);
    let mut quotients = vec![Vec::with_capacity(degree); moduli.len()];
    for coeff_idx in 0..degree {
        let mut residues = Vec::with_capacity(moduli.len());
        let mut sum = BigInt::from(0);
        for (mod_idx, &q) in moduli.iter().enumerate() {
            let q = BigInt::from(q);
            let residue = reduce(&secret_crt.limb(mod_idx).coefficients()[coeff_idx], &q);
            sum += &residue * &basis[mod_idx];
            residues.push(e3_polynomial::center(&residue, &q));
        }
        let value = e3_polynomial::center(&reduce(&sum, &q_product), &q_product);
        for (mod_idx, &q) in moduli.iter().enumerate() {
            let q = BigInt::from(q);
            let difference = &value - &residues[mod_idx];
            if (&difference % &q) != BigInt::from(0) {
                return Err(CircuitsErrors::Sample(format!(
                    "e_sm CRT lift is inconsistent at coefficient {coeff_idx}, limb {mod_idx}"
                )));
            }
            quotients[mod_idx].push(difference / q);
        }
        lifted.push(value);
    }
    Ok((lifted, quotients))
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
        let e_sm_bound = calculate_smudging_bound(
            threshold_params,
            data.n_parties as usize,
            num_ciphertexts as usize,
            defaults.mult_depth,
            lambda,
        )
        .map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to calculate smudging bound: {:?}", e))
        })?;

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

        for (limb_idx, limb) in data.secret.limbs.iter().enumerate() {
            if limb.coefficients().len() != degree {
                return Err(CircuitsErrors::Sample(format!(
                    "CRT limb {limb_idx} has {} coefficients; expected {degree}",
                    limb.coefficients().len()
                )));
            }
        }

        let mut secret_crt = data.secret.clone();
        let sss = &data.secret_sss;

        // Normalize both secret types to [0, q_j) so the chunk and normal circuits use the same
        // field representation before they center values for the root commitment.
        secret_crt
            .reduce(moduli)
            .map_err(|e| CircuitsErrors::Sample(format!("secret_crt reduce: {:?}", e)))?;
        if data.dkg_input_type == DkgInputType::SecretKey {
            secret_crt
                .center(moduli)
                .map_err(|e| CircuitsErrors::Sample(format!("secret_crt center: {:?}", e)))?;
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
        let chunk_size = data.chunk_size as usize;
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
        let dkg_degree = dkg_params.degree();
        // The trBFV path's single C2 proof commits the secret whole; the l-BFV path's chunked C2
        // commits it as a root over `chunk_size`-coefficient chunks.
        let lbfv = e3_fhe_params::is_lbfv_path(preset);
        if lbfv && chunk_size == 0 {
            return Err(CircuitsErrors::Sample(
                "C2 chunk size must be greater than zero".to_string(),
            ));
        }
        if lbfv && !dkg_degree.is_multiple_of(chunk_size) {
            return Err(CircuitsErrors::Sample(format!(
                "C2 chunk size {chunk_size} must divide polynomial degree {dkg_degree}"
            )));
        }
        // Reverse+center before committing to match C1 (PkGeneration)'s convention:
        // C1 applies reverse then center to sk/e_sm before computing the commitment.
        // For SK the values are already centered ({-1,0,1}) so centering is a no-op.
        // For e_sm values are in [0,q) here, so we must center to [-(q-1)/2, (q-1)/2].
        let expected_secret_commitment = match data.dkg_input_type {
            DkgInputType::SecretKey => {
                let mut reversed = secret_crt.limb(0).clone();
                reversed.reverse();
                if lbfv {
                    compute_sc_sk_secret_root_commitment(&reversed, bits.bit_sk_secret, chunk_size)
                } else {
                    compute_share_computation_sk_commitment(&reversed, bits.bit_sk_secret)
                }
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
                if lbfv {
                    compute_sc_esm_secret_root_commitment(
                        &centered_reversed_crt,
                        bits.bit_e_sm_secret,
                        chunk_size,
                    )
                } else {
                    compute_share_computation_e_sm_commitment(
                        &centered_reversed_crt,
                        bits.bit_e_sm_secret,
                    )
                }
            }
        };

        let e_sm_lift = if lbfv && data.dkg_input_type == DkgInputType::SmudgingNoise {
            Some(e_sm_crt_lift(&data.secret, moduli)?)
        } else {
            None
        };

        Ok(Inputs {
            secret_crt,
            y,
            expected_secret_commitment,
            dkg_input_type: data.dkg_input_type,
            e_sm_lift,
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

        if let Some((lifted, quotients)) = &self.e_sm_lift {
            let object = json.as_object_mut().unwrap();
            object.insert(
                "e_sm_lifted".to_string(),
                poly_coefficients_to_toml_json(lifted),
            );
            object.insert(
                "e_sm_quotients".to_string(),
                serde_json::Value::Array(
                    quotients
                        .iter()
                        .map(|limb| poly_coefficients_to_toml_json(limb))
                        .collect(),
                ),
            );
        }

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
    use e3_polynomial::Polynomial;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold, &bounds).unwrap();
        let expected_sk_bits = calculate_bit_width(BigInt::from(bounds.sk_bound.clone()));

        assert_eq!(bits.bit_sk_secret, expected_sk_bits);
    }

    #[test]
    fn insecure_smudging_ranges_match_pk_generation() {
        let preset = BfvPreset::InsecureThreshold;
        for (size, expected_bits) in [
            (CiphernodesCommitteeSize::Minimum, 55),
            (CiphernodesCommitteeSize::Micro, 55),
            (CiphernodesCommitteeSize::Small, 55),
        ] {
            let committee = size.values();
            let sample = ShareComputationCircuitData::generate_sample(
                preset,
                committee.clone(),
                DkgInputType::SmudgingNoise,
            )
            .unwrap();
            let c2_bounds = Bounds::compute(preset, &sample).unwrap();
            let c2_bits = Bits::compute(preset, &c2_bounds).unwrap();
            let c1 = crate::threshold::pk_generation::Configs::compute(preset, &committee).unwrap();

            assert_eq!(c1.bounds.e_sm_bound, c2_bounds.e_sm_bound);
            assert_eq!(c1.bits.e_sm_bit, c2_bits.bit_e_sm_secret);
            assert_eq!(c1.bits.e_sm_bit, expected_bits);
        }
    }

    #[test]
    fn test_input_smudging_noise_secret_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold,
            committee,
            DkgInputType::SmudgingNoise,
        )
        .unwrap();
        let inputs = Inputs::compute(BfvPreset::InsecureThreshold, &sample).unwrap();
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
    fn e_sm_crt_lift_recovers_bounded_noise() {
        let preset = BfvPreset::InsecureThreshold;
        let sample = ShareComputationCircuitData::generate_sample(
            preset,
            CiphernodesCommitteeSize::Small.values(),
            DkgInputType::SmudgingNoise,
        )
        .unwrap();
        let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
        let moduli = threshold_params.moduli();
        let bound = BigInt::from(Bounds::compute(preset, &sample).unwrap().e_sm_bound);
        let (lifted, quotients) = e_sm_crt_lift(&sample.secret, moduli).unwrap();

        assert_eq!(lifted.len(), threshold_params.degree());
        for (coeff_idx, value) in lifted.iter().enumerate() {
            assert!(value.magnitude() <= bound.magnitude());
            for (mod_idx, &q) in moduli.iter().enumerate() {
                let q = BigInt::from(q);
                let residue = e3_polynomial::center(
                    &reduce(&sample.secret.limb(mod_idx).coefficients()[coeff_idx], &q),
                    &q,
                );
                assert_eq!(*value, residue + &quotients[mod_idx][coeff_idx] * q);
            }
        }
    }

    #[test]
    fn rejects_short_non_first_secret_limb() {
        let preset = BfvPreset::InsecureThreshold;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let mut sample = ShareComputationCircuitData::generate_sample(
            preset,
            committee,
            DkgInputType::SmudgingNoise,
        )
        .unwrap();
        let short_coefficients = sample.secret.limbs[1].coefficients()[..127].to_vec();
        sample.secret.limbs[1] = Polynomial::new(short_coefficients);

        let error = Inputs::compute(preset, &sample).unwrap_err().to_string();
        assert!(error.contains("CRT limb 1 has 127 coefficients; expected 128"));
    }
}
