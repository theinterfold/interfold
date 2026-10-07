// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bounds, configs, bits, and input computation for the Decryption Share Aggregation TRBFV circuit.
//!
//! Uses [`crate::threshold::decrypted_shares_aggregation::utils`] for Q/delta, modular inverses,
//! Lagrange-at-zero recovery, and scalar CRT reconstruction. Decryption shares are normalized
//! with [`e3_polynomial::CrtPolynomial::reduce`]; all input coefficients are reduced to
//! [0, zkp_modulus) with [`e3_polynomial::reduce`] inside [`Inputs::compute`].

/// Max message coefficients in the C7 circuit (matches Noir's MAX_MSG_NON_ZERO_COEFFS).
pub const MAX_MSG_NON_ZERO_COEFFS: usize = 50;

use crate::calculate_bit_width;
use crate::circuits::commitments::compute_threshold_decryption_share_commitment;
use crate::compute_q_mod_t;
use crate::compute_q_mod_t_centered;
use crate::get_zkp_modulus;
use crate::threshold::decrypted_shares_aggregation::circuit::DecryptedSharesAggregationCircuit;
use crate::threshold::decrypted_shares_aggregation::circuit::DecryptedSharesAggregationCircuitData;
use crate::threshold::decrypted_shares_aggregation::utils;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::reduce;
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe_math::rq::{Poly, PowerBasis};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
/// Output of [`CircuitComputation::compute`] for [`DecryptedSharesAggregationCircuit`].
#[derive(Debug)]
pub struct DecryptedSharesAggregationComputationOutput {
    pub bounds: Bounds,
    pub bits: Bits,
    pub inputs: Inputs,
}

impl CircuitComputation for DecryptedSharesAggregationCircuit {
    type Preset = BfvPreset;
    type Data = DecryptedSharesAggregationCircuitData;
    type Output = DecryptedSharesAggregationComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(DecryptedSharesAggregationComputationOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

/// Bounds for noise and scaling: delta = floor(Q/t), delta_half = floor(delta/2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub delta: BigUint,
    pub delta_half: BigUint,
}

/// Bit widths used by the circuit (e.g. noise bit for range checks).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub noise_bit: u32,
    /// Native \([0, q_l)\) width for hashing decryption-share coefficients (C6/C7 `d_commitment`).
    pub d_native_bit: u32,
    /// Width of a single CRT residue, `max_l bits(q_l - 1)`. Every value the interpolation and the
    /// Garner step read is a residue in `[0, q_l)`.
    pub q_bit: u32,
    /// Quotient width for the in-circuit `x mod q_l` reductions. The widest input is the Lagrange
    /// interpolation sum, below `H * q_l^2`, so the quotient stays under `H * q_l`.
    pub k_bit: u32,
    /// Width of the rounded plaintext, `bits(t)`. The decode returns a value in `[0, t]`.
    pub t_bit: u32,
    /// Width of `Q`, the product of the moduli, for the rounded-decode remainder interval.
    pub q_total_bit: u32,
}

/// Circuit config: moduli count, plaintext modulus, q_inverse_mod_t, bits, bounds, and message polynomial length.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    pub l: usize,
    pub threshold: usize,
    pub moduli: Vec<u64>,
    pub plaintext_modulus: u64,
    pub q_mod_t: BigUint,
    pub q_mod_t_centered: BigInt,
    pub q_inverse_mod_t: u64,
    pub bits: Bits,
    pub bounds: Bounds,
    /// Max number of non-zero coefficients in the message polynomial (matches Noir's MAX_MSG_NON_ZERO_COEFFS).
    pub max_msg_non_zero_coeffs: usize,
}

/// Input for decrypted shares aggregation (same shape as old DecSharesAggTrBfvVectors).
/// All polynomial-shaped data uses [`Polynomial`] / [`CrtPolynomial`] to match the Noir circuit;
/// coefficients are reduced to [0, zkp_modulus) by compute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Public `d` commitments (one per party), same as circuit 6 outputs; checked in-circuit.
    pub expected_d_commitments: Vec<BigInt>,
    /// One CrtPolynomial per party (secret witness); circuit: `[[Polynomial; L]; T+1]`
    pub decryption_shares: Vec<CrtPolynomial>,
    /// Party IDs (1-based: 1, 2, ..., T+1)
    pub party_ids: Vec<BigInt>,
    /// Message polynomial (public witness)
    pub message: Polynomial,
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let moduli = threshold_params.moduli();
        let t = threshold_params.plaintext();
        let q = utils::compute_q_product(moduli);
        let delta = utils::compute_delta(&q, t);
        let delta_half = utils::compute_delta_half(&delta);
        Ok(Bounds { delta, delta_half })
    }
}

impl Computation for Bits {
    type Preset = BfvPreset;
    type Data = Bounds;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let noise_bit = calculate_bit_width(BigInt::from(data.delta_half.clone()));
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let ctx = threshold_params
            .context_at_level(0)
            .map_err(|e| CircuitsErrors::Other(format!("context_at_level: {:?}", e)))?;
        let mut d_native_bit = 0u32;
        let mut modulus_product = BigInt::from(1u32);
        for qi in ctx.moduli_operators() {
            let q = BigInt::from(**qi);
            d_native_bit = d_native_bit.max(calculate_bit_width(q.clone() - 1));
            modulus_product *= q;
        }
        // A residue fits `bits(q_l - 1)`; `d_native_bit` is already that maximum.
        let q_bit = d_native_bit;
        // Reduction quotients: the widest reduced input is the interpolation sum, under `H * q^2`,
        // so its quotient is under `H * q`. Six spare bits cover any committee up to 64 parties.
        let k_bit = q_bit + 6;
        let t_bit = calculate_bit_width(BigInt::from(threshold_params.plaintext()));
        let q_total_bit = calculate_bit_width(modulus_product.clone());
        Ok(Bits {
            noise_bit,
            d_native_bit,
            q_bit,
            k_bit,
            t_bit,
            q_total_bit,
        })
    }
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let moduli = threshold_params.moduli().to_vec();
        let t = threshold_params.plaintext();
        let q = utils::compute_q_product(&moduli);
        let q_mod_t = compute_q_mod_t(&q, t);
        let q_mod_t_centered = compute_q_mod_t_centered(&moduli, t);
        let q_inverse_mod_t = utils::compute_q_inverse_mod_t(&q, t)?;
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;
        Ok(Configs {
            threshold: 0, // Not derived from preset; set by caller if needed.
            l: moduli.len(),
            moduli,
            plaintext_modulus: t,
            q_mod_t,
            q_mod_t_centered,
            q_inverse_mod_t,
            bits,
            bounds,
            // TODO: make this configurable based on the application (e.g., CRISP = 80).
            max_msg_non_zero_coeffs: MAX_MSG_NON_ZERO_COEFFS,
        })
    }
}

/// Truncate to first max_len coefficients (index 0 = constant term, ascending order).
fn truncate_to_max_coeffs(v: &[BigInt], max_len: usize) -> Vec<BigInt> {
    v.iter().take(max_len).cloned().collect()
}

/// Truncate each limb of a [`CrtPolynomial`] to max_len coefficients.
fn truncate_crt_to_max_coeffs(crt: CrtPolynomial, max_len: usize) -> CrtPolynomial {
    let limbs = crt
        .limbs
        .iter()
        .map(|limb| Polynomial::new(truncate_to_max_coeffs(limb.coefficients(), max_len)))
        .collect();
    CrtPolynomial::new(limbs)
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = DecryptedSharesAggregationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let configs = Configs::compute(preset, &())?;
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let ctx = threshold_params
            .context_at_level(0)
            .map_err(|e| CircuitsErrors::Other(format!("context_at_level: {:?}", e)))?;
        let num_moduli = ctx.moduli().len();
        let degree = ctx.degree;
        let threshold = data.committee.threshold;
        let max_msg_non_zero_coeffs = configs.max_msg_non_zero_coeffs;
        let moduli = ctx.moduli();

        let d_share_polys: Vec<Poly<PowerBasis>> = data.d_share_polys.clone();

        if d_share_polys.len() < threshold + 1 {
            return Err(CircuitsErrors::Other(format!(
                "d_share_polys.len() {} < threshold + 1 ({}); need at least {} polynomials",
                d_share_polys.len(),
                threshold + 1,
                threshold + 1
            )));
        }

        // Decryption shares: one CrtPolynomial per party (from_fhe + reduce)
        let mut decryption_shares: Vec<CrtPolynomial> = Vec::with_capacity(d_share_polys.len());
        for d_share in &d_share_polys {
            let crt = CrtPolynomial::from_fhe_polynomial(d_share);
            decryption_shares.push(crt);
        }

        let party_ids: Vec<BigInt> = data
            .reconstructing_parties
            .iter()
            .map(|&x| BigInt::from(x))
            .collect();
        let mut message: Vec<BigInt> = data.message_vec.iter().map(|&x| BigInt::from(x)).collect();
        message.resize(degree, BigInt::zero());

        // u^{(l)} per modulus via Lagrange at zero
        let reconstructing_parties = &data.reconstructing_parties;
        let mut u_per_modulus: Vec<Vec<u64>> = Vec::new();
        for (m, &modulus) in moduli.iter().enumerate().take(num_moduli) {
            let mut u_modulus_coeffs = Vec::with_capacity(degree);
            for coeff_idx in 0..degree {
                let shares: Vec<BigInt> = (0..=threshold)
                    .map(|party_idx| {
                        let coeffs = d_share_polys[party_idx].coefficients();
                        let row = coeffs.row(m);
                        BigInt::from(row[coeff_idx])
                    })
                    .collect();
                let u_coeff_u64 =
                    utils::lagrange_recover_at_zero(reconstructing_parties, &shares, modulus)?;
                u_modulus_coeffs.push(u_coeff_u64);
            }
            u_per_modulus.push(u_modulus_coeffs);
        }

        // `u_global` and the CRT quotients are no longer witnesses: the circuit reconstructs `u`
        // from the residues by Garner, so there is nothing for a prover to supply or for the circuit
        // to bound. `u_per_modulus` above is kept only to validate the interpolation here.
        let _ = &u_per_modulus;

        // Truncate to max_msg_non_zero_coeffs (index 0 = constant term, ascending order)
        decryption_shares = decryption_shares
            .into_iter()
            .map(|crt| truncate_crt_to_max_coeffs(crt, max_msg_non_zero_coeffs))
            .collect();
        let message_trunc = truncate_to_max_coeffs(&message, max_msg_non_zero_coeffs);

        let zkp_modulus = get_zkp_modulus();

        let party_ids: Vec<BigInt> = party_ids.iter().map(|c| reduce(c, &zkp_modulus)).collect();
        let message = Polynomial::new(
            message_trunc
                .iter()
                .map(|c| reduce(c, &zkp_modulus))
                .collect(),
        );

        let expected_d_commitments: Vec<BigInt> = decryption_shares
            .iter()
            .map(|share| {
                compute_threshold_decryption_share_commitment(
                    share,
                    configs.bits.d_native_bit,
                    max_msg_non_zero_coeffs,
                )
            })
            .collect();

        Ok(Inputs {
            expected_d_commitments,
            decryption_shares,
            party_ids,
            message,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        use crate::bigint_1d_to_json_values;
        use crate::crt_polynomial_to_toml_json;
        use crate::polynomial_to_toml_json;

        let decryption_shares_json: Vec<Vec<serde_json::Value>> = self
            .decryption_shares
            .iter()
            .map(crt_polynomial_to_toml_json)
            .collect();
        let party_ids_json = bigint_1d_to_json_values(&self.party_ids);
        let message_json = polynomial_to_toml_json(&self.message);
        let expected_d_commitments_json = bigint_1d_to_json_values(&self.expected_d_commitments);

        let json = serde_json::json!({
            "expected_d_commitments": expected_d_commitments_json,
            "decryption_shares": decryption_shares_json,
            "party_ids": party_ids_json,
            "message": message_json,
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::decrypted_shares_aggregation::DecryptedSharesAggregationCircuitData;
    use crate::CiphernodesCommitteeSize;

    #[test]
    fn test_bounds_and_bits_consistency() {
        let preset = BfvPreset::InsecureThreshold512;
        let bounds = Bounds::compute(preset, &()).unwrap();
        let bits = Bits::compute(preset, &bounds).unwrap();

        assert!(!bounds.delta.is_zero());
        assert!(!bounds.delta_half.is_zero());
        assert!(bounds.delta_half < bounds.delta);
        assert!(bits.noise_bit > 0);
        assert!(bits.d_native_bit > 0);
    }

    #[test]
    fn test_configs_compute() {
        let preset = BfvPreset::InsecureThreshold512;
        let configs = Configs::compute(preset, &()).unwrap();

        assert_eq!(configs.moduli.len(), configs.l);
        assert!(configs.q_inverse_mod_t > 0);
    }

    #[test]
    fn test_full_computation_with_sample() {
        let preset = BfvPreset::InsecureThreshold512;
        let committee = CiphernodesCommitteeSize::Small.values();
        let input =
            DecryptedSharesAggregationCircuitData::generate_sample(preset, committee.clone())
                .unwrap();

        let out = DecryptedSharesAggregationCircuit::compute(preset, &input).unwrap();

        let configs = Configs::compute(preset, &()).unwrap();
        assert_eq!(out.inputs.decryption_shares.len(), committee.threshold + 1);
        assert_eq!(
            out.inputs.expected_d_commitments.len(),
            committee.threshold + 1
        );
        assert_eq!(out.inputs.party_ids.len(), committee.threshold + 1);
        assert_eq!(
            out.inputs.message.coefficients().len(),
            configs.max_msg_non_zero_coeffs
        );
        assert_eq!(out.inputs.decryption_shares.len(), committee.threshold + 1);
        assert_eq!(out.inputs.decryption_shares[0].limbs.len(), configs.l);
        assert!(out.bits.noise_bit > 0);
        assert!(out.bits.d_native_bit > 0);
        // The reduced path derives `u` by Garner, so these bound the reductions and the decode
        // instead of a CRT quotient witness.
        assert!(out.bits.q_bit > 0);
        assert!(out.bits.k_bit > out.bits.q_bit);
        assert!(out.bits.t_bit > 0);
        assert!(out.bits.q_total_bit >= out.bits.q_bit);
    }
}
