// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::commitments::compute_share_computation_e_sm_commitment;
use crate::commitments::compute_share_computation_sk_commitment;
use crate::commitments::{
    compute_sc_esm_secret_root_commitment, compute_sc_sk_secret_root_commitment,
};
use crate::encoding::bigint_3d_to_json_values;
use crate::encoding::crt_polynomial_to_toml_json;
use crate::encoding::poly_coefficients_to_toml_json;
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_zk_config::dkg::share_computation::Configs;
use e3_zk_config::threshold::pk_generation::ESmSplit;
use e3_zk_config::DkgInputType;
use ndarray::Array2;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{Signed, Zero};
use serde::Deserialize;
use serde::Serialize;

pub struct ShareComputationCircuitData {
    pub parity_matrix: Vec<e3_parity_matrix::ParityMatrix>,
    pub n_parties: u32,
    pub threshold: u32,
    pub chunk_size: u32,
    /// Which secret type this data is for (determines which branch to use in data).
    pub dkg_input_type: DkgInputType,
    pub secret: CrtPolynomial,
    pub secret_sss: Vec<Array2<BigInt>>,
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
    /// l-BFV smudging noise only: the split witness the C2b chunk leaves check against the
    /// smudging bound (see [`ESmSplitLift`]). `None` for the secret key and on the trBFV path,
    /// whose single C2 proof takes no such inputs.
    #[serde(default)]
    pub e_sm_lift: Option<ESmSplitLift>,
}

/// Center a residue already in `[0, modulus)` around zero.
fn center(residue: &BigInt, modulus: &BigInt) -> BigInt {
    if residue > &((modulus - 1u32) / 2u32) {
        residue - modulus
    } else {
        residue.clone()
    }
}

/// The l-BFV C2b smudging witness, per coefficient in natural order (the order of `y`).
///
/// For each coefficient `e` of the lifted noise, `B + e = plus_high * 2^K + plus_low` and
/// `B - e = minus_high * 2^K + minus_low`, `carry` is the carry out of `plus_low + minus_low`, and
/// `quotients[l]` solves `plus_high * radix_mod_q[l] + plus_low - bound_mod_q[l] - r_l = q_l * t` for
/// the centered residue `r_l`. The leaf checks these instead of `e`, which can exceed the field.
/// See [`ESmSplit`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ESmSplitLift {
    pub plus_high: Vec<BigInt>,
    pub plus_low: Vec<BigInt>,
    pub minus_high: Vec<BigInt>,
    pub minus_low: Vec<BigInt>,
    pub carry: Vec<BigInt>,
    pub quotients: Vec<Vec<BigInt>>,
}

/// The smudging noise lifted to one integer per coefficient, and its centered residue per limb.
///
/// The noise is bounded far below `Q / 2`, so the centered CRT reconstruction recovers it exactly.
fn e_sm_crt_values(
    secret_crt: &CrtPolynomial,
    moduli: &[u64],
) -> Result<(Vec<BigInt>, Vec<Vec<BigInt>>), WitnessError> {
    if secret_crt.limbs.len() != moduli.len() {
        return Err(WitnessError::Sample(format!(
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
            .ok_or_else(|| WitnessError::Sample(format!("CRT moduli are not coprime at {q}")))?;
        basis.push(BigInt::from(cofactor * inverse));
    }
    let q_product = BigInt::from(q_product);

    let degree = secret_crt.limb(0).coefficients().len();
    let mut lifted = Vec::with_capacity(degree);
    let mut residues = vec![Vec::with_capacity(degree); moduli.len()];
    for coeff_idx in 0..degree {
        let mut sum = BigInt::from(0);
        for (mod_idx, &q) in moduli.iter().enumerate() {
            let q = BigInt::from(q);
            let residue = secret_crt.limb(mod_idx).coefficients()[coeff_idx].mod_floor(&q);
            sum += &residue * &basis[mod_idx];
            residues[mod_idx].push(center(&residue, &q));
        }
        lifted.push(center(&sum.mod_floor(&q_product), &q_product));
    }
    Ok((lifted, residues))
}

/// The C2b leaf witness for the smudging noise (see [`ESmSplitLift`]).
pub fn e_sm_split_lift(
    secret_crt: &CrtPolynomial,
    moduli: &[u64],
    split: &ESmSplit,
) -> Result<ESmSplitLift, WitnessError> {
    let (lifted, residues) = e_sm_crt_values(secret_crt, moduli)?;
    let bound = BigInt::from(split.bound.clone());
    let radix = BigInt::from(1) << split.split_bits;
    let twice_bound_low = BigInt::from(split.twice_bound_low.clone());
    let degree = lifted.len();
    let mut lift = ESmSplitLift {
        plus_high: Vec::with_capacity(degree),
        plus_low: Vec::with_capacity(degree),
        minus_high: Vec::with_capacity(degree),
        minus_low: Vec::with_capacity(degree),
        carry: Vec::with_capacity(degree),
        quotients: vec![Vec::with_capacity(degree); moduli.len()],
    };
    for (coeff_idx, value) in lifted.iter().enumerate() {
        let plus = &bound + value;
        let minus = &bound - value;
        if plus.is_negative() || minus.is_negative() {
            return Err(WitnessError::Sample(format!(
                "e_sm coefficient {coeff_idx} exceeds the smudging bound"
            )));
        }
        let (plus_high, plus_low) = plus.div_mod_floor(&radix);
        let (minus_high, minus_low) = minus.div_mod_floor(&radix);
        let carry = (&plus_low + &minus_low - &twice_bound_low) / &radix;
        for (mod_idx, &q) in moduli.iter().enumerate() {
            let q = BigInt::from(q);
            let numerator = &plus_high * BigInt::from(split.radix_mod_q[mod_idx].clone())
                + &plus_low
                - BigInt::from(split.bound_mod_q[mod_idx].clone())
                - &residues[mod_idx][coeff_idx];
            if !(&numerator % &q).is_zero() {
                return Err(WitnessError::Sample(format!(
                    "e_sm split is inconsistent at coefficient {coeff_idx}, limb {mod_idx}"
                )));
            }
            lift.quotients[mod_idx].push(numerator / q);
        }
        lift.plus_high.push(plus_high);
        lift.plus_low.push(plus_low);
        lift.minus_high.push(minus_high);
        lift.minus_low.push(minus_low);
        lift.carry.push(carry);
    }
    Ok(lift)
}

impl ESmSplitLift {
    /// Noir inputs for coefficients `start..end`, with `suffix` appended to each name (`_chunk`
    /// for a leaf, empty for the whole polynomial).
    fn insert_json(
        &self,
        json: &mut serde_json::Value,
        suffix: &str,
        range: std::ops::Range<usize>,
    ) -> Result<(), WitnessError> {
        let slice = |values: &[BigInt]| {
            values
                .get(range.clone())
                .map(poly_coefficients_to_toml_json)
                .ok_or_else(|| {
                    WitnessError::Other(
                        "C2b smudging witness does not match the configured degree".into(),
                    )
                })
        };
        json[format!("e_sm_plus_high{suffix}")] = slice(&self.plus_high)?;
        json[format!("e_sm_plus_low{suffix}")] = slice(&self.plus_low)?;
        json[format!("e_sm_minus_high{suffix}")] = slice(&self.minus_high)?;
        json[format!("e_sm_minus_low{suffix}")] = slice(&self.minus_low)?;
        json[format!("e_sm_carry{suffix}")] = slice(&self.carry)?;
        json[format!("e_sm_quotients{suffix}")] = serde_json::Value::Array(
            self.quotients
                .iter()
                .map(|limb| slice(limb))
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok(())
    }
}

impl Inputs {
    /// Prepare one coefficient leaf from already computed C2 inputs.
    pub fn chunk_json(
        &self,
        config: &Configs,
        index: usize,
    ) -> Result<serde_json::Value, WitnessError> {
        let size = config.chunk_size;
        let degree = config.params.degree();
        if size == 0 || !degree.is_multiple_of(size) || index >= degree / size {
            return Err(WitnessError::Other(
                "C2 coefficient chunk is outside the configured layout".into(),
            ));
        }
        let start = index * size;
        let end = start + size;
        let slice = |values: &[BigInt]| -> Result<Vec<BigInt>, WitnessError> {
            values
                .get(start..end)
                .map(<[BigInt]>::to_vec)
                .ok_or_else(|| {
                    WitnessError::Other("C2 coefficients do not match the configured degree".into())
                })
        };
        let secret = match self.dkg_input_type {
            DkgInputType::SecretKey => {
                poly_coefficients_to_toml_json(&slice(self.secret_crt.limb(0).coefficients())?)
            }
            DkgInputType::SmudgingNoise => serde_json::Value::Array(
                self.secret_crt
                    .limbs
                    .iter()
                    .map(|limb| {
                        slice(limb.coefficients())
                            .map(|values| poly_coefficients_to_toml_json(&values))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };
        let y = self.y.get(start..end).ok_or_else(|| {
            WitnessError::Other("C2 shares do not match the configured degree".into())
        })?;
        let mut json = serde_json::json!({
            "chunk_idx": index,
            "secret_chunk": secret,
            "y_chunk": bigint_3d_to_json_values(y),
        });
        if self.dkg_input_type == DkgInputType::SmudgingNoise {
            let lift = self.e_sm_lift.as_ref().ok_or_else(|| {
                WitnessError::Other("C2b input is missing the smudging split".into())
            })?;
            lift.insert_json(&mut json, "_chunk", start..end)?;
        }
        Ok(json)
    }

    pub fn compute(
        config: &Configs,
        data: &ShareComputationCircuitData,
    ) -> Result<Self, WitnessError> {
        let threshold_params = &config.params;
        let moduli = threshold_params.moduli();
        let degree = threshold_params.degree();
        let num_moduli = moduli.len();
        let committee = config.committee.values();
        if data.n_parties as usize != committee.n || data.threshold as usize != committee.threshold
        {
            return Err(WitnessError::Other(
                "C2 secret_sss committee dimensions do not match the configured committee".into(),
            ));
        }
        if e3_fhe_params::is_lbfv_path(config.preset)
            && data.chunk_size as usize != config.chunk_size
        {
            return Err(WitnessError::Other(
                "C2 data does not match the configured chunk size".into(),
            ));
        }
        crate::validation::crt("secret", &data.secret, threshold_params)?;
        if data.secret_sss.len() != num_moduli
            || data
                .secret_sss
                .iter()
                .any(|shares| shares.dim() != (committee.n, degree))
        {
            return Err(WitnessError::Other(
                "secret_sss does not match the configured committee and CRT shape".into(),
            ));
        }
        let n_parties = committee.n;

        for (limb_idx, limb) in data.secret.limbs.iter().enumerate() {
            if limb.coefficients().len() != degree {
                return Err(WitnessError::Sample(format!(
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
            .map_err(|e| WitnessError::Sample(format!("secret_crt reduce: {:?}", e)))?;
        if data.dkg_input_type == DkgInputType::SecretKey {
            secret_crt
                .center(moduli)
                .map_err(|e| WitnessError::Sample(format!("secret_crt center: {:?}", e)))?;
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
                    y_mod.push(share_value.mod_floor(&q_j));
                }
                y_coeff.push(y_mod);
            }
            y.push(y_coeff);
        }
        let bits = &config.bits;
        let lbfv = e3_fhe_params::is_lbfv_path(config.preset);
        let chunk_size = config.chunk_size;
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
            let split = config.e_sm_split.as_ref().ok_or_else(|| {
                WitnessError::Other("the l-BFV C2 configuration has no smudging split".into())
            })?;
            Some(e_sm_split_lift(&data.secret, moduli, split)?)
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
    pub fn to_json(&self) -> serde_json::Value {
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
            "y": bigint_3d_to_json_values(&self.y),
            "expected_secret_commitment": self.expected_secret_commitment.to_string(),
        });

        json.as_object_mut().unwrap().insert(key.to_string(), value);
        if let Some(lift) = &self.e_sm_lift {
            lift.insert_json(&mut json, "", 0..lift.plus_low.len())
                .expect("the whole range is in bounds");
        }

        json
    }
}

/// Compute a C2 witness and prepare exactly one coefficient leaf.
pub fn prepare_chunk(
    config: &Configs,
    data: &ShareComputationCircuitData,
    index: usize,
) -> Result<serde_json::Value, WitnessError> {
    Inputs::compute(config, data)?.chunk_json(config, index)
}
