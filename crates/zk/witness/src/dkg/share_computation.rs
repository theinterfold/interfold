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
use e3_zk_config::DkgInputType;
use ndarray::Array2;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
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
    /// l-BFV smudging noise only: the lifted noise and its CRT quotients (see [`e_sm_crt_lift`]),
    /// which the C2b chunk leaves range-check. `None` for the secret key and on the trBFV path,
    /// whose single C2 proof takes no such inputs.
    #[serde(default)]
    pub e_sm_lift: Option<(Vec<BigInt>, Vec<Vec<BigInt>>)>,
}

/// Center a residue already in `[0, modulus)` around zero.
fn center(residue: &BigInt, modulus: &BigInt) -> BigInt {
    if residue > &((modulus - 1u32) / 2u32) {
        residue - modulus
    } else {
        residue.clone()
    }
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
    let mut quotients = vec![Vec::with_capacity(degree); moduli.len()];
    for coeff_idx in 0..degree {
        let mut residues = Vec::with_capacity(moduli.len());
        let mut sum = BigInt::from(0);
        for (mod_idx, &q) in moduli.iter().enumerate() {
            let q = BigInt::from(q);
            let residue = secret_crt.limb(mod_idx).coefficients()[coeff_idx].mod_floor(&q);
            sum += &residue * &basis[mod_idx];
            residues.push(center(&residue, &q));
        }
        let value = center(&sum.mod_floor(&q_product), &q_product);
        for (mod_idx, &q) in moduli.iter().enumerate() {
            let q = BigInt::from(q);
            let difference = &value - &residues[mod_idx];
            if (&difference % &q) != BigInt::from(0) {
                return Err(WitnessError::Sample(format!(
                    "e_sm CRT lift is inconsistent at coefficient {coeff_idx}, limb {mod_idx}"
                )));
            }
            quotients[mod_idx].push(difference / q);
        }
        lifted.push(value);
    }
    Ok((lifted, quotients))
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
            let (lifted, quotients) = self.e_sm_lift.as_ref().ok_or_else(|| {
                WitnessError::Other("C2b input is missing the lifted e_sm".into())
            })?;
            json["e_sm_lifted_chunk"] = poly_coefficients_to_toml_json(&slice(lifted)?);
            json["e_sm_quotients_chunk"] = serde_json::Value::Array(
                quotients
                    .iter()
                    .map(|limb| slice(limb).map(|values| poly_coefficients_to_toml_json(&values)))
                    .collect::<Result<Vec<_>, _>>()?,
            );
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
        if let Some((lifted, quotients)) = &self.e_sm_lift {
            json["e_sm_lifted"] = poly_coefficients_to_toml_json(lifted);
            json["e_sm_quotients"] = serde_json::Value::Array(
                quotients
                    .iter()
                    .map(|limb| poly_coefficients_to_toml_json(limb))
                    .collect(),
            );
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
