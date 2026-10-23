// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::commitments::compute_share_computation_e_sm_commitment;
use crate::commitments::compute_share_computation_sk_commitment;
use crate::encoding::bigint_3d_to_json_values;
use crate::encoding::crt_polynomial_to_toml_json;
use crate::encoding::poly_coefficients_to_toml_json;
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_zk_config::dkg::share_computation::Configs;
use e3_zk_config::DkgInputType;
use ndarray::Array2;
use num_bigint::BigInt;
use num_integer::Integer;
use serde::Deserialize;
use serde::Serialize;

pub struct ShareComputationCircuitData {
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
}

impl Inputs {
    pub fn compute(
        config: &Configs,
        data: &ShareComputationCircuitData,
    ) -> Result<Self, WitnessError> {
        let threshold_params = &config.params;
        let moduli = threshold_params.moduli();
        let degree = threshold_params.degree();
        let num_moduli = moduli.len();
        let committee = config.committee.values();
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

        let mut secret_crt = data.secret.clone();
        let sss = &data.secret_sss;

        if data.dkg_input_type == DkgInputType::SmudgingNoise {
            // Normalize secret_crt to [0, q_j) per limb so it matches what we put in y and what the circuit expects (e_sm_secret[j][i] == y[i][j][0]).
            secret_crt
                .reduce(moduli)
                .map_err(|e| WitnessError::Sample(format!("secret_crt reduce: {:?}", e)))?;
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

        json
    }
}
