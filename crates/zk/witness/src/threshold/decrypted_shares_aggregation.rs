// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::commitments::compute_threshold_decryption_share_commitment;
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use e3_zk_config::threshold::decrypted_shares_aggregation::Configs;
use fhe_math::rq::Poly;
use fhe_math::rq::PowerBasis;
use num_bigint::BigInt;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;

/// Circuit identifier for threshold decrypted-shares aggregation (Noir circuit 7).

/// Raw input for circuit input computation: decryption share polynomials from T+1 parties,
/// party IDs (1-based), and decoded message. Noir performs interpolation and rounding.
#[derive(Debug, Clone)]
pub struct DecryptedSharesAggregationCircuitData {
    /// Decryption shares from T+1 parties (Poly in RNS form).
    pub d_share_polys: Vec<Poly<PowerBasis>>,
    /// Party IDs (1-based: 1, 2, ..., T+1) for the reconstructing parties.
    pub reconstructing_parties: Vec<usize>,
    /// Decoded message polynomial coefficients.
    pub message_vec: Vec<u64>,
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

impl Inputs {
    pub fn compute(
        config: &Configs,
        data: &DecryptedSharesAggregationCircuitData,
    ) -> Result<Self, WitnessError> {
        let threshold_params = &config.params;
        let ctx = threshold_params
            .context_at_level(0)
            .map_err(|e| WitnessError::Other(format!("context_at_level: {:?}", e)))?;
        let num_moduli = ctx.moduli().len();
        let degree = ctx.degree;
        let committee = config.committee.values();
        let threshold = committee.threshold;
        let max_msg_non_zero_coeffs = config.max_msg_non_zero_coeffs;
        let moduli = ctx.moduli();

        let d_share_polys = &data.d_share_polys;
        if max_msg_non_zero_coeffs > degree {
            return Err(WitnessError::Other(
                "max_msg_non_zero_coeffs exceeds the polynomial degree".into(),
            ));
        }
        if data.message_vec.len() > degree {
            return Err(WitnessError::Other(
                "message_vec exceeds the configured polynomial degree".into(),
            ));
        }

        let dropped_non_zero = data
            .message_vec
            .iter()
            .enumerate()
            .skip(max_msg_non_zero_coeffs)
            .filter(|(_, v)| **v != 0)
            .count();
        if dropped_non_zero > 0 {
            return Err(WitnessError::Other(format!(
                "message_vec has {} non-zero coefficient(s) at index >= MAX_MSG_NON_ZERO_COEFFS ({}); they would be silently dropped by truncation",
                dropped_non_zero, max_msg_non_zero_coeffs
            )));
        }

        // The circuit takes exactly T+1 shares and T+1 party IDs, and the Lagrange weights pair
        // them by position. One polynomial more would copy into the witness unpaired and make it
        // the wrong shape; one party ID more would weight a share that does not exist.
        if d_share_polys.len() != threshold + 1 {
            return Err(WitnessError::Other(format!(
                "d_share_polys.len() {} != threshold + 1 ({}); the circuit takes exactly {} polynomials",
                d_share_polys.len(),
                threshold + 1,
                threshold + 1
            )));
        }
        let reconstructing_parties = &data.reconstructing_parties;
        if reconstructing_parties.len() != threshold + 1 {
            return Err(WitnessError::Other(format!(
                "reconstructing_parties.len() {} != threshold + 1 ({}); one party ID per polynomial",
                reconstructing_parties.len(),
                threshold + 1
            )));
        }
        // Distinct ordered IDs in [1, N] have nonzero differences smaller than every
        // supported prime CRT modulus, so the in-circuit Lagrange denominators are invertible.
        if data
            .reconstructing_parties
            .iter()
            .any(|&id| id == 0 || id > committee.n)
            || data
                .reconstructing_parties
                .windows(2)
                .any(|ids| ids[0] >= ids[1])
            || moduli.iter().any(|&q| q <= committee.n as u64)
        {
            return Err(WitnessError::Other("reconstructing_parties must be strictly increasing one-based committee IDs below every CRT modulus".into()));
        }

        // Read only the native ascending prefix required by the selected artifact.
        let mut decryption_shares: Vec<CrtPolynomial> = Vec::with_capacity(d_share_polys.len());
        for (party, d_share) in d_share_polys.iter().enumerate() {
            let coefficients = d_share.coefficients();
            crate::validation::context(
                &format!("d_share_polys[{party}]"),
                d_share.ctx(),
                coefficients.nrows(),
                coefficients.ncols(),
                threshold_params,
            )?;
            let mut limbs = Vec::with_capacity(num_moduli);
            for (index, &q) in moduli.iter().enumerate() {
                let row = coefficients.row(index);
                if row
                    .iter()
                    .take(max_msg_non_zero_coeffs)
                    .any(|&value| value >= q)
                {
                    return Err(WitnessError::Other(format!(
                        "d_share_polys[{party}][{index}] contains a non-native CRT coefficient"
                    )));
                }
                limbs.push(Polynomial::new(
                    row.iter()
                        .take(max_msg_non_zero_coeffs)
                        .map(|&value| BigInt::from(value))
                        .collect(),
                ));
            }
            decryption_shares.push(CrtPolynomial::new(limbs));
        }

        let party_ids: Vec<BigInt> = data
            .reconstructing_parties
            .iter()
            .map(|&x| BigInt::from(x))
            .collect();
        let mut message: Vec<BigInt> = data
            .message_vec
            .iter()
            .take(max_msg_non_zero_coeffs)
            .map(|&value| BigInt::from(value))
            .collect();
        message.resize(max_msg_non_zero_coeffs, BigInt::zero());
        let message = Polynomial::new(message);

        let expected_d_commitments: Vec<BigInt> = decryption_shares
            .iter()
            .map(|share| {
                compute_threshold_decryption_share_commitment(
                    share,
                    config.bits.d_native_bit,
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

    pub fn to_json(&self) -> serde_json::Value {
        use crate::encoding::bigint_1d_to_json_values;
        use crate::encoding::crt_polynomial_to_toml_json;
        use crate::encoding::polynomial_to_toml_json;

        let decryption_shares_json: Vec<Vec<serde_json::Value>> = self
            .decryption_shares
            .iter()
            .map(crt_polynomial_to_toml_json)
            .collect();
        serde_json::json!({
            "expected_d_commitments": bigint_1d_to_json_values(&self.expected_d_commitments),
            "decryption_shares": decryption_shares_json,
            "party_ids": bigint_1d_to_json_values(&self.party_ids),
            "message": polynomial_to_toml_json(&self.message),
        })
    }
}
