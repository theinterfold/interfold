// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::compute_threshold_pk_commitment;
use crate::encoding::bigint_1d_to_json_values;
use crate::encoding::crt_polynomial_to_toml_json;
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::threshold::pk_aggregation::Configs;
use fhe::bfv::PublicKey;
use num_bigint::BigInt;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct PkAggregationCircuitData {
    pub public_key: PublicKey,
    pub pk0_shares: Vec<CrtPolynomial>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub expected_threshold_pk_commitments: Vec<BigInt>,
    pub pk0: Vec<CrtPolynomial>,
    pub pk0_agg: CrtPolynomial,
}

impl Inputs {
    pub fn compute(
        config: &Configs,
        data: &PkAggregationCircuitData,
    ) -> Result<Self, WitnessError> {
        let threshold_params = &config.params;
        let h = config.committee.values().h;
        if data.pk0_shares.len() != h {
            return Err(WitnessError::Other(format!(
                "pk0_shares has {} shares; expected H={h}",
                data.pk0_shares.len()
            )));
        }
        for (index, share) in data.pk0_shares.iter().enumerate() {
            crate::validation::crt(&format!("pk0_shares[{index}]"), share, threshold_params)?;
        }
        if data.public_key.c.len() != 2 {
            return Err(WitnessError::Other(
                "aggregated public key must have two components".into(),
            ));
        }
        crate::validation::parameters("public_key", &data.public_key.params, threshold_params)?;
        for (index, component) in data.public_key.c.iter().enumerate() {
            let coefficients = component.coefficients();
            crate::validation::context(
                &format!("public_key[{index}]"),
                component.ctx(),
                coefficients.nrows(),
                coefficients.ncols(),
                threshold_params,
            )?;
        }

        let bit_pk = config.pk_bit;

        let mut pk0: Vec<CrtPolynomial> = data.pk0_shares.clone();
        let mut pk0_agg = CrtPolynomial::from_fhe_polynomial(&data.public_key.c[0]);

        pk0_agg.reverse();
        pk0_agg.center(threshold_params.moduli())?;

        let mut expected_threshold_pk_commitments = Vec::new();

        for pk in &mut pk0 {
            pk.reverse();
            pk.center(threshold_params.moduli())?;

            let commitment = compute_threshold_pk_commitment(pk, bit_pk);

            expected_threshold_pk_commitments.push(commitment);
        }

        Ok(Inputs {
            expected_threshold_pk_commitments,
            pk0,
            pk0_agg,
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        let pk0: Vec<Vec<serde_json::Value>> =
            self.pk0.iter().map(crt_polynomial_to_toml_json).collect();
        serde_json::json!({
            "expected_threshold_pk_commitments": bigint_1d_to_json_values(&self.expected_threshold_pk_commitments),
            "pk0": pk0,
            "pk0_agg": crt_polynomial_to_toml_json(&self.pk0_agg),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::{build_pair_for_preset, utils::compute_modulus_bit, BfvPreset};
    use num_bigint::BigUint;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let preset = BfvPreset::InsecureThreshold;
        let (threshold_params, _) = build_pair_for_preset(preset).unwrap();

        let config = Configs::new(
            &threshold_params,
            e3_committee::CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();

        let expected_bits = compute_modulus_bit(&threshold_params);

        let modulus_bound =
            (BigUint::from(*threshold_params.moduli().iter().max().unwrap()) - 1u32) / 2u32;
        assert_eq!(
            modulus_bound,
            BigUint::from(
                (e3_fhe_params::constants::insecure::threshold::MODULI
                    .iter()
                    .max()
                    .unwrap()
                    - 1)
                    / 2
            )
        );
        assert_eq!(config.pk_bit, expected_bits);
    }
}
