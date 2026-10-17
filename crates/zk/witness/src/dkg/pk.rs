// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::encoding::crt_polynomial_to_toml_json;
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_zk_config::dkg::pk::Configs;
use fhe::bfv::PublicKey;
use serde::Deserialize;
use serde::Serialize;

/// Input for the pk circuit: public key polynomials in CRT form for the prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Public key polynomials (pk0, pk1) for each CRT basis.
    pub pk0is: CrtPolynomial,
    pub pk1is: CrtPolynomial,
}

impl Inputs {
    pub fn compute(config: &Configs, public_key: &PublicKey) -> Result<Self, WitnessError> {
        let dkg_params = &config.params;
        let moduli = dkg_params.moduli();
        crate::validation::parameters("public_key", &public_key.params, dkg_params)?;
        if public_key.c.len() != 2 {
            return Err(WitnessError::Other(
                "public key must have two components".into(),
            ));
        }
        for (index, component) in public_key.c.iter().enumerate() {
            let coefficients = component.coefficients();
            crate::validation::context(
                &format!("public_key[{index}]"),
                component.ctx(),
                coefficients.nrows(),
                coefficients.ncols(),
                dkg_params,
            )?;
        }

        let pk0is = crate::encoding::fhe_poly_to_crt_centered(&public_key.c[0], moduli)?;
        let pk1is = crate::encoding::fhe_poly_to_crt_centered(&public_key.c[1], moduli)?;

        Ok(Inputs { pk0is, pk1is })
    }

    // Used as inputs for Nargo execution.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
            "pk1is": crt_polynomial_to_toml_json(&self.pk1is),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::{build_pair_for_preset, utils::compute_modulus_bit};
    use num_bigint::BigUint;

    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let (_, dkg_params) = build_pair_for_preset(BfvPreset::InsecureThreshold64).unwrap();

        let config = Configs::new(&dkg_params).unwrap();
        let expected_bits = compute_modulus_bit(&dkg_params);

        let modulus_bound =
            (BigUint::from(*dkg_params.moduli().iter().max().unwrap()) - 1u32) / 2u32;
        assert_eq!(
            modulus_bound,
            BigUint::from(
                (e3_fhe_params::constants::insecure_64::dkg::MODULI
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
