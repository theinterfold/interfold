// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Shared utilities for the pk_generation circuit (e.g. CRP matrix constant).

use crate::math::fhe_poly_to_crt_centered;
use crate::utils::bigint_to_field;
use crate::CircuitsErrors;
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_polynomial::CrtPolynomial;

/// Returns the deterministic CRP (common random polynomial) as a CRT polynomial with limbs
/// reversed and coefficients centered per modulus, matching the representation used in the circuit.
pub fn deterministic_crp_crt_polynomial(
    threshold_params: &std::sync::Arc<fhe::bfv::BfvParameters>,
) -> Result<CrtPolynomial, CircuitsErrors> {
    let crp = create_deterministic_crp_from_default_seed(threshold_params);
    Ok(fhe_poly_to_crt_centered(
        crp.poly(),
        threshold_params.moduli(),
    )?)
}

/// Builds the CRP matrix (deterministic common random polynomial) constant string for Noir.
pub fn crp_matrix_constant_string(
    threshold_params: &std::sync::Arc<fhe::bfv::BfvParameters>,
) -> Result<String, CircuitsErrors> {
    let a = deterministic_crp_crt_polynomial(threshold_params)?;

    let limb_strings: Vec<String> = a
        .limbs
        .iter()
        .map(|limb| {
            let coeffs: Vec<String> = limb
                .coefficients()
                .iter()
                .map(|c| {
                    let field_val = bigint_to_field(c);
                    field_val.to_string()
                })
                .collect();
            let arr = format!("[{}]", coeffs.join(", "));
            format!("Polynomial::new({})", arr)
        })
        .collect();

    Ok(format!(
        "pub global CRP: [Polynomial<N>; L] = [\n    {}];",
        limb_strings.join(",\n    ")
    ))
}
