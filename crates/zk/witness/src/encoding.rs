// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Prepare descending, centered CRT coefficients and canonical field/JSON encodings for Noir witnesses.
use crate::WitnessError;

use ark_ff::BigInteger;
use ark_ff::PrimeField;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::{FromFhePolynomial as _, ToPowerBasisPoly};
use fhe::bfv::{Encoding, Plaintext, SecretKey};
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, PowerBasis, RepresentationTag};
use fhe_traits::FheDecoder;
use num_bigint::BigInt;
use num_bigint::Sign;
use num_traits::ToPrimitive;
use std::fmt::Display;

use std::sync::Arc;

/// Prepare descending, centered CRT coefficients for Noir witnesses.
pub fn fhe_poly_to_crt_centered(
    poly: &impl ToPowerBasisPoly,
    moduli: &[u64],
) -> std::result::Result<CrtPolynomial, e3_polynomial::CrtPolynomialError> {
    let mut crt = CrtPolynomial::from_fhe_polynomial(poly);
    crt.reverse();
    crt.center(moduli)?;
    Ok(crt)
}

/// Convert an FHE polynomial to centered CRT form and validate its circuit shape.
pub fn fhe_poly_to_crt_centered_checked(
    poly: &impl ToPowerBasisPoly,
    moduli: &[u64],
    degree: usize,
) -> std::result::Result<CrtPolynomial, WitnessError> {
    let crt = fhe_poly_to_crt_centered(poly, moduli)?;
    validate_crt_shape(&crt, moduli.len(), degree)
        .map_err(|error| WitnessError::Other(format!("invalid FHE polynomial shape: {error}")))?;
    Ok(crt)
}

/// Convert an FHE secret key to centered CRT form for circuit witnesses.
pub fn fhe_secret_key_to_crt_centered(
    secret_key: &SecretKey,
    context: &Arc<Context>,
    moduli: &[u64],
    degree: usize,
) -> std::result::Result<CrtPolynomial, WitnessError> {
    if secret_key.coeffs.len() != degree {
        return Err(WitnessError::Other(format!(
            "secret key has {} coefficients; expected {degree}",
            secret_key.coeffs.len()
        )));
    }
    let poly = Poly::<PowerBasis>::try_convert_from(secret_key.coeffs.as_ref(), context, false)
        .map_err(|error| WitnessError::Other(error.to_string()))?;
    fhe_poly_to_crt_centered_checked(&poly, moduli, degree)
}

/// Verify that an FHE polynomial uses the expected ring context.
pub fn validate_fhe_poly_context<R: RepresentationTag>(
    poly: &Poly<R>,
    context: &Context,
    name: &str,
) -> std::result::Result<(), WitnessError> {
    if poly.ctx().degree != context.degree || poly.ctx().moduli() != context.moduli() {
        return Err(WitnessError::Other(format!(
            "{name} context does not match the adapter"
        )));
    }
    Ok(())
}

/// Encoded plaintext coefficients in poly encoding (u64 limb values).
pub fn plaintext_poly_u64(pt: &Plaintext) -> std::result::Result<Vec<u64>, WitnessError> {
    Vec::<u64>::try_decode(pt, Encoding::poly()).map_err(WitnessError::Fhe)
}

/// Verify that a CRT polynomial has exactly `l` limbs, each with exactly `degree` coefficients.
///
/// Returns an error when the shape does not match so that zipped computations fail closed
/// instead of silently truncating mismatched limbs.
pub fn validate_crt_shape(crt: &CrtPolynomial, l: usize, degree: usize) -> anyhow::Result<()> {
    if crt.limbs.len() != l {
        anyhow::bail!("expected {l} CRT limbs, got {}", crt.limbs.len());
    }
    for (i, limb) in crt.limbs.iter().enumerate() {
        if limb.coefficients().len() != degree {
            anyhow::bail!(
                "CRT limb {i} has {} coefficients; expected {degree}",
                limb.coefficients().len()
            );
        }
    }
    Ok(())
}

/// Verify that every CRT polynomial in `crts` matches the expected `(l, degree)` shape.
pub fn verify_crt_shapes(crts: &[&CrtPolynomial], l: usize, degree: usize) -> anyhow::Result<()> {
    for (i, crt) in crts.iter().enumerate() {
        validate_crt_shape(crt, l, degree)
            .map_err(|e| anyhow::Error::msg(format!("CRT polynomial at index {i}: {e}")))?;
    }
    Ok(())
}

/// Join a vector of values into a string with the given separator.
///
/// # Arguments
/// * `vec` - Slice of values to join
/// * `sep` - Separator to use between values
///
/// # Returns
/// A string with the values joined by the separator
pub fn join_display<T: Display>(vec: &[T], sep: &str) -> String {
    vec.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(sep)
}

/// Convert BigInt to Field by reducing modulo ZKP modulus.
///
/// This is a helper to simplify BigInt to Field conversion.
/// Handles negative values by reducing them to the positive range [0, ZKP_MODULUS).
///
/// # Arguments
/// * `value` - BigInt value to convert
///
/// # Returns
/// A field element representing the value modulo ZKP modulus

/// Get the ZKP modulus as a BigInt.
///
/// The ZKP modulus is the BN254 scalar field modulus:
/// 21888242871839275222246405745257275088548364400416034343698204186575808495617
///
/// # Returns
/// The ZKP modulus as a BigInt
///
/// # Panics
/// Panics if the modulus constant is invalid (should never happen)

/// Normalize to power basis and prepare only the first centered, descending CRT limb.
pub(crate) fn fhe_poly_first_limb_centered(
    poly: &impl ToPowerBasisPoly,
    modulus: u64,
) -> Polynomial {
    let power = poly.to_power_basis_poly();
    let mut first = Polynomial::new(
        power
            .coefficients()
            .row(0)
            .iter()
            .copied()
            .map(BigInt::from)
            .collect(),
    );
    first.center(&BigInt::from(modulus));
    first.reverse();
    first
}

/// Converts a BigInt to a JSON value for Noir witness ABI: canonical field element in `[0, p)`,
/// as a JSON number when it fits in `i64`, else decimal string. Never emits negative numbers
/// (noirc rejects signed integers for `Field` inputs).
pub fn bigint_to_json_value(n: &BigInt) -> serde_json::Value {
    let field_val = bigint_to_field(n);
    let bytes = field_val.into_bigint().to_bytes_le();
    let canonical = BigInt::from_bytes_le(Sign::Plus, &bytes);
    canonical
        .to_i64()
        .map(serde_json::Number::from)
        .map(serde_json::Value::Number)
        .unwrap_or_else(|| serde_json::Value::String(canonical.to_string()))
}

/// Poly-with-coefficients shape for TOML JSON: `{"coefficients": [number|string, ...]}`.
/// Coefficients use numbers when they fit in i64, else strings.
pub fn poly_coefficients_to_toml_json(coefficients: &[BigInt]) -> serde_json::Value {
    serde_json::json!({
        "coefficients": coefficients.iter().map(bigint_to_json_value).collect::<Vec<_>>()
    })
}

/// Map a CRT polynomial to a vector of JSON values (one `{"coefficients": [number|string, ...]}` per limb).
/// Coefficients use numbers when they fit in i64, else strings.
pub fn crt_polynomial_to_toml_json(crt_polynomial: &CrtPolynomial) -> Vec<serde_json::Value> {
    crt_polynomial
        .limbs
        .iter()
        .map(|limb| poly_coefficients_to_toml_json(limb.coefficients()))
        .collect()
}

/// Convert a 1D vector of BigInt to a vector of JSON values (numbers when fit in i64, else strings).
pub fn bigint_1d_to_json_values(bigint_1d: &[BigInt]) -> Vec<serde_json::Value> {
    bigint_1d.iter().map(bigint_to_json_value).collect()
}

/// Convert a 2D vector of BigInt to a vector of vectors of JSON values (numbers when fit in i64, else strings).
pub fn bigint_2d_to_json_values(y: &[Vec<BigInt>]) -> Vec<Vec<serde_json::Value>> {
    y.iter()
        .map(|coeff| coeff.iter().map(bigint_to_json_value).collect())
        .collect()
}

/// Nested BigInt structure to JSON (numbers when fit in i64, else strings).
pub fn bigint_3d_to_json_values(y: &[Vec<Vec<BigInt>>]) -> Vec<Vec<Vec<serde_json::Value>>> {
    y.iter()
        .map(|coeff| {
            coeff
                .iter()
                .map(|v| v.iter().map(bigint_to_json_value).collect())
                .collect()
        })
        .collect()
}

/// Map a polynomial to TOML JSON: `{"coefficients": [number|string, ...]}`.
pub fn polynomial_to_toml_json(polynomial: &Polynomial) -> serde_json::Value {
    poly_coefficients_to_toml_json(polynomial.coefficients())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signed_coefficients_keep_canonical_field_values_and_witness_shapes() {
        let cases = [
            ("0", json!(0)),
            ("5", json!(5)),
            ("9223372036854775807", json!(9223372036854775807_i64)),
            ("9223372036854775808", json!("9223372036854775808")),
            (
                "-1",
                json!(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495616"
                ),
            ),
            (
                "21888242871839275222246405745257275088548364400416034343698204186575808495622",
                json!(5),
            ),
            (
                "-21888242871839275222246405745257275088548364400416034343698204186575808495617",
                json!(0),
            ),
            (
                "-21888242871839275222246405745257275088548364400416034343698204186575808495618",
                json!(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495616"
                ),
            ),
        ];
        let coefficients: Vec<BigInt> = cases.iter().map(|(s, _)| s.parse().unwrap()).collect();
        let expected: Vec<_> = cases.iter().map(|(_, value)| value.clone()).collect();
        for (input, expected) in coefficients.iter().zip(&expected) {
            assert_eq!(bigint_to_json_value(input), *expected);
            let text = expected
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| expected.to_string());
            let field = bigint_to_field(input);
            assert_eq!(
                BigInt::from_bytes_le(Sign::Plus, &field.into_bigint().to_bytes_le()),
                text.parse::<BigInt>().unwrap()
            );
        }
        assert_eq!(bigint_1d_to_json_values(&coefficients), expected);
        assert_eq!(
            bigint_2d_to_json_values(std::slice::from_ref(&coefficients)),
            vec![expected.clone()]
        );
        assert_eq!(
            bigint_3d_to_json_values(&[vec![coefficients.clone()]]),
            vec![vec![expected.clone()]]
        );
        let polynomial = Polynomial::new(coefficients);
        let expected_poly = json!({"coefficients": expected});
        assert_eq!(polynomial_to_toml_json(&polynomial), expected_poly);
        assert_eq!(
            crt_polynomial_to_toml_json(&CrtPolynomial::new(vec![polynomial])),
            vec![expected_poly]
        );
    }
}

pub use e3_zk_config::field::{bigint_to_field, get_zkp_modulus};
