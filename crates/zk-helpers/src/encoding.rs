// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Canonical signed-field and JSON witness encoding for Noir circuits.
use ark_bn254::Fr as FieldElement;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use e3_polynomial::{CrtPolynomial, Polynomial};
use num_bigint::BigInt;
use num_bigint::Sign;
use num_traits::{ToPrimitive, Zero};
use std::fmt::Display;
use std::str::FromStr;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum ZkHelpersUtilsError {
    #[error("Failed to parse bound: {0}")]
    ParseBound(String),

    #[error("Conversion error: {0}")]
    ConversionError(String),

    #[error("Commitment too long: {0}")]
    CommitmentTooLong(usize),

    /// A ciphertext carrying more than `c[0]` and `c[1]`.
    ///
    /// Deliberately not phrased as advice to relinearize. A fresh BFV encryption has exactly two
    /// components, and this conversion only ever runs on published bytes, so more than two means
    /// the bytes were padded — the commitment covers `c[0]` and `c[1]`, so a padded ciphertext
    /// commits to the same value as its own two-component prefix. Rejecting it is the point, not a
    /// step on the way to accepting it.
    #[error(
        "Expected 2 ciphertext components, got {0}; the commitment covers c[0] and c[1] only, so \
         additional components would share a commitment with the two-component prefix"
    )]
    UnexpectedCiphertextComponents(usize),
}

pub type Result<T> = std::result::Result<T, ZkHelpersUtilsError>;

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
pub fn bigint_to_field(value: &BigInt) -> FieldElement {
    let zkp_modulus = get_zkp_modulus();
    let reduced = if value < &BigInt::zero() {
        (value % &zkp_modulus) + &zkp_modulus
    } else {
        value % &zkp_modulus
    };
    let biguint = reduced
        .to_biguint()
        .unwrap_or_else(|| (&zkp_modulus + reduced).to_biguint().unwrap());
    let bytes = biguint.to_bytes_le();
    FieldElement::from_le_bytes_mod_order(&bytes)
}

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
pub fn get_zkp_modulus() -> BigInt {
    BigInt::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .expect("Invalid ZKP modulus")
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
