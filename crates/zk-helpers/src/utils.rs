// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Utility functions for zkFHE circuit generation
//!
//! This module contains helper functions for:
//! - String conversion of BigInt vectors
//! - SAFE sponge hash computation
//! - BigInt to Field element conversion
//! - Bit width calculation from bounds
//! - ZKP modulus constants

use ark_bn254::Fr as Field;
use ark_bn254::Fr as FieldElement;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_safe::SafeSponge;
use fhe::bfv::BfvParameters;
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
}

pub type Result<T> = std::result::Result<T, ZkHelpersUtilsError>;

/// Convert a 1D vector of BigInt to a vector of strings.
///
/// # Arguments
/// * `vec` - Slice of BigInt values
///
/// # Returns
/// A vector of strings, one per BigInt value
pub fn to_string_1d_vec(vec: &[BigInt]) -> Vec<String> {
    vec.iter().map(|x| x.to_string()).collect()
}

/// Convert a 2D vector of BigInt to a vector of vectors of strings.
///
/// # Arguments
/// * `poly` - Slice of BigInt vectors (e.g., polynomial coefficients per modulus)
///
/// # Returns
/// A 2D vector of strings
pub fn to_string_2d_vec(poly: &[Vec<BigInt>]) -> Vec<Vec<String>> {
    poly.iter().map(|row| to_string_1d_vec(row)).collect()
}

/// Convert a 3D vector of BigInt to a vector of vectors of vectors of strings.
///
/// # Arguments
/// * `vec` - 3D slice of BigInt values
///
/// # Returns
/// A 3D vector of strings
pub fn to_string_3d_vec(vec: &[Vec<Vec<BigInt>>]) -> Vec<Vec<Vec<String>>> {
    vec.iter().map(|d1| to_string_2d_vec(d1)).collect()
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

/// Compute SAFE sponge hash with the given domain separator and inputs.
///
/// This is a convenience wrapper around the SAFE sponge API that performs
/// START, ABSORB, SQUEEZE, and FINISH operations in sequence.
///
/// # Arguments
/// * `domain_separator` - 64-byte domain separator for cross-protocol security
/// * `inputs` - Vector of field elements to absorb
/// * `io_pattern` - IO pattern array `[ABSORB(input_size), SQUEEZE(output_size)]`
///
/// # Returns
/// A vector of field elements squeezed from the sponge
pub fn compute_safe(
    domain_separator: [u8; 64],
    inputs: Vec<Field>,
    io_pattern: [u32; 2],
) -> Vec<Field> {
    let mut sponge = SafeSponge::start(io_pattern, domain_separator);
    sponge.absorb(inputs);
    let digests = sponge.squeeze();
    sponge.finish();

    digests
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

/// Calculate bit width from a bound.
///
/// # Arguments
/// * `bound` - Bound value
///
/// # Returns
/// The calculated bit width
pub fn calculate_bit_width(bound: BigInt) -> u32 {
    if bound <= BigInt::from(0) {
        return 1; // Minimum 1 bit
    }

    bound.bits() as u32
}

/// Computes the bit width of ring elements (coefficients bounded by the coefficient modulus).
///
/// # Arguments
/// * `params` - BFV parameters
///
/// # Returns
/// The bit width of ring elements (coefficients bounded by the coefficient modulus)
pub fn compute_modulus_bit(params: &BfvParameters) -> u32 {
    let moduli = params.moduli();
    let modulus = BigInt::from(compute_max_modulus(moduli));
    let bound = (modulus - BigInt::from(1)) / BigInt::from(2);

    calculate_bit_width(bound)
}

/// Computes the maximum modulus from a vector of moduli.
///
/// # Arguments
/// * `moduli` - Vector of moduli
///
/// # Returns
/// The maximum modulus
pub fn compute_max_modulus(moduli: &[u64]) -> u64 {
    moduli.iter().copied().max().unwrap()
}

/// Bit width to pack/hash native CRT coefficients in \([0, q)\) (per-limb), for commitment I/O.
///
/// Uses `max_l bits(q_l - 1)`, strictly wider than centered bounds `(q_l-1)/2` when needed.
pub fn compute_native_crt_coeff_bit(moduli: &[u64]) -> u32 {
    moduli
        .iter()
        .map(|&q| calculate_bit_width(BigInt::from(q) - 1))
        .max()
        .unwrap_or(1)
}

/// Computes the bit width of the message.
///
/// # Arguments
/// * `params` - BFV parameters
///
/// # Returns
/// The bit width of the message
pub fn compute_msg_bit(params: &BfvParameters) -> u32 {
    let t = BigInt::from(params.plaintext());
    let bound = t.clone() - BigInt::from(1);
    calculate_bit_width(bound)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculate_bit_width_handles_zero_and_positive_bounds() {
        assert_eq!(calculate_bit_width(BigInt::from(0)), 1);
        assert_eq!(calculate_bit_width(BigInt::from(1)), 1);
        assert_eq!(calculate_bit_width(BigInt::from(2)), 2);
        assert_eq!(calculate_bit_width(BigInt::from(3)), 2);
        assert_eq!(calculate_bit_width(BigInt::from(4)), 3);
        assert_eq!(calculate_bit_width(BigInt::from(7)), 3);
        assert_eq!(calculate_bit_width(BigInt::from(8)), 4);
    }

    #[test]
    fn calculate_bit_width_handles_negative_bounds() {
        assert_eq!(calculate_bit_width(BigInt::from(-1)), 1);
    }

    #[test]
    fn bigint_to_field_reduces_modulus() {
        let modulus = get_zkp_modulus();
        let value = modulus.clone() + BigInt::from(5);
        let reduced = bigint_to_field(&value);
        assert_eq!(reduced, bigint_to_field(&BigInt::from(5)));
    }

    #[test]
    fn bigint_to_field_handles_negative() {
        let modulus = get_zkp_modulus();
        let value = BigInt::from(-1);
        let expected = bigint_to_field(&(modulus - BigInt::from(1)));
        assert_eq!(bigint_to_field(&value), expected);
    }

    #[test]
    fn bigint_to_json_value_never_emits_negative_for_field_witness() {
        let neg = BigInt::from(-13449214110323435_i64);
        let v = bigint_to_json_value(&neg);
        let as_text = match v {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s,
            _ => panic!("expected number or string"),
        };
        assert!(!as_text.starts_with('-'));
    }

    #[test]
    fn to_string_helpers_round_trip() {
        let one = BigInt::from(1);
        let two = BigInt::from(2);
        let three = BigInt::from(3);

        assert_eq!(
            to_string_1d_vec(&[one.clone(), two.clone()]),
            vec!["1", "2"]
        );
        assert_eq!(
            to_string_2d_vec(&[vec![one.clone(), two.clone()], vec![three.clone()]]),
            vec![vec!["1", "2"], vec!["3"]]
        );
        assert_eq!(
            to_string_3d_vec(&[vec![vec![one, two, three]]]),
            vec![vec![vec!["1", "2", "3"]]]
        );
    }
}
