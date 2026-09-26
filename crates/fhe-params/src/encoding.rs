// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV Parameter Encoding/Decoding
//!
//! This module provides functions for encoding and decoding BFV parameters
//! using Solidity ABI format. This enables serialization for smart contracts
//! and cross-platform parameter exchange.

use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use std::sync::Arc;
use thiserror::Error as ThisError;

#[cfg(feature = "abi-encoding")]
use alloy_dyn_abi::{DynSolType, DynSolValue};
#[cfg(feature = "abi-encoding")]
use alloy_primitives::U256;

#[derive(ThisError, Debug)]
pub enum EncodingError {
    #[error("Failed to ABI decode bytes: {0}")]
    AbiDecodeFailed(String),
    #[error("Invalid ABI structure: expected tuple")]
    InvalidAbiStructure,
    #[error("Invalid degree value: {0}")]
    InvalidDegree(String),
    #[error("Invalid plaintext modulus value: {0}")]
    InvalidPlaintextModulus(String),
    #[error("Invalid modulus value: {0}")]
    InvalidModulus(String),
    #[error("Invalid error1_variance: {0}")]
    InvalidError1Variance(String),
    #[error("Failed to build BFV parameters: {0}")]
    BuildFailed(String),
}

/// Encodes BFV parameters into ABI-encoded bytes.
///
/// This function converts BFV parameters into a tuple structure of
/// `(degree, plaintext_modulus, moduli[], error1_variance)` and then
/// ABI-encodes the tuple using Solidity ABI format. The resulting bytes
/// can be used in smart contracts or for cross-platform serialization.
#[cfg(feature = "abi-encoding")]
pub fn encode_bfv_params(params: &BfvParameters) -> Vec<u8> {
    let value = DynSolValue::Tuple(vec![
        DynSolValue::Uint(U256::from(params.degree()), 256),
        DynSolValue::Uint(U256::from(params.plaintext()), 256),
        DynSolValue::Array(
            params
                .moduli()
                .iter()
                .map(|val| DynSolValue::Uint(U256::from(*val), 256))
                .collect(),
        ),
        DynSolValue::String(params.get_error1_variance().to_string()),
    ]);
    value.abi_encode()
}

/// Decodes BFV parameters from ABI-encoded bytes.
///
/// This function converts ABI-encoded bytes back into BFV parameters.
/// The bytes should represent a tuple `(uint256, uint256, uint256[], string)`
/// containing `(degree, plaintext_modulus, moduli[], error1_variance)` as
/// produced by `encode_bfv_params`.
#[cfg(feature = "abi-encoding")]
pub fn decode_bfv_params(bytes: &[u8]) -> Result<BfvParameters, EncodingError> {
    // Define the expected tuple type: (uint256, uint256, uint256[], string)
    let tuple_type = DynSolType::Tuple(vec![
        DynSolType::Uint(256),                              // degree
        DynSolType::Uint(256),                              // plaintext_modulus
        DynSolType::Array(Box::new(DynSolType::Uint(256))), // moduli array
        DynSolType::String,                                 // error1_variance (as decimal string)
    ]);

    let decoded = tuple_type.abi_decode(bytes).map_err(|e| {
        EncodingError::AbiDecodeFailed(format!("Failed to ABI decode bytes: {}", e))
    })?;

    match decoded {
        DynSolValue::Tuple(inner_values) => {
            // Extract degree (first element)
            let degree: u64 = match &inner_values[0] {
                DynSolValue::Uint(val, _) => (*val).try_into().map_err(|e| {
                    EncodingError::InvalidDegree(format!("Failed to convert degree to u64: {}", e))
                })?,
                _ => return Err(EncodingError::InvalidAbiStructure),
            };

            // Extract plaintext modulus (second element)
            let plaintext: u64 = match &inner_values[1] {
                DynSolValue::Uint(val, _) => (*val).try_into().map_err(|e| {
                    EncodingError::InvalidPlaintextModulus(format!(
                        "Failed to convert plaintext to u64: {}",
                        e
                    ))
                })?,
                _ => return Err(EncodingError::InvalidAbiStructure),
            };

            // Extract moduli array (third element)
            let moduli: Vec<u64> = match &inner_values[2] {
                DynSolValue::Array(moduli_array) => moduli_array
                    .iter()
                    .map(|val| match val {
                        DynSolValue::Uint(modulus, _) => (*modulus).try_into().map_err(|e| {
                            EncodingError::InvalidModulus(format!(
                                "Failed to convert modulus to u64: {}",
                                e
                            ))
                        }),
                        _ => Err(EncodingError::InvalidAbiStructure),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(EncodingError::InvalidAbiStructure),
            };

            // Extract error1_variance (fourth element)
            let error1_variance: String = match &inner_values[3] {
                DynSolValue::String(val) => val.clone(),
                _ => return Err(EncodingError::InvalidAbiStructure),
            };

            let params = BfvParametersBuilder::new()
                .set_degree(degree as usize)
                .set_plaintext_modulus(plaintext)
                .set_moduli(&moduli)
                .set_error1_variance_str(&error1_variance)
                .map_err(|e| {
                    EncodingError::InvalidError1Variance(format!(
                        "Failed to set error1_variance: {}",
                        e
                    ))
                })?
                .build()
                .map_err(|e| {
                    EncodingError::BuildFailed(format!("Failed to build BFV Parameters: {}", e))
                })?;

            Ok(params)
        }
        _ => Err(EncodingError::InvalidAbiStructure),
    }
}

/// Decodes BFV parameters from ABI-encoded bytes and wraps them in an `Arc`.
///
/// This is a convenience function that combines `decode_bfv_params` with `Arc::new`
/// to provide thread-safe shared ownership of the decoded parameters.
#[cfg(feature = "abi-encoding")]
pub fn decode_bfv_params_arc(bytes: &[u8]) -> Result<Arc<BfvParameters>, EncodingError> {
    Ok(Arc::new(decode_bfv_params(bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{insecure, secure_8192};
    use crate::presets::BfvPreset;
    use std::str::FromStr;

    #[cfg(feature = "abi-encoding")]
    #[test]
    fn test_encode_decode_roundtrip_preset() {
        use crate::presets::BfvParamSet;

        let preset = BfvPreset::SecureThreshold8192;
        let param_set: BfvParamSet = preset.into();
        let params = param_set.build();

        let encoded = encode_bfv_params(&params);
        let decoded = decode_bfv_params(&encoded).expect("should decode successfully");

        assert_eq!(decoded.degree(), params.degree());
        assert_eq!(decoded.plaintext(), params.plaintext());
        assert_eq!(decoded.moduli(), params.moduli());
        assert_eq!(decoded.get_error1_variance(), params.get_error1_variance());
    }

    #[cfg(feature = "abi-encoding")]
    #[test]
    fn test_encode_decode_roundtrip_arbitrary() {
        use crate::builder::build_bfv_params;

        // Use insecure DKG preset constants for testing arbitrary parameter encoding
        let degree = insecure::DEGREE;
        let plaintext_modulus = insecure::dkg::PLAINTEXT_MODULUS;
        let moduli = insecure::dkg::MODULI;

        let params = build_bfv_params(degree, plaintext_modulus, moduli, None);
        let encoded = encode_bfv_params(&params);
        let decoded = decode_bfv_params(&encoded).expect("should decode successfully");

        assert_eq!(decoded.degree(), degree);
        assert_eq!(decoded.plaintext(), plaintext_modulus);
        assert_eq!(decoded.moduli(), moduli);
        // Verify error1_variance is preserved (defaults to 10 for standard BFV)
        assert_eq!(
            decoded.get_error1_variance(),
            &num_bigint::BigUint::from_str(insecure::dkg::ERROR1_VARIANCE).unwrap()
        );
        assert_eq!(decoded.get_error1_variance(), params.get_error1_variance());
    }

    #[cfg(feature = "abi-encoding")]
    #[test]
    fn test_encode_decode_roundtrip_threshold() {
        use crate::builder::build_bfv_params;
        use num_bigint::BigUint;
        use std::str::FromStr;

        // Use secure threshold preset constants for testing threshold parameter encoding
        let degree = secure_8192::DEGREE;
        let plaintext_modulus = secure_8192::threshold::PLAINTEXT_MODULUS;
        let moduli = secure_8192::threshold::MODULI;
        let error1_variance = secure_8192::threshold::ERROR1_VARIANCE;

        let params = build_bfv_params(degree, plaintext_modulus, moduli, Some(error1_variance));
        let encoded = encode_bfv_params(&params);
        let decoded = decode_bfv_params(&encoded).expect("should decode successfully");

        assert_eq!(decoded.degree(), degree);
        assert_eq!(decoded.plaintext(), plaintext_modulus);
        assert_eq!(decoded.moduli(), moduli);
        // Verify error1_variance is preserved for threshold
        assert_eq!(
            decoded.get_error1_variance(),
            &BigUint::from_str(error1_variance).unwrap()
        );
    }

    #[cfg(feature = "abi-encoding")]
    #[test]
    fn test_encode_decode_arc_roundtrip() {
        use crate::presets::BfvParamSet;

        let preset = BfvPreset::InsecureThreshold;
        let param_set: BfvParamSet = preset.into();
        let params = param_set.build_arc();

        let encoded = encode_bfv_params(&params);
        let decoded = decode_bfv_params_arc(&encoded).expect("should decode successfully");

        assert_eq!(decoded.degree(), params.degree());
        assert_eq!(decoded.plaintext(), params.plaintext());
        assert_eq!(decoded.moduli(), params.moduli());
        assert_eq!(decoded.get_error1_variance(), params.get_error1_variance());
    }

    #[cfg(feature = "abi-encoding")]
    #[test]
    fn test_encode_decode_arc_roundtrip_arbitrary() {
        use crate::builder::build_bfv_params_arc;

        // Use insecure DKG preset constants for testing arbitrary parameter encoding with Arc
        let degree = insecure::DEGREE;
        let plaintext_modulus = insecure::dkg::PLAINTEXT_MODULUS;
        let moduli = insecure::dkg::MODULI;

        let params = build_bfv_params_arc(degree, plaintext_modulus, moduli, None);
        let encoded = encode_bfv_params(&params);

        // Verify we can decode back to the original parameters with Arc
        let decoded = decode_bfv_params_arc(&encoded).expect("should decode successfully");
        assert_eq!(decoded.degree(), degree);
        assert_eq!(decoded.plaintext(), plaintext_modulus);
        assert_eq!(decoded.moduli(), moduli);
        // Verify error1_variance is preserved (defaults to 10 for standard BFV)
        assert_eq!(
            decoded.get_error1_variance(),
            &num_bigint::BigUint::from_str(insecure::dkg::ERROR1_VARIANCE).unwrap()
        );
        assert_eq!(decoded.get_error1_variance(), params.get_error1_variance());
    }

    #[cfg(feature = "abi-encoding")]
    #[test]
    fn test_encode_deterministic() {
        use crate::presets::BfvParamSet;

        let preset = BfvPreset::SecureThreshold8192;
        let param_set: BfvParamSet = preset.into();
        let params = param_set.build();

        let encoded1 = encode_bfv_params(&params);
        let encoded2 = encode_bfv_params(&params);

        assert_eq!(encoded1, encoded2, "ABI encoding should be deterministic");
    }

    #[cfg(feature = "abi-encoding")]
    #[test]
    fn test_decode_invalid_bytes() {
        let invalid_bytes = vec![0u8; 10];
        let result = decode_bfv_params(&invalid_bytes);
        assert!(result.is_err());
    }
}
