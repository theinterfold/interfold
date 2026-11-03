// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_bfv_client::client::{
    bfv_encrypt, bfv_verifiable_encrypt, compute_ct_commitment as _compute_ct_commitment,
    compute_pk_commitment as _compute_pk_commitment, generate_public_key as _generate_public_key,
};
use e3_fhe_params::{BfvParamSet, BfvPreset};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
/// A function to encrypt a u64 value using BFV and default params.
///
/// # Arguments
///
/// * `data` - The data to encrypt - must be a u64
/// * `public_key` - The public key to be used for encryption
/// * `degree` - Polynomial degree for BFV parameters
/// * `plaintext_modulus` - Plaintext modulus for BFV parameters
/// * `moduli` - Modulus for BFV parameters
///
/// # Returns
///
/// Returns a `Result<Vec<u8>, JsValue>` containing the encrypted data and any errors.
///
/// # Panics
///
/// Panics if the data cannot be encrypted
pub fn bfv_encrypt_number(
    data: u64,
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<Vec<u8>, JsValue> {
    let encrypted_data = bfv_encrypt([data], public_key, degree, plaintext_modulus, &moduli)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(encrypted_data)
}

/// Generate a public key from JavaScript.
#[wasm_bindgen]
pub fn generate_public_key(
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<Vec<u8>, JsValue> {
    let public_key = _generate_public_key(degree, plaintext_modulus, moduli)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(public_key)
}

/// A function to compute the public key commitment for a given public key.
///
/// # Arguments
///
/// * `public_key` - The public key to compute the commitment for
///
/// # Returns
/// Returns a `Result<Vec<u8>, JsValue>` containing the commitment and any errors.
///
/// # Panics
///
/// Panics if the public key cannot be computed
#[wasm_bindgen]
pub fn compute_pk_commitment(
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<Vec<u8>, JsValue> {
    let commitment = _compute_pk_commitment(public_key, degree, plaintext_modulus, moduli)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(commitment.to_vec())
}

/// Compute the SAFE commitment for serialized BFV ciphertext bytes.
#[wasm_bindgen]
pub fn compute_ct_commitment(
    ciphertext: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<Vec<u8>, JsValue> {
    let commitment = _compute_ct_commitment(ciphertext, degree, plaintext_modulus, moduli)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(commitment.to_vec())
}

#[wasm_bindgen]
/// A function to encrypt a Vec<u64> value using BFV and default params.
///
/// # Arguments
///
/// * `data` - The data to encrypt - must be a Vec<u64>
/// * `public_key` - The public key to be used for encryption
/// * `degree` - Polynomial degree for BFV parameters
/// * `plaintext_modulus` - Plaintext modulus for BFV parameters
/// * `moduli` - Modulus for BFV parameters
///
/// # Returns
///
/// Returns a `Result<Vec<u8>, JsValue>` containing the encrypted data and any errors.
///
/// # Panics
///
/// Panics if the data cannot be encrypted
pub fn bfv_encrypt_vector(
    data: Vec<u64>,
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<Vec<u8>, JsValue> {
    let encrypted_data = bfv_encrypt(data, public_key, degree, plaintext_modulus, &moduli)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(encrypted_data)
}

#[wasm_bindgen]
/// A function to encrypt a u64 value using BFV and default params and
/// generate circuit inputs for Greco
///
/// # Arguments
///
/// * `data` - The data to encrypt - must be a u64
/// * `public_key` - The public key to be used for encryption
/// * `degree` - Polynomial degree for BFV parameters
/// * `plaintext_modulus` - Plaintext modulus for BFV parameters
/// * `moduli` - Modulus for BFV parameters
///
/// # Returns
///
/// Returns a `Result<Vec<JsValue>, JsValue>` containing the encrypted data, circuit inputs and any errors.
///
/// # Panics
///
/// Panics if the data cannot be encrypted
pub fn bfv_verifiable_encrypt_number(
    data: u64,
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<Vec<JsValue>, JsValue> {
    let result = bfv_verifiable_encrypt([data], public_key, degree, plaintext_modulus, moduli)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    // Return as a vector of JsValues
    Ok(vec![
        JsValue::from(result.encrypted_data),
        JsValue::from(result.circuit_inputs),
    ])
}

#[wasm_bindgen]
/// A function to encrypt a Vec<u64> value using BFV and default params and
/// generate circuit inputs for Greco
///
/// # Arguments
///
/// * `data` - The data to encrypt - must be a Vec<u64>
/// * `public_key` - The public key to be used for encryption
/// * `degree` - Polynomial degree for BFV parameters
/// * `plaintext_modulus` - Plaintext modulus for BFV parameters
/// * `moduli` - Modulus for BFV parameters
///
/// # Returns
///
/// Returns a `Result<Vec<JsValue>, JsValue>` containing the encrypted data, circuit inputs and any errors.
///
/// # Panics
///
/// Panics if the data cannot be encrypted
pub fn bfv_verifiable_encrypt_vector(
    data: Vec<u64>,
    public_key: Vec<u8>,
    degree: usize,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
) -> Result<Vec<JsValue>, JsValue> {
    let result = bfv_verifiable_encrypt(data, public_key, degree, plaintext_modulus, moduli)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;

    // Return as a vector of JsValues
    Ok(vec![
        JsValue::from(result.encrypted_data),
        JsValue::from(result.circuit_inputs),
    ])
}

#[wasm_bindgen]
/// Retrieves a BFV parameter set by name.
///
/// # Parameters
/// * `name` - Parameter set identifier (e.g., "SECURE_THRESHOLD_8192" or "SECURE_THRESHOLD_16384")
///
/// # Returns
/// A JavaScript object with the following structure:
/// ```typescript
/// {
///   degree: number;              // Polynomial degree (e.g., 8192)
///   plaintext_modulus: number;   // Plaintext modulus value (e.g., 1000)
///   moduli: bigint[];            // Array of moduli
///   error1_variance: string | null; // Error variance as string or null
/// }
/// ```
///
/// # Errors
/// Returns error if the parameter set name is invalid or serialization fails.
pub fn get_bfv_params(name: &str) -> Result<JsValue, JsValue> {
    let preset = BfvPreset::from_name(name).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: BfvParamSet = preset.into();
    let js_params = BfvParamSetJs::from(&params);
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    js_params
        .serialize(&serializer)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

#[wasm_bindgen]
/// Returns all available BFV parameter set identifiers.
///
/// # Returns
/// Array of parameter set names that can be passed to `get_bfv_params()`.
/// Includes production-ready sets (e.g., "SECURE_THRESHOLD_8192" and "SECURE_THRESHOLD_16384") and
/// insecure sets for testing (prefixed with "INSECURE_").
pub fn get_bfv_params_list() -> Vec<String> {
    BfvPreset::list()
        .into_iter()
        .map(|name| name.to_string())
        .collect()
}

#[derive(Serialize, Deserialize)]
pub struct BfvParamSetJs {
    pub degree: usize,
    pub plaintext_modulus: u64,
    pub moduli: Vec<u64>,
    pub error1_variance: Option<String>,
}

impl From<&BfvParamSet> for BfvParamSetJs {
    fn from(params: &BfvParamSet) -> Self {
        BfvParamSetJs {
            degree: params.degree,
            plaintext_modulus: params.plaintext_modulus,
            moduli: params.moduli.to_vec(),
            error1_variance: params.error1_variance.map(|s| s.to_string()),
        }
    }
}
