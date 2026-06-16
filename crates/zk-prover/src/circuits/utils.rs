// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use std::collections::BTreeMap;

use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use acir::FieldElement;
use e3_events::{CircuitName, CircuitVariant, Proof};
use noirc_abi::{input_parser::InputValue, InputMap};

const FIELD_SIZE: usize = 32;

/// Matches `bb_proof_verification::RECURSIVE_ZK_PROOF_LENGTH` (`UltraHonkZKProof`).
#[allow(dead_code)]
pub const ULTRA_HONK_ZK_PROOF_FIELD_COUNT: usize = 508;

/// Converts raw ZK proof bytes to field strings for `UltraHonkZKProof` witness input.
///
/// Barretenberg often emits fewer than [`ULTRA_HONK_ZK_PROOF_FIELD_COUNT`] 32-byte limbs; the Noir
/// type is a fixed-width array, so shorter proofs are zero-padded at the end.
#[allow(dead_code)]
pub fn zk_proof_bytes_to_field_strings(bytes: &[u8]) -> Result<Vec<String>, ZkError> {
    let need = ULTRA_HONK_ZK_PROOF_FIELD_COUNT * FIELD_SIZE;
    if bytes.len() > need {
        return Err(ZkError::InvalidInput(format!(
            "zk proof bytes length {} exceeds fixed width {}",
            bytes.len(),
            need
        )));
    }
    if !bytes.len().is_multiple_of(FIELD_SIZE) {
        return Err(ZkError::InvalidInput(format!(
            "zk proof bytes length must be multiple of {FIELD_SIZE}, got {}",
            bytes.len()
        )));
    }
    let mut buf = bytes.to_vec();
    buf.resize(need, 0);
    bytes_to_field_strings(&buf)
}

/// Converts raw proof/public-signal bytes (32-byte big-endian chunks) to hex-encoded field strings.
pub fn bytes_to_field_strings(bytes: &[u8]) -> Result<Vec<String>, ZkError> {
    if !bytes.len().is_multiple_of(FIELD_SIZE) {
        return Err(ZkError::InvalidInput(format!(
            "expected length multiple of {FIELD_SIZE}, got {}",
            bytes.len()
        )));
    }
    Ok(bytes
        .chunks(FIELD_SIZE)
        .map(|chunk| format!("0x{}", hex::encode(chunk)))
        .collect())
}

/// Proves a circuit given a serializable input struct (ZK blinding enabled).
///
/// Handles the common pattern: serialize → load compiled circuit → generate witness → prove.
#[allow(dead_code)]
pub fn prove_recursive_circuit(
    prover: &ZkProver,
    circuit_name: CircuitName,
    input: &impl serde::Serialize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let witness = generate_recursive_witness(prover, circuit_name, input, artifacts_dir)?;
    prover.generate_proof_with_variant(
        circuit_name,
        &witness,
        e3_id,
        CircuitVariant::Recursive,
        artifacts_dir,
    )
}

/// Shared helper: load compiled circuit from Recursive dir, serialize input, generate witness.
#[allow(dead_code)]
fn generate_recursive_witness(
    prover: &ZkProver,
    circuit_name: CircuitName,
    input: &impl serde::Serialize,
    artifacts_dir: &str,
) -> Result<Vec<u8>, ZkError> {
    let recursive_dir = prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir);
    let circuit_path = recursive_dir
        .join(circuit_name.dir_path())
        .join(format!("{}.json", circuit_name.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json =
        serde_json::to_value(input).map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;

    let witness_gen = WitnessGenerator::new();
    witness_gen.generate_witness(&compiled, input_map)
}

/// Converts inputs JSON (from `Inputs::to_json()`) to `InputMap` for Noir ABI.
/// Expects the same structure: CRT fields as arrays of `{coefficients: [...]}`,
/// polynomial fields as `{coefficients: [...]}`.
pub fn inputs_json_to_input_map(json: &serde_json::Value) -> Result<InputMap, ZkError> {
    let obj = json
        .as_object()
        .ok_or_else(|| ZkError::SerializationError("inputs json must be an object".into()))?;

    let mut inputs = InputMap::new();
    for (key, value) in obj {
        let input_value = json_value_to_input_value(value)?;
        inputs.insert(key.clone(), input_value);
    }
    Ok(inputs)
}

fn json_value_to_input_value(v: &serde_json::Value) -> Result<InputValue, ZkError> {
    if let Some(s) = v.as_str() {
        return FieldElement::try_from_str(s)
            .map(InputValue::Field)
            .ok_or_else(|| ZkError::SerializationError(format!("invalid field element: {}", s)));
    }
    if let Some(b) = v.as_bool() {
        let n = u64::from(b);
        return FieldElement::try_from_str(&n.to_string())
            .map(InputValue::Field)
            .ok_or_else(|| ZkError::SerializationError(format!("invalid field element: {}", n)));
    }
    if let Some(n) = v.as_i64() {
        return FieldElement::try_from_str(&n.to_string())
            .map(InputValue::Field)
            .ok_or_else(|| ZkError::SerializationError(format!("invalid field element: {}", n)));
    }
    if let Some(n) = v.as_u64() {
        return FieldElement::try_from_str(&n.to_string())
            .map(InputValue::Field)
            .ok_or_else(|| ZkError::SerializationError(format!("invalid field element: {}", n)));
    }
    if let Some(arr) = v.as_array() {
        let items = arr
            .iter()
            .map(json_value_to_input_value)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(InputValue::Vec(items));
    }
    if let Some(n) = v.as_i64() {
        return FieldElement::try_from_str(&n.to_string())
            .map(InputValue::Field)
            .ok_or_else(|| ZkError::SerializationError(format!("invalid field element: {}", n)));
    }
    if let Some(n) = v.as_u64() {
        return FieldElement::try_from_str(&n.to_string())
            .map(InputValue::Field)
            .ok_or_else(|| ZkError::SerializationError(format!("invalid field element: {}", n)));
    }
    if let Some(obj) = v.as_object() {
        if let Some(coeffs) = obj.get("coefficients") {
            let coeff_arr = coeffs
                .as_array()
                .ok_or_else(|| ZkError::SerializationError("coefficients must be array".into()))?;
            let fields = coeff_arr
                .iter()
                .map(|c| {
                    let s = c
                        .as_str()
                        .map(String::from)
                        .or_else(|| c.as_i64().map(|n| n.to_string()))
                        .or_else(|| c.as_u64().map(|n| n.to_string()))
                        .ok_or_else(|| {
                            ZkError::SerializationError(
                                "coefficient must be string or number".into(),
                            )
                        })?;
                    FieldElement::try_from_str(&s)
                        .map(InputValue::Field)
                        .ok_or_else(|| {
                            ZkError::SerializationError(format!("invalid field element: {}", s))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut map = BTreeMap::new();
            map.insert("coefficients".into(), InputValue::Vec(fields));
            return Ok(InputValue::Struct(map));
        }
    }
    Err(ZkError::SerializationError(
        "unexpected json structure".into(),
    ))
}
