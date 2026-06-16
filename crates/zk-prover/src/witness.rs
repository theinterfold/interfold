// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::error::ZkError;
use acir::{
    circuit::Program,
    native_types::{WitnessMap, WitnessStack},
    FieldElement,
};
use base64::engine::{general_purpose, Engine};
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use flate2::write::GzEncoder;
use flate2::Compression;
use nargo::foreign_calls::default::DefaultForeignCallBuilder;
use nargo::ops::execute_program;
use noirc_abi::{input_parser::InputValue, Abi, InputMap};
use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledCircuit {
    pub bytecode: String,
    pub abi: Abi,
}

impl CompiledCircuit {
    pub fn from_json(json: &str) -> Result<Self, ZkError> {
        serde_json::from_str(json).map_err(ZkError::JsonError)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, ZkError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            ZkError::CircuitNotFound(format!("circuit JSON at {}: {}", path.display(), e))
        })?;
        Self::from_json(&contents)
    }
}

fn get_acir_buffer(bytecode: &str) -> Result<Vec<u8>, ZkError> {
    general_purpose::STANDARD
        .decode(bytecode)
        .map_err(|e| ZkError::SerializationError(format!("base64 decode: {}", e)))
}

fn get_program(bytecode: &str) -> Result<Program<FieldElement>, ZkError> {
    let acir_buffer = get_acir_buffer(bytecode)?;
    Program::deserialize_program(&acir_buffer)
        .map_err(|e| ZkError::SerializationError(format!("ACIR decode: {:?}", e)))
}

fn execute(
    bytecode: &str,
    initial_witness: WitnessMap<FieldElement>,
) -> Result<WitnessStack<FieldElement>, ZkError> {
    let program = get_program(bytecode)?;
    let blackbox_solver = Bn254BlackBoxSolver::default();
    let mut foreign_call_executor = DefaultForeignCallBuilder::default().build();

    execute_program(
        &program,
        initial_witness,
        &blackbox_solver,
        &mut foreign_call_executor,
    )
    .map_err(|e| ZkError::WitnessGenerationFailed(e.to_string()))
}

fn serialize_witness(witness_stack: &WitnessStack<FieldElement>) -> Result<Vec<u8>, ZkError> {
    let buf = bincode::serialize(witness_stack)
        .map_err(|e| ZkError::SerializationError(format!("bincode: {}", e)))?;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&buf)
        .map_err(|e| ZkError::SerializationError(format!("gzip: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| ZkError::SerializationError(format!("gzip finish: {}", e)))
}

pub struct WitnessGenerator;

impl WitnessGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_witness(
        &self,
        circuit: &CompiledCircuit,
        inputs: InputMap,
    ) -> Result<Vec<u8>, ZkError> {
        let initial_witness = circuit
            .abi
            .encode(&inputs, None)
            .map_err(|e| ZkError::WitnessGenerationFailed(format!("ABI encode: {:?}", e)))?;

        let witness_stack = execute(&circuit.bytecode, initial_witness)?;
        serialize_witness(&witness_stack)
    }
}

impl Default for WitnessGenerator {
    fn default() -> Self {
        Self::new()
    }
}

pub fn input_map<I, K, V>(iter: I) -> Result<InputMap, ZkError>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: AsRef<str>,
{
    iter.into_iter()
        .map(|(k, v)| {
            let key = k.into();
            let field = FieldElement::try_from_str(v.as_ref()).ok_or_else(|| {
                ZkError::SerializationError(format!(
                    "invalid field element for key '{}': {}",
                    key,
                    v.as_ref()
                ))
            })?;
            Ok((key, InputValue::Field(field)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY_CIRCUIT: &str = include_str!("../tests/fixtures/dummy.json");

    #[test]
    fn test_load_circuit() {
        let circuit = CompiledCircuit::from_json(DUMMY_CIRCUIT).unwrap();
        assert_eq!(circuit.abi.parameters.len(), 3);
    }

    #[test]
    fn test_generate_witness() {
        let circuit = CompiledCircuit::from_json(DUMMY_CIRCUIT).unwrap();
        let generator = WitnessGenerator::new();
        let inputs = input_map([("x", "5"), ("y", "3"), ("_sum", "8")]).unwrap();

        let witness = generator.generate_witness(&circuit, inputs).unwrap();

        assert!(witness.len() > 2);
        assert_eq!(witness[0], 0x1f);
        assert_eq!(witness[1], 0x8b);
    }

    #[test]
    fn test_wrong_sum_fails() {
        let circuit = CompiledCircuit::from_json(DUMMY_CIRCUIT).unwrap();
        let generator = WitnessGenerator::new();
        let inputs = input_map([("x", "5"), ("y", "3"), ("_sum", "10")]).unwrap();

        let result = generator.generate_witness(&circuit, inputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_field_element() {
        let result = input_map([("x", "not_a_number"), ("y", "3")]);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ZkError::SerializationError(_)));
        assert!(err.to_string().contains("invalid field element"));
        assert!(err.to_string().contains("'x'"));
    }
}
