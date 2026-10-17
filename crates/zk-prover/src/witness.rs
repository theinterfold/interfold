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
use nargo::foreign_calls::default::DefaultForeignCallBuilder;
use nargo::ops::execute_program;
use noirc_abi::{input_parser::InputValue, Abi, InputMap};
use serde::{Deserialize, Serialize};

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
    let blackbox_solver = Bn254BlackBoxSolver;
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
    witness_stack
        .serialize()
        .map_err(|e| ZkError::SerializationError(format!("witness stack: {}", e)))
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

    #[test]
    #[ignore = "requires matching local insecure/minimum compiled C6/C7 artifacts"]
    fn local_c6_c7_zero_products_execute_and_nondefault_widths_reject_fixed_abi() {
        use crate::circuits::utils::inputs_json_to_input_map;
        use e3_committee::CiphernodesCommitteeSize;
        use e3_fhe_params::BfvPreset;
        use e3_polynomial::{CrtPolynomial, Polynomial};
        use e3_zk_config::threshold::{decrypted_shares_aggregation as c7, share_decryption as c6};
        use e3_zk_witness::threshold::{
            decrypted_shares_aggregation as w7, share_decryption as w6,
        };
        use fhe::bfv::Ciphertext;
        use fhe_math::rq::{Poly, PowerBasis};
        use num_bigint::BigInt;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits/bin");
        let active: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join(".active-preset.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(active["preset"], "insecure-64");
        assert_eq!(active["committee"], "minimum");
        let mut config7 = c7::Configs::for_preset(
            BfvPreset::InsecureThreshold64,
            CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();
        let mut config6 = c6::Configs::new(&config7.params).unwrap();
        let poly = Poly::<PowerBasis>::zero(config7.params.context_at_level(0).unwrap());
        let crt = CrtPolynomial::new(vec![
            Polynomial::new(vec![
                BigInt::from(0);
                config6.params.degree()
            ]);
            config6.params.moduli().len()
        ]);
        let data6 = w6::ShareDecryptionCircuitData {
            ciphertext: Ciphertext::new(
                vec![poly.clone().into_ntt(), poly.clone().into_ntt()],
                &config6.params,
            )
            .unwrap(),
            s: crt.clone(),
            e: crt.clone(),
            d_share: crt,
            domain_hi: 0,
            domain_lo: 0,
        };
        let count = config7.committee.values().threshold + 1;
        let data7 = w7::DecryptedSharesAggregationCircuitData {
            d_share_polys: vec![poly; count],
            reconstructing_parties: (1..=count).collect(),
            message_vec: vec![0],
        };
        let compiled6 =
            CompiledCircuit::from_file(&root.join("threshold/target/share_decryption.json"))
                .unwrap();
        let compiled7 = CompiledCircuit::from_file(
            &root.join("threshold/target/decrypted_shares_aggregation.json"),
        )
        .unwrap();
        let generator = WitnessGenerator::new();
        let json6 = w6::Inputs::compute(&config6, &data6).unwrap().to_json();
        let json7 = w7::Inputs::compute(&config7, &data7).unwrap().to_json();
        generator
            .generate_witness(&compiled6, inputs_json_to_input_map(&json6).unwrap())
            .unwrap();
        generator
            .generate_witness(&compiled7, inputs_json_to_input_map(&json7).unwrap())
            .unwrap();
        let mut wrong_quotient = json6;
        wrong_quotient["r"][0]["coefficients"][0] = serde_json::json!(1);
        assert!(generator
            .generate_witness(
                &compiled6,
                inputs_json_to_input_map(&wrong_quotient).unwrap()
            )
            .is_err());
        let mut wrong_message = json7;
        wrong_message["message"]["coefficients"][0] = serde_json::json!(1);
        assert!(generator
            .generate_witness(
                &compiled7,
                inputs_json_to_input_map(&wrong_message).unwrap()
            )
            .is_err());
        let sample6 = e3_zk_samples::threshold::share_decryption::generate(
            &config6.params,
            BfvPreset::InsecureThreshold64,
            CiphernodesCommitteeSize::Minimum.values(),
        )
        .unwrap();
        let sample7 = e3_zk_samples::threshold::decrypted_shares_aggregation::generate(
            &config7,
            BfvPreset::InsecureThreshold64,
        )
        .unwrap();
        for (compiled, json) in [
            (
                &compiled6,
                w6::Inputs::compute(&config6, &sample6).unwrap().to_json(),
            ),
            (
                &compiled7,
                w7::Inputs::compute(&config7, &sample7).unwrap().to_json(),
            ),
        ] {
            generator
                .generate_witness(compiled, inputs_json_to_input_map(&json).unwrap())
                .unwrap();
        }
        config6.max_msg_non_zero_coeffs = 7;
        config7.max_msg_non_zero_coeffs = 7;
        for (compiled, json) in [
            (
                &compiled6,
                w6::Inputs::compute(&config6, &data6).unwrap().to_json(),
            ),
            (
                &compiled7,
                w7::Inputs::compute(&config7, &data7).unwrap().to_json(),
            ),
        ] {
            let error = generator
                .generate_witness(compiled, inputs_json_to_input_map(&json).unwrap())
                .unwrap_err();
            assert!(error.to_string().contains("ABI encode"), "{error}");
        }
    }

    const DUMMY_CIRCUIT: &str = include_str!("../tests/fixtures/dummy.json");

    #[test]
    #[ignore = "requires E3_TEST_UDE_ARTIFACTS_DIR with matching secure-8192 UDE artifacts"]
    fn local_secure_ude_material_executes_both_legs_and_rejects_bad_carry() {
        use crate::circuits::utils::inputs_json_to_input_map;
        use e3_fhe_params::BfvPreset;
        use e3_zk_config::threshold::user_data_encryption::Configs;
        use e3_zk_witness::threshold::user_data_encryption::Inputs;
        let root = std::path::PathBuf::from(
            std::env::var_os("E3_TEST_UDE_ARTIFACTS_DIR")
                .expect("set E3_TEST_UDE_ARTIFACTS_DIR to verified secure threshold artifacts"),
        );
        let config = Configs::for_preset(BfvPreset::SecureThreshold8192).unwrap();
        let sample =
            e3_zk_samples::threshold::user_data_encryption::generate(&config.params).unwrap();
        let (ct, material) = sample
            .public_key
            .try_encrypt_with_intermediates(&sample.plaintext, &mut rand::rng())
            .unwrap();
        let inputs = Inputs::compute(&config, &sample, &ct, &material).unwrap();
        let json = inputs.to_json();
        let generator = WitnessGenerator::new();
        for name in ["user_data_encryption_ct0", "user_data_encryption_ct1"] {
            let compiled =
                CompiledCircuit::from_file(&root.join(name).join(format!("{name}.json"))).unwrap();
            let mut leg = json.clone();
            leg.as_object_mut().unwrap().retain(|key, _| {
                compiled
                    .abi
                    .parameters
                    .iter()
                    .any(|parameter| &parameter.name == key)
            });
            generator
                .generate_witness(&compiled, inputs_json_to_input_map(&leg).unwrap())
                .unwrap();
            let key = if name.ends_with("ct0") { "r" } else { "r_ct1" };
            leg[key][0]["coefficients"][0] = serde_json::json!(0);
            // Choose a different carry even if the first coefficient happened to be zero.
            if leg[key][0]["coefficients"][0] == json[key][0]["coefficients"][0] {
                leg[key][0]["coefficients"][0] = serde_json::json!(1);
            }
            assert!(generator
                .generate_witness(&compiled, inputs_json_to_input_map(&leg).unwrap())
                .is_err());
        }
    }

    #[test]
    fn test_generate_witness() {
        let circuit = CompiledCircuit::from_json(DUMMY_CIRCUIT).unwrap();
        let generator = WitnessGenerator::new();
        let inputs = input_map([("x", "5"), ("y", "3"), ("_sum", "8")]).unwrap();

        let witness = generator.generate_witness(&circuit, inputs).unwrap();

        assert!(witness.len() > 2);
        WitnessStack::<FieldElement>::deserialize(&witness).unwrap();
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
