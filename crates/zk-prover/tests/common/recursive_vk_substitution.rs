// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{fs, path::Path, process::Command};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use e3_events::{CircuitName, Proof};
use e3_zk_prover::test_utils::{
    fold_witness_field_strings, fold_witness_input_map, get_tempdir, load_vk_artifacts,
};
use e3_zk_prover::{CircuitVariant, CompiledCircuit, WitnessGenerator, ZkError, ZkProver};
use serde_json::{json, Value};

pub struct SubstituteProof {
    pub vk: Vec<String>,
    pub key_hash: String,
    pub proof: Proof,
}

pub fn fields(proof: &Proof) -> Vec<String> {
    fold_witness_field_strings(proof.public_signals.as_ref()).unwrap()
}

pub fn vk_hash(keys: &[String]) -> String {
    let keys = keys
        .iter()
        .map(|key| Fr::from_be_bytes_mod_order(&hex::decode(key.trim_start_matches("0x")).unwrap()))
        .collect();
    let bytes = e3_zk_helpers::compute_vk_hash(keys)
        .into_bigint()
        .to_bytes_be();
    format!("0x{:0>64}", hex::encode(bytes))
}

pub fn witness(path: &Path, input: &Value) -> Result<Vec<u8>, ZkError> {
    WitnessGenerator::new().generate_witness(
        &CompiledCircuit::from_file(path)?,
        fold_witness_input_map(input)?,
    )
}

/// Recursive opcodes defer verification to Barretenberg, so witness success is not proof acceptance.
pub fn assert_fold_rejected(
    prover: &ZkProver,
    circuit: CircuitName,
    path: &Path,
    input: &Value,
    artifacts_dir: &str,
    case: &str,
) {
    let witness = match witness(path, input) {
        Ok(witness) => witness,
        Err(ZkError::WitnessGenerationFailed(_)) => return,
        Err(error) => panic!("{case}: unexpected witness error: {error}"),
    };
    let proof = prover
        .generate_recursive_aggregation_bin_proof(circuit, &witness, case, artifacts_dir)
        .unwrap_or_else(|error| panic!("{case}: proof process failed: {error}"));
    assert!(
        !prover
            .verify_fold_proof(&proof, case, 0, artifacts_dir)
            .expect("recursive verifier result"),
        "{case}: an unauthorized recursive VK was accepted",
    );
}

/// Prove an arbitrary statement under a different relation with the same public-input length.
pub fn substitute_proof(
    prover: &ZkProver,
    circuit: CircuitName,
    variant: CircuitVariant,
    statement: &[String],
    self_key_index: Option<usize>,
    case: &str,
) -> SubstituteProof {
    let temp = get_tempdir().unwrap();
    fs::create_dir(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("Nargo.toml"),
        "[package]\nname = \"vk_substitute\"\ntype = \"bin\"\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src/main.nr"),
        format!(
            "fn main(values: pub [Field; {}], private_value: Field) {{ assert(values[0] == private_value); }}\n",
            statement.len()
        ),
    )
    .unwrap();
    let compiled = Command::new("nargo")
        .arg("compile")
        .current_dir(temp.path())
        .output()
        .expect("nargo is required for recursive VK substitution tests");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let artifacts_dir = format!("substitute-{case}");
    let base = prover.circuits_dir(variant, &artifacts_dir);
    let dir = base.join(circuit.dir_path());
    fs::create_dir_all(&dir).unwrap();
    let circuit_path = dir.join(format!("{}.json", circuit.as_str()));
    fs::copy(temp.path().join("target/vk_substitute.json"), &circuit_path).unwrap();
    let vk = Command::new(prover.bb_binary())
        .arg("write_vk")
        .arg("-b")
        .arg(&circuit_path)
        .arg("-o")
        .arg(&dir)
        .arg("-t")
        .arg(variant.verifier_target())
        .output()
        .unwrap();
    assert!(
        vk.status.success(),
        "{}",
        String::from_utf8_lossy(&vk.stderr)
    );
    fs::rename(dir.join("vk"), dir.join(format!("{}.vk", circuit.as_str()))).unwrap();
    fs::rename(
        dir.join("vk_hash"),
        dir.join(format!("{}.vk_hash", circuit.as_str())),
    )
    .unwrap();
    let vk = load_vk_artifacts(&base, circuit).unwrap();
    let mut values = statement.to_vec();
    if let Some(index) = self_key_index {
        values[index] = vk.key_hash.clone();
    }
    let input = json!({"values": values, "private_value": values[0]});
    let witness = witness(&circuit_path, &input).unwrap();
    let proof = prover
        .generate_proof_with_variant(circuit, &witness, case, variant, &artifacts_dir)
        .expect("substitute proof");
    assert!(prover
        .verify_proof_with_variant(&proof, case, 0, variant, &artifacts_dir)
        .expect("verify substitute proof"));
    let parse_fields = |values: &[String]| {
        values
            .iter()
            .map(|value| acir::FieldElement::try_from_str(value).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(parse_fields(&fields(&proof)), parse_fields(&values));
    SubstituteProof {
        vk: vk.verification_key,
        key_hash: vk.key_hash,
        proof,
    }
}
