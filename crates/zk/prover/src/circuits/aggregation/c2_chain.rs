// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunked C2: proves the chunk chain of `lib::core::dkg::share_computation_chain`, then the final
//! `sk_share_computation` / `e_sm_share_computation` proof that verifies every chunk and that peers
//! and `c2ab_fold` consume. The chunk proofs never leave this node, so they are non-ZK; the final
//! proof is a ZK proof of the same circuit name as the unchunked C2.

use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_zk_config::dkg::share_computation::Configs;
use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_computation::{Inputs, ShareComputationCircuitData};
use e3_zk_witness::dkg::share_computation_chain::Chain;
use serde_json::{json, Value};

/// Chunk circuits for the secret `input_type` shares: `(full, last)`.
fn chunk_circuits(input_type: DkgInputType) -> (CircuitName, CircuitName) {
    match input_type {
        DkgInputType::SecretKey => (
            CircuitName::SkShareComputationChain,
            CircuitName::SkShareComputationChainLast,
        ),
        DkgInputType::SmudgingNoise => (
            CircuitName::ESmShareComputationChain,
            CircuitName::ESmShareComputationChainLast,
        ),
    }
}

/// The final C2 circuit for `input_type`.
pub fn final_circuit(input_type: DkgInputType) -> CircuitName {
    match input_type {
        DkgInputType::SecretKey => CircuitName::SkShareComputation,
        DkgInputType::SmudgingNoise => CircuitName::ESmShareComputation,
    }
}

fn prove_circuit(
    prover: &ZkProver,
    circuit: CircuitName,
    variant: CircuitVariant,
    inputs: &Value,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let path = prover
        .circuits_dir(variant, artifacts_dir)
        .join(circuit.dir_path())
        .join(format!("{}.json", circuit.as_str()));
    let compiled = CompiledCircuit::from_file(&path)?;
    let witness = WitnessGenerator::new()
        .generate_witness(&compiled, inputs_json_to_input_map(inputs)?)
        .map_err(|e| ZkError::WitnessGenerationFailed(format!("{circuit}: {e}")))?;
    prover.generate_proof_with_variant(circuit, &witness, job_id, variant, artifacts_dir)
}

/// Proves C2 for `input` as a chunk chain and returns the final proof.
pub fn prove_share_computation_chain(
    prover: &ZkProver,
    config: &Configs,
    input: &ShareComputationCircuitData,
    e3_id: &str,
    variant: CircuitVariant,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let inputs = Inputs::compute(config, input)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    let chain = Chain::compute(config, &inputs)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    let (full, last) = chunk_circuits(inputs.dkg_input_type);
    let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
    let full_vk = vk::load_vk_artifacts(&default_dir, full)?;
    let last_vk = vk::load_vk_artifacts(&default_dir, last)?;
    let tag = match inputs.dkg_input_type {
        DkgInputType::SecretKey => "c2a",
        DkgInputType::SmudgingNoise => "c2b",
    };

    let mut chunk_proofs = Vec::with_capacity(chain.chunks.len());
    let mut chunk_links = Vec::with_capacity(chain.chunks.len());
    for (c, chunk) in chain.chunks.iter().enumerate() {
        let circuit = if chunk.is_last { last } else { full };
        let job_id = format!("{e3_id}-{tag}-chunk-{c}");
        let proof = prove_circuit(
            prover,
            circuit,
            CircuitVariant::Default,
            &chunk.to_json(),
            &job_id,
            artifacts_dir,
        )?;
        let _ = prover.cleanup(&job_id);
        chunk_proofs.push(bytes_to_field_strings(&proof.data)?);
        chunk_links.push(bytes_to_field_strings(&proof.public_signals)?);
    }

    let mut final_inputs = inputs.to_json();
    let fields = final_inputs
        .as_object_mut()
        .expect("C2 inputs serialize as an object");
    fields.remove("y");
    fields.insert("full_vk".into(), json!(full_vk.verification_key));
    fields.insert("full_key_hash".into(), json!(full_vk.key_hash));
    fields.insert("last_vk".into(), json!(last_vk.verification_key));
    fields.insert("last_key_hash".into(), json!(last_vk.key_hash));
    fields.insert("chunk_proofs".into(), json!(chunk_proofs));
    fields.insert("chunk_links".into(), json!(chunk_links));
    fields.insert("chain_outputs".into(), json!(chain.outputs_json()));

    prove_circuit(
        prover,
        final_circuit(inputs.dkg_input_type),
        variant,
        &final_inputs,
        e3_id,
        artifacts_dir,
    )
}

/// The key tree a final C2 proof must expose last: the hash of the full-chunk and last-chunk keys
/// for `circuit`'s secret, as the final circuit computes it.
pub fn expected_key_tree(
    prover: &ZkProver,
    circuit: CircuitName,
    artifacts_dir: &str,
) -> Result<Fr, ZkError> {
    let input_type = match circuit {
        CircuitName::SkShareComputation => DkgInputType::SecretKey,
        CircuitName::ESmShareComputation => DkgInputType::SmudgingNoise,
        other => {
            return Err(ZkError::InvalidInput(format!(
                "{other} is not a final C2 circuit"
            )))
        }
    };
    let (full, last) = chunk_circuits(input_type);
    let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
    let hashes = [
        vk::load_vk_artifacts(&default_dir, full)?.key_hash,
        vk::load_vk_artifacts(&default_dir, last)?.key_hash,
    ]
    .iter()
    .map(|hash| hex_to_field(hash))
    .collect::<Result<Vec<_>, _>>()?;
    Ok(e3_zk_witness::compute_vk_hash(hashes))
}

/// Checks a verified final C2 proof was built from this node's chunk circuits.
///
/// The final circuit verifies its chunks against whatever keys the prover passes and exposes
/// their hash, so a C2 proof alone does not pin them. `c2ab_fold` anchors them in the VK tree for
/// the on-chain path; a peer checking a C2 directly compares the hash here.
pub fn check_key_tree(
    prover: &ZkProver,
    proof: &Proof,
    artifacts_dir: &str,
) -> Result<bool, ZkError> {
    let publics = bytes_to_field_strings(&proof.public_signals)?;
    let Some(last) = publics.last() else {
        return Ok(false);
    };
    Ok(hex_to_field(last)? == expected_key_tree(prover, proof.circuit, artifacts_dir)?)
}

fn hex_to_field(value: &str) -> Result<Fr, ZkError> {
    let digits = value.trim_start_matches("0x");
    let bytes = hex::decode(if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    })
    .map_err(|e| ZkError::InvalidInput(format!("key hash {value}: {e}")))?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ZkBackend;
    use crate::test_utils::get_tempdir;
    use ark_ff::BigInteger;
    use e3_config::BBPath;
    use e3_utils::ArcBytes;

    fn field_bytes(value: Fr) -> Vec<u8> {
        let repr = value.into_bigint().to_bytes_be();
        let mut out = vec![0; 32 - repr.len()];
        out.extend(repr);
        out
    }

    /// A C2 proof passes only when its last public field is the hash of this node's two chunk keys
    /// for its secret.
    #[test]
    fn key_tree_check_pins_the_chain_keys() {
        let temp = get_tempdir().unwrap();
        let backend = ZkBackend::new(
            BBPath::Default(temp.path().join("bb")),
            temp.path().join("circuits"),
            temp.path().join("work"),
        );
        let prover = ZkProver::new(&backend);
        let artifacts_dir = "insecure-64/minimum";
        let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
        for (i, circuit) in [
            CircuitName::SkShareComputationChain,
            CircuitName::SkShareComputationChainLast,
        ]
        .into_iter()
        .enumerate()
        {
            let dir = default_dir.join(circuit.dir_path());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{}.vk", circuit.as_str())), [0u8; 32]).unwrap();
            std::fs::write(
                dir.join(format!("{}.vk_hash", circuit.as_str())),
                field_bytes(Fr::from(i as u64 + 1)),
            )
            .unwrap();
        }
        let tree = e3_zk_witness::compute_vk_hash(vec![Fr::from(1u64), Fr::from(2u64)]);
        let proof = |last: Fr| {
            let mut signals = field_bytes(Fr::from(7u64));
            signals.extend(field_bytes(last));
            Proof::new(
                CircuitName::SkShareComputation,
                ArcBytes::from_bytes(&[0u8; 8]),
                ArcBytes::from_bytes(&signals),
            )
        };

        assert!(check_key_tree(&prover, &proof(tree), artifacts_dir).unwrap());
        assert!(!check_key_tree(&prover, &proof(tree + Fr::from(1u64)), artifacts_dir).unwrap());
        let other = Proof::new(
            CircuitName::ShareEncryption,
            ArcBytes::from_bytes(&[0u8; 8]),
            ArcBytes::from_bytes(&field_bytes(tree)),
        );
        assert!(check_key_tree(&prover, &other, artifacts_dir).is_err());
    }
}
