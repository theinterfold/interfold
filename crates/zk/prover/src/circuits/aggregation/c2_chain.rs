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
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_zk_config::dkg::share_computation::Configs;
use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_computation::{Inputs, ShareComputationCircuitData};
use e3_zk_witness::dkg::share_computation_chain::Chain;
use serde_json::{json, Value};

/// The final C2 circuit for `input_type`.
pub fn final_circuit(input_type: DkgInputType) -> CircuitName {
    match input_type {
        DkgInputType::SecretKey => CircuitName::SkShareComputation,
        DkgInputType::SmudgingNoise => CircuitName::ESmShareComputation,
    }
}

pub(super) fn prove_circuit(
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
    let chunks = super::chain_keys::chunk_circuits(final_circuit(inputs.dkg_input_type))
        .expect("final C2 circuits are chunked");
    let (full, last) = (chunks[0], chunks[1]);
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
