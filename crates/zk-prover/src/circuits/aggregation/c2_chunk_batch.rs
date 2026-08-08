// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Batch C2 chunk proofs and root finalization.

use crate::circuits::aggregation::c2_chunk_config::{
    chunks_per_batch, compiled_batch_count, compiled_chunk_count,
};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::{CircuitName, CircuitVariant, Proof};
use rayon::prelude::*;
use serde::Serialize;

const BATCH_PUBLIC_PREFIX_LEN: usize = 2;
#[derive(Serialize)]
struct C2ChunkBatchInput {
    chunk_vk: Vec<String>,
    chunk_proofs: Vec<Vec<String>>,
    chunk_public_inputs: Vec<Vec<String>>,
    chunk_key_hash: String,
    batch_idx: u32,
}

#[derive(Serialize)]
struct C2ChunkBatchFinalizeInput {
    batch_vk: Vec<String>,
    batch_proofs: Vec<Vec<String>>,
    batch_public_inputs: Vec<Vec<String>>,
    batch_key_hash: String,
}

fn public_fields(proof: &Proof, context: &str) -> Result<Vec<String>, ZkError> {
    bytes_to_field_strings(proof.public_signals.as_ref())
        .map_err(|error| ZkError::InvalidInput(format!("{context} public signals: {error}")))
}

/// Aggregate fixed-size groups of independent C2 chunk proofs.
pub fn generate_c2_chunk_batches(
    prover: &ZkProver,
    chunk_circuit: CircuitName,
    chunk_proofs: &[Proof],
    chunk_count: usize,
    degree: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Vec<Proof>, ZkError> {
    if chunk_count == 0 || chunk_proofs.len() != chunk_count {
        return Err(ZkError::InvalidInput(format!(
            "C2 chunk batches require {chunk_count} chunk proofs, got {}",
            chunk_proofs.len()
        )));
    }
    let expected_chunk_count = compiled_chunk_count(degree);
    if chunk_count != expected_chunk_count {
        return Err(ZkError::InvalidInput(format!(
            "C2 chunk count {chunk_count} does not match compiled artifact count {expected_chunk_count}"
        )));
    }
    let per_batch = chunks_per_batch(degree);
    if chunk_count % per_batch != 0 {
        return Err(ZkError::InvalidInput(format!(
            "C2 chunk count {chunk_count} is not divisible by batch size {per_batch}"
        )));
    }
    let batch_count = chunk_count / per_batch;
    let expected_batch_count = compiled_batch_count(degree);
    if batch_count != expected_batch_count {
        return Err(ZkError::InvalidInput(format!(
            "C2 batch count {batch_count} does not match compiled artifact count {expected_batch_count}"
        )));
    }

    let circuits_dir = prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir);
    let chunk_vk = vk::load_vk_artifacts(&circuits_dir, chunk_circuit)?;
    let batch_circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C2ChunkBatch.dir_path())
        .join(format!("{}.json", CircuitName::C2ChunkBatch.as_str()));
    let compiled = CompiledCircuit::from_file(&batch_circuit_path)?;

    let mut batches = Vec::with_capacity(chunk_count / per_batch);
    batches = chunk_proofs
        .par_chunks(per_batch)
        .enumerate()
        .map(|(batch_idx, proofs)| {
            let mut chunk_public_inputs = Vec::with_capacity(per_batch);
            let mut chunk_proof_fields = Vec::with_capacity(per_batch);
            for proof in proofs {
                if proof.circuit != chunk_circuit {
                    return Err(ZkError::InvalidInput(format!(
                        "C2 chunk batch expected {}, got {}",
                        chunk_circuit, proof.circuit
                    )));
                }
                chunk_public_inputs.push(public_fields(proof, "C2 chunk")?);
                chunk_proof_fields.push(bytes_to_field_strings(&proof.data)?);
            }

            let input = C2ChunkBatchInput {
                chunk_vk: chunk_vk.verification_key.clone(),
                chunk_proofs: chunk_proof_fields,
                chunk_public_inputs,
                chunk_key_hash: chunk_vk.key_hash.clone(),
                batch_idx: batch_idx as u32,
            };
            let json = serde_json::to_value(&input)
                .map_err(|error| ZkError::SerializationError(error.to_string()))?;
            let input_map = inputs_json_to_input_map(&json)?;
            let witness = WitnessGenerator::new()
                .generate_witness(&compiled, input_map)
                .map_err(|error| {
                    ZkError::WitnessGenerationFailed(format!(
                        "C2 batch {batch_idx} witness: {error}"
                    ))
                })?;
            prover.generate_recursive_aggregation_bin_proof(
                CircuitName::C2ChunkBatch,
                &witness,
                &format!("{e3_id}-c2-batch-{batch_idx}"),
                artifacts_dir,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(batches)
}

/// Verify all C2 chunk batches and reconstruct the C2 root commitments.
pub fn finalize_c2_chunk_batches(
    prover: &ZkProver,
    batch_proofs: &[Proof],
    finalizer_circuit: CircuitName,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if finalizer_circuit != CircuitName::SkC2ChunkFinalize
        && finalizer_circuit != CircuitName::ESmC2ChunkFinalize
    {
        return Err(ZkError::InvalidInput(format!(
            "invalid C2 chunk finalizer circuit {finalizer_circuit}"
        )));
    }
    if batch_proofs.is_empty() {
        return Err(ZkError::InvalidInput(
            "C2 chunk finalizer requires at least one batch".into(),
        ));
    }
    let batch_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C2ChunkBatch,
    )?;
    let mut batch_public_inputs = Vec::with_capacity(batch_proofs.len());
    let mut batch_proof_fields = Vec::with_capacity(batch_proofs.len());
    let mut public_len = None;
    for proof in batch_proofs {
        if proof.circuit != CircuitName::C2ChunkBatch {
            return Err(ZkError::InvalidInput(format!(
                "C2 finalizer expected {}, got {}",
                CircuitName::C2ChunkBatch,
                proof.circuit
            )));
        }
        let fields = public_fields(proof, "C2 batch")?;
        if public_len
            .replace(fields.len())
            .is_some_and(|len| len != fields.len())
        {
            return Err(ZkError::InvalidInput(
                "C2 batch proofs have different public input lengths".into(),
            ));
        }
        if fields.len() <= BATCH_PUBLIC_PREFIX_LEN {
            return Err(ZkError::InvalidInput(
                "C2 batch proof has no returned commitments".into(),
            ));
        }
        batch_public_inputs.push(fields);
        batch_proof_fields.push(bytes_to_field_strings(&proof.data)?);
    }

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(finalizer_circuit.dir_path())
        .join(format!("{}.json", finalizer_circuit.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let input = C2ChunkBatchFinalizeInput {
        batch_vk: batch_vk.verification_key,
        batch_proofs: batch_proof_fields,
        batch_public_inputs,
        batch_key_hash: batch_vk.key_hash,
    };
    let json = serde_json::to_value(&input)
        .map_err(|error| ZkError::SerializationError(error.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let witness = WitnessGenerator::new()
        .generate_witness(&compiled, input_map)
        .map_err(|error| {
            ZkError::WitnessGenerationFailed(format!("C2 finalizer witness: {error}"))
        })?;
    prover.generate_proof_with_variant(
        finalizer_circuit,
        &witness,
        &format!("{e3_id}-c2-finalize"),
        CircuitVariant::Recursive,
        artifacts_dir,
    )
}

#[cfg(test)]
mod tests {
    use super::chunks_per_batch;

    #[test]
    fn uses_one_batch_chunk_for_insecure_degree() {
        assert_eq!(chunks_per_batch(512), 1);
    }

    #[test]
    fn uses_four_batch_chunks_for_secure_degree() {
        assert_eq!(chunks_per_batch(8192), 4);
    }
}
