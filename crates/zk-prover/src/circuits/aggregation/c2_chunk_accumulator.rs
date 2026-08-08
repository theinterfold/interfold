// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C2 chunk folding.

use crate::circuits::aggregation::helpers::{u64_to_field_hex, ACC_NONZK_PROOF_FIELDS};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::{CircuitName, CircuitVariant, Proof};
use serde::Serialize;

const C2_CHUNK_FOLD_PUBLIC_PREFIX_LEN: usize = 6;

struct C2ChunkFoldVks {
    base_vk: vk::VkArtifacts,
    chunk_vk: vk::VkArtifacts,
    fold_vk: vk::VkArtifacts,
    kernel_vk: vk::VkArtifacts,
}

impl C2ChunkFoldVks {
    fn load(
        prover: &ZkProver,
        base_circuit: CircuitName,
        artifacts_dir: &str,
    ) -> Result<Self, ZkError> {
        Ok(Self {
            base_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                base_circuit,
            )?,
            chunk_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                CircuitName::ShareComputationChunk,
            )?,
            fold_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C2ChunkFold,
            )?,
            kernel_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C2ChunkFoldKernel,
            )?,
        })
    }
}

#[derive(Serialize)]
struct C2ChunkFoldStepInput {
    base_vk: Vec<String>,
    base_proof: Vec<String>,
    base_public_inputs: Vec<String>,
    chunk_vk: Vec<String>,
    chunk_proof: Vec<String>,
    chunk_public_inputs: [String; 2],
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    base_key_hash: String,
    chunk_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    is_last_step: bool,
    chunk_idx: u32,
}

#[derive(Serialize)]
struct C2ChunkFinalizeInput {
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    acc_key_hash: String,
    variant: bool,
}

fn base_circuit_for(proof: &Proof) -> Result<CircuitName, ZkError> {
    match proof.circuit {
        CircuitName::SkShareComputationBase | CircuitName::ESmShareComputationBase => {
            Ok(proof.circuit)
        }
        other => Err(ZkError::InvalidInput(format!(
            "expected a C2 base proof, got {other}"
        ))),
    }
}

fn parse_fields(
    proof: &Proof,
    expected: CircuitName,
    context: &str,
) -> Result<Vec<String>, ZkError> {
    if proof.circuit != expected {
        return Err(ZkError::InvalidInput(format!(
            "{context}: expected {expected} proof, got {}",
            proof.circuit
        )));
    }
    bytes_to_field_strings(proof.public_signals.as_ref())
}

fn parse_chunk_fields(proof: &Proof) -> Result<[String; 2], ZkError> {
    let fields = parse_fields(proof, CircuitName::ShareComputationChunk, "C2 chunk proof")?;
    fields.try_into().map_err(|fields: Vec<String>| {
        ZkError::InvalidInput(format!(
            "C2 chunk proof has {} public fields, expected 2",
            fields.len()
        ))
    })
}

fn parse_accumulator_fields(
    proof: &Proof,
    expected_len: usize,
    context: &str,
) -> Result<Vec<String>, ZkError> {
    if proof.circuit != CircuitName::C2ChunkFold && proof.circuit != CircuitName::C2ChunkFoldKernel
    {
        return Err(ZkError::InvalidInput(format!(
            "{context}: expected C2 chunk fold proof, got {}",
            proof.circuit
        )));
    }
    let fields = bytes_to_field_strings(proof.public_signals.as_ref())?;
    if fields.len() != expected_len {
        return Err(ZkError::InvalidInput(format!(
            "{context} has {} public fields, expected {}",
            fields.len(),
            expected_len
        )));
    }
    Ok(fields)
}

fn validate_chunk_inputs(
    chunk_proofs: &[Proof],
    chunk_indices: &[u32],
    chunk_count: usize,
) -> Result<(), ZkError> {
    if chunk_count == 0 {
        return Err(ZkError::InvalidInput(
            "C2 chunk fold requires at least one chunk".into(),
        ));
    }
    if chunk_proofs.len() != chunk_count || chunk_indices.len() != chunk_count {
        return Err(ZkError::InvalidInput(format!(
            "C2 chunk fold requires exactly {chunk_count} proofs and indices, got {} and {}",
            chunk_proofs.len(),
            chunk_indices.len()
        )));
    }

    let mut seen = vec![false; chunk_count];
    for (proof, &idx) in chunk_proofs.iter().zip(chunk_indices) {
        if proof.circuit != CircuitName::ShareComputationChunk {
            return Err(ZkError::InvalidInput(format!(
                "C2 chunk fold expected ShareComputationChunk, got {}",
                proof.circuit
            )));
        }
        let index = idx as usize;
        if index >= chunk_count {
            return Err(ZkError::InvalidInput(format!(
                "C2 chunk index {idx} out of range for {chunk_count} chunks"
            )));
        }
        if seen[index] {
            return Err(ZkError::InvalidInput(format!(
                "C2 chunk index {idx} appears more than once"
            )));
        }
        seen[index] = true;
        let fields = parse_chunk_fields(proof)?;
        if fields[1] != u64_to_field_hex(idx as u64) {
            return Err(ZkError::InvalidInput(format!(
                "C2 chunk proof index does not match slot {idx}"
            )));
        }
    }
    Ok(())
}

fn generate_kernel_genesis_proof(
    prover: &ZkProver,
    base: &Proof,
    first_chunk: &Proof,
    base_public_inputs: &[String],
    chunk_public_inputs: [String; 2],
    chunk_idx: u32,
    is_last_step: bool,
    chunk_fold_public_len: usize,
    e3_id: &str,
    artifacts_dir: &str,
    vks: &C2ChunkFoldVks,
) -> Result<Proof, ZkError> {
    let acc_public_inputs = bytes_to_field_strings(&vec![0u8; chunk_fold_public_len * 32])?;
    let acc_proof = bytes_to_field_strings(&vec![0u8; ACC_NONZK_PROOF_FIELDS * 32])?;
    let full_input = C2ChunkFoldStepInput {
        base_vk: vks.base_vk.verification_key.clone(),
        base_proof: bytes_to_field_strings(&base.data)?,
        base_public_inputs: base_public_inputs.to_vec(),
        chunk_vk: vks.chunk_vk.verification_key.clone(),
        chunk_proof: bytes_to_field_strings(&first_chunk.data)?,
        chunk_public_inputs,
        acc_vk: vks.kernel_vk.verification_key.clone(),
        acc_proof,
        acc_public_inputs,
        base_key_hash: vks.base_vk.key_hash.clone(),
        chunk_key_hash: vks.chunk_vk.key_hash.clone(),
        acc_key_hash: vks.kernel_vk.key_hash.clone(),
        is_first_step: true,
        is_last_step,
        chunk_idx,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C2ChunkFoldKernel.dir_path())
        .join(format!("{}.json", CircuitName::C2ChunkFoldKernel.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C2ChunkFoldKernel,
        &witness,
        &format!("{e3_id}-c2chunk-kernel"),
        artifacts_dir,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_fold_step(
    prover: &ZkProver,
    base: &Proof,
    chunk: &Proof,
    prior_fold: Option<&Proof>,
    base_public_inputs: &[String],
    chunk_public_inputs: [String; 2],
    chunk_idx: u32,
    is_last_step: bool,
    chunk_fold_public_len: usize,
    e3_id: &str,
    artifacts_dir: &str,
    vks: &C2ChunkFoldVks,
) -> Result<Proof, ZkError> {
    let is_first_step = prior_fold.is_none();
    let (acc_vk, acc_proof, acc_public_inputs, acc_key_hash) = if is_first_step {
        let genesis = generate_kernel_genesis_proof(
            prover,
            base,
            chunk,
            base_public_inputs,
            chunk_public_inputs.clone(),
            chunk_idx,
            is_last_step,
            chunk_fold_public_len,
            e3_id,
            artifacts_dir,
            vks,
        )?;
        let public_inputs = parse_fields(
            &genesis,
            CircuitName::C2ChunkFoldKernel,
            "C2 chunk fold kernel proof",
        )?;
        if public_inputs.len() != chunk_fold_public_len {
            return Err(ZkError::InvalidInput(format!(
                "C2 chunk fold kernel has {} public fields, expected {}",
                public_inputs.len(),
                chunk_fold_public_len
            )));
        }
        (
            vks.kernel_vk.verification_key.clone(),
            bytes_to_field_strings(&genesis.data)?,
            public_inputs,
            vks.kernel_vk.key_hash.clone(),
        )
    } else {
        let prior = prior_fold.expect("prior fold exists when step is not first");
        let (acc_vk, acc_key_hash) = match prior.circuit {
            CircuitName::C2ChunkFold => (
                vks.fold_vk.verification_key.clone(),
                vks.fold_vk.key_hash.clone(),
            ),
            CircuitName::C2ChunkFoldKernel => (
                vks.kernel_vk.verification_key.clone(),
                vks.kernel_vk.key_hash.clone(),
            ),
            other => {
                return Err(ZkError::InvalidInput(format!(
                    "C2 chunk fold prior proof has circuit {other}"
                )))
            }
        };
        (
            acc_vk,
            bytes_to_field_strings(&prior.data)?,
            parse_accumulator_fields(prior, chunk_fold_public_len, "C2 chunk fold proof")?,
            acc_key_hash,
        )
    };

    let full_input = C2ChunkFoldStepInput {
        base_vk: vks.base_vk.verification_key.clone(),
        base_proof: bytes_to_field_strings(&base.data)?,
        base_public_inputs: base_public_inputs.to_vec(),
        chunk_vk: vks.chunk_vk.verification_key.clone(),
        chunk_proof: bytes_to_field_strings(&chunk.data)?,
        chunk_public_inputs,
        acc_vk,
        acc_proof,
        acc_public_inputs,
        base_key_hash: vks.base_vk.key_hash.clone(),
        chunk_key_hash: vks.chunk_vk.key_hash.clone(),
        acc_key_hash,
        is_first_step,
        is_last_step,
        chunk_idx,
    };
    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C2ChunkFold.dir_path())
        .join(format!("{}.json", CircuitName::C2ChunkFold.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C2ChunkFold,
        &witness,
        e3_id,
        artifacts_dir,
    )
}

/// Fold every C2 coefficient chunk into one accumulator proof.
pub fn generate_sequential_c2_chunk_fold(
    prover: &ZkProver,
    base_proof: &Proof,
    chunk_proofs: &[Proof],
    chunk_indices: &[u32],
    chunk_count: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let base_circuit = base_circuit_for(base_proof)?;
    validate_chunk_inputs(chunk_proofs, chunk_indices, chunk_count)?;

    let base_public_inputs = parse_fields(base_proof, base_circuit, "C2 base proof")?;
    let expected_base_len = base_public_inputs.len();
    if expected_base_len <= chunk_count {
        return Err(ZkError::InvalidInput(format!(
            "C2 base proof has {} public fields, too few for {chunk_count} chunks",
            expected_base_len
        )));
    }
    let c2_public_len = expected_base_len - chunk_count;
    let chunk_fold_state_len = c2_public_len + (2 * chunk_count);
    let chunk_fold_public_len = C2_CHUNK_FOLD_PUBLIC_PREFIX_LEN + chunk_fold_state_len;
    let vks = C2ChunkFoldVks::load(prover, base_circuit, artifacts_dir)?;
    let mut prior: Option<Proof> = None;

    for (step, (&idx, chunk)) in chunk_indices.iter().zip(chunk_proofs).enumerate() {
        let folded = generate_fold_step(
            prover,
            base_proof,
            chunk,
            prior.as_ref(),
            &base_public_inputs,
            parse_chunk_fields(chunk)?,
            idx,
            step + 1 == chunk_count,
            chunk_fold_public_len,
            e3_id,
            artifacts_dir,
            &vks,
        )?;
        prior = Some(folded);
    }

    Ok(prior.expect("chunk_count > 0 produces an accumulator proof"))
}

/// Project a complete chunk accumulator to the existing C2 public layout.
pub fn finalize_c2_chunk_fold(
    prover: &ZkProver,
    accumulator: &Proof,
    chunk_count: usize,
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
    if accumulator.circuit != CircuitName::C2ChunkFold
        && accumulator.circuit != CircuitName::C2ChunkFoldKernel
    {
        return Err(ZkError::InvalidInput(format!(
            "expected a C2 chunk accumulator, got {}",
            accumulator.circuit
        )));
    }
    if chunk_count == 0 {
        return Err(ZkError::InvalidInput(
            "C2 chunk finalizer requires at least one chunk".into(),
        ));
    }

    let acc_public_inputs = bytes_to_field_strings(accumulator.public_signals.as_ref())?;
    if acc_public_inputs.len() <= 2 * chunk_count {
        return Err(ZkError::InvalidInput(
            "C2 chunk accumulator layout is too short".into(),
        ));
    }
    let c2_public_len = acc_public_inputs
        .len()
        .checked_sub(C2_CHUNK_FOLD_PUBLIC_PREFIX_LEN + (2 * chunk_count))
        .ok_or_else(|| ZkError::InvalidInput("C2 chunk accumulator layout is too short".into()))?;
    if c2_public_len == 0 {
        return Err(ZkError::InvalidInput(
            "C2 chunk accumulator has no C2 public fields".into(),
        ));
    }

    let acc_vk = match accumulator.circuit {
        CircuitName::C2ChunkFold => CircuitName::C2ChunkFold,
        CircuitName::C2ChunkFoldKernel => CircuitName::C2ChunkFoldKernel,
        _ => unreachable!("circuit checked above"),
    };
    let acc_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        acc_vk,
    )?;
    let full_input = C2ChunkFinalizeInput {
        acc_vk: acc_vk.verification_key,
        acc_proof: bytes_to_field_strings(&accumulator.data)?,
        acc_public_inputs,
        acc_key_hash: acc_vk.key_hash,
        variant: finalizer_circuit != CircuitName::SkC2ChunkFinalize,
    };
    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(finalizer_circuit.dir_path())
        .join(format!("{}.json", finalizer_circuit.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    let proof = prover.generate_proof_with_variant(
        finalizer_circuit,
        &witness,
        &format!("{e3_id}-c2chunk-finalize"),
        CircuitVariant::Recursive,
        artifacts_dir,
    )?;
    let output_fields = bytes_to_field_strings(proof.public_signals.as_ref())?;
    if output_fields.len() != c2_public_len {
        return Err(ZkError::InvalidInput(format!(
            "C2 chunk finalizer has {} public fields, expected {}",
            output_fields.len(),
            c2_public_len
        )));
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_utils::utility_types::ArcBytes;

    fn chunk_proof(index: u8) -> Proof {
        let mut public_signals = vec![0u8; 64];
        public_signals[63] = index;
        Proof::new(
            CircuitName::ShareComputationChunk,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&public_signals),
        )
    }

    #[test]
    fn rejects_duplicate_chunk_indices() {
        let result = validate_chunk_inputs(&[chunk_proof(0), chunk_proof(0)], &[0, 0], 2);
        assert!(result.unwrap_err().to_string().contains("more than once"));
    }

    #[test]
    fn rejects_out_of_range_chunk_indices() {
        let result = validate_chunk_inputs(&[chunk_proof(1)], &[1], 1);
        assert!(result.unwrap_err().to_string().contains("out of range"));
    }

    #[test]
    fn rejects_chunk_index_mismatch() {
        let result = validate_chunk_inputs(&[chunk_proof(1)], &[0], 1);
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }
}
