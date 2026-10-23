// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential [`CircuitName::NodesFold`]. The first inner [`CircuitName::NodeFold`] proof goes into
//! [`CircuitName::NodesFoldKernel`], whose proof carries that node's row and starts the chain (see
//! `circuits/bin/recursive_aggregation/nodes_fold_kernel`). Each later step verifies one more node
//! proof and the accumulator: the kernel proof on the first step, a `nodes_fold` proof after that.

use crate::circuits::aggregation::helpers::{
    parse_acc_public_field_strings_flat, sequential_fold, zero_field_hex_strings,
    ACC_NONZK_PROOF_FIELDS,
};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::{CircuitName, CircuitVariant, Proof};
use serde::Serialize;

/// Public-signal layout of `nodes_fold`: five prefix fields, then complete node statements.
const NODES_FOLD_PREFIX_LEN: usize = 5;

fn node_fold_statement_field_count(proof: &Proof) -> Result<usize, ZkError> {
    if proof.circuit != CircuitName::NodeFold {
        return Err(ZkError::InvalidInput(format!(
            "expected NodeFold inner proof, got {}",
            proof.circuit
        )));
    }
    let v = bytes_to_field_strings(proof.public_signals.as_ref())?;
    if v.is_empty() {
        return Err(ZkError::InvalidInput(
            "NodeFold proof has empty public_signals".into(),
        ));
    }
    Ok(v.len())
}

fn nodes_fold_acc_public_len(node_fold_fields: usize, total_slots: usize) -> usize {
    NODES_FOLD_PREFIX_LEN + total_slots * node_fold_fields
}

#[derive(Serialize)]
struct NodesFoldStepInput {
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    node_fold_public_inputs: Vec<String>,
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    inner_key_hash: String,
    fold_key_hash: String,
    kernel_key_hash: String,
    is_first_step: bool,
    slot_index: u32,
}

struct NodesFoldVks {
    inner_vk: vk::VkArtifacts,
    fold_vk: vk::VkArtifacts,
    kernel_vk: vk::VkArtifacts,
}

impl NodesFoldVks {
    fn load(prover: &ZkProver, artifacts_dir: &str) -> Result<Self, ZkError> {
        Ok(Self {
            inner_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::NodeFold,
            )?,
            fold_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::NodesFold,
            )?,
            kernel_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::NodesFoldKernel,
            )?,
        })
    }
}

/// Proves [`CircuitName::NodesFoldKernel`] over the chain's first node proof, at its slot. The proof
/// carries that row and is the accumulator the first fold step verifies.
fn generate_nodes_fold_kernel_genesis_proof(
    prover: &ZkProver,
    inner: &Proof,
    total_slots: usize,
    slot_index: u32,
    artifacts_dir: &str,
    job_id: &str,
) -> Result<Proof, ZkError> {
    let inner_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::NodeFold,
    )?;
    let kernel_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::NodesFoldKernel,
    )?;
    let fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::NodesFold,
    )?;
    let nf_fields = node_fold_statement_field_count(inner)?;
    let node_fold_public_inputs = bytes_to_field_strings(inner.public_signals.as_ref())?;
    if node_fold_public_inputs.len() != nf_fields {
        return Err(ZkError::InvalidInput(
            "NodeFold public field length mismatch".into(),
        ));
    }
    let expected_acc_pub = nodes_fold_acc_public_len(nf_fields, total_slots);
    let acc_pi = zero_field_hex_strings(expected_acc_pub)?;
    let acc_pf = zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?;

    let full_input = NodesFoldStepInput {
        inner_vk: inner_vk.verification_key,
        inner_proof: bytes_to_field_strings(&inner.data)?,
        node_fold_public_inputs,
        acc_vk: kernel_vk.verification_key,
        acc_proof: acc_pf,
        acc_public_inputs: acc_pi,
        inner_key_hash: inner_vk.key_hash,
        fold_key_hash: fold_vk.key_hash,
        kernel_key_hash: kernel_vk.key_hash,
        is_first_step: true,
        slot_index,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::NodesFoldKernel.dir_path())
        .join(format!("{}.json", CircuitName::NodesFoldKernel.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&compiled, input_map)?;

    let proof = prover.generate_recursive_aggregation_bin_proof(
        CircuitName::NodesFoldKernel,
        &witness,
        job_id,
        artifacts_dir,
    )?;
    let _ = prover.cleanup(job_id);
    Ok(proof)
}

fn parse_nodes_fold_public_field_strings(
    proof: &Proof,
    circuit: CircuitName,
) -> Result<Vec<String>, ZkError> {
    // `nodes_fold` per-slot width is the inner `node_fold` statement length, which is only known at
    // runtime; use the prefix-only parser and let the caller verify the total length against
    // `nodes_fold_acc_public_len(node_fold_fields, total_slots)`.
    parse_acc_public_field_strings_flat(proof, circuit, NODES_FOLD_PREFIX_LEN)
}

#[allow(clippy::too_many_arguments)]
fn generate_nodes_fold_step_with_vks(
    prover: &ZkProver,
    inner: &Proof,
    prior_fold: Option<&Proof>,
    slot_index: u32,
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
    vks: &NodesFoldVks,
) -> Result<Proof, ZkError> {
    // The first node proof goes into the kernel on its own. The kernel proof already carries that
    // row, so it is the accumulator the next step verifies; folding the same proof again on top of
    // it would only repeat that verification.
    let Some(prior) = prior_fold else {
        // With one slot the chain would end on the kernel, which `DkgAggregator` does not accept.
        if total_slots < 2 {
            return Err(ZkError::InvalidInput(format!(
                "nodes_fold needs at least two slots, got {total_slots}"
            )));
        }
        let kernel_job_id = format!("{e3_id}-nodesfold-kernel");
        return generate_nodes_fold_kernel_genesis_proof(
            prover,
            inner,
            total_slots,
            slot_index,
            artifacts_dir,
            &kernel_job_id,
        );
    };
    // A kernel predecessor marks the first fold step, which the circuit verifies with the kernel key.
    let is_first_step = prior.circuit == CircuitName::NodesFoldKernel;

    let nf_fields = node_fold_statement_field_count(inner)?;
    let node_fold_public_inputs = bytes_to_field_strings(inner.public_signals.as_ref())?;
    if node_fold_public_inputs.len() != nf_fields {
        return Err(ZkError::InvalidInput(
            "NodeFold public field length mismatch".into(),
        ));
    }

    let expected_acc_pub = nodes_fold_acc_public_len(nf_fields, total_slots);

    let acc_pi = parse_nodes_fold_public_field_strings(
        prior,
        if is_first_step {
            CircuitName::NodesFoldKernel
        } else {
            CircuitName::NodesFold
        },
    )?;
    if acc_pi.len() != expected_acc_pub {
        return Err(ZkError::InvalidInput(format!(
            "prior {} public field count {} != expected {} (total_slots={})",
            prior.circuit,
            acc_pi.len(),
            expected_acc_pub,
            total_slots
        )));
    }
    let acc_vk_fields = if is_first_step {
        vks.kernel_vk.verification_key.clone()
    } else {
        vks.fold_vk.verification_key.clone()
    };
    let acc_proof = bytes_to_field_strings(&prior.data)?;
    let acc_public_inputs = acc_pi;

    let full_input = NodesFoldStepInput {
        inner_vk: vks.inner_vk.verification_key.clone(),
        inner_proof: bytes_to_field_strings(&inner.data)?,
        node_fold_public_inputs,
        acc_vk: acc_vk_fields,
        acc_proof,
        acc_public_inputs,
        inner_key_hash: vks.inner_vk.key_hash.clone(),
        fold_key_hash: vks.fold_vk.key_hash.clone(),
        kernel_key_hash: vks.kernel_vk.key_hash.clone(),
        is_first_step,
        slot_index,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::NodesFold.dir_path())
        .join(format!("{}.json", CircuitName::NodesFold.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;

    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&compiled, input_map)?;

    prover.generate_recursive_aggregation_bin_proof(
        CircuitName::NodesFold,
        &witness,
        e3_id,
        artifacts_dir,
    )
}

/// Single streaming step — loads VKs from disk on each call (suitable for async dispatch).
pub fn generate_nodes_fold_step(
    prover: &ZkProver,
    inner: &Proof,
    prior_fold: Option<&Proof>,
    slot_index: u32,
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let vks = NodesFoldVks::load(prover, artifacts_dir)?;
    generate_nodes_fold_step_with_vks(
        prover,
        inner,
        prior_fold,
        slot_index,
        total_slots,
        e3_id,
        artifacts_dir,
        &vks,
    )
}

/// Folds `inner_proofs` (one [`CircuitName::NodeFold`] per honest party) into a single
/// [`CircuitName::NodesFold`] proof for [`CircuitName::DkgAggregator`].
///
/// `slot_indices[i]` is the honest-slot index for `inner_proofs[i]` (must be `< total_slots`).
/// `total_slots` is `H` (honest committee size).
pub fn generate_sequential_nodes_fold(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let vks = NodesFoldVks::load(prover, artifacts_dir)?;
    sequential_fold(
        "generate_sequential_nodes_fold",
        inner_proofs,
        slot_indices,
        |inner, prior, slot| {
            generate_nodes_fold_step_with_vks(
                prover,
                inner,
                prior,
                slot,
                total_slots,
                e3_id,
                artifacts_dir,
                &vks,
            )
        },
    )
}
