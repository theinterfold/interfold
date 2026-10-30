// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential [`CircuitName::NodesFold`]. The first inner [`CircuitName::NodeFold`] proofs go into
//! [`CircuitName::NodesFoldKernel`], whose proof carries their rows and starts the chain (see
//! `circuits/bin/recursive_aggregation/nodes_fold_kernel`). Each later step verifies up to
//! [`NODES_FOLD_LEAVES`] more node proofs and the accumulator: the kernel proof on the first step, a
//! `nodes_fold` proof after that. [`nodes_fold_step_len`] fixes how many slots each step takes, so
//! the aggregator that streams the steps and [`generate_sequential_nodes_fold`] agree. A step with
//! fewer nodes fills its empty places with a repeat of its first node under the sentinel slot
//! `total_slots`, which the circuit verifies and does not write.

use crate::circuits::aggregation::helpers::{
    parse_acc_public_field_strings_flat, zero_field_hex_strings, ACC_NONZK_PROOF_FIELDS,
};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::Proof;
use e3_zk_config::{CircuitName, CircuitVariant};
use serde::Serialize;

/// Node proofs each kernel or fold step verifies (`lib::math::nodes_fold::NODES_FOLD_LEAVES`).
pub const NODES_FOLD_LEAVES: usize = 3;

/// Public-signal layout of `nodes_fold`: three key hashes, `is_first_step`, one slot index per
/// leaf, then complete node statements.
const NODES_FOLD_PREFIX_LEN: usize = 4 + NODES_FOLD_LEAVES;

/// Slots the step after `completed` slots takes, of `total` (at least two). Whole steps of
/// [`NODES_FOLD_LEAVES`]; a chain that fits one step splits so a fold step follows the kernel,
/// because the aggregator does not accept a kernel proof.
pub fn nodes_fold_step_len(completed: usize, total: usize) -> usize {
    if completed == 0 && total <= NODES_FOLD_LEAVES {
        1
    } else {
        NODES_FOLD_LEAVES.min(total.saturating_sub(completed))
    }
}

fn node_fold_statement(proof: &Proof) -> Result<Vec<String>, ZkError> {
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
    Ok(v)
}

fn nodes_fold_acc_public_len(node_fold_fields: usize, total_slots: usize) -> usize {
    NODES_FOLD_PREFIX_LEN + total_slots * node_fold_fields
}

#[derive(Serialize)]
struct NodesFoldStepInput {
    inner_vk: Vec<String>,
    inner_proofs: Vec<Vec<String>>,
    node_fold_public_inputs: Vec<Vec<String>>,
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    inner_key_hash: String,
    fold_key_hash: String,
    kernel_key_hash: String,
    is_first_step: bool,
    slot_indices: Vec<u32>,
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

/// Proves one kernel (`prior_fold` is `None`) or fold step over `leaves`, at most
/// [`NODES_FOLD_LEAVES`] `(node proof, slot)` pairs.
fn prove_nodes_fold_step(
    prover: &ZkProver,
    leaves: &[(&Proof, u32)],
    prior_fold: Option<&Proof>,
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
    vks: &NodesFoldVks,
) -> Result<Proof, ZkError> {
    let Some((first, _)) = leaves.first() else {
        return Err(ZkError::InvalidInput(
            "nodes_fold step without nodes".into(),
        ));
    };
    if leaves.len() > NODES_FOLD_LEAVES {
        return Err(ZkError::InvalidInput(format!(
            "nodes_fold step with {} nodes; at most {NODES_FOLD_LEAVES}",
            leaves.len()
        )));
    }
    // With one slot the chain would end on the kernel, which `DkgAggregator` does not accept.
    if total_slots < 2 {
        return Err(ZkError::InvalidInput(format!(
            "nodes_fold needs at least two slots, got {total_slots}"
        )));
    }
    let mut inner_proofs = Vec::with_capacity(NODES_FOLD_LEAVES);
    let mut node_fold_public_inputs = Vec::with_capacity(NODES_FOLD_LEAVES);
    let mut slot_indices = Vec::with_capacity(NODES_FOLD_LEAVES);
    for k in 0..NODES_FOLD_LEAVES {
        // An empty place repeats the step's first node under the sentinel slot, which the circuit
        // verifies and does not write.
        let (proof, slot) = leaves
            .get(k)
            .copied()
            .unwrap_or((*first, total_slots as u32));
        inner_proofs.push(bytes_to_field_strings(&proof.data)?);
        node_fold_public_inputs.push(node_fold_statement(proof)?);
        slot_indices.push(slot);
    }
    let statement_len = node_fold_public_inputs[0].len();
    if node_fold_public_inputs
        .iter()
        .any(|statement| statement.len() != statement_len)
    {
        return Err(ZkError::InvalidInput(
            "NodeFold statements differ in length".into(),
        ));
    }

    let expected_acc_pub = nodes_fold_acc_public_len(statement_len, total_slots);
    let (circuit, is_first_step, acc_vk, acc_proof, acc_public_inputs) = match prior_fold {
        None => (
            CircuitName::NodesFoldKernel,
            true,
            vks.kernel_vk.verification_key.clone(),
            zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?,
            zero_field_hex_strings(expected_acc_pub)?,
        ),
        Some(prior) => {
            // A kernel predecessor marks the first fold step, which verifies with the kernel key.
            let is_first_step = prior.circuit == CircuitName::NodesFoldKernel;
            // The per-slot width is the inner statement length, known only at runtime, so only
            // the prefix is parsed here and the total length is checked below.
            let acc_pi = parse_acc_public_field_strings_flat(
                prior,
                if is_first_step {
                    CircuitName::NodesFoldKernel
                } else {
                    CircuitName::NodesFold
                },
                NODES_FOLD_PREFIX_LEN,
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
            let acc_vk = if is_first_step {
                vks.kernel_vk.verification_key.clone()
            } else {
                vks.fold_vk.verification_key.clone()
            };
            (
                CircuitName::NodesFold,
                is_first_step,
                acc_vk,
                bytes_to_field_strings(&prior.data)?,
                acc_pi,
            )
        }
    };

    let full_input = NodesFoldStepInput {
        inner_vk: vks.inner_vk.verification_key.clone(),
        inner_proofs,
        node_fold_public_inputs,
        acc_vk,
        acc_proof,
        acc_public_inputs,
        inner_key_hash: vks.inner_vk.key_hash.clone(),
        fold_key_hash: vks.fold_vk.key_hash.clone(),
        kernel_key_hash: vks.kernel_vk.key_hash.clone(),
        is_first_step,
        slot_indices,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit.dir_path())
        .join(format!("{}.json", circuit.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let witness =
        WitnessGenerator::new().generate_witness(&compiled, inputs_json_to_input_map(&json)?)?;
    let proof = prover.generate_recursive_aggregation_bin_proof(
        circuit,
        &witness,
        job_id,
        artifacts_dir,
    )?;
    let _ = prover.cleanup(job_id);
    Ok(proof)
}

/// One streaming step over `inner_proofs` at `slot_indices` (at most [`NODES_FOLD_LEAVES`]) —
/// loads VKs from disk on each call (suitable for async dispatch).
pub fn generate_nodes_fold_step(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    prior_fold: Option<&Proof>,
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inner_proofs.len() != slot_indices.len() {
        return Err(ZkError::InvalidInput(format!(
            "nodes_fold step: {} proofs for {} slots",
            inner_proofs.len(),
            slot_indices.len()
        )));
    }
    let vks = NodesFoldVks::load(prover, artifacts_dir)?;
    let leaves: Vec<(&Proof, u32)> = inner_proofs
        .iter()
        .zip(slot_indices.iter().copied())
        .collect();
    prove_nodes_fold_step(
        prover,
        &leaves,
        prior_fold,
        total_slots,
        e3_id,
        artifacts_dir,
        &vks,
    )
}

/// Folds `inner_proofs` (one [`CircuitName::NodeFold`] per honest party) into a single
/// [`CircuitName::NodesFold`] proof for [`CircuitName::DkgAggregator`], in the steps
/// [`nodes_fold_step_len`] gives.
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
    if inner_proofs.len() != slot_indices.len() || inner_proofs.len() < 2 {
        return Err(ZkError::InvalidInput(format!(
            "generate_sequential_nodes_fold: need matching proofs and slots, at least two; got {} and {}",
            inner_proofs.len(),
            slot_indices.len()
        )));
    }
    let vks = NodesFoldVks::load(prover, artifacts_dir)?;
    let leaves: Vec<(&Proof, u32)> = inner_proofs
        .iter()
        .zip(slot_indices.iter().copied())
        .collect();
    let mut acc: Option<Proof> = None;
    let mut done = 0;
    while done < leaves.len() {
        let len = nodes_fold_step_len(done, leaves.len());
        acc = Some(prove_nodes_fold_step(
            prover,
            &leaves[done..done + len],
            acc.as_ref(),
            total_slots,
            &format!("{e3_id}-nodesfold-{done}"),
            artifacts_dir,
            &vks,
        )?);
        done += len;
    }
    Ok(acc.expect("at least two proofs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_cover_every_slot_and_never_end_on_the_kernel() {
        for total in 2..=40 {
            let mut done = 0;
            let mut steps = Vec::new();
            while done < total {
                let len = nodes_fold_step_len(done, total);
                assert!((1..=NODES_FOLD_LEAVES).contains(&len));
                steps.push(len);
                done += len;
            }
            assert_eq!(done, total);
            assert!(steps.len() >= 2, "total={total} ends on the kernel");
        }
        assert_eq!(nodes_fold_step_len(0, 28), 3);
        assert_eq!(nodes_fold_step_len(27, 28), 1);
        assert_eq!(nodes_fold_step_len(0, 3), 1);
        assert_eq!(nodes_fold_step_len(1, 3), 2);
    }
}
