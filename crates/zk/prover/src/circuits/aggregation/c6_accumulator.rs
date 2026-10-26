// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C6 fold. The first [`C6_FOLD_LEAVES`] inner `ThresholdShareDecryption` proofs go
//! into [`CircuitName::C6FoldKernel`], whose proof carries their rows and starts the chain (see
//! `circuits/bin/recursive_aggregation/c6_fold_kernel`). Each later step verifies up to
//! [`C6_FOLD_LEAVES`] more inner proofs and the accumulator: the kernel proof on the first step, a
//! `c6_fold` proof after that. A step with fewer leaves fills its empty places with a repeat of its
//! first leaf under the sentinel slot `total_slots`, which the circuit verifies and does not write.

use crate::circuits::aggregation::helpers::{
    extract_single_field, field_keys, parse_acc_public_field_strings, zero_field_hex_strings,
    ACC_NONZK_PROOF_FIELDS,
};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::{CircuitName, CircuitVariant, Proof};
use serde::Serialize;

/// Inner C6 proofs each kernel or fold step verifies (`lib::math::c6_fold::C6_FOLD_LEAVES`).
pub const C6_FOLD_LEAVES: usize = 4;

/// Public-signal layout of `c6_fold`: three key hashes, `is_first_step`, one slot index per leaf,
/// the two common domain limbs, then four columns of slots.
const C6_FOLD_PREFIX_LEN: usize = 6 + C6_FOLD_LEAVES;
const C6_FOLD_SLOT_WIDTH: usize = 4;

/// `total_slots` = `T + 1` (one slot per party index in the C6 leaf layout).
fn c6_fold_public_input_field_count(total_slots: usize) -> usize {
    C6_FOLD_PREFIX_LEN + C6_FOLD_SLOT_WIDTH * total_slots
}

struct C6FoldVks {
    inner_vk: vk::VkArtifacts,
    fold_vk: vk::VkArtifacts,
    kernel_vk: vk::VkArtifacts,
}

impl C6FoldVks {
    fn load(prover: &ZkProver, artifacts_dir: &str) -> Result<Self, ZkError> {
        Ok(Self {
            inner_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                CircuitName::ThresholdShareDecryption,
            )?,
            fold_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C6Fold,
            )?,
            kernel_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C6FoldKernel,
            )?,
        })
    }
}

fn threshold_share_decryption_inner_public_inputs(proof: &Proof) -> Result<[String; 6], ZkError> {
    if proof.circuit != CircuitName::ThresholdShareDecryption {
        return Err(ZkError::InvalidInput(format!(
            "expected ThresholdShareDecryption inner proof, got {}",
            proof.circuit
        )));
    }
    let ctx = "C6 inner ThresholdShareDecryption proof";
    Ok([
        extract_single_field(proof, "input", field_keys::EXPECTED_SK_COMMITMENT, ctx)?,
        extract_single_field(proof, "input", field_keys::EXPECTED_E_SM_COMMITMENT, ctx)?,
        extract_single_field(proof, "input", field_keys::CT_COMMITMENT, ctx)?,
        extract_single_field(proof, "input", field_keys::DOMAIN_HI, ctx)?,
        extract_single_field(proof, "input", field_keys::DOMAIN_LO, ctx)?,
        extract_single_field(proof, "output", field_keys::D_COMMITMENT, ctx)?,
    ])
}

#[derive(Serialize)]
struct C6FoldStepInput {
    inner_vk: Vec<String>,
    inner_proofs: Vec<Vec<String>>,
    c6_public_inputs: Vec<[String; 6]>,
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    inner_key_hash: String,
    fold_key_hash: String,
    kernel_key_hash: String,
    is_first_step: bool,
    slot_indices: Vec<u32>,
}

/// Proves one kernel (`prior_fold` is `None`) or fold step over `leaves`, at most
/// [`C6_FOLD_LEAVES`] `(inner proof, slot)` pairs.
fn prove_c6_fold_step(
    prover: &ZkProver,
    leaves: &[(&Proof, u32)],
    prior_fold: Option<&Proof>,
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
    vks: &C6FoldVks,
) -> Result<Proof, ZkError> {
    let Some((first, _)) = leaves.first() else {
        return Err(ZkError::InvalidInput("C6 fold step without leaves".into()));
    };
    let mut inner_proofs = Vec::with_capacity(C6_FOLD_LEAVES);
    let mut c6_public_inputs = Vec::with_capacity(C6_FOLD_LEAVES);
    let mut slot_indices = Vec::with_capacity(C6_FOLD_LEAVES);
    for k in 0..C6_FOLD_LEAVES {
        // An empty place repeats the step's first leaf under the sentinel slot, which the circuit
        // verifies and does not write.
        let (proof, slot) = leaves
            .get(k)
            .copied()
            .unwrap_or((*first, total_slots as u32));
        inner_proofs.push(bytes_to_field_strings(&proof.data)?);
        c6_public_inputs.push(threshold_share_decryption_inner_public_inputs(proof)?);
        slot_indices.push(slot);
    }

    let expected_acc_pub = c6_fold_public_input_field_count(total_slots);
    let (circuit, is_first_step, acc_vk, acc_proof, acc_public_inputs) = match prior_fold {
        None => (
            CircuitName::C6FoldKernel,
            true,
            vks.kernel_vk.verification_key.clone(),
            zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?,
            zero_field_hex_strings(expected_acc_pub)?,
        ),
        Some(prior) => {
            // A kernel predecessor marks the first fold step, which verifies with the kernel key.
            let is_first_step = prior.circuit == CircuitName::C6FoldKernel;
            let acc_pi = parse_acc_public_field_strings(
                prior,
                if is_first_step {
                    CircuitName::C6FoldKernel
                } else {
                    CircuitName::C6Fold
                },
                C6_FOLD_PREFIX_LEN,
                C6_FOLD_SLOT_WIDTH,
            )?;
            if acc_pi.len() != expected_acc_pub {
                return Err(ZkError::InvalidInput(format!(
                    "prior {} has {} public fields; expected {} for total_slots={}",
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
                CircuitName::C6Fold,
                is_first_step,
                acc_vk,
                bytes_to_field_strings(&prior.data)?,
                acc_pi,
            )
        }
    };

    let full_input = C6FoldStepInput {
        inner_vk: vks.inner_vk.verification_key.clone(),
        inner_proofs,
        c6_public_inputs,
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

/// Folds `inner_proofs` in order, [`C6_FOLD_LEAVES`] inner C6 proofs per step — the integration
/// surface for ciphernodes (batch in, single `C6Fold` proof out).
///
/// `slot_indices[i]` is the party slot index for `inner_proofs[i]`.
/// `total_slots` must equal `T + 1` and determines the accumulator width.
pub fn generate_sequential_c6_fold(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    // Defense in depth: every C6 slot must be filled exactly once and indices must be in range.
    // Without this a partial fold or duplicate slot could reach the decryption aggregator.
    if inner_proofs.len() != total_slots || slot_indices.len() != total_slots {
        return Err(ZkError::InvalidInput(format!(
            "generate_sequential_c6_fold: expected {total_slots} inner proofs and slots, got {} and {}",
            inner_proofs.len(),
            slot_indices.len()
        )));
    }
    // The kernel alone would end the chain on a kernel proof, which the aggregator does not accept.
    if inner_proofs.len() < 2 {
        return Err(ZkError::InvalidInput(format!(
            "generate_sequential_c6_fold: need at least two inner proofs, got {}",
            inner_proofs.len()
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "generate_sequential_c6_fold: slot index {s} out of range (total_slots={total_slots})"
            )));
        }
        if seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_sequential_c6_fold: duplicate slot index {s}"
            )));
        }
        seen[idx] = true;
    }
    let vks = C6FoldVks::load(prover, artifacts_dir)?;
    let leaves: Vec<(&Proof, u32)> = inner_proofs
        .iter()
        .zip(slot_indices.iter().copied())
        .collect();
    // Whole steps of `C6_FOLD_LEAVES`; a chain that fits one step splits so a fold step follows
    // the kernel.
    let first = if leaves.len() <= C6_FOLD_LEAVES {
        1
    } else {
        C6_FOLD_LEAVES
    };
    let (kernel_leaves, rest) = leaves.split_at(first);
    let mut acc = prove_c6_fold_step(
        prover,
        kernel_leaves,
        None,
        total_slots,
        &format!("{e3_id}-c6fold-kernel"),
        artifacts_dir,
        &vks,
    )?;
    for (step, group) in rest.chunks(C6_FOLD_LEAVES).enumerate() {
        acc = prove_c6_fold_step(
            prover,
            group,
            Some(&acc),
            total_slots,
            &format!("{e3_id}-c6fold-{step}"),
            artifacts_dir,
            &vks,
        )?;
    }
    Ok(acc)
}
