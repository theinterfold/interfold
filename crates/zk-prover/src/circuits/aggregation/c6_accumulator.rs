// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C6 fold: each step verifies one inner `ThresholdShareDecryption` proof and the
//! accumulator (`c6_fold` non-ZK proof). The first step proves [`CircuitName::C6FoldKernel`] at
//! runtime to obtain a valid genesis `UltraHonkProof` (see `circuits/bin/recursive_aggregation/c6_fold_kernel`).

use crate::circuits::aggregation::helpers::{
    extract_single_field, field_keys, parse_acc_public_field_strings, sequential_fold,
    zero_field_hex_strings, ACC_NONZK_PROOF_FIELDS,
};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::{CircuitName, CircuitVariant, Proof};
use serde::Serialize;

/// `total_slots` = `T + 1` (one slot per party index in the C6 leaf layout).
fn c6_fold_public_input_field_count(total_slots: usize) -> usize {
    4 + 4 * total_slots
}

/// Public-signal layout of `c6_fold`: 4-field prefix, then 4-field-wide per-slot tail.
const C6_FOLD_PREFIX_LEN: usize = 4;
const C6_FOLD_SLOT_WIDTH: usize = 4;

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

fn generate_c6_fold_kernel_genesis_proof(
    prover: &ZkProver,
    inner: &Proof,
    slot_index: u32,
    total_slots: usize,
    artifacts_dir: &str,
    job_id: &str,
) -> Result<Proof, ZkError> {
    let inner_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::ThresholdShareDecryption,
    )?;
    let kernel_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C6FoldKernel,
    )?;
    let c6_public_inputs = threshold_share_decryption_inner_public_inputs(inner)?;
    let expected_acc_pub = c6_fold_public_input_field_count(total_slots);
    let acc_pi = zero_field_hex_strings(expected_acc_pub)?;
    let acc_pf = zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?;

    let full_input = C6FoldStepInput {
        inner_vk: inner_vk.verification_key,
        inner_proof: bytes_to_field_strings(&inner.data)?,
        c6_public_inputs,
        acc_vk: kernel_vk.verification_key,
        acc_proof: acc_pf,
        acc_public_inputs: acc_pi,
        inner_key_hash: inner_vk.key_hash,
        acc_key_hash: kernel_vk.key_hash,
        is_first_step: true,
        slot_index,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C6FoldKernel.dir_path())
        .join(format!("{}.json", CircuitName::C6FoldKernel.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&compiled, input_map)?;

    let proof = prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C6FoldKernel,
        &witness,
        job_id,
        artifacts_dir,
    )?;
    let _ = prover.cleanup(job_id);
    Ok(proof)
}

fn threshold_share_decryption_inner_public_inputs(proof: &Proof) -> Result<[String; 4], ZkError> {
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
        extract_single_field(proof, "output", field_keys::D_COMMITMENT, ctx)?,
    ])
}

#[derive(Serialize)]
struct C6FoldStepInput {
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    c6_public_inputs: [String; 4],
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    inner_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    slot_index: u32,
}

fn parse_c6_fold_public_field_strings(proof: &Proof) -> Result<Vec<String>, ZkError> {
    parse_acc_public_field_strings(
        proof,
        CircuitName::C6Fold,
        C6_FOLD_PREFIX_LEN,
        C6_FOLD_SLOT_WIDTH,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_c6_fold_step_with_vks(
    prover: &ZkProver,
    inner: &Proof,
    prior_fold: Option<&Proof>,
    slot_index: u32,
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
    vks: &C6FoldVks,
) -> Result<Proof, ZkError> {
    let is_first_step = prior_fold.is_none();

    let c6_public_inputs = threshold_share_decryption_inner_public_inputs(inner)?;
    let expected_acc_pub = c6_fold_public_input_field_count(total_slots);

    let (acc_vk_fields, acc_vk_hash, acc_proof, acc_public_inputs) = if is_first_step {
        let kernel_job_id = format!("{e3_id}-c6fold-kernel");
        let kernel_proof = generate_c6_fold_kernel_genesis_proof(
            prover,
            inner,
            slot_index,
            total_slots,
            artifacts_dir,
            &kernel_job_id,
        )?;
        let acc_pi = bytes_to_field_strings(kernel_proof.public_signals.as_ref())?;
        if acc_pi.len() != expected_acc_pub {
            return Err(ZkError::InvalidInput(format!(
                "c6_fold kernel proof public_inputs field count {} != expected {} (total_slots={})",
                acc_pi.len(),
                expected_acc_pub,
                total_slots
            )));
        }
        (
            vks.kernel_vk.verification_key.clone(),
            vks.kernel_vk.key_hash.clone(),
            bytes_to_field_strings(&kernel_proof.data)?,
            acc_pi,
        )
    } else {
        let p = prior_fold.expect("prior_fold required when is_first_step is false");
        let acc_pi = parse_c6_fold_public_field_strings(p)?;
        let prior_slots = (acc_pi.len() - 4) / 4;
        if prior_slots == 0 {
            return Err(ZkError::InvalidInput(
                "c6_fold proof implies zero slots".into(),
            ));
        }
        if prior_slots != total_slots {
            return Err(ZkError::InvalidInput(format!(
                "prior c6_fold slot count {} != expected {}",
                prior_slots, total_slots
            )));
        }
        if acc_pi.len() != expected_acc_pub {
            return Err(ZkError::InvalidInput(format!(
                "prior c6_fold public field count {} != expected {} for total_slots={}",
                acc_pi.len(),
                expected_acc_pub,
                total_slots
            )));
        }
        (
            vks.fold_vk.verification_key.clone(),
            vks.fold_vk.key_hash.clone(),
            bytes_to_field_strings(&p.data)?,
            acc_pi,
        )
    };

    let full_input = C6FoldStepInput {
        inner_vk: vks.inner_vk.verification_key.clone(),
        inner_proof: bytes_to_field_strings(&inner.data)?,
        c6_public_inputs,
        acc_vk: acc_vk_fields,
        acc_proof,
        acc_public_inputs,
        inner_key_hash: vks.inner_vk.key_hash.clone(),
        acc_key_hash: acc_vk_hash,
        is_first_step,
        slot_index,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C6Fold.dir_path())
        .join(format!("{}.json", CircuitName::C6Fold.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;

    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&compiled, input_map)?;

    prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C6Fold,
        &witness,
        e3_id,
        artifacts_dir,
    )
}

/// Folds `inner_proofs` in order, one inner C6 proof per step — the integration surface for
/// ciphernodes (batch in, single `C6Fold` proof out).
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
    if inner_proofs.len() != total_slots {
        return Err(ZkError::InvalidInput(format!(
            "generate_sequential_c6_fold: expected {total_slots} inner proofs, got {}",
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
    sequential_fold(
        "generate_sequential_c6_fold",
        inner_proofs,
        slot_indices,
        |inner, prior, slot| {
            generate_c6_fold_step_with_vks(
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
