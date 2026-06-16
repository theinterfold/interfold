// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C3 fold: each step verifies one inner `ShareEncryption` proof and the accumulator
//! (`c3_fold` non-ZK proof). The first step proves [`CircuitName::C3FoldKernel`] at runtime to obtain
//! a valid genesis `UltraHonkProof` (see `circuits/bin/recursive_aggregation/c3_fold_kernel`).
//!
//! Ciphernodes integrate via [`generate_sequential_c3_fold`] only: they supply the full list of C3
//! inner proofs and slot indices; per-step folding is not exposed outside this crate.

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

/// `total_slots` = N_PARTIES * L_THRESHOLD (one slot per party-modulus pair).
fn c3_fold_public_input_field_count(total_slots: usize) -> usize {
    4 + 3 * total_slots
}

/// Public-signal layout of `c3_fold`: 4-field prefix, then 3-field-wide per-slot tail.
const C3_FOLD_PREFIX_LEN: usize = 4;
const C3_FOLD_SLOT_WIDTH: usize = 3;

struct C3FoldVks {
    inner_vk: vk::VkArtifacts,
    fold_vk: vk::VkArtifacts,
    kernel_vk: vk::VkArtifacts,
}

impl C3FoldVks {
    fn load(prover: &ZkProver, artifacts_dir: &str) -> Result<Self, ZkError> {
        Ok(Self {
            inner_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                CircuitName::ShareEncryption,
            )?,
            fold_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C3Fold,
            )?,
            kernel_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C3FoldKernel,
            )?,
        })
    }
}

/// Proves [`CircuitName::C3FoldKernel`] for the same `inner` / `total_slots` as the fold step.
///
/// Uses work dir `job_id` (caller should use a suffix of the fold `e3_id` so jobs stay distinct).
/// Removes that work dir after the proof is returned.
fn generate_c3_fold_kernel_genesis_proof(
    prover: &ZkProver,
    inner: &Proof,
    total_slots: usize,
    artifacts_dir: &str,
    job_id: &str,
) -> Result<Proof, ZkError> {
    let inner_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::ShareEncryption,
    )?;
    let kernel_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C3FoldKernel,
    )?;
    let c3_public_inputs = share_encryption_inner_public_inputs(inner)?;
    let expected_acc_pub = c3_fold_public_input_field_count(total_slots);
    let acc_pi = zero_field_hex_strings(expected_acc_pub)?;
    let acc_pf = zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?;

    let full_input = C3FoldStepInput {
        inner_vk: inner_vk.verification_key,
        inner_proof: bytes_to_field_strings(&inner.data)?,
        c3_public_inputs,
        acc_vk: kernel_vk.verification_key,
        acc_proof: acc_pf,
        acc_public_inputs: acc_pi,
        inner_key_hash: inner_vk.key_hash,
        acc_key_hash: kernel_vk.key_hash,
        is_first_step: true,
        slot_index: 0,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C3FoldKernel.dir_path())
        .join(format!("{}.json", CircuitName::C3FoldKernel.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&compiled, input_map)?;

    let proof = prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C3FoldKernel,
        &witness,
        job_id,
        artifacts_dir,
    )?;
    Ok(proof)
}

/// Inner C3 public transcript: two inputs + `ct_commitment` output.
fn share_encryption_inner_public_inputs(proof: &Proof) -> Result<[String; 3], ZkError> {
    if proof.circuit != CircuitName::ShareEncryption {
        return Err(ZkError::InvalidInput(format!(
            "expected ShareEncryption inner proof, got {}",
            proof.circuit
        )));
    }
    let ctx = "C3 inner ShareEncryption proof";
    Ok([
        extract_single_field(proof, "input", field_keys::EXPECTED_PK_COMMITMENT, ctx)?,
        extract_single_field(proof, "input", field_keys::EXPECTED_MESSAGE_COMMITMENT, ctx)?,
        extract_single_field(proof, "output", field_keys::CT_COMMITMENT, ctx)?,
    ])
}

#[derive(Serialize)]
struct C3FoldStepInput {
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    c3_public_inputs: [String; 3],
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    inner_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    slot_index: u32,
}

fn parse_c3_fold_public_field_strings(proof: &Proof) -> Result<Vec<String>, ZkError> {
    parse_acc_public_field_strings(
        proof,
        CircuitName::C3Fold,
        C3_FOLD_PREFIX_LEN,
        C3_FOLD_SLOT_WIDTH,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_c3_fold_step_with_vks(
    prover: &ZkProver,
    inner: &Proof,
    prior_fold: Option<&Proof>,
    slot_index: u32,
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
    vks: &C3FoldVks,
) -> Result<Proof, ZkError> {
    let is_first_step = prior_fold.is_none();

    let c3_public_inputs = share_encryption_inner_public_inputs(inner)?;
    let expected_acc_pub = c3_fold_public_input_field_count(total_slots);

    let (acc_vk_fields, acc_vk_hash, acc_proof, acc_public_inputs) = if is_first_step {
        let kernel_job_id = format!("{e3_id}-c3fold-kernel");
        let kernel_proof = generate_c3_fold_kernel_genesis_proof(
            prover,
            inner,
            total_slots,
            artifacts_dir,
            &kernel_job_id,
        )?;
        let acc_pi = bytes_to_field_strings(kernel_proof.public_signals.as_ref())?;
        if acc_pi.len() != expected_acc_pub {
            return Err(ZkError::InvalidInput(format!(
                "c3_fold kernel proof public_inputs field count {} != expected {} (total_slots={})",
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
        let acc_pi = parse_c3_fold_public_field_strings(p)?;
        let prior_slots = (acc_pi.len() - 4) / 3;
        if prior_slots == 0 {
            return Err(ZkError::InvalidInput(
                "c3_fold proof implies zero slots".into(),
            ));
        }
        if prior_slots != total_slots {
            return Err(ZkError::InvalidInput(format!(
                "prior c3_fold slot count {} != expected {}",
                prior_slots, total_slots
            )));
        }
        if acc_pi.len() != expected_acc_pub {
            return Err(ZkError::InvalidInput(format!(
                "prior c3_fold public field count {} != expected {} for total_slots={}",
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

    let full_input = C3FoldStepInput {
        inner_vk: vks.inner_vk.verification_key.clone(),
        inner_proof: bytes_to_field_strings(&inner.data)?,
        c3_public_inputs,
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
        .join(CircuitName::C3Fold.dir_path())
        .join(format!("{}.json", CircuitName::C3Fold.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;

    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&compiled, input_map)?;

    prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C3Fold,
        &witness,
        e3_id,
        artifacts_dir,
    )
}

/// Folds `inner_proofs` in order, one inner C3 proof per step — the integration surface for
/// ciphernodes (batch in, single `C3Fold` proof out).
///
/// `slot_indices[i]` is the `(party * L_THRESHOLD + modulus)` slot for `inner_proofs[i]`.
/// `total_slots` must equal `N_PARTIES * L_THRESHOLD` and determines the accumulator size.
pub fn generate_sequential_c3_fold(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    // Defense in depth: every slot index must be in range and used at most once. C3 chains are
    // allowed to be partial (one C3 per (recipient, modulus) actually computed by this party),
    // unlike C6 which must cover all `T + 1` slots, so length equality is intentionally not
    // enforced here.
    if inner_proofs.len() != slot_indices.len() {
        return Err(ZkError::InvalidInput(format!(
            "generate_sequential_c3_fold: inner_proofs and slot_indices length mismatch ({} vs {})",
            inner_proofs.len(),
            slot_indices.len()
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "generate_sequential_c3_fold: slot index {s} out of range (total_slots={total_slots})"
            )));
        }
        if seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_sequential_c3_fold: duplicate slot index {s}"
            )));
        }
        seen[idx] = true;
    }
    let vks = C3FoldVks::load(prover, artifacts_dir)?;
    sequential_fold(
        "generate_sequential_c3_fold",
        inner_proofs,
        slot_indices,
        |inner, prior, slot| {
            generate_c3_fold_step_with_vks(
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
