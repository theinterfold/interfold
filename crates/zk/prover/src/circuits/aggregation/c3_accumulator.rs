// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C3 fold. The first [`C3_FOLD_LEAVES`] inner `ShareEncryption` proofs go into
//! [`CircuitName::C3FoldKernel`], whose proof carries their rows and starts the chain (see
//! `circuits/bin/recursive_aggregation/c3_fold_kernel`). Each later step verifies up to
//! [`C3_FOLD_LEAVES`] more inner proofs and the accumulator: the kernel proof on the first step, a
//! `c3_fold` proof after that. A step with fewer leaves fills its empty places with a repeat of its
//! first leaf under the sentinel slot `total_slots`, which the circuit verifies and does not write.
//!
//! Ciphernodes integrate via [`generate_sequential_c3_fold`] only: they supply the full list of C3
//! inner proofs and slot indices; per-step folding is not exposed outside this crate.

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

/// Inner C3 proofs each kernel or fold step verifies (`lib::math::c3_fold::C3_FOLD_LEAVES`).
pub const C3_FOLD_LEAVES: usize = 4;

/// Public-signal layout of `c3_fold`: three key hashes, `is_first_step`, one slot index per leaf,
/// then three columns of slots.
const C3_FOLD_PREFIX_LEN: usize = 4 + C3_FOLD_LEAVES;
const C3_FOLD_SLOT_WIDTH: usize = 3;

/// `total_slots` = N_PARTIES * L_THRESHOLD (one slot per party-modulus pair).
fn c3_fold_public_input_field_count(total_slots: usize) -> usize {
    C3_FOLD_PREFIX_LEN + C3_FOLD_SLOT_WIDTH * total_slots
}

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
    inner_proofs: Vec<Vec<String>>,
    c3_public_inputs: Vec<[String; 3]>,
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
/// [`C3_FOLD_LEAVES`] `(inner proof, slot)` pairs.
#[allow(clippy::too_many_arguments)]
fn prove_c3_fold_step(
    prover: &ZkProver,
    leaves: &[(&Proof, u32)],
    prior_fold: Option<&Proof>,
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
    vks: &C3FoldVks,
) -> Result<Proof, ZkError> {
    let Some((first, _)) = leaves.first() else {
        return Err(ZkError::InvalidInput("C3 fold step without leaves".into()));
    };
    let mut inner_proofs = Vec::with_capacity(C3_FOLD_LEAVES);
    let mut c3_public_inputs = Vec::with_capacity(C3_FOLD_LEAVES);
    let mut slot_indices = Vec::with_capacity(C3_FOLD_LEAVES);
    for k in 0..C3_FOLD_LEAVES {
        // An empty place repeats the step's first leaf under the sentinel slot, which the circuit
        // verifies and does not write.
        let (proof, slot) = leaves
            .get(k)
            .copied()
            .unwrap_or((*first, total_slots as u32));
        inner_proofs.push(bytes_to_field_strings(&proof.data)?);
        c3_public_inputs.push(share_encryption_inner_public_inputs(proof)?);
        slot_indices.push(slot);
    }

    let expected_acc_pub = c3_fold_public_input_field_count(total_slots);
    let (circuit, is_first_step, acc_vk, acc_proof, acc_public_inputs) = match prior_fold {
        None => (
            CircuitName::C3FoldKernel,
            true,
            vks.kernel_vk.verification_key.clone(),
            zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?,
            zero_field_hex_strings(expected_acc_pub)?,
        ),
        Some(prior) => {
            // A kernel predecessor marks the first fold step, which verifies with the kernel key.
            let is_first_step = prior.circuit == CircuitName::C3FoldKernel;
            let acc_pi = parse_acc_public_field_strings(
                prior,
                if is_first_step {
                    CircuitName::C3FoldKernel
                } else {
                    CircuitName::C3Fold
                },
                C3_FOLD_PREFIX_LEN,
                C3_FOLD_SLOT_WIDTH,
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
                CircuitName::C3Fold,
                is_first_step,
                acc_vk,
                bytes_to_field_strings(&prior.data)?,
                acc_pi,
            )
        }
    };

    let full_input = C3FoldStepInput {
        inner_vk: vks.inner_vk.verification_key.clone(),
        inner_proofs,
        c3_public_inputs,
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

/// Folds `inner_proofs` in order, [`C3_FOLD_LEAVES`] inner C3 proofs per step — the integration
/// surface for ciphernodes (batch in, single `C3Fold` proof out).
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
    // The kernel alone would end the chain on a kernel proof, which `c3ab_fold` does not accept.
    if inner_proofs.len() < 2 {
        return Err(ZkError::InvalidInput(format!(
            "generate_sequential_c3_fold: need at least two inner proofs, got {}",
            inner_proofs.len()
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
    let leaves: Vec<(&Proof, u32)> = inner_proofs
        .iter()
        .zip(slot_indices.iter().copied())
        .collect();
    // Whole steps of `C3_FOLD_LEAVES`; a chain that fits one step splits so a fold step follows
    // the kernel.
    let first = if leaves.len() <= C3_FOLD_LEAVES {
        1
    } else {
        C3_FOLD_LEAVES
    };
    let (kernel_leaves, rest) = leaves.split_at(first);
    let mut acc = prove_c3_fold_step(
        prover,
        kernel_leaves,
        None,
        total_slots,
        &format!("{e3_id}-c3fold-kernel"),
        artifacts_dir,
        &vks,
    )?;
    for (step, group) in rest.chunks(C3_FOLD_LEAVES).enumerate() {
        acc = prove_c3_fold_step(
            prover,
            group,
            Some(&acc),
            total_slots,
            &format!("{e3_id}-c3fold-{step}"),
            artifacts_dir,
            &vks,
        )?;
    }
    Ok(acc)
}
