// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C6 over Chonk (see `circuits/lib/src/math/chonk.nr`). A decryption's `T + 1` inner
//! `ThresholdShareDecryption` proofs go into one Chonk stack whose app verifies them all, a
//! [`CircuitName::C6ChonkTube`] rollup proof verifies the stack's Chonk proof, and
//! [`CircuitName::C6ChonkRoot`] closes the tube's IPA claim. The decryption aggregator verifies
//! the root proof.

use crate::circuits::aggregation::chonk_stack::{load_compiled, witness, ChonkStack};
use crate::circuits::aggregation::helpers::{extract_single_field, field_keys};
use crate::circuits::utils::bytes_to_field_strings;
use crate::circuits::vk::{self, VkArtifacts};
use crate::error::ZkError;
use crate::prover::ZkProver;
use e3_events::{CircuitName, CircuitVariant, Proof};
use serde::Serialize;

/// `c6_chonk_root` public layout: the chain key hash, the two domain limbs, then the sk, esm, ct
/// and d columns of `T + 1` slots each.
pub(crate) const C6_ROOT_DOMAIN_HI: usize = 1;
pub(crate) const C6_ROOT_COLUMNS: usize = 3;

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

/// The C6 Chonk circuits, loaded once and reused for every ciphertext.
pub(crate) struct C6ChonkCircuits {
    leaf: VkArtifacts,
    stack: ChonkStack,
    tube: VkArtifacts,
    pub(crate) root: VkArtifacts,
}

impl C6ChonkCircuits {
    pub(crate) fn load(prover: &ZkProver, artifacts_dir: &str) -> Result<Self, ZkError> {
        let default = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
        Ok(Self {
            leaf: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                CircuitName::ThresholdShareDecryption,
            )?,
            stack: ChonkStack::load(
                prover,
                artifacts_dir,
                [
                    CircuitName::C6ChonkApp,
                    CircuitName::C6ChonkInitKernel,
                    CircuitName::C6ChonkTailKernel,
                    CircuitName::C6ChonkHidingKernel,
                ],
            )?,
            tube: vk::load_vk_artifacts(&default, CircuitName::C6ChonkTube)?,
            root: vk::load_vk_artifacts(&default, CircuitName::C6ChonkRoot)?,
        })
    }
}

#[derive(Serialize)]
struct AppInput {
    leaf_vk: Vec<String>,
    leaf_key_hash: String,
    proofs: Vec<Vec<String>>,
    c6_public_inputs: Vec<[String; 6]>,
    slot_indices: Vec<u32>,
}

#[derive(Serialize)]
struct TubeInput {
    chonk_vk: Vec<String>,
    chonk_key_hash: String,
    proof: Vec<String>,
    stack_outputs: Vec<String>,
    own_key_hash: String,
}

/// The root closes exactly two IPA claims, so it takes the one tube twice.
#[derive(Serialize)]
struct RootInput {
    tube_vk: Vec<String>,
    tube_proofs: [Vec<String>; 2],
    tube_publics: [Vec<String>; 2],
}

/// Proves one decryption's C6 column: the stack over all `total_slots` (`T + 1`) inner proofs, its
/// tube and the root. Returns the [`CircuitName::C6ChonkRoot`] proof.
///
/// `slot_indices[i]` is the party slot index for `inner_proofs[i]`; every slot appears once.
pub(crate) fn generate_c6_chonk(
    prover: &ZkProver,
    circuits: &C6ChonkCircuits,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    // Defense in depth: the app requires every slot exactly once.
    let leaves = circuits.stack.app_leaves()?;
    if inner_proofs.len() != total_slots
        || slot_indices.len() != total_slots
        || total_slots != leaves
    {
        return Err(ZkError::InvalidInput(format!(
            "generate_c6_chonk: {} proofs and {} slots for {total_slots} slots; the app takes {leaves}",
            inner_proofs.len(),
            slot_indices.len()
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots || seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_c6_chonk: slot index {s} out of range or repeated (total_slots={total_slots})"
            )));
        }
        seen[idx] = true;
    }

    let zero = format!("0x{}", "0".repeat(64));
    let mut columns = vec![zero; 4 * total_slots];
    let mut proofs = Vec::with_capacity(total_slots);
    let mut c6_public_inputs = Vec::with_capacity(total_slots);
    for (proof, &slot) in inner_proofs.iter().zip(slot_indices) {
        let public = threshold_share_decryption_inner_public_inputs(proof)?;
        for (column, field) in [0, 1, 2, 5].into_iter().enumerate() {
            columns[column * total_slots + slot as usize] = public[field].clone();
        }
        proofs.push(bytes_to_field_strings(&proof.data)?);
        c6_public_inputs.push(public);
    }
    // The app's data: the first leaf's domain limbs, the four columns, then the leaf key hash.
    let mut outputs = vec![
        c6_public_inputs[0][3].clone(),
        c6_public_inputs[0][4].clone(),
    ];
    outputs.extend(columns);
    outputs.push(circuits.leaf.key_hash.clone());
    let (stack_outputs, chonk_proof) = circuits.stack.prove(
        prover,
        &AppInput {
            leaf_vk: circuits.leaf.verification_key.clone(),
            leaf_key_hash: circuits.leaf.key_hash.clone(),
            proofs,
            c6_public_inputs,
            slot_indices: slot_indices.to_vec(),
        },
        outputs,
        job_id,
    )?;

    let tube_witness = witness(
        &load_compiled(prover, CircuitName::C6ChonkTube, artifacts_dir)?,
        &TubeInput {
            chonk_vk: circuits.stack.chonk_key().verification_key.clone(),
            chonk_key_hash: circuits.stack.chonk_key().key_hash.clone(),
            proof: chonk_proof,
            stack_outputs,
            own_key_hash: circuits.tube.key_hash.clone(),
        },
    )?;
    let tube = prover.generate_rollup_proof(
        CircuitName::C6ChonkTube,
        &tube_witness,
        job_id,
        artifacts_dir,
    )?;

    let tube_proof = bytes_to_field_strings(&tube.data)?;
    let tube_public = bytes_to_field_strings(&tube.public_signals)?;
    let root_witness = witness(
        &load_compiled(prover, CircuitName::C6ChonkRoot, artifacts_dir)?,
        &RootInput {
            tube_vk: circuits.tube.verification_key.clone(),
            tube_proofs: [tube_proof.clone(), tube_proof],
            tube_publics: [tube_public.clone(), tube_public],
        },
    )?;
    let root = prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C6ChonkRoot,
        &root_witness,
        job_id,
        artifacts_dir,
    )?;
    let _ = prover.cleanup(job_id);
    Ok(root)
}

/// [`generate_c6_chonk`] that loads the circuits itself — for callers proving one column.
pub fn generate_c6_chonk_root(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let circuits = C6ChonkCircuits::load(prover, artifacts_dir)?;
    generate_c6_chonk(
        prover,
        &circuits,
        inner_proofs,
        slot_indices,
        total_slots,
        job_id,
        artifacts_dir,
    )
}

/// [`generate_c6_chonk_root`] with stack stage `stage` (0 app, 1 init kernel, 2 tail kernel)
/// claimed under stage `from`'s key. Negative tests only: the root must fail to prove or verify.
pub fn generate_c6_chonk_root_with_substituted_key(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    (stage, from): (usize, usize),
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let mut circuits = C6ChonkCircuits::load(prover, artifacts_dir)?;
    circuits.stack.substitute_key(stage, from);
    generate_c6_chonk(
        prover,
        &circuits,
        inner_proofs,
        slot_indices,
        total_slots,
        job_id,
        artifacts_dir,
    )
}
