// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C3 over Chonk (see `circuits/lib/src/math/chonk.nr`). The inner `ShareEncryption` proofs go
//! into stacks of `lib::math::chonk::C3_CHONK_LEAVES`; each stack is an app and three kernels proved as one Chonk
//! proof, which a [`CircuitName::C3ChonkTube`] rollup proof verifies. A chain of
//! [`CircuitName::C3ChonkAccumulate`] proofs merges the tubes in order, and `c3ab_fold` closes
//! the last accumulator's IPA claim. A chain always has at least two stacks, so it ends on an
//! accumulator.
//!
//! A stack with fewer leaves fills its empty places with a repeat of its first leaf under the
//! sentinel slot `total_slots`, which the app verifies and does not write.

use crate::chonk::{prove_stack, ChonkStackCircuit};
use crate::circuits::aggregation::helpers::extract_single_field;
use crate::circuits::aggregation::helpers::field_keys;
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk::{self, VkArtifacts};
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::{CircuitName, CircuitVariant, Proof};
use noirc_abi::AbiType;
use serde::Serialize;
use std::fs;

/// Key hashes a tube or accumulate proof exposes before its rows
/// (`lib::math::chonk::C3_CHONK_KEYS`).
const C3_CHONK_KEYS: usize = 7;

/// Fields of a Chonk proof after its public inputs (`lib::math::chonk::CHONK_PROOF_LENGTH`).
const CHONK_PROOF_LENGTH: usize = 1270;

/// The stack circuits in accumulation order.
const STACK: [CircuitName; 4] = [
    CircuitName::C3ChonkApp,
    CircuitName::C3ChonkInitKernel,
    CircuitName::C3ChonkTailKernel,
    CircuitName::C3ChonkHidingKernel,
];

struct StackCircuit {
    compiled: CompiledCircuit,
    key: Vec<u8>,
    vk: VkArtifacts,
}

struct C3ChonkCircuits {
    /// Inner C3 proofs one app verifies, read from its ABI so the Rust side never disagrees with
    /// the compiled `C3_CHONK_LEAVES`.
    leaves_per_stack: usize,
    leaf: VkArtifacts,
    stack: Vec<StackCircuit>,
    tube: VkArtifacts,
    accumulate: VkArtifacts,
}

impl C3ChonkCircuits {
    fn load(prover: &ZkProver, artifacts_dir: &str) -> Result<Self, ZkError> {
        let default = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
        let stack: Vec<StackCircuit> = STACK
            .iter()
            .map(|&circuit| {
                let dir = default.join(circuit.dir_path());
                let key_path = dir.join(format!("{}.vk", circuit.as_str()));
                Ok(StackCircuit {
                    compiled: CompiledCircuit::from_file(
                        &dir.join(format!("{}.json", circuit.as_str())),
                    )?,
                    key: fs::read(&key_path).map_err(|e| {
                        ZkError::CircuitNotFound(format!("{}: {e}", key_path.display()))
                    })?,
                    vk: vk::load_vk_artifacts(&default, circuit)?,
                })
            })
            .collect::<Result<_, ZkError>>()?;
        let leaves_per_stack = app_leaves(&stack)?;
        Ok(Self {
            leaves_per_stack,
            leaf: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                CircuitName::ShareEncryption,
            )?,
            stack,
            tube: vk::load_vk_artifacts(&default, CircuitName::C3ChonkTube)?,
            accumulate: vk::load_vk_artifacts(&default, CircuitName::C3ChonkAccumulate)?,
        })
    }
}

/// The length of the app's `slot_indices` parameter.
fn app_leaves(stack: &[StackCircuit]) -> Result<usize, ZkError> {
    stack[0]
        .compiled
        .abi
        .parameters
        .iter()
        .find(|parameter| parameter.name == "slot_indices")
        .and_then(|parameter| match &parameter.typ {
            AbiType::Array { length, .. } => Some(*length as usize),
            _ => None,
        })
        .filter(|&length| length > 0)
        .ok_or_else(|| ZkError::InvalidInput("c3_chonk_app has no slot_indices array".into()))
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
struct AppInput {
    leaf_vk: Vec<String>,
    leaf_key_hash: String,
    proofs: Vec<Vec<String>>,
    c3_public_inputs: Vec<[String; 3]>,
    slot_indices: Vec<u32>,
}

#[derive(Serialize)]
struct MegaKey {
    key: Vec<String>,
    hash: String,
}

#[derive(Serialize)]
struct InitKernelInput {
    app_outputs: Vec<String>,
    app_vk: MegaKey,
}

#[derive(Serialize)]
struct KernelInput {
    prev_outputs: Vec<String>,
    kernel_vk: MegaKey,
}

#[derive(Serialize)]
struct TubeInput {
    chonk_vk: Vec<String>,
    chonk_key_hash: String,
    proof: Vec<String>,
    stack_outputs: Vec<String>,
    own_key_hash: String,
}

#[derive(Serialize)]
struct AccumulateInput {
    left_vk: Vec<String>,
    left_proof: Vec<String>,
    left_public: Vec<String>,
    right_vk: Vec<String>,
    right_proof: Vec<String>,
    right_public: Vec<String>,
    own_key_hash: String,
}

fn witness<T: Serialize>(compiled: &CompiledCircuit, input: &T) -> Result<Vec<u8>, ZkError> {
    let json =
        serde_json::to_value(input).map_err(|e| ZkError::SerializationError(e.to_string()))?;
    WitnessGenerator::new().generate_witness(compiled, inputs_json_to_input_map(&json)?)
}

fn mega_key(circuit: &StackCircuit) -> MegaKey {
    MegaKey {
        key: circuit.vk.verification_key.clone(),
        hash: circuit.vk.key_hash.clone(),
    }
}

/// Proves one stack over `leaves`, at most `leaves_per_stack` `(inner proof, slot)` pairs, and
/// its tube. Returns the tube proof.
fn prove_stack_and_tube(
    prover: &ZkProver,
    leaves: &[(&Proof, u32)],
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
    circuits: &C3ChonkCircuits,
) -> Result<Proof, ZkError> {
    let Some((first, _)) = leaves.first() else {
        return Err(ZkError::InvalidInput(
            "C3 Chonk stack without leaves".into(),
        ));
    };
    let zero = format!("0x{}", "0".repeat(64));
    let mut rows = vec![zero; 3 * total_slots];
    let per_stack = circuits.leaves_per_stack;
    let mut proofs = Vec::with_capacity(per_stack);
    let mut c3_public_inputs = Vec::with_capacity(per_stack);
    let mut slot_indices = Vec::with_capacity(per_stack);
    for k in 0..per_stack {
        // An empty place repeats the stack's first leaf under the sentinel slot, which the app
        // verifies and does not write.
        let (proof, slot) = leaves
            .get(k)
            .copied()
            .unwrap_or((*first, total_slots as u32));
        let public = share_encryption_inner_public_inputs(proof)?;
        if (slot as usize) < total_slots {
            for (column, value) in public.iter().enumerate() {
                rows[column * total_slots + slot as usize] = value.clone();
            }
        }
        proofs.push(bytes_to_field_strings(&proof.data)?);
        c3_public_inputs.push(public);
        slot_indices.push(slot);
    }

    // Each stage passes on the data before it plus the hash of the key it verified.
    let [app, init, tail, hiding] = &circuits.stack[..] else {
        unreachable!("four stack circuits");
    };
    let mut outputs = rows;
    outputs.push(circuits.leaf.key_hash.clone());
    let app_witness = witness(
        &app.compiled,
        &AppInput {
            leaf_vk: circuits.leaf.verification_key.clone(),
            leaf_key_hash: circuits.leaf.key_hash.clone(),
            proofs,
            c3_public_inputs,
            slot_indices,
        },
    )?;
    let init_witness = witness(
        &init.compiled,
        &InitKernelInput {
            app_outputs: outputs.clone(),
            app_vk: mega_key(app),
        },
    )?;
    outputs.push(app.vk.key_hash.clone());
    let tail_witness = witness(
        &tail.compiled,
        &KernelInput {
            prev_outputs: outputs.clone(),
            kernel_vk: mega_key(init),
        },
    )?;
    outputs.push(init.vk.key_hash.clone());
    let hiding_witness = witness(
        &hiding.compiled,
        &KernelInput {
            prev_outputs: outputs.clone(),
            kernel_vk: mega_key(tail),
        },
    )?;
    outputs.push(tail.vk.key_hash.clone());

    let witnesses = [app_witness, init_witness, tail_witness, hiding_witness];
    let stack: Vec<_> = STACK
        .iter()
        .zip(&circuits.stack)
        .zip(&witnesses)
        .map(|((&circuit, stage), witness)| ChonkStackCircuit {
            circuit,
            compiled: &stage.compiled,
            verification_key: &stage.key,
            witness,
        })
        .collect();
    let chonk = bytes_to_field_strings(&prove_stack(
        prover.bb_binary(),
        &stack,
        job_id,
        prover.bb_timeout(),
    )?)?;
    if chonk.len() != outputs.len() + CHONK_PROOF_LENGTH {
        return Err(ZkError::ProveFailed(format!(
            "Chonk proof has {} fields; expected {} public and {CHONK_PROOF_LENGTH} proof fields",
            chonk.len(),
            outputs.len()
        )));
    }
    let (public, proof) = chonk.split_at(outputs.len());
    if public != outputs.as_slice() {
        return Err(ZkError::ProveFailed(
            "Chonk proof public inputs differ from the stack outputs".into(),
        ));
    }

    let tube_circuit = CircuitName::C3ChonkTube;
    let tube_witness = witness(
        &load_compiled(prover, tube_circuit, artifacts_dir)?,
        &TubeInput {
            chonk_vk: hiding.vk.verification_key.clone(),
            chonk_key_hash: hiding.vk.key_hash.clone(),
            proof: proof.to_vec(),
            stack_outputs: outputs,
            own_key_hash: circuits.tube.key_hash.clone(),
        },
    )?;
    let tube = prover.generate_rollup_proof(tube_circuit, &tube_witness, job_id, artifacts_dir)?;
    let _ = prover.cleanup(job_id);
    Ok(tube)
}

fn load_compiled(
    prover: &ZkProver,
    circuit: CircuitName,
    artifacts_dir: &str,
) -> Result<CompiledCircuit, ZkError> {
    CompiledCircuit::from_file(
        &prover
            .circuits_dir(CircuitVariant::Default, artifacts_dir)
            .join(circuit.dir_path())
            .join(format!("{}.json", circuit.as_str())),
    )
}

/// Merges `left` (a tube or accumulator) with the tube `right`.
fn prove_accumulate(
    prover: &ZkProver,
    left: &Proof,
    right: &Proof,
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
    circuits: &C3ChonkCircuits,
) -> Result<Proof, ZkError> {
    let expected = C3_CHONK_KEYS + 3 * total_slots;
    let public = |proof: &Proof| -> Result<Vec<String>, ZkError> {
        let fields = bytes_to_field_strings(&proof.public_signals)?;
        if fields.len() != expected {
            return Err(ZkError::InvalidInput(format!(
                "{} has {} public fields; expected {expected} for total_slots={total_slots}",
                proof.circuit,
                fields.len()
            )));
        }
        Ok(fields)
    };
    let left_vk = match left.circuit {
        CircuitName::C3ChonkTube => &circuits.tube,
        CircuitName::C3ChonkAccumulate => &circuits.accumulate,
        other => {
            return Err(ZkError::InvalidInput(format!(
                "C3 Chonk accumulate: left child {other} is neither a tube nor an accumulator"
            )))
        }
    };
    if right.circuit != CircuitName::C3ChonkTube {
        return Err(ZkError::InvalidInput(format!(
            "C3 Chonk accumulate: right child {} is not a tube",
            right.circuit
        )));
    }
    let circuit = CircuitName::C3ChonkAccumulate;
    let input = AccumulateInput {
        left_vk: left_vk.verification_key.clone(),
        left_proof: bytes_to_field_strings(&left.data)?,
        left_public: public(left)?,
        right_vk: circuits.tube.verification_key.clone(),
        right_proof: bytes_to_field_strings(&right.data)?,
        right_public: public(right)?,
        own_key_hash: circuits.accumulate.key_hash.clone(),
    };
    let witness = witness(&load_compiled(prover, circuit, artifacts_dir)?, &input)?;
    let proof = prover.generate_rollup_proof(circuit, &witness, job_id, artifacts_dir)?;
    let _ = prover.cleanup(job_id);
    Ok(proof)
}

/// Accumulates `inner_proofs` in order into one [`CircuitName::C3ChonkAccumulate`] proof — the
/// integration surface for ciphernodes.
///
/// `slot_indices[i]` is the `(party * L_THRESHOLD + modulus)` slot for `inner_proofs[i]`.
/// `total_slots` must equal `N_PARTIES * L_THRESHOLD` and determines the row count.
pub fn generate_c3_chonk_chain(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    // C3 chains may be partial (one C3 per (recipient, modulus) this party computed), so only
    // range and uniqueness are checked; the circuits enforce both again.
    if inner_proofs.len() != slot_indices.len() {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_chonk_chain: inner_proofs and slot_indices length mismatch ({} vs {})",
            inner_proofs.len(),
            slot_indices.len()
        )));
    }
    // Two stacks, each with a real leaf, make the chain end on an accumulator.
    if inner_proofs.len() < 2 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_chonk_chain: need at least two inner proofs, got {}",
            inner_proofs.len()
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "generate_c3_chonk_chain: slot index {s} out of range (total_slots={total_slots})"
            )));
        }
        if seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_c3_chonk_chain: duplicate slot index {s}"
            )));
        }
        seen[idx] = true;
    }
    let circuits = C3ChonkCircuits::load(prover, artifacts_dir)?;
    let leaves: Vec<(&Proof, u32)> = inner_proofs
        .iter()
        .zip(slot_indices.iter().copied())
        .collect();
    // The fewest stacks that hold every leaf, at least two, sized as evenly as possible.
    let stacks = leaves.len().div_ceil(circuits.leaves_per_stack).max(2);
    let size = leaves.len().div_ceil(stacks);
    let mut tubes = leaves.chunks(size).enumerate().map(|(i, group)| {
        prove_stack_and_tube(
            prover,
            group,
            total_slots,
            &format!("{e3_id}-c3chonk-stack-{i}"),
            artifacts_dir,
            &circuits,
        )
    });
    let mut acc = tubes.next().expect("at least two stacks")?;
    for (step, tube) in tubes.enumerate() {
        acc = prove_accumulate(
            prover,
            &acc,
            &tube?,
            total_slots,
            &format!("{e3_id}-c3chonk-acc-{step}"),
            artifacts_dir,
            &circuits,
        )?;
    }
    Ok(acc)
}
