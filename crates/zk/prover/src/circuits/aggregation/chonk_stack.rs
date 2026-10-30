// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A Chonk stack of an app and three kernels (`circuits/lib/src/math/chonk.nr`), shared by the C3
//! and C6 Chonk paths. Each kernel passes on the data before it and appends the hash of the key it
//! verified, so the stack's public outputs are the app's data, the leaf key hash, then the app,
//! init and tail key hashes.

use crate::chonk::{prove_stack, ChonkKind, ChonkStackCircuit};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk::{self, VkArtifacts};
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::{CircuitName, CircuitVariant};
use noirc_abi::AbiType;
use serde::Serialize;
use std::fs;

/// Fields of a Chonk proof after its public inputs (`lib::math::chonk::CHONK_PROOF_LENGTH`).
const CHONK_PROOF_LENGTH: usize = 1221;

pub(crate) struct StackCircuit {
    compiled: CompiledCircuit,
    key: Vec<u8>,
    pub(crate) vk: VkArtifacts,
}

/// The app, init, tail and hiding kernel of one Chonk stack, in accumulation order.
pub(crate) struct ChonkStack {
    circuits: [CircuitName; 4],
    stages: Vec<StackCircuit>,
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

pub(crate) fn witness<T: Serialize>(
    compiled: &CompiledCircuit,
    input: &T,
) -> Result<Vec<u8>, ZkError> {
    let json =
        serde_json::to_value(input).map_err(|e| ZkError::SerializationError(e.to_string()))?;
    WitnessGenerator::new().generate_witness(compiled, inputs_json_to_input_map(&json)?)
}

pub(crate) fn load_compiled(
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

impl ChonkStack {
    pub(crate) fn load(
        prover: &ZkProver,
        artifacts_dir: &str,
        circuits: [CircuitName; 4],
    ) -> Result<Self, ZkError> {
        let default = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
        let stages = circuits
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
        Ok(Self { circuits, stages })
    }

    /// The length of the app's `slot_indices` parameter: the leaves one stack verifies, read
    /// from the ABI so the Rust side never disagrees with the compiled circuit.
    pub(crate) fn app_leaves(&self) -> Result<usize, ZkError> {
        self.stages[0]
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
            .ok_or_else(|| {
                ZkError::InvalidInput(format!(
                    "{} has no slot_indices array",
                    self.circuits[0].as_str()
                ))
            })
    }

    /// Hands the kernel after `stage` the key of stage `from` in place of `stage`'s own, as a
    /// prover passing off one circuit's proof as another's would. Negative tests only.
    pub(crate) fn substitute_key(&mut self, stage: usize, from: usize) {
        self.stages[stage].vk = VkArtifacts {
            verification_key: self.stages[from].vk.verification_key.clone(),
            key_hash: self.stages[from].vk.key_hash.clone(),
        };
    }

    /// The hiding kernel's Chonk key, which a tube verifies the stack's proof against.
    pub(crate) fn chonk_key(&self) -> &VkArtifacts {
        &self.stages[3].vk
    }

    /// Proves the stack from the app's input and the data it returns (its data, then the leaf
    /// key hash). Returns the stack's public outputs and the Chonk proof without them.
    pub(crate) fn prove<T: Serialize>(
        &self,
        prover: &ZkProver,
        app_input: &T,
        app_outputs: Vec<String>,
        job_id: &str,
    ) -> Result<(Vec<String>, Vec<String>), ZkError> {
        let [app, init, tail, hiding] = &self.stages[..] else {
            unreachable!("four stack circuits");
        };
        let mega_key = |stage: &StackCircuit| MegaKey {
            key: stage.vk.verification_key.clone(),
            hash: stage.vk.key_hash.clone(),
        };
        let mut outputs = app_outputs;
        let app_witness = witness(&app.compiled, app_input)?;
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
        let kinds = [
            ChonkKind::App,
            ChonkKind::Kernel,
            ChonkKind::Kernel,
            ChonkKind::Hiding,
        ];
        let stack: Vec<_> = self
            .circuits
            .iter()
            .zip(&self.stages)
            .zip(&witnesses)
            .zip(kinds)
            .map(|(((&circuit, stage), witness), kind)| ChonkStackCircuit {
                circuit,
                kind,
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
        Ok((outputs, proof.to_vec()))
    }
}
