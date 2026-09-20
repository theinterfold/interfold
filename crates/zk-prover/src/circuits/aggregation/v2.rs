// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Witness builders for the secure-16384 recursive l-BFV aggregation family.

use crate::circuits::aggregation::helpers::{
    address_to_field_hex, u64_to_field_hex, zero_field_hex_strings, ACC_NONZK_PROOF_FIELDS,
};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use alloy::primitives::Address;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use serde::Serialize;
use std::collections::HashSet;

const LEGACY_VK_BINDING_LEN: usize = 16;
const V2_VK_BINDING_LEN: usize = 13;
const C1_PUBLIC_FIELDS: usize = 3;
const LBFV_PK_GENERATION_PUBLIC_FIELDS: usize = 7;
const RLK_GENERATION_PUBLIC_FIELDS: usize = 9;

fn generation_fold_public_fields(row_count: usize) -> usize {
    14 + (3 * row_count)
}

fn node_fold_public_fields(committee: CiphernodesCommitteeSize, row_count: usize) -> usize {
    let values = committee.values();
    14 + values.n + (2 * (values.n + values.h) * row_count)
}

fn node_fold_v2_public_fields(committee: CiphernodesCommitteeSize, row_count: usize) -> usize {
    4 + node_fold_public_fields(committee, row_count) + 3 + (3 * row_count)
}

fn nodes_fold_v2_public_fields(committee: CiphernodesCommitteeSize, row_count: usize) -> usize {
    6 + (committee.values().h * node_fold_v2_public_fields(committee, row_count))
}

fn lbfv_pk_aggregation_public_fields(committee_h: usize) -> usize {
    7 + committee_h
}

fn rlk_aggregation_public_fields(committee_h: usize) -> usize {
    8 + (2 * committee_h)
}

fn aggregation_fold_public_fields(committee_h: usize, row_count: usize) -> usize {
    12 + (3 * row_count * committee_h) + (3 * row_count)
}

fn c5_public_fields(committee_h: usize) -> usize {
    committee_h + 1
}

fn proof_fields(proof: &Proof) -> Result<Vec<String>, ZkError> {
    bytes_to_field_strings(proof.data.as_ref())
}

fn public_fields(proof: &Proof) -> Result<Vec<String>, ZkError> {
    bytes_to_field_strings(proof.public_signals.as_ref())
}

fn checked_public_fields(
    proof: &Proof,
    expected_circuit: CircuitName,
    expected_len: usize,
    label: &str,
) -> Result<Vec<String>, ZkError> {
    if proof.circuit != expected_circuit {
        return Err(ZkError::InvalidInput(format!(
            "{label} must be a {expected_circuit} proof, got {}",
            proof.circuit
        )));
    }
    let fields = public_fields(proof)?;
    if fields.len() != expected_len {
        return Err(ZkError::InvalidInput(format!(
            "{label} must contain {expected_len} public fields, got {}",
            fields.len()
        )));
    }
    Ok(fields)
}

fn one_field(bytes: &ArcBytes, label: &str) -> Result<String, ZkError> {
    let fields = bytes_to_field_strings(bytes.as_ref())?;
    if fields.len() != 1 {
        return Err(ZkError::InvalidInput(format!(
            "{label} must contain one field, got {}",
            fields.len()
        )));
    }
    Ok(fields.into_iter().next().expect("one field was verified"))
}

fn load_vk(
    prover: &ZkProver,
    variant: CircuitVariant,
    artifacts_dir: &str,
    circuit: CircuitName,
) -> Result<vk::VkArtifacts, ZkError> {
    vk::load_vk_artifacts(&prover.circuits_dir(variant, artifacts_dir), circuit)
}

fn prove_bin<W: Serialize>(
    prover: &ZkProver,
    circuit: CircuitName,
    input: &W,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let json = serde_json::to_value(input)
        .map_err(|error| ZkError::SerializationError(error.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit.dir_path())
        .join(format!("{}.json", circuit.as_str()));
    let compiled = CompiledCircuit::from_file(&path)?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(circuit, &witness, job_id, artifacts_dir)
}

#[derive(Serialize)]
struct GenerationFoldWitness {
    pk_vk: Vec<String>,
    pk_proof: Vec<String>,
    pk_public: Vec<String>,
    rlk_vk: Vec<String>,
    rlk_proof: Vec<String>,
    rlk_public: Vec<String>,
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public: Vec<String>,
    pk_key_hash: String,
    rlk_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    row_index: u32,
    expected_kernel_key_hash: String,
    expected_fold_key_hash: String,
    trusted_pk_limb_key_hash: String,
    trusted_rlk_limb_key_hash: String,
}

fn generation_fold_witness(
    prover: &ZkProver,
    pk_proof: &Proof,
    rlk_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    row_index: u32,
    trusted_pk_limb_key_hash: &str,
    trusted_rlk_limb_key_hash: &str,
    row_count: usize,
    artifacts_dir: &str,
) -> Result<(CircuitName, GenerationFoldWitness), ZkError> {
    let generation_fields = generation_fold_public_fields(row_count);
    if row_index >= row_count as u32 {
        return Err(ZkError::InvalidInput(format!(
            "generation fold row {row_index} is out of range"
        )));
    }
    let pk_public = checked_public_fields(
        pk_proof,
        CircuitName::LbfvPkGeneration,
        LBFV_PK_GENERATION_PUBLIC_FIELDS,
        "l-BFV PK generation proof",
    )?;
    let rlk_public = checked_public_fields(
        rlk_proof,
        CircuitName::RlkGeneration,
        RLK_GENERATION_PUBLIC_FIELDS,
        "RLK generation proof",
    )?;
    let pk_vk = load_vk(
        prover,
        CircuitVariant::Recursive,
        artifacts_dir,
        CircuitName::LbfvPkGeneration,
    )?;
    let rlk_vk = load_vk(
        prover,
        CircuitVariant::Recursive,
        artifacts_dir,
        CircuitName::RlkGeneration,
    )?;
    let kernel_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::LbfvGenerationFoldKernel,
    )?;
    let fold_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::LbfvGenerationFold,
    )?;

    let (circuit, acc_vk, acc_key_hash, acc_proof, acc_public, is_first_step) =
        if let Some(prior) = prior_accumulator {
            if row_index == 0 {
                return Err(ZkError::InvalidInput(
                    "row zero cannot have a prior generation accumulator".into(),
                ));
            }
            (
                CircuitName::LbfvGenerationFold,
                if row_index == 1 {
                    kernel_vk.clone()
                } else {
                    fold_vk.clone()
                },
                if row_index == 1 {
                    kernel_vk.key_hash.clone()
                } else {
                    fold_vk.key_hash.clone()
                },
                proof_fields(prior)?,
                checked_public_fields(
                    prior,
                    if row_index == 1 {
                        CircuitName::LbfvGenerationFoldKernel
                    } else {
                        CircuitName::LbfvGenerationFold
                    },
                    generation_fields,
                    "prior l-BFV generation accumulator",
                )?,
                false,
            )
        } else {
            if row_index != 0 {
                return Err(ZkError::InvalidInput(
                    "nonzero generation rows require a prior accumulator".into(),
                ));
            }
            (
                CircuitName::LbfvGenerationFoldKernel,
                kernel_vk.clone(),
                kernel_vk.key_hash.clone(),
                zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?,
                zero_field_hex_strings(generation_fields)?,
                true,
            )
        };

    Ok((
        circuit,
        GenerationFoldWitness {
            pk_vk: pk_vk.verification_key,
            pk_proof: proof_fields(pk_proof)?,
            pk_public,
            rlk_vk: rlk_vk.verification_key,
            rlk_proof: proof_fields(rlk_proof)?,
            rlk_public,
            acc_vk: acc_vk.verification_key,
            acc_proof,
            acc_public,
            pk_key_hash: pk_vk.key_hash,
            rlk_key_hash: rlk_vk.key_hash,
            acc_key_hash,
            is_first_step,
            row_index,
            expected_kernel_key_hash: kernel_vk.key_hash,
            expected_fold_key_hash: fold_vk.key_hash,
            trusted_pk_limb_key_hash: trusted_pk_limb_key_hash.to_owned(),
            trusted_rlk_limb_key_hash: trusted_rlk_limb_key_hash.to_owned(),
        },
    ))
}

/// Prove one row of the secure-16384 generation fold.
pub fn prove_lbfv_generation_fold_step(
    prover: &ZkProver,
    pk_proof: &Proof,
    rlk_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    row_index: u32,
    trusted_pk_limb_key_hash: &ArcBytes,
    trusted_rlk_limb_key_hash: &ArcBytes,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    prove_lbfv_generation_fold_step_for_preset(
        prover,
        pk_proof,
        rlk_proof,
        prior_accumulator,
        row_index,
        trusted_pk_limb_key_hash,
        trusted_rlk_limb_key_hash,
        BfvPreset::SecureThreshold16384,
        job_id,
        artifacts_dir,
    )
}

/// Prove one row of the l-BFV generation fold for a preset.
pub fn prove_lbfv_generation_fold_step_for_preset(
    prover: &ZkProver,
    pk_proof: &Proof,
    rlk_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    row_index: u32,
    trusted_pk_limb_key_hash: &ArcBytes,
    trusted_rlk_limb_key_hash: &ArcBytes,
    preset: BfvPreset,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let trusted_pk_limb_key_hash =
        one_field(trusted_pk_limb_key_hash, "trusted public-key limb VK hash")?;
    let trusted_rlk_limb_key_hash =
        one_field(trusted_rlk_limb_key_hash, "trusted RLK limb VK hash")?;
    let (circuit, witness) = generation_fold_witness(
        prover,
        pk_proof,
        rlk_proof,
        prior_accumulator,
        row_index,
        &trusted_pk_limb_key_hash,
        &trusted_rlk_limb_key_hash,
        e3_fhe_params::lbfv_row_count(preset).ok_or_else(|| {
            ZkError::InvalidInput("the selected preset does not support l-BFV".into())
        })?,
        artifacts_dir,
    )?;
    prove_bin(prover, circuit, &witness, job_id, artifacts_dir)
}

#[derive(Serialize)]
struct NodeFoldV2Witness {
    node_fold_vk: Vec<String>,
    node_fold_proof: Vec<String>,
    node_fold_public: Vec<String>,
    c1_vk: Vec<String>,
    c1_proof: Vec<String>,
    c1_public: Vec<String>,
    generation_vk: Vec<String>,
    generation_proof: Vec<String>,
    generation_public: Vec<String>,
    generation_key_hash: String,
    node_fold_key_hash: String,
    c1_key_hash: String,
    party_id: String,
}

fn prove_node_dkg_fold_v2_with_shape(
    prover: &ZkProver,
    legacy_node_fold_proof: &Proof,
    c1_proof: &Proof,
    generation_proof: &Proof,
    party_id: u64,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let row_count = e3_fhe_params::lbfv_row_count(preset).ok_or_else(|| {
        ZkError::InvalidInput("the selected preset does not support l-BFV".into())
    })?;
    let node_fields = node_fold_public_fields(committee, row_count);
    let generation_fields = generation_fold_public_fields(row_count);
    let node_fold_public = checked_public_fields(
        legacy_node_fold_proof,
        CircuitName::NodeFold,
        node_fields,
        "V2 legacy node fold",
    )?;
    let node_fold_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::NodeFold,
    )?;
    let c1_public = checked_public_fields(
        c1_proof,
        CircuitName::PkGeneration,
        C1_PUBLIC_FIELDS,
        "V2 legacy C1",
    )?;
    let c1_vk = load_vk(
        prover,
        CircuitVariant::Recursive,
        artifacts_dir,
        CircuitName::PkGeneration,
    )?;
    let generation_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::LbfvGenerationFold,
    )?;
    let generation_public = checked_public_fields(
        generation_proof,
        CircuitName::LbfvGenerationFold,
        generation_fields,
        "V2 generation fold",
    )?;

    let witness = NodeFoldV2Witness {
        node_fold_vk: node_fold_vk.verification_key,
        node_fold_proof: proof_fields(legacy_node_fold_proof)?,
        node_fold_public,
        c1_vk: c1_vk.verification_key,
        c1_proof: proof_fields(c1_proof)?,
        c1_public,
        generation_vk: generation_vk.verification_key,
        generation_proof: proof_fields(generation_proof)?,
        generation_public,
        generation_key_hash: generation_vk.key_hash.clone(),
        node_fold_key_hash: node_fold_vk.key_hash,
        c1_key_hash: c1_vk.key_hash,
        party_id: u64_to_field_hex(party_id),
    };
    prove_bin(
        prover,
        CircuitName::NodeFoldV2,
        &witness,
        job_id,
        artifacts_dir,
    )
}

/// Prove one secure-16384 per-node fold from the legacy folded DKG proofs.
pub fn prove_node_dkg_fold_v2(
    prover: &ZkProver,
    legacy_node_fold_proof: &Proof,
    c1_proof: &Proof,
    generation_proof: &Proof,
    party_id: u64,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    prove_node_dkg_fold_v2_with_shape(
        prover,
        legacy_node_fold_proof,
        c1_proof,
        generation_proof,
        party_id,
        BfvPreset::SecureThreshold16384,
        CiphernodesCommitteeSize::Minimum,
        job_id,
        artifacts_dir,
    )
}

/// Prove one per-node fold for an l-BFV preset and committee.
pub fn prove_node_dkg_fold_v2_for_preset(
    prover: &ZkProver,
    legacy_node_fold_proof: &Proof,
    c1_proof: &Proof,
    generation_proof: &Proof,
    party_id: u64,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    prove_node_dkg_fold_v2_with_shape(
        prover,
        legacy_node_fold_proof,
        c1_proof,
        generation_proof,
        party_id,
        preset,
        committee,
        job_id,
        artifacts_dir,
    )
}

#[derive(Serialize)]
struct NodesFoldV2Witness {
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    node_public: Vec<String>,
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public: Vec<String>,
    inner_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    slot_index: u32,
    expected_kernel_key_hash: String,
    expected_fold_key_hash: String,
}

fn prove_nodes_fold_v2_step_impl(
    prover: &ZkProver,
    inner_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    slot_index: u32,
    total_slots: usize,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let row_count = e3_fhe_params::lbfv_row_count(preset).ok_or_else(|| {
        ZkError::InvalidInput("the selected preset does not support l-BFV".into())
    })?;
    let expected_h = committee.values().h;
    if total_slots != expected_h {
        return Err(ZkError::InvalidInput(format!(
            "V2 node folding requires {} slots, got {total_slots}",
            expected_h
        )));
    }
    let node_v2_fields = node_fold_v2_public_fields(committee, row_count);
    let accumulator_fields = nodes_fold_v2_public_fields(committee, row_count);
    let node_fields = checked_public_fields(
        inner_proof,
        CircuitName::NodeFoldV2,
        node_v2_fields,
        "V2 node proof",
    )?;
    let inner_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::NodeFoldV2,
    )?;
    let kernel_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::NodesFoldV2Kernel,
    )?;
    let fold_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::NodesFoldV2,
    )?;
    let (circuit, acc_vk, acc_key_hash, acc_proof, acc_public, is_first_step) =
        if let Some(prior) = prior_accumulator {
            if slot_index == 0 || slot_index as usize >= total_slots {
                return Err(ZkError::InvalidInput(format!(
                    "invalid V2 node fold slot {slot_index}"
                )));
            }
            (
                CircuitName::NodesFoldV2,
                if slot_index == 1 {
                    kernel_vk.clone()
                } else {
                    fold_vk.clone()
                },
                if slot_index == 1 {
                    kernel_vk.key_hash.clone()
                } else {
                    fold_vk.key_hash.clone()
                },
                proof_fields(prior)?,
                checked_public_fields(
                    prior,
                    if slot_index == 1 {
                        CircuitName::NodesFoldV2Kernel
                    } else {
                        CircuitName::NodesFoldV2
                    },
                    accumulator_fields,
                    "prior V2 nodes accumulator",
                )?,
                false,
            )
        } else {
            if slot_index != 0 || total_slots == 0 {
                return Err(ZkError::InvalidInput(
                    "V2 node fold genesis must be slot zero".into(),
                ));
            }
            (
                CircuitName::NodesFoldV2Kernel,
                kernel_vk.clone(),
                kernel_vk.key_hash.clone(),
                zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?,
                zero_field_hex_strings(accumulator_fields)?,
                true,
            )
        };

    let witness = NodesFoldV2Witness {
        inner_vk: inner_vk.verification_key,
        inner_proof: proof_fields(inner_proof)?,
        node_public: node_fields,
        acc_vk: acc_vk.verification_key,
        acc_proof,
        acc_public,
        inner_key_hash: inner_vk.key_hash,
        acc_key_hash,
        is_first_step,
        slot_index,
        expected_kernel_key_hash: kernel_vk.key_hash,
        expected_fold_key_hash: fold_vk.key_hash,
    };
    prove_bin(prover, circuit, &witness, job_id, artifacts_dir)
}

/// Prove one secure-16384 cross-node accumulator step.
pub fn prove_nodes_fold_v2_step(
    prover: &ZkProver,
    inner_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    slot_index: u32,
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    prove_nodes_fold_v2_step_impl(
        prover,
        inner_proof,
        prior_accumulator,
        slot_index,
        total_slots,
        BfvPreset::SecureThreshold16384,
        CiphernodesCommitteeSize::Minimum,
        job_id,
        artifacts_dir,
    )
}

/// Prove one cross-node accumulator step for an l-BFV preset and committee.
pub fn prove_nodes_fold_v2_step_for_preset(
    prover: &ZkProver,
    inner_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    slot_index: u32,
    total_slots: usize,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    prove_nodes_fold_v2_step_impl(
        prover,
        inner_proof,
        prior_accumulator,
        slot_index,
        total_slots,
        preset,
        committee,
        job_id,
        artifacts_dir,
    )
}

#[derive(Serialize)]
struct AggregationFoldWitness {
    pk_vk: Vec<String>,
    pk_proof: Vec<String>,
    pk_public: Vec<String>,
    rlk_vk: Vec<String>,
    rlk_proof: Vec<String>,
    rlk_public: Vec<String>,
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public: Vec<String>,
    pk_key_hash: String,
    rlk_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    row_index: u32,
    expected_kernel_key_hash: String,
    expected_fold_key_hash: String,
}

fn aggregation_fold_witness(
    prover: &ZkProver,
    pk_proof: &Proof,
    rlk_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    row_index: u32,
    committee_h: usize,
    row_count: usize,
    artifacts_dir: &str,
) -> Result<(CircuitName, AggregationFoldWitness), ZkError> {
    let pk_fields = lbfv_pk_aggregation_public_fields(committee_h);
    let rlk_fields = rlk_aggregation_public_fields(committee_h);
    let aggregation_fields = aggregation_fold_public_fields(committee_h, row_count);
    if row_index >= row_count as u32 {
        return Err(ZkError::InvalidInput(format!(
            "aggregation fold row {row_index} is out of range"
        )));
    }
    let pk_public = checked_public_fields(
        pk_proof,
        CircuitName::LbfvPkAggregation,
        pk_fields,
        "l-BFV PK aggregation proof",
    )?;
    let rlk_public = checked_public_fields(
        rlk_proof,
        CircuitName::RlkAggregation,
        rlk_fields,
        "RLK aggregation proof",
    )?;
    let pk_vk = load_vk(
        prover,
        CircuitVariant::Recursive,
        artifacts_dir,
        CircuitName::LbfvPkAggregation,
    )?;
    let rlk_vk = load_vk(
        prover,
        CircuitVariant::Recursive,
        artifacts_dir,
        CircuitName::RlkAggregation,
    )?;
    let kernel_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::LbfvAggregationFoldKernel,
    )?;
    let fold_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::LbfvAggregationFold,
    )?;
    let accumulator_fields = aggregation_fields;

    let (circuit, acc_vk, acc_key_hash, acc_proof, acc_public, is_first_step) =
        if let Some(prior) = prior_accumulator {
            if row_index == 0 {
                return Err(ZkError::InvalidInput(
                    "row zero cannot have a prior aggregation accumulator".into(),
                ));
            }
            (
                CircuitName::LbfvAggregationFold,
                if row_index == 1 {
                    kernel_vk.clone()
                } else {
                    fold_vk.clone()
                },
                if row_index == 1 {
                    kernel_vk.key_hash.clone()
                } else {
                    fold_vk.key_hash.clone()
                },
                proof_fields(prior)?,
                checked_public_fields(
                    prior,
                    if row_index == 1 {
                        CircuitName::LbfvAggregationFoldKernel
                    } else {
                        CircuitName::LbfvAggregationFold
                    },
                    aggregation_fields,
                    "prior l-BFV aggregation accumulator",
                )?,
                false,
            )
        } else {
            if row_index != 0 {
                return Err(ZkError::InvalidInput(
                    "nonzero aggregation rows require a prior accumulator".into(),
                ));
            }
            (
                CircuitName::LbfvAggregationFoldKernel,
                kernel_vk.clone(),
                kernel_vk.key_hash.clone(),
                zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?,
                zero_field_hex_strings(accumulator_fields)?,
                true,
            )
        };

    Ok((
        circuit,
        AggregationFoldWitness {
            pk_vk: pk_vk.verification_key,
            pk_proof: proof_fields(pk_proof)?,
            pk_public,
            rlk_vk: rlk_vk.verification_key,
            rlk_proof: proof_fields(rlk_proof)?,
            rlk_public,
            acc_vk: acc_vk.verification_key,
            acc_proof,
            acc_public,
            pk_key_hash: pk_vk.key_hash,
            rlk_key_hash: rlk_vk.key_hash,
            acc_key_hash,
            is_first_step,
            row_index,
            expected_kernel_key_hash: kernel_vk.key_hash,
            expected_fold_key_hash: fold_vk.key_hash,
        },
    ))
}

/// Prove one row of the secure-16384 aggregation fold.
pub fn prove_lbfv_aggregation_fold_step(
    prover: &ZkProver,
    pk_proof: &Proof,
    rlk_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    row_index: u32,
    committee_h: usize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    prove_lbfv_aggregation_fold_step_for_preset(
        prover,
        pk_proof,
        rlk_proof,
        prior_accumulator,
        row_index,
        committee_h,
        BfvPreset::SecureThreshold16384,
        job_id,
        artifacts_dir,
    )
}

/// Prove one row of the l-BFV aggregation fold for a preset.
pub fn prove_lbfv_aggregation_fold_step_for_preset(
    prover: &ZkProver,
    pk_proof: &Proof,
    rlk_proof: &Proof,
    prior_accumulator: Option<&Proof>,
    row_index: u32,
    committee_h: usize,
    preset: BfvPreset,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let (circuit, witness) = aggregation_fold_witness(
        prover,
        pk_proof,
        rlk_proof,
        prior_accumulator,
        row_index,
        committee_h,
        e3_fhe_params::lbfv_row_count(preset).ok_or_else(|| {
            ZkError::InvalidInput("the selected preset does not support l-BFV".into())
        })?,
        artifacts_dir,
    )?;
    prove_bin(prover, circuit, &witness, job_id, artifacts_dir)
}

#[derive(Serialize)]
struct DkgAggregationV2Witness {
    nodes_fold_vk: Vec<String>,
    nodes_fold_proof: Vec<String>,
    nodes_fold_public: Vec<String>,
    c5_vk: Vec<String>,
    c5_proof: Vec<String>,
    c5_public: Vec<String>,
    nodes_fold_key_hash: String,
    c5_key_hash: String,
    party_ids: Vec<String>,
    committee_members: Vec<String>,
    committee_hash_hi: String,
    committee_hash_lo: String,
    vk_binding: Vec<String>,
    aggregation_fold_vk: Vec<String>,
    aggregation_fold_proof: Vec<String>,
    aggregation_fold_public: Vec<String>,
    aggregation_fold_key_hash: String,
    v2_vk_binding: Vec<String>,
}

fn legacy_vk_binding(
    prover: &ZkProver,
    artifacts_dir: &str,
) -> Result<Vec<vk::VkArtifacts>, ZkError> {
    let circuits = [
        CircuitName::NodeFold,
        CircuitName::PkBfv,
        CircuitName::PkGeneration,
        CircuitName::C2abChunkFold,
        CircuitName::C3abFold,
        CircuitName::C4abFold,
        CircuitName::SkC2ChunkFinalize,
        CircuitName::ESmC2ChunkFinalize,
        CircuitName::C2ChunkBatch,
        CircuitName::SkShareComputationChunk,
        CircuitName::ESmShareComputationChunk,
        CircuitName::C3Fold,
        CircuitName::ShareEncryption,
        CircuitName::DkgShareDecryption,
        CircuitName::C3FoldKernel,
        CircuitName::NodesFoldKernel,
    ];
    circuits
        .into_iter()
        .map(|circuit| {
            let variant = match circuit {
                CircuitName::PkBfv
                | CircuitName::PkGeneration
                | CircuitName::SkC2ChunkFinalize
                | CircuitName::ESmC2ChunkFinalize
                | CircuitName::SkShareComputationChunk
                | CircuitName::ESmShareComputationChunk
                | CircuitName::ShareEncryption
                | CircuitName::DkgShareDecryption => CircuitVariant::Recursive,
                _ => CircuitVariant::Default,
            };
            load_vk(prover, variant, artifacts_dir, circuit)
        })
        .collect()
}

fn v2_vk_binding(prover: &ZkProver, artifacts_dir: &str) -> Result<Vec<vk::VkArtifacts>, ZkError> {
    let circuits = [
        CircuitName::NodeFoldV2,
        CircuitName::NodesFoldV2,
        CircuitName::NodesFoldV2Kernel,
        CircuitName::LbfvGenerationFold,
        CircuitName::LbfvGenerationFoldKernel,
        CircuitName::LbfvPkGeneration,
        CircuitName::RlkGeneration,
        CircuitName::RlkGenerationLimb,
        CircuitName::LbfvAggregationFold,
        CircuitName::LbfvAggregationFoldKernel,
        CircuitName::LbfvPkAggregation,
        CircuitName::RlkAggregation,
        CircuitName::LbfvPkGenerationLimb,
    ];
    circuits
        .into_iter()
        .map(|circuit| {
            let variant = match circuit {
                CircuitName::LbfvPkGeneration
                | CircuitName::LbfvPkGenerationLimb
                | CircuitName::RlkGeneration
                | CircuitName::RlkGenerationLimb
                | CircuitName::LbfvPkAggregation
                | CircuitName::RlkAggregation => CircuitVariant::Recursive,
                _ => CircuitVariant::Default,
            };
            load_vk(prover, variant, artifacts_dir, circuit)
        })
        .collect()
}

/// Prove the EVM-facing l-BFV DKG aggregator.
pub fn prove_dkg_aggregation_v2(
    prover: &ZkProver,
    nodes_fold_proof: &Proof,
    c5_proof: &Proof,
    aggregation_fold_proof: &Proof,
    party_ids: &[u64],
    committee_addresses: &[Address],
    job_id: &str,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
) -> Result<Proof, ZkError> {
    let row_count = e3_fhe_params::lbfv_row_count(preset).ok_or_else(|| {
        ZkError::InvalidInput("V2 DKG aggregation requires a preset with l-BFV artifacts".into())
    })?;
    let expected = committee.values();
    if party_ids.len() != expected.h || committee_addresses.len() != expected.n {
        return Err(ZkError::InvalidInput(format!(
            "V2 DKG aggregation requires H={} party IDs and N={} committee addresses",
            expected.h, expected.n
        )));
    }
    let mut seen = HashSet::with_capacity(party_ids.len());
    if party_ids
        .iter()
        .any(|party_id| !seen.insert(*party_id) || *party_id >= expected.n as u64)
    {
        return Err(ZkError::InvalidInput(
            "V2 DKG aggregation party IDs must be unique and in range".into(),
        ));
    }
    if party_ids.windows(2).any(|ids| ids[0] >= ids[1]) {
        return Err(ZkError::InvalidInput(
            "V2 DKG aggregation party IDs must be ascending".into(),
        ));
    }

    let nodes_fields = nodes_fold_v2_public_fields(committee, row_count);
    let aggregation_fields = aggregation_fold_public_fields(expected.h, row_count);

    let nodes_fold_public = checked_public_fields(
        nodes_fold_proof,
        CircuitName::NodesFoldV2,
        nodes_fields,
        "V2 nodes fold",
    )?;
    let c5_public = checked_public_fields(
        c5_proof,
        CircuitName::PkAggregation,
        c5_public_fields(expected.h),
        "C5",
    )?;
    let aggregation_fold_public = checked_public_fields(
        aggregation_fold_proof,
        CircuitName::LbfvAggregationFold,
        aggregation_fields,
        "l-BFV aggregation fold",
    )?;

    let artifacts_dir = prover.resolve_artifacts_dir(preset, committee.as_str());
    let artifacts_dir = artifacts_dir.as_str();
    let legacy = legacy_vk_binding(prover, artifacts_dir)?;
    let v2 = v2_vk_binding(prover, artifacts_dir)?;
    if legacy.len() != LEGACY_VK_BINDING_LEN || v2.len() != V2_VK_BINDING_LEN {
        return Err(ZkError::InvalidInput(
            "recursive VK binding has the wrong length".into(),
        ));
    }
    let nodes_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::NodesFoldV2,
    )?;
    let c5_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::PkAggregation,
    )?;
    let aggregation_vk = load_vk(
        prover,
        CircuitVariant::Default,
        artifacts_dir,
        CircuitName::LbfvAggregationFold,
    )?;
    let (committee_hash_hi, committee_hash_lo) =
        e3_committee_hash::committee_hash_field_hex(committee_addresses);

    let witness = DkgAggregationV2Witness {
        nodes_fold_vk: nodes_vk.verification_key,
        nodes_fold_proof: proof_fields(nodes_fold_proof)?,
        nodes_fold_public,
        c5_vk: c5_vk.verification_key,
        c5_proof: proof_fields(c5_proof)?,
        c5_public,
        nodes_fold_key_hash: nodes_vk.key_hash,
        c5_key_hash: c5_vk.key_hash,
        party_ids: party_ids.iter().copied().map(u64_to_field_hex).collect(),
        committee_members: committee_addresses
            .iter()
            .map(address_to_field_hex)
            .collect(),
        committee_hash_hi,
        committee_hash_lo,
        vk_binding: legacy
            .into_iter()
            .map(|artifact| artifact.key_hash)
            .collect(),
        aggregation_fold_vk: aggregation_vk.verification_key,
        aggregation_fold_proof: proof_fields(aggregation_fold_proof)?,
        aggregation_fold_public,
        aggregation_fold_key_hash: aggregation_vk.key_hash,
        v2_vk_binding: v2.into_iter().map(|artifact| artifact.key_hash).collect(),
    };

    let json = serde_json::to_value(&witness)
        .map_err(|error| ZkError::SerializationError(error.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let circuit = CircuitName::DkgAggregatorV2;
    let compiled_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit.dir_path())
        .join(format!("{}.json", circuit.as_str()));
    let compiled = CompiledCircuit::from_file(&compiled_path)?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_proof_with_variant(
        circuit,
        &witness,
        job_id,
        CircuitVariant::Evm,
        artifacts_dir,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof_with_public_fields(circuit: CircuitName, count: usize) -> Proof {
        Proof::new(
            circuit,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&vec![0; count * 32]),
        )
    }

    #[test]
    fn secure_v2_public_shapes_are_fixed() {
        let committee = CiphernodesCommitteeSize::Minimum;
        assert_eq!(node_fold_public_fields(committee, 5), 67);
        assert_eq!(node_fold_v2_public_fields(committee, 5), 89);
        assert_eq!(nodes_fold_v2_public_fields(committee, 5), 184);
        assert_eq!(generation_fold_public_fields(5), 29);
        assert_eq!(aggregation_fold_public_fields(2, 5), 57);
        assert_eq!(c5_public_fields(2), 3);
    }

    #[test]
    fn checked_public_fields_rejects_an_off_by_one_shape() {
        let fields = node_fold_v2_public_fields(CiphernodesCommitteeSize::Minimum, 5);
        let proof = proof_with_public_fields(CircuitName::NodeFoldV2, fields - 1);
        let error = checked_public_fields(&proof, CircuitName::NodeFoldV2, fields, "V2 node proof")
            .expect_err("an invalid shape must fail");
        assert!(error.to_string().contains("must contain 89 public fields"));
    }

    #[test]
    fn checked_public_fields_rejects_the_wrong_circuit() {
        let fields = node_fold_v2_public_fields(CiphernodesCommitteeSize::Minimum, 5);
        let proof = proof_with_public_fields(CircuitName::NodeFold, fields);
        let error = checked_public_fields(&proof, CircuitName::NodeFoldV2, fields, "V2 node proof")
            .expect_err("the wrong circuit must fail");
        assert!(matches!(
            error,
            ZkError::InvalidInput(message)
                if message.contains("V2 node proof must be a")
                    && message.contains(&CircuitName::NodeFoldV2.to_string())
        ));
    }
}
