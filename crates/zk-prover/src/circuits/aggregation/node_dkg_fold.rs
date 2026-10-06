// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Production witness builders and provers for the per-node DKG fold pipeline and aggregator
//! proofs ([`CircuitName::NodeFold`], [`CircuitName::DkgAggregator`], [`CircuitName::DecryptionAggregator`]).

use crate::circuits::aggregation::c3_accumulator::generate_sequential_c3_fold;
use crate::circuits::aggregation::c6_accumulator::generate_sequential_c6_fold;
use crate::circuits::aggregation::helpers::{address_to_field_hex, u64_to_field_hex};
use crate::circuits::aggregation::nodes_fold_accumulator::generate_sequential_nodes_fold;
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use alloy::primitives::Address;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::CiphernodesCommitteeSize;
use serde::Serialize;
use std::collections::HashSet;
use std::time::Instant;

fn proof_field_strings(proof: &Proof) -> Result<Vec<String>, ZkError> {
    bytes_to_field_strings(proof.data.as_ref())
}

fn proof_public_field_strings(proof: &Proof) -> Result<Vec<String>, ZkError> {
    bytes_to_field_strings(proof.public_signals.as_ref())
}

/// Load `<artifacts_dir>/<variant>/<circuit>/<circuit>.json` as a [`CompiledCircuit`]. Centralised
/// so the layout is in one place across all aggregation builders below.
fn load_compiled_circuit(
    prover: &ZkProver,
    circuit: CircuitName,
    variant: CircuitVariant,
    artifacts_dir: &str,
) -> Result<CompiledCircuit, ZkError> {
    let path = prover
        .circuits_dir(variant, artifacts_dir)
        .join(circuit.dir_path())
        .join(format!("{}.json", circuit.as_str()));
    CompiledCircuit::from_file(&path)
}

/// Build a witness from a `Serialize` Noir input struct and prove `circuit` via the recursive-bin
/// path. Collapses the repeated `serde_json::to_value → inputs_json_to_input_map → CompiledCircuit::from_file
/// → WitnessGenerator → generate_recursive_aggregation_bin_proof` boilerplate used by every fold
/// builder (c2ab chunk / c3ab / c4ab / node_fold) in this module.
fn build_and_prove_recursive_bin<W: Serialize>(
    prover: &ZkProver,
    circuit: CircuitName,
    witness_input: &W,
    job_label: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let json = serde_json::to_value(witness_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let compiled = load_compiled_circuit(prover, circuit, CircuitVariant::Default, artifacts_dir)?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(circuit, &witness, job_label, artifacts_dir)
}

#[derive(Serialize)]
struct NodeFoldWitness {
    c0_vk: Vec<String>,
    c0_proof: Vec<String>,
    c0_public: Vec<String>,
    c1_vk: Vec<String>,
    c1_proof: Vec<String>,
    c1_public: Vec<String>,
    c2_vk: Vec<String>,
    c2_proof: Vec<String>,
    c2_public: Vec<String>,
    c3_vk: Vec<String>,
    c3_proof: Vec<String>,
    c3_public: Vec<String>,
    c4_vk: Vec<String>,
    c4_proof: Vec<String>,
    c4_public: Vec<String>,
    party_id: String,
    c0_key_hash: String,
    c1_key_hash: String,
    c2_key_hash: String,
    c3_key_hash: String,
    c4_key_hash: String,
}

/// Inputs for [`prove_node_dkg_fold`]: recursive inner proofs and C3 slot metadata.
pub struct NodeDkgFoldInput<'a> {
    pub c0_proof: &'a Proof,
    pub c1_proof: &'a Proof,
    pub c2a_proof: &'a Proof,
    pub c3a_inner_proofs: &'a [Proof],
    pub c3_slot_indices_a: &'a [u32],
    pub c3_total_slots: usize,
    pub c3_n_parties: usize,
    pub c4a_proof: &'a Proof,
    pub party_id: u64,
}

/// Per-step prove wall time inside [`prove_node_dkg_fold`] (for benchmarks / audit reports).
#[derive(Clone, Debug, Serialize)]
pub struct FoldProveStepTiming {
    pub step: String,
    pub seconds: f64,
}

/// Output of [`prove_node_dkg_fold`] including sub-step timings.
#[derive(Clone, Debug)]
pub struct NodeDkgFoldProveResult {
    pub proof: Proof,
    pub step_timings: Vec<FoldProveStepTiming>,
}

fn push_step(timings: &mut Vec<FoldProveStepTiming>, step: &str, started: Instant) {
    timings.push(FoldProveStepTiming {
        step: step.to_string(),
        seconds: started.elapsed().as_secs_f64(),
    });
}

/// Run the C3a fold, then NodeFold over C0, C1, the C2a finalizer, that fold, and C4a.
pub fn prove_node_dkg_fold(
    prover: &ZkProver,
    input: &NodeDkgFoldInput,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<NodeDkgFoldProveResult, ZkError> {
    let mut step_timings = Vec::with_capacity(6);
    let c2a_circuit = match input.c2a_proof.circuit {
        CircuitName::SkC2ChunkFinalize => input.c2a_proof.circuit,
        other => {
            return Err(ZkError::InvalidInput(format!(
                "invalid C2a proof circuit {other}"
            )))
        }
    };
    let c2_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        c2a_circuit,
    )?;
    let t = Instant::now();
    let c3_folded = generate_sequential_c3_fold(
        prover,
        input.c3a_inner_proofs,
        input.c3_slot_indices_a,
        input.c3_total_slots,
        input.c3_n_parties,
        &format!("{e3_id}-c3a"),
        artifacts_dir,
    )?;
    push_step(&mut step_timings, "c3_fold", t);

    let c3_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C3Fold,
    )?;
    let c4_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::DkgShareDecryption,
    )?;
    let c0_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::PkBfv,
    )?;
    let c1_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::PkGeneration,
    )?;

    let nf = NodeFoldWitness {
        c0_vk: c0_vk.verification_key,
        c0_proof: proof_field_strings(input.c0_proof)?,
        c0_public: proof_public_field_strings(input.c0_proof)?,
        c1_vk: c1_vk.verification_key,
        c1_proof: proof_field_strings(input.c1_proof)?,
        c1_public: proof_public_field_strings(input.c1_proof)?,
        c2_vk: c2_vk.verification_key.clone(),
        c2_proof: proof_field_strings(input.c2a_proof)?,
        c2_public: proof_public_field_strings(input.c2a_proof)?,
        c3_vk: c3_vk.verification_key.clone(),
        c3_proof: proof_field_strings(&c3_folded)?,
        c3_public: proof_public_field_strings(&c3_folded)?,
        c4_vk: c4_vk.verification_key.clone(),
        c4_proof: proof_field_strings(input.c4a_proof)?,
        c4_public: proof_public_field_strings(input.c4a_proof)?,
        party_id: u64_to_field_hex(input.party_id),
        c0_key_hash: c0_vk.key_hash,
        c1_key_hash: c1_vk.key_hash,
        c2_key_hash: c2_vk.key_hash,
        c3_key_hash: c3_vk.key_hash,
        c4_key_hash: c4_vk.key_hash,
    };

    let t = Instant::now();
    let proof = build_and_prove_recursive_bin(
        prover,
        CircuitName::NodeFold,
        &nf,
        &format!("{e3_id}-nodefold"),
        artifacts_dir,
    )?;
    push_step(&mut step_timings, "node_fold", t);

    Ok(NodeDkgFoldProveResult {
        proof,
        step_timings,
    })
}

/// Inputs for [`prove_dkg_aggregation`].
pub struct DkgAggregationInput<'a> {
    pub node_fold_proofs: &'a [Proof],
    /// Pre-computed nodes_fold accumulator. When `Some`, the sequential fold is skipped.
    pub nodes_fold_proof: Option<&'a Proof>,
    pub c5_proof: &'a Proof,
    /// Honest party ids in the same order as `node_fold_proofs` (e.g. sorted ascending).
    pub party_ids: &'a [u64],
    /// Address-ordered committee (`topNodes` / party order) for `committee_hash_*` public inputs.
    pub committee_addresses: &'a [Address],
}

fn validate_dkg_aggregation_shape(
    node_fold_count: usize,
    party_ids: &[u64],
    committee_address_count: usize,
    committee: CiphernodesCommitteeSize,
) -> Result<(), ZkError> {
    let expected = committee.values();
    if node_fold_count != party_ids.len() {
        return Err(ZkError::InvalidInput(
            "node_fold_proofs and party_ids length mismatch".into(),
        ));
    }
    if node_fold_count != expected.h {
        return Err(ZkError::InvalidInput(format!(
            "DkgAggregator requires H={} honest NodeFold proofs for committee {}, got {}",
            expected.h, committee, node_fold_count
        )));
    }
    if committee_address_count != expected.n {
        return Err(ZkError::InvalidInput(format!(
            "DkgAggregator requires N={} full committee addresses for committee {}, got {}",
            expected.n, committee, committee_address_count
        )));
    }

    let mut seen = HashSet::with_capacity(party_ids.len());
    for &party_id in party_ids {
        let party_index = usize::try_from(party_id).map_err(|_| {
            ZkError::InvalidInput(format!(
                "DkgAggregator party id {party_id} does not fit a committee index"
            ))
        })?;
        if party_index >= expected.n {
            return Err(ZkError::InvalidInput(format!(
                "DkgAggregator party id {party_id} is outside committee N={}",
                expected.n
            )));
        }
        if !seen.insert(party_id) {
            return Err(ZkError::InvalidInput(format!(
                "DkgAggregator party id {party_id} is duplicated"
            )));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct DkgAggregatorWitness {
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
}

/// [`CircuitName::DkgAggregator`] over sequential [`CircuitName::NodesFold`] + C5, proved with
/// [`CircuitVariant::Evm`] for on-chain verification.
pub fn prove_dkg_aggregation(
    prover: &ZkProver,
    input: &DkgAggregationInput,
    e3_id: &str,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
) -> Result<Proof, ZkError> {
    validate_dkg_aggregation_shape(
        input.node_fold_proofs.len(),
        input.party_ids,
        input.committee_addresses.len(),
        committee,
    )?;
    let artifacts_dir = prover.resolve_artifacts_dir(preset, committee.as_str());
    let artifacts_dir = artifacts_dir.as_str();
    let h = input.node_fold_proofs.len();
    let nodes_fold_proof = if let Some(precomputed) = input.nodes_fold_proof {
        precomputed.clone()
    } else {
        let slot_indices: Vec<u32> = (0u32..h as u32).collect();
        generate_sequential_nodes_fold(
            prover,
            input.node_fold_proofs,
            &slot_indices,
            h,
            &format!("{e3_id}-nodesfold"),
            artifacts_dir,
        )?
    };

    let nodes_fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::NodesFold,
    )?;
    let c5_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::PkAggregation,
    )?;
    let node_fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::NodeFold,
    )?;
    let c0_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::PkBfv,
    )?;
    let c1_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::PkGeneration,
    )?;
    let c2ab_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C2abChunkFold,
    )?;
    let c3ab_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C3abFold,
    )?;
    let c4ab_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C4abFold,
    )?;
    let c2a_finalize_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::SkC2ChunkFinalize,
    )?;
    let c2_batch_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C2ChunkBatch,
    )?;
    let c2a_chunk_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::SkShareComputationChunk,
    )?;
    let c3_fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C3Fold,
    )?;
    let share_encryption_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::ShareEncryption,
    )?;
    let c4_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::DkgShareDecryption,
    )?;
    let c3_fold_kernel_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C3FoldKernel,
    )?;
    let nodes_fold_kernel_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::NodesFoldKernel,
    )?;

    let party_id_fields: Vec<String> = input
        .party_ids
        .iter()
        .copied()
        .map(u64_to_field_hex)
        .collect();

    let (committee_hash_hi, committee_hash_lo) =
        e3_committee_hash::committee_hash_field_hex(input.committee_addresses);

    let committee_members: Vec<String> = input
        .committee_addresses
        .iter()
        .map(address_to_field_hex)
        .collect();

    let witness = DkgAggregatorWitness {
        nodes_fold_vk: nodes_fold_vk.verification_key.clone(),
        nodes_fold_proof: proof_field_strings(&nodes_fold_proof)?,
        nodes_fold_public: proof_public_field_strings(&nodes_fold_proof)?,
        c5_vk: c5_vk.verification_key.clone(),
        c5_proof: proof_field_strings(input.c5_proof)?,
        c5_public: proof_public_field_strings(input.c5_proof)?,
        nodes_fold_key_hash: nodes_fold_vk.key_hash.clone(),
        c5_key_hash: c5_vk.key_hash.clone(),
        party_ids: party_id_fields,
        committee_members,
        committee_hash_hi,
        committee_hash_lo,
        vk_binding: vec![
            node_fold_vk.key_hash,
            c0_vk.key_hash,
            c1_vk.key_hash,
            c2ab_vk.key_hash,
            c3ab_vk.key_hash,
            c4ab_vk.key_hash,
            c2a_finalize_vk.key_hash,
            "0x0".to_string(),
            c2_batch_vk.key_hash,
            c2a_chunk_vk.key_hash,
            "0x0".to_string(),
            c3_fold_vk.key_hash,
            share_encryption_vk.key_hash,
            c4_vk.key_hash,
            c3_fold_kernel_vk.key_hash,
            nodes_fold_kernel_vk.key_hash,
        ],
    };

    let json =
        serde_json::to_value(&witness).map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let compiled = load_compiled_circuit(
        prover,
        CircuitName::DkgAggregator,
        CircuitVariant::Default,
        artifacts_dir,
    )?;
    let w = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_proof_with_variant(
        CircuitName::DkgAggregator,
        &w,
        e3_id,
        CircuitVariant::Evm,
        artifacts_dir,
    )
}

/// One ciphertext index: C6 inners + C7 proof.
pub struct DecryptionAggregationJob<'a> {
    pub c6_inner_proofs: &'a [Proof],
    pub c6_slot_indices: &'a [u32],
    pub c7_proof: &'a Proof,
}

#[derive(Serialize)]
struct DecryptionAggregatorWitness {
    c6_fold_vk: Vec<String>,
    c6_fold_proof: Vec<String>,
    c6_fold_public: Vec<String>,
    c7_vk: Vec<String>,
    c7_proof: Vec<String>,
    c7_public: Vec<String>,
    c6_fold_key_hash: String,
    c7_key_hash: String,
    committee_members: Vec<String>,
    committee_hash_hi: String,
    committee_hash_lo: String,
    domain_hi: String,
    domain_lo: String,
    ciphertext_commitment: String,
}

/// Prove [`CircuitName::DecryptionAggregator`] for each job (C6 fold + C7), with
/// [`CircuitVariant::Evm`] for on-chain verification.
pub fn prove_decryption_aggregation_jobs(
    prover: &ZkProver,
    c6_total_slots: usize,
    jobs: &[DecryptionAggregationJob],
    committee_addresses: &[Address],
    e3_id: &str,
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
) -> Result<Vec<Proof>, ZkError> {
    let artifacts_dir = prover.resolve_artifacts_dir(preset, committee.as_str());
    let artifacts_dir = artifacts_dir.as_str();
    // VKs and the compiled circuit are job-independent: load once, reuse per ciphertext.
    let c6_fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C6Fold,
    )?;
    let c7_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::DecryptedSharesAggregation,
    )?;
    let compiled = load_compiled_circuit(
        prover,
        CircuitName::DecryptionAggregator,
        CircuitVariant::Default,
        artifacts_dir,
    )?;

    if committee_addresses.is_empty() {
        return Err(ZkError::InvalidInput(
            "prove_decryption_aggregation_jobs: committee_addresses must be non-empty (on-chain topNodes)".into(),
        ));
    }

    let (committee_hash_hi, committee_hash_lo) =
        e3_committee_hash::committee_hash_field_hex(committee_addresses);

    let committee_members: Vec<String> = committee_addresses
        .iter()
        .map(address_to_field_hex)
        .collect();

    let mut out = Vec::with_capacity(jobs.len());
    for (i, job) in jobs.iter().enumerate() {
        let c6_fold = generate_sequential_c6_fold(
            prover,
            job.c6_inner_proofs,
            job.c6_slot_indices,
            c6_total_slots,
            committee_addresses.len(),
            &format!("{e3_id}-c6fold-{i}"),
            artifacts_dir,
        )?;
        let c6_fold_public = proof_public_field_strings(&c6_fold)?;
        let domain_hi = c6_fold_public.get(4).cloned().ok_or_else(|| {
            ZkError::InvalidInput("C6 fold proof is missing domain_hi at public input 4".into())
        })?;
        let domain_lo = c6_fold_public.get(5).cloned().ok_or_else(|| {
            ZkError::InvalidInput("C6 fold proof is missing domain_lo at public input 5".into())
        })?;
        let ciphertext_commitment = c6_fold_public
            .get(6 + (2 * c6_total_slots))
            .cloned()
            .ok_or_else(|| {
                ZkError::InvalidInput(
                    "C6 fold proof is missing the ciphertext commitment column".into(),
                )
            })?;

        let witness = DecryptionAggregatorWitness {
            c6_fold_vk: c6_fold_vk.verification_key.clone(),
            c6_fold_proof: proof_field_strings(&c6_fold)?,
            c6_fold_public,
            c7_vk: c7_vk.verification_key.clone(),
            c7_proof: proof_field_strings(job.c7_proof)?,
            c7_public: proof_public_field_strings(job.c7_proof)?,
            c6_fold_key_hash: c6_fold_vk.key_hash.clone(),
            c7_key_hash: c7_vk.key_hash.clone(),
            committee_members: committee_members.clone(),
            committee_hash_hi: committee_hash_hi.clone(),
            committee_hash_lo: committee_hash_lo.clone(),
            domain_hi,
            domain_lo,
            ciphertext_commitment,
        };

        let json = serde_json::to_value(&witness)
            .map_err(|e| ZkError::SerializationError(e.to_string()))?;
        let input_map = inputs_json_to_input_map(&json)?;
        let w = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
        let proof = prover.generate_proof_with_variant(
            CircuitName::DecryptionAggregator,
            &w,
            &format!("{e3_id}-decagg-{i}"),
            CircuitVariant::Evm,
            artifacts_dir,
        )?;
        out.push(proof);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::validate_dkg_aggregation_shape;
    use e3_zk_helpers::CiphernodesCommitteeSize;

    #[test]
    fn dkg_aggregation_accepts_all_canonical_h_of_n_shapes() {
        for (committee, h, n) in [
            (CiphernodesCommitteeSize::Minimum, 2, 3),
            (CiphernodesCommitteeSize::Micro, 5, 9),
            (CiphernodesCommitteeSize::Small, 14, 19),
        ] {
            let party_ids: Vec<u64> = (0..h as u64).collect();
            validate_dkg_aggregation_shape(h, &party_ids, n, committee)
                .expect("canonical committee must have H honest proofs and N addresses");
        }
    }

    #[test]
    fn dkg_aggregation_rejects_h_equal_to_n_for_minimum_committee() {
        let error =
            validate_dkg_aggregation_shape(3, &[0, 1, 2], 3, CiphernodesCommitteeSize::Minimum)
                .unwrap_err();
        assert!(error.to_string().contains("requires H=2"));
    }

    #[test]
    fn dkg_aggregation_rejects_incomplete_honest_set() {
        let error = validate_dkg_aggregation_shape(1, &[0], 3, CiphernodesCommitteeSize::Minimum)
            .unwrap_err();
        assert!(error.to_string().contains("requires H=2"));
    }

    #[test]
    fn dkg_aggregation_rejects_wrong_full_committee_size() {
        let error =
            validate_dkg_aggregation_shape(2, &[0, 1], 2, CiphernodesCommitteeSize::Minimum)
                .unwrap_err();
        assert!(error.to_string().contains("requires N=3"));
    }

    #[test]
    fn dkg_aggregation_rejects_duplicate_or_out_of_range_party_ids() {
        let duplicate =
            validate_dkg_aggregation_shape(2, &[1, 1], 3, CiphernodesCommitteeSize::Minimum)
                .unwrap_err();
        assert!(duplicate.to_string().contains("duplicated"));

        let out_of_range =
            validate_dkg_aggregation_shape(2, &[0, 3], 3, CiphernodesCommitteeSize::Minimum)
                .unwrap_err();
        assert!(out_of_range.to_string().contains("outside committee N=3"));
    }
}
