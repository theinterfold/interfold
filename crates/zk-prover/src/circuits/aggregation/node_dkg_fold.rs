// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Production witness builders and provers for the per-node DKG fold pipeline and aggregator
//! proofs ([`CircuitName::NodeFold`], [`CircuitName::DkgAggregator`], [`CircuitName::DecryptionAggregator`]).

use crate::circuits::aggregation::c3_accumulator::{
    generate_c3_merge_m7x, generate_sequential_c3_fold,
};
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
/// builder (c2ab / c3ab / c4ab / node_fold) in this module.
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
struct C2abFoldWitness {
    c2a_vk: Vec<String>,
    c2a_proof: Vec<String>,
    c2a_public: Vec<String>,
    c2b_vk: Vec<String>,
    c2b_proof: Vec<String>,
    c2b_public: Vec<String>,
    c2a_key_hash: String,
    c2b_key_hash: String,
}

#[derive(Serialize)]
struct C3abFoldWitness {
    c3a_vk: Vec<String>,
    c3a_proof: Vec<String>,
    c3a_public: Vec<String>,
    c3b_vk: Vec<String>,
    c3b_proof: Vec<String>,
    c3b_public: Vec<String>,
    c3a_key_hash: String,
    c3b_key_hash: String,
}

#[derive(Serialize)]
struct C4abFoldWitness {
    c4a_vk: Vec<String>,
    c4a_proof: Vec<String>,
    c4a_public: Vec<String>,
    c4b_vk: Vec<String>,
    c4b_proof: Vec<String>,
    c4b_public: Vec<String>,
    c4a_key_hash: String,
    c4b_key_hash: String,
}

#[derive(Serialize)]
struct NodeFoldWitness {
    c0_vk: Vec<String>,
    c0_proof: Vec<String>,
    c0_public: Vec<String>,
    c1_vk: Vec<String>,
    c1_proof: Vec<String>,
    c1_public: Vec<String>,
    c2ab_vk: Vec<String>,
    c2ab_proof: Vec<String>,
    c2ab_public: Vec<String>,
    c3ab_vk: Vec<String>,
    c3ab_proof: Vec<String>,
    c3ab_public: Vec<String>,
    c4ab_vk: Vec<String>,
    c4ab_proof: Vec<String>,
    c4ab_public: Vec<String>,
    party_id: String,
    c0_key_hash: String,
    c1_key_hash: String,
    c2ab_key_hash: String,
    c3ab_key_hash: String,
    c4ab_key_hash: String,
}

/// Inputs for [`prove_node_dkg_fold`]: recursive inner proofs and C3 slot metadata.
pub struct NodeDkgFoldInput<'a> {
    pub c0_proof: &'a Proof,
    pub c1_proof: &'a Proof,
    pub c2a_proof: &'a Proof,
    pub c2b_proof: &'a Proof,
    pub c3a_inner_proofs: &'a [Proof],
    pub c3b_inner_proofs: &'a [Proof],
    pub c3_slot_indices_a: &'a [u32],
    pub c3_slot_indices_b: &'a [u32],
    pub c3_total_slots: usize,
    pub c4a_proof: &'a Proof,
    pub c4b_proof: &'a Proof,
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

/// Run C2abFold || (C3a fold || C3b fold) → C3abFold → C4abFold → NodeFold; returns a [`CircuitName::NodeFold`] proof.
///
/// C2abFold and the two C3 fold chains are mutually independent and run concurrently via
/// `rayon::join`. C3a and C3b are also independent of each other and run as a nested join.
pub fn prove_node_dkg_fold(
    prover: &ZkProver,
    input: &NodeDkgFoldInput,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<NodeDkgFoldProveResult, ZkError> {
    let mut step_timings = Vec::with_capacity(6);
    let c2a_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::SkShareComputation,
    )?;
    let c2b_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::ESmShareComputation,
    )?;

    let c2ab = C2abFoldWitness {
        c2a_vk: c2a_vk.verification_key.clone(),
        c2a_proof: proof_field_strings(input.c2a_proof)?,
        c2a_public: proof_public_field_strings(input.c2a_proof)?,
        c2b_vk: c2b_vk.verification_key.clone(),
        c2b_proof: proof_field_strings(input.c2b_proof)?,
        c2b_public: proof_public_field_strings(input.c2b_proof)?,
        c2a_key_hash: c2a_vk.key_hash.clone(),
        c2b_key_hash: c2b_vk.key_hash.clone(),
    };

    // c2ab_fold is independent of the c3 chains; c3a and c3b are independent of each other.
    // Run all three concurrently: c2ab || (c3a || c3b).
    let ((c2ab_result, c2ab_elapsed), ((c3a_result, c3a_elapsed), (c3b_result, c3b_elapsed))) =
        rayon::join(
            || {
                let t = Instant::now();
                let r = build_and_prove_recursive_bin(
                    prover,
                    CircuitName::C2abFold,
                    &c2ab,
                    &format!("{e3_id}-c2ab"),
                    artifacts_dir,
                );
                (r, t.elapsed())
            },
            || {
                rayon::join(
                    || {
                        let t = Instant::now();
                        let r = generate_sequential_c3_fold(
                            prover,
                            input.c3a_inner_proofs,
                            input.c3_slot_indices_a,
                            input.c3_total_slots,
                            &format!("{e3_id}-c3a"),
                            artifacts_dir,
                        );
                        (r, t.elapsed())
                    },
                    || {
                        let t = Instant::now();
                        let r = if input.c3b_inner_proofs.len() == 54
                            && input.c3_slot_indices_b.len() == 54
                        {
                            // Production N=19 C3b geometry (N=19, L=3): the batched M7x merge
                            // (1 kernel + 5 x B10 + 1 x B3 sub-gates + 1 M7x merge = 8
                            // top-level proves) replaces the 54-step c3_fold chain with a
                            // BYTE-IDENTICAL slot state (verified at production geometry,
                            // r61/r62/r63 e2e) at a one-fold-layer wall of 298.1 s vs the
                            // serial arm's 449.1 s (r63 RAN). M7x's public layout is
                            // c3_fold-EXACT (175 = 4 + 3*57) and its final proof carries the
                            // C3FoldBatchMergeM7x circular-dh ownership, so the c3ab witness
                            // pins c3b against the M7x VK (single VK per arm — the r35
                            // pattern). The legacy M7 (r55/r58) was NOT production-shape
                            // (r60 premise kill); only the parameterized M7x is eligible.
                            generate_c3_merge_m7x(
                                prover,
                                input.c3b_inner_proofs,
                                input.c3_slot_indices_b,
                                input.c3_total_slots,
                                &format!("{e3_id}-c3b"),
                                artifacts_dir,
                            )
                        } else {
                            // Non-production geometry (other committees / partial chains):
                            // the generic sequential fold (M7x hard-requires the exact
                            // 54-inner / 54-slot production fan-out shape).
                            generate_sequential_c3_fold(
                                prover,
                                input.c3b_inner_proofs,
                                input.c3_slot_indices_b,
                                input.c3_total_slots,
                                &format!("{e3_id}-c3b"),
                                artifacts_dir,
                            )
                        };
                        (r, t.elapsed())
                    },
                )
            },
        );

    let c2ab_proof = c2ab_result?;
    step_timings.push(FoldProveStepTiming {
        step: "c2ab_fold".to_string(),
        seconds: c2ab_elapsed.as_secs_f64(),
    });
    let c3a_folded = c3a_result?;
    step_timings.push(FoldProveStepTiming {
        step: "c3a_fold".to_string(),
        seconds: c3a_elapsed.as_secs_f64(),
    });
    let c3b_folded = c3b_result?;
    step_timings.push(FoldProveStepTiming {
        step: "c3b_fold".to_string(),
        seconds: c3b_elapsed.as_secs_f64(),
    });

    let c3_fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C3Fold,
    )?;
    // The c3ab witness must pin each arm against the VK of the circuit that PRODUCED its
    // final proof. The c3a arm stays a sequential c3_fold chain (c3_fold VK, unchanged).
    // The c3b arm: the M7x merge (production N=19 geometry) returns a C3FoldBatchMergeM7x
    // proof over the c3_fold-EXACT 175-field public layout — c3ab_fold's in-circuit verify
    // is VK-polymorphic at runtime (c3b_vk/c3b_key_hash are witness inputs, exactly like the
    // prior-accumulator verify in the batch gates, r9 `c3_batch`), so c3ab_fold needs no
    // recompile: this wiring is the "VK-rebuild-only" drop-in (r35 pattern). Any other
    // geometry folds the c3b arm sequentially (c3_fold VK).
    let c3b_arm_used_m7x = input.c3b_inner_proofs.len() == 54 && input.c3_slot_indices_b.len() == 54;
    let c3b_final_vk = if c3b_arm_used_m7x {
        vk::load_vk_artifacts(
            &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
            CircuitName::C3FoldBatchMergeM7x,
        )?
    } else {
        vk::load_vk_artifacts(
            &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
            CircuitName::C3Fold,
        )?
    };
    let c3b_circuit_name = if c3b_arm_used_m7x {
        CircuitName::C3FoldBatchMergeM7x
    } else {
        CircuitName::C3Fold
    };
    // Defense-in-depth: the c3b final proof's circuit identity must match the VK arm chosen
    // above (a geometry/ABI mismatch would otherwise pin c3ab against the wrong VK and fail
    // at witness gen or, worse, be rejected at verify).
    if c3b_folded.circuit != c3b_circuit_name {
        return Err(ZkError::InvalidInput(format!(
            "c3b final fold proof circuit {:?} does not match the expected arm {:?} (inners={}, slots={})",
            c3b_folded.circuit,
            c3b_circuit_name,
            input.c3b_inner_proofs.len(),
            input.c3_slot_indices_b.len()
        )));
    }
    let c3ab = C3abFoldWitness {
        c3a_vk: c3_fold_vk.verification_key.clone(),
        c3a_proof: proof_field_strings(&c3a_folded)?,
        c3a_public: proof_public_field_strings(&c3a_folded)?,
        c3b_vk: c3b_final_vk.verification_key.clone(),
        c3b_proof: proof_field_strings(&c3b_folded)?,
        c3b_public: proof_public_field_strings(&c3b_folded)?,
        c3a_key_hash: c3_fold_vk.key_hash.clone(),
        c3b_key_hash: c3b_final_vk.key_hash.clone(),
    };
    let t = Instant::now();
    let c3ab_proof = build_and_prove_recursive_bin(
        prover,
        CircuitName::C3abFold,
        &c3ab,
        &format!("{e3_id}-c3ab"),
        artifacts_dir,
    )?;
    push_step(&mut step_timings, "c3ab_fold", t);

    // C4a and C4b are both proofs of the same `DkgShareDecryption` circuit, so they share the
    // same VK. Load it once and clone into both witness slots.
    let c4_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::DkgShareDecryption,
    )?;
    let c4ab = C4abFoldWitness {
        c4a_vk: c4_vk.verification_key.clone(),
        c4a_proof: proof_field_strings(input.c4a_proof)?,
        c4a_public: proof_public_field_strings(input.c4a_proof)?,
        c4b_vk: c4_vk.verification_key.clone(),
        c4b_proof: proof_field_strings(input.c4b_proof)?,
        c4b_public: proof_public_field_strings(input.c4b_proof)?,
        c4a_key_hash: c4_vk.key_hash.clone(),
        c4b_key_hash: c4_vk.key_hash.clone(),
    };
    let t = Instant::now();
    let c4ab_proof = build_and_prove_recursive_bin(
        prover,
        CircuitName::C4abFold,
        &c4ab,
        &format!("{e3_id}-c4ab"),
        artifacts_dir,
    )?;
    push_step(&mut step_timings, "c4ab_fold", t);

    let c0_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::PkBfv,
    )?;
    let c1_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::PkGeneration,
    )?;
    let c2ab_fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C2abFold,
    )?;
    let c3ab_fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C3abFold,
    )?;
    let c4ab_fold_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C4abFold,
    )?;

    let nf = NodeFoldWitness {
        c0_vk: c0_vk.verification_key,
        c0_proof: proof_field_strings(input.c0_proof)?,
        c0_public: proof_public_field_strings(input.c0_proof)?,
        c1_vk: c1_vk.verification_key,
        c1_proof: proof_field_strings(input.c1_proof)?,
        c1_public: proof_public_field_strings(input.c1_proof)?,
        c2ab_vk: c2ab_fold_vk.verification_key,
        c2ab_proof: proof_field_strings(&c2ab_proof)?,
        c2ab_public: proof_public_field_strings(&c2ab_proof)?,
        c3ab_vk: c3ab_fold_vk.verification_key,
        c3ab_proof: proof_field_strings(&c3ab_proof)?,
        c3ab_public: proof_public_field_strings(&c3ab_proof)?,
        c4ab_vk: c4ab_fold_vk.verification_key,
        c4ab_proof: proof_field_strings(&c4ab_proof)?,
        c4ab_public: proof_public_field_strings(&c4ab_proof)?,
        party_id: u64_to_field_hex(input.party_id),
        c0_key_hash: c0_vk.key_hash,
        c1_key_hash: c1_vk.key_hash,
        c2ab_key_hash: c2ab_fold_vk.key_hash,
        c3ab_key_hash: c3ab_fold_vk.key_hash,
        c4ab_key_hash: c4ab_fold_vk.key_hash,
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
            (CiphernodesCommitteeSize::Small, 10, 19),
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
