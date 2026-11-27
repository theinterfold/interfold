// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::circuits::aggregation::c2_chunk_batch::{
    finalize_c2_chunk_batches, generate_c2_chunk_batches,
};
use crate::circuits::aggregation::c2_chunk_config::c2_proof_pool;
use crate::circuits::aggregation::c2_chunk_layout::C2ChunkLayout;
use crate::circuits::aggregation::node_dkg_fold::FoldProveStepTiming;
use crate::circuits::utils::inputs_json_to_input_map;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::traits::Provable;
use e3_zk_config::CircuitName;
use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_computation::{Inputs, ShareComputationCircuitData};

use rayon::prelude::*;

use std::time::Instant;

#[derive(Debug)]
pub struct ShareComputationCircuit;

pub use crate::circuits::aggregation::c2_chunk_config::c2_chunk_size;

/// The trBFV path's C2: one final `sk_share_computation` or `e_sm_share_computation` proof per
/// dealer, over its chunk chain. The l-BFV path proves C2 in root-committed chunks instead
/// ([`prove_chunked_share_computation`]).
impl Provable for ShareComputationCircuit {
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        let _ = (config, input);
        Err(ZkError::InputsGenerationFailed(
            "C2 is proven as a chunk chain; its final inputs need the chunk proofs".into(),
        ))
    }

    /// Proves the chunk chain and the final C2 proof (see
    /// [`crate::circuits::aggregation::c2_chain`]).
    fn prove_with_variant(
        &self,
        prover: &crate::ZkProver,
        config: &Self::Config,
        input: &Self::Input,
        e3_id: &str,
        variant: e3_events::CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<e3_events::Proof, ZkError> {
        crate::circuits::aggregation::c2_chain::prove_share_computation_chain(
            prover,
            config,
            input,
            e3_id,
            variant,
            artifacts_dir,
        )
    }

    /// Verifies the final C2 proof and its chunk key tree. The final circuit verifies its chunk
    /// proofs against keys it only exposes as a hash, so a valid outer proof alone does not show
    /// the chunks ran this node's chunk circuits.
    fn verify_with_variant(
        &self,
        prover: &crate::ZkProver,
        proof: &e3_events::Proof,
        e3_id: &str,
        party_id: u64,
        variant: e3_events::CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        if !self.valid_circuits().contains(&proof.circuit) {
            return Err(ZkError::VerifyFailed(format!(
                "circuit mismatch: expected one of {:?}, got {}",
                self.valid_circuits(),
                proof.circuit
            )));
        }
        Ok(
            prover.verify_proof_with_variant(proof, e3_id, party_id, variant, artifacts_dir)?
                && crate::circuits::aggregation::chain_keys::check_key_tree(
                    prover,
                    proof,
                    artifacts_dir,
                )?,
        )
    }

    type Config = e3_zk_config::dkg::share_computation::Configs;
    type Input = ShareComputationCircuitData;

    fn resolve_circuit_name(&self, _config: &Self::Config, input: &Self::Input) -> CircuitName {
        match input.dkg_input_type {
            DkgInputType::SecretKey => CircuitName::SkShareComputation,
            DkgInputType::SmudgingNoise => CircuitName::ESmShareComputation,
        }
    }

    fn valid_circuits(&self) -> Vec<CircuitName> {
        vec![
            CircuitName::SkShareComputation,
            CircuitName::ESmShareComputation,
        ]
    }

    fn circuit(&self) -> CircuitName {
        CircuitName::SkShareComputation
    }
}

pub struct ChunkedShareComputationProofs {
    pub proof: e3_events::Proof,
    pub chunk_count: usize,
    /// Per-step prove wall time inside [`prove_chunked_share_computation`] (for benchmarks / audit reports).
    pub step_timings: Vec<FoldProveStepTiming>,
}

fn push_step(timings: &mut Vec<FoldProveStepTiming>, step: &str, started: Instant) {
    timings.push(FoldProveStepTiming {
        step: step.to_string(),
        seconds: started.elapsed().as_secs_f64(),
    });
}

/// Generate the terminal C2 proof from all deterministic coefficient chunks.
///
/// `config.chunk_size` must be the chunk size the selected artifacts were compiled for.
pub fn prove_chunked_share_computation(
    prover: &ZkProver,
    config: &e3_zk_config::dkg::share_computation::Configs,
    data: &ShareComputationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<ChunkedShareComputationProofs, ZkError> {
    let degree = config.params.degree();
    let n_parties = config.committee.values().n;
    let layout = C2ChunkLayout::compiled(degree, n_parties)?;
    if config.chunk_size != layout.chunk_size {
        return Err(ZkError::InvalidInput(format!(
            "C2 chunk size {} does not match the chunk size {} the selected artifacts use",
            config.chunk_size, layout.chunk_size
        )));
    }
    let chunk_count = layout.chunk_count;
    let inputs = Inputs::compute(config, data)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    let chunk_circuit = match data.dkg_input_type {
        DkgInputType::SecretKey => CircuitName::SkShareComputationChunk,
        DkgInputType::SmudgingNoise => CircuitName::ESmShareComputationChunk,
    };
    let circuit_path = prover
        .circuits_dir(e3_events::CircuitVariant::Recursive, artifacts_dir)
        .join(chunk_circuit.dir_path())
        .join(format!("{}.json", chunk_circuit.as_str()));
    let compiled = crate::witness::CompiledCircuit::from_file(&circuit_path)?;
    let mut step_timings = Vec::new();
    let t_chunks = Instant::now();
    let proof_pool = c2_proof_pool()?;
    let chunks: Vec<e3_events::Proof> = proof_pool.install(|| {
        (0..chunk_count)
            .into_par_iter()
            .map(|chunk_idx| {
                let chunk_json = inputs
                    .chunk_json(config, chunk_idx)
                    .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
                let input_map = inputs_json_to_input_map(&chunk_json)?;
                let witness = crate::witness::WitnessGenerator::new()
                    .generate_witness(&compiled, input_map)
                    .map_err(|error| {
                        ZkError::WitnessGenerationFailed(format!(
                            "C2 chunk {chunk_idx} witness: {error}"
                        ))
                    })?;
                let job_id = format!("{e3_id}-c2-chunk-{chunk_idx}");
                let proof = prover.generate_proof_with_variant(
                    chunk_circuit,
                    &witness,
                    &job_id,
                    e3_events::CircuitVariant::Recursive,
                    artifacts_dir,
                )?;
                let _ = prover.cleanup(&job_id);
                Ok::<_, ZkError>(proof)
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    push_step(&mut step_timings, "chunks", t_chunks);

    let t_batches = Instant::now();
    let batches = generate_c2_chunk_batches(
        prover,
        &proof_pool,
        chunk_circuit,
        &chunks,
        degree,
        n_parties,
        e3_id,
        artifacts_dir,
    )?;
    push_step(&mut step_timings, "batches", t_batches);
    let finalizer_circuit = match data.dkg_input_type {
        DkgInputType::SecretKey => CircuitName::SkC2ChunkFinalize,
        DkgInputType::SmudgingNoise => CircuitName::ESmC2ChunkFinalize,
    };
    let t_finalize = Instant::now();
    let proof =
        finalize_c2_chunk_batches(prover, &batches, finalizer_circuit, e3_id, artifacts_dir)?;
    push_step(&mut step_timings, "finalize", t_finalize);
    Ok(ChunkedShareComputationProofs {
        proof,
        chunk_count,
        step_timings,
    })
}
