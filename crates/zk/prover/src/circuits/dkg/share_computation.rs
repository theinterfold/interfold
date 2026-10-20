// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::circuits::aggregation::c2_chunk_batch::{
    finalize_c2_chunk_batches, generate_c2_chunk_batches,
};
use crate::circuits::aggregation::c2_chunk_layout::C2ChunkLayout;
use crate::circuits::aggregation::node_dkg_fold::FoldProveStepTiming;
use crate::circuits::utils::inputs_json_to_input_map;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::traits::Provable;
use e3_events::CircuitName;

use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_computation::{Inputs, ShareComputationCircuitData};

use rayon::prelude::*;

use std::time::Instant;

#[derive(Debug)]
pub struct ShareComputationCircuit;

pub use crate::circuits::aggregation::c2_chunk_config::{c2_chunk_size, DEFAULT_C2_CHUNK_SIZE};

/// The trBFV path's single-proof C2: one `sk_share_computation` or `e_sm_share_computation`
/// proof per dealer. The l-BFV path proves C2 in chunks instead
/// ([`prove_chunked_share_computation`]).
impl Provable for ShareComputationCircuit {
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        let inputs = Inputs::compute(config, input)
            .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
        crate::circuits::utils::inputs_json_to_input_map(&inputs.to_json())
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

fn validate_c2_chunk_layout(
    degree: usize,
    n_parties: usize,
    chunk_size: usize,
) -> Result<(usize, usize), ZkError> {
    let layout = C2ChunkLayout::from_degree_chunk_size(degree, chunk_size)?;
    let compiled = C2ChunkLayout::compiled(degree, n_parties)?;
    if layout.chunk_count != compiled.chunk_count {
        return Err(ZkError::InvalidInput(format!(
            "C2 chunk size {chunk_size} produces {} chunks, but the selected artifacts require {}",
            layout.chunk_count, compiled.chunk_count
        )));
    }
    if layout.batch_count != compiled.batch_count {
        return Err(ZkError::InvalidInput(format!(
            "C2 chunk size {chunk_size} produces {} batches, but the selected artifacts require {}",
            layout.batch_count, compiled.batch_count
        )));
    }
    Ok((layout.chunk_count, layout.batch_count))
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

/// How many C2 chunk leaves are proved at once (`E3_C2_CHUNK_PROOF_CONCURRENCY`, default 2).
///
/// Each leaf proof runs its own `bb prove`, which uses every core, so the bound costs little time
/// while keeping the peak at about two leaf proofs (roughly 9 GB at secure-16384, small committee).
fn c2_chunk_proof_concurrency() -> usize {
    std::env::var("E3_C2_CHUNK_PROOF_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&jobs| jobs > 0)
        .unwrap_or(2)
}

/// Generate the terminal C2 proof from all deterministic coefficient chunks.
pub fn prove_chunked_share_computation(
    prover: &ZkProver,
    config: &e3_zk_config::dkg::share_computation::Configs,
    data: &ShareComputationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<ChunkedShareComputationProofs, ZkError> {
    prove_chunked_share_computation_with_chunk_size(
        prover,
        config,
        data,
        e3_id,
        artifacts_dir,
        config.chunk_size,
    )
}

pub fn prove_chunked_share_computation_with_chunk_size(
    prover: &ZkProver,
    config: &e3_zk_config::dkg::share_computation::Configs,
    data: &ShareComputationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
    chunk_size: usize,
) -> Result<ChunkedShareComputationProofs, ZkError> {
    let degree = config.params.degree();
    let (chunk_count, _batch_count) =
        validate_c2_chunk_layout(degree, config.committee.values().n, chunk_size)?;
    let chunk_config = config
        .clone()
        .with_chunk_size(chunk_size)
        .map_err(|e| ZkError::InvalidInput(e.to_string()))?;
    let inputs = Inputs::compute(&chunk_config, data)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    let chunk_circuit = match data.dkg_input_type {
        DkgInputType::SecretKey => CircuitName::SkShareComputationChunk,
        DkgInputType::SmudgingNoise => CircuitName::ESmShareComputationChunk,
    };
    let mut step_timings = Vec::new();
    let t_chunks = Instant::now();
    // Each chunk leaf is a separate `bb prove` that already uses every core, so proving many at once
    // buys little speed but multiplies memory: at the small committee all 8 secure-16384 leaves at
    // once exceed a 32 GB node. A small dedicated pool bounds how many run together.
    let chunk_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(c2_chunk_proof_concurrency())
        .build()
        .map_err(|error| ZkError::ProveFailed(format!("C2 chunk proof pool: {error}")))?;
    let chunks: Vec<e3_events::Proof> = chunk_pool.install(|| {
        (0..chunk_count)
            .into_par_iter()
            .map(|chunk_idx| {
                let chunk_json = inputs
                    .chunk_json(&chunk_config, chunk_idx)
                    .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
                let input_map = inputs_json_to_input_map(&chunk_json)?;
                let circuit_path = prover
                    .circuits_dir(e3_events::CircuitVariant::Recursive, artifacts_dir)
                    .join(chunk_circuit.dir_path())
                    .join(format!("{}.json", chunk_circuit.as_str()));
                let compiled = crate::witness::CompiledCircuit::from_file(&circuit_path)?;
                let witness = crate::witness::WitnessGenerator::new()
                    .generate_witness(&compiled, input_map)
                    .map_err(|error| {
                        ZkError::WitnessGenerationFailed(format!(
                            "C2 chunk {chunk_idx} witness: {error}"
                        ))
                    })?;
                let proof = prover.generate_proof_with_variant(
                    chunk_circuit,
                    &witness,
                    &format!("{e3_id}-c2-chunk-{chunk_idx}"),
                    e3_events::CircuitVariant::Recursive,
                    artifacts_dir,
                )?;
                Ok::<_, ZkError>(proof)
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    push_step(&mut step_timings, "chunks", t_chunks);

    let t_batches = Instant::now();
    let batches = generate_c2_chunk_batches(
        prover,
        chunk_circuit,
        &chunks,
        chunk_count,
        degree,
        config.committee.values().n,
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

#[cfg(test)]
mod tests {
    use super::validate_c2_chunk_layout;

    #[test]
    fn rejects_chunk_size_with_a_different_compiled_chunk_count() {
        assert!(validate_c2_chunk_layout(8192, 3, 256).is_err());
    }

    #[test]
    fn secure_16384_accepts_only_the_committee_chunk_size() {
        assert!(validate_c2_chunk_layout(16384, 3, 8192).is_ok());
        assert!(validate_c2_chunk_layout(16384, 3, 4096).is_err());
        assert!(validate_c2_chunk_layout(16384, 3, 512).is_err());
        assert!(validate_c2_chunk_layout(16384, 19, 2048).is_ok());
        assert!(validate_c2_chunk_layout(16384, 19, 512).is_err());
    }
}
