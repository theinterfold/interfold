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
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::{Computation, DkgInputType};
use e3_zk_helpers::dkg::share_computation::{Inputs, ShareComputationCircuitData};
use rayon::prelude::*;
use serde_json::Value;
use std::time::Instant;

pub use crate::circuits::aggregation::c2_chunk_config::DEFAULT_C2_CHUNK_SIZE;

fn validate_c2_chunk_layout(degree: usize, chunk_size: usize) -> Result<(usize, usize), ZkError> {
    let layout = C2ChunkLayout::from_degree_chunk_size(degree, chunk_size)?;
    let compiled = C2ChunkLayout::compiled(degree)?;
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

fn slice_coefficients(
    values: &[Value],
    start: usize,
    chunk_size: usize,
    context: &str,
) -> Result<Vec<Value>, ZkError> {
    let end = start.checked_add(chunk_size).ok_or_else(|| {
        ZkError::InvalidInput(format!(
            "{context} coefficient range overflows: start={start}, chunk_size={chunk_size}"
        ))
    })?;
    values
        .get(start..end)
        .map(<[Value]>::to_vec)
        .ok_or_else(|| {
            ZkError::InvalidInput(format!(
                "{context} has {} coefficients, need at least {}",
                values.len(),
                end
            ))
        })
}

/// Generate the terminal C2 proof from all deterministic coefficient chunks.
pub fn prove_chunked_share_computation(
    prover: &ZkProver,
    preset: BfvPreset,
    data: &ShareComputationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<ChunkedShareComputationProofs, ZkError> {
    prove_chunked_share_computation_with_chunk_size(
        prover,
        preset,
        data,
        e3_id,
        artifacts_dir,
        DEFAULT_C2_CHUNK_SIZE,
    )
}

pub fn prove_chunked_share_computation_with_chunk_size(
    prover: &ZkProver,
    preset: BfvPreset,
    data: &ShareComputationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
    chunk_size: usize,
) -> Result<ChunkedShareComputationProofs, ZkError> {
    let degree = preset
        .threshold_counterpart()
        .unwrap_or(preset)
        .metadata()
        .degree;
    let (chunk_count, _batch_count) = validate_c2_chunk_layout(degree, chunk_size)?;
    let inputs = Inputs::compute(preset, data)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    let base_json = inputs
        .to_json()
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let chunk_circuit = match data.dkg_input_type {
        DkgInputType::SecretKey => CircuitName::SkShareComputationChunk,
        DkgInputType::SmudgingNoise => CircuitName::ESmShareComputationChunk,
    };
    let y = base_json
        .get("y")
        .and_then(Value::as_array)
        .ok_or_else(|| ZkError::SerializationError("C2 input is missing y".into()))?;
    if y.len() != degree {
        return Err(ZkError::InvalidInput(format!(
            "C2 y has {} coefficients, expected {degree}",
            y.len()
        )));
    }

    let mut step_timings = Vec::new();
    let t_chunks = Instant::now();
    let chunks: Vec<e3_events::Proof> = (0..chunk_count)
        .into_par_iter()
        .map(|chunk_idx| {
            let start = chunk_idx * chunk_size;
            let mut chunk_json = serde_json::Map::new();
            chunk_json.insert("chunk_idx".into(), Value::from(chunk_idx as u64));
            let secret_key = match data.dkg_input_type {
                DkgInputType::SecretKey => "sk_secret",
                DkgInputType::SmudgingNoise => "e_sm_secret",
            };
            let secret = base_json.get(secret_key).ok_or_else(|| {
                ZkError::SerializationError(format!("C2 input is missing {secret_key}"))
            })?;
            let secret_chunk = if data.dkg_input_type == DkgInputType::SecretKey {
                let coefficients = secret
                    .as_object()
                    .and_then(|object| object.get("coefficients"))
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        ZkError::SerializationError("SK secret JSON is malformed".into())
                    })?;
                Value::Object(
                    [(
                        "coefficients".into(),
                        Value::Array(slice_coefficients(
                            coefficients,
                            start,
                            chunk_size,
                            "SK secret",
                        )?),
                    )]
                    .into_iter()
                    .collect(),
                )
            } else {
                let limbs = secret.as_array().ok_or_else(|| {
                    ZkError::SerializationError("ESM secret JSON must contain CRT limbs".into())
                })?;
                Value::Array(
                    limbs
                        .iter()
                        .map(|limb| {
                            let values = limb
                                .as_object()
                                .and_then(|object| object.get("coefficients"))
                                .and_then(Value::as_array)
                                .ok_or_else(|| {
                                    ZkError::SerializationError(
                                        "ESM secret JSON must contain CRT limbs".into(),
                                    )
                                })?;
                            Ok::<Value, ZkError>(Value::Object(
                                [(
                                    "coefficients".into(),
                                    Value::Array(slice_coefficients(
                                        values,
                                        start,
                                        chunk_size,
                                        "ESM secret limb",
                                    )?),
                                )]
                                .into_iter()
                                .collect(),
                            ))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                )
            };
            chunk_json.insert("secret_chunk".into(), secret_chunk);
            chunk_json.insert(
                "y_chunk".into(),
                Value::Array(y[start..start + chunk_size].to_vec()),
            );
            let input_map = inputs_json_to_input_map(&Value::Object(chunk_json))?;
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
        .collect::<Result<Vec<_>, _>>()?;
    push_step(&mut step_timings, "chunks", t_chunks);

    let t_batches = Instant::now();
    let batches = generate_c2_chunk_batches(
        prover,
        chunk_circuit,
        &chunks,
        chunk_count,
        degree,
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
        assert!(validate_c2_chunk_layout(8192, 256).is_err());
    }
}
