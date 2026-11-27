// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    records::{Record, SharedPreparation, Stage},
    selection::Case,
};
use anyhow::{bail, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvPreset;
use e3_zk_config::CircuitName;
use e3_zk_config::{dkg, threshold, DkgInputType};
use e3_zk_prover::{CompiledCircuit, Provable, ZkProver};
use fhe::bfv::BfvParameters;
use noirc_abi::InputMap;
use std::{sync::Arc, time::Instant};

pub(crate) struct Material {
    pub preset: BfvPreset,
    pub committee: CiphernodesCommitteeSize,
    pub threshold: Arc<BfvParameters>,
    pub dkg: Arc<BfvParameters>,
}
impl Material {
    pub fn new(preset: BfvPreset, committee: CiphernodesCommitteeSize) -> Result<Self> {
        let (threshold, dkg) = preset.build_pair()?;
        Ok(Self {
            preset,
            committee,
            threshold,
            dkg,
        })
    }
}

pub(crate) struct Ude {
    json: std::result::Result<serde_json::Value, String>,
}

fn prepared<P: Provable>(
    adapter: P,
    config: P::Config,
    sample: P::Input,
    record: &mut Record,
) -> Result<InputMap> {
    let resolved = adapter.resolve_circuit_name(&config, &sample);
    if record.circuit_path != format!("circuits/bin/{}", resolved.package_path()) {
        bail!("Production adapter resolved a different circuit: {resolved}");
    }
    let start = Instant::now();
    let result = adapter
        .build_inputs(&config, &sample)
        .map_err(anyhow::Error::from);
    record.preparation.finish(start.elapsed(), &result);
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare(
    material: &Material,
    case: Case,
    compiled: &CompiledCircuit,
    prover: &ZkProver,
    pair: &str,
    ude: &mut Option<Ude>,
    shared: &mut Vec<SharedPreparation>,
    record: &mut Record,
) -> Result<InputMap> {
    let m = material;
    match case {
        Case::Config => Ok(InputMap::new()),
        Case::Ude => {
            if ude.is_none() {
                let outcome = (|| -> Result<serde_json::Value> {
                    let config = threshold::user_data_encryption::Configs::new(&m.threshold)?;
                    let sample =
                        e3_zk_samples::threshold::user_data_encryption::generate(&m.threshold)?;
                    let start = Instant::now();
                    let result =
                        e3_zk_witness::threshold::user_data_encryption::encrypt_and_prepare(
                            &config, &sample,
                        )
                        .map(|(_, inputs)| inputs.to_json())
                        .map_err(anyhow::Error::from);
                    let mut preparation =
                        Stage::unmeasured("production_encryption_and_preparation_wall");
                    preparation.finish(start.elapsed(), &result);
                    shared.push(SharedPreparation {
                        id: "ude",
                        preparation,
                    });
                    result
                })();
                *ude = Some(Ude {
                    json: outcome.map_err(|error| format!("{error:#}")),
                });
            }
            record.shared_preparation_id = Some("ude".into());
            record.preparation.metric = "production_abi_input_projection_wall".into();
            let start = Instant::now();
            let json = ude
                .as_ref()
                .unwrap()
                .json
                .as_ref()
                .map_err(|error| anyhow::anyhow!("Shared UDE preparation failed: {error}"))?;
            let result = project_ude(json, compiled);
            record.preparation.finish(start.elapsed(), &result);
            result
        }
        Case::Named(CircuitName::PkBfv) => {
            let config = dkg::pk::Configs::new(&m.dkg)?;
            let sample = e3_zk_samples::dkg::pk::generate(&m.dkg)?;
            prepared(e3_zk_prover::PkCircuit, config, sample, record)
        }
        Case::Named(
            name @ (CircuitName::SkShareComputation
            | CircuitName::SkShareComputationChain
            | CircuitName::SkShareComputationChainLast
            | CircuitName::ESmShareComputation
            | CircuitName::ESmShareComputationChain
            | CircuitName::ESmShareComputationChainLast),
        ) => {
            // C2 is proven as a chunk chain: the full-size chunk, the last chunk and the final
            // circuit that verifies them are the three circuits of every C2 proof.
            let input_type = if matches!(
                name,
                CircuitName::SkShareComputation
                    | CircuitName::SkShareComputationChain
                    | CircuitName::SkShareComputationChainLast
            ) {
                DkgInputType::SecretKey
            } else {
                DkgInputType::SmudgingNoise
            };
            let config = dkg::share_computation::Configs::new(m.preset, &m.threshold, m.committee)?;
            let sample =
                e3_zk_samples::dkg::share_computation::generate(&config, m.preset, input_type)?;
            let is_final = matches!(
                name,
                CircuitName::SkShareComputation | CircuitName::ESmShareComputation
            );
            // The final circuit's inputs are the chunk proofs, so preparing them proves the chain.
            // Its chunk circuits are artifacts: they load before the timer starts.
            let chunks = if is_final {
                record.preparation.metric = "chunk_chain_proving_and_input_projection_wall".into();
                Some(e3_zk_prover::ChunkCircuits::load(prover, input_type, pair)?)
            } else {
                None
            };
            let start = Instant::now();
            let result = (|| -> Result<InputMap> {
                if let Some(chunks) = &chunks {
                    let (_, json) = e3_zk_prover::final_circuit_inputs(
                        prover,
                        &config,
                        &sample,
                        chunks,
                        "benchmark-c2",
                        pair,
                    )?;
                    return Ok(e3_zk_prover::inputs_json_to_input_map(&json)?);
                }
                let inputs =
                    e3_zk_witness::dkg::share_computation::Inputs::compute(&config, &sample)?;
                let chain =
                    e3_zk_witness::dkg::share_computation_chain::Chain::compute(&config, &inputs)?;
                let chunk = if matches!(
                    name,
                    CircuitName::SkShareComputationChainLast
                        | CircuitName::ESmShareComputationChainLast
                ) {
                    chain.chunks.last()
                } else {
                    chain.chunks.first()
                }
                .expect("a chain has chunks");
                Ok(e3_zk_prover::inputs_json_to_input_map(&chunk.to_json())?)
            })();
            record.preparation.finish(start.elapsed(), &result);
            result
        }
        Case::Named(
            CircuitName::SkShareComputationChunk | CircuitName::ESmShareComputationChunk,
        ) => {
            let input_type = if case == Case::Named(CircuitName::SkShareComputationChunk) {
                DkgInputType::SecretKey
            } else {
                DkgInputType::SmudgingNoise
            };
            let config = dkg::share_computation::Configs::new(m.preset, &m.threshold, m.committee)?;
            let sample =
                e3_zk_samples::dkg::share_computation::generate(&config, m.preset, input_type)?;
            let start = Instant::now();
            let result = (|| -> Result<InputMap> {
                let json =
                    e3_zk_witness::dkg::share_computation::prepare_chunk(&config, &sample, 0)?;
                Ok(e3_zk_prover::inputs_json_to_input_map(&json)?)
            })();
            record.preparation.finish(start.elapsed(), &result);
            result
        }
        Case::Named(CircuitName::ShareEncryption) => {
            let config = dkg::share_encryption::Configs::new(&m.dkg)?
                .with_preset(m.preset)?
                .with_chunk_size(e3_zk_config::chunks::c2_chunk_size(
                    m.threshold.degree(),
                    m.committee.values().n,
                ))?;
            let sample = e3_zk_samples::dkg::share_encryption::generate(
                &m.threshold,
                &m.dkg,
                m.preset,
                m.committee.values(),
                DkgInputType::SecretKey,
                m.preset.search_defaults().unwrap().z,
            )?;
            prepared(e3_zk_prover::ShareEncryptionCircuit, config, sample, record)
        }
        Case::Named(
            name @ (CircuitName::DkgShareDecryption
            | CircuitName::DkgShareDecryptionLimb0
            | CircuitName::DkgShareDecryptionLimb1
            | CircuitName::DkgShareDecryptionLimb2),
        ) => {
            // C4 is proven as a limb chain: the final circuit's inputs are the limb proofs, and
            // each limb circuit is measured on its own limb of the same sample.
            let config =
                dkg::share_decryption::Configs::new(&m.threshold, &m.dkg)?.with_preset(m.preset)?;
            let sample = e3_zk_samples::dkg::share_decryption::generate(
                &config,
                m.preset,
                m.committee.values(),
                DkgInputType::SecretKey,
            )?;
            // The limb circuits are artifacts: they load before the timer starts.
            let limbs = if name == CircuitName::DkgShareDecryption {
                record.preparation.metric = "limb_chain_proving_and_input_projection_wall".into();
                Some(e3_zk_prover::LimbCircuits::load(prover, pair)?)
            } else {
                None
            };
            let start = Instant::now();
            let result = (|| -> Result<InputMap> {
                if let Some(limbs) = &limbs {
                    let json = e3_zk_prover::final_share_decryption_inputs(
                        prover,
                        &config,
                        &sample,
                        limbs,
                        "benchmark-c4",
                        pair,
                    )?;
                    return Ok(e3_zk_prover::inputs_json_to_input_map(&json)?);
                }
                let inputs =
                    e3_zk_witness::dkg::share_decryption::Inputs::compute(&config, &sample)?;
                let chain = e3_zk_witness::dkg::share_decryption_chain::LimbChain::compute(
                    &config, &inputs,
                )?;
                let limb = match name {
                    CircuitName::DkgShareDecryptionLimb0 => 0,
                    CircuitName::DkgShareDecryptionLimb1 => 1,
                    _ => 2,
                };
                Ok(e3_zk_prover::inputs_json_to_input_map(
                    &chain.limbs[limb].to_json(),
                )?)
            })();
            record.preparation.finish(start.elapsed(), &result);
            result
        }
        Case::Named(CircuitName::PkGeneration) => {
            let config =
                threshold::pk_generation::Configs::new(m.preset, &m.threshold, m.committee)?;
            let sample = e3_zk_samples::threshold::pk_generation::generate(&config)?;
            prepared(e3_zk_prover::PkGenerationCircuit, config, sample, record)
        }
        Case::Named(CircuitName::PkAggregation) => {
            let config = threshold::pk_aggregation::Configs::new(&m.threshold, m.committee)?;
            let sample = e3_zk_samples::threshold::pk_aggregation::generate(&config)?;
            prepared(e3_zk_prover::PkAggregationCircuit, config, sample, record)
        }
        Case::Named(CircuitName::LbfvPkGeneration) => {
            let config =
                threshold::pk_generation::Configs::new(m.preset, &m.threshold, m.committee)?;
            let sample = e3_zk_samples::threshold::lbfv_pk_generation::generate_sample_for_row(
                m.preset,
                m.committee.values(),
                0,
            )?;
            prepared(
                e3_zk_prover::LbfvPkGenerationCircuit,
                config,
                sample,
                record,
            )
        }
        Case::Named(CircuitName::LbfvPkAggregation) => {
            let config = threshold::lbfv_pk_aggregation::LbfvPkAggregationConfigs::new(
                m.preset,
                &m.threshold,
                m.committee,
            )?;
            let sample = e3_zk_samples::threshold::lbfv_pk_aggregation::generate_sample_for_row(
                m.preset,
                m.committee.values(),
                0,
            )?;
            prepared(
                e3_zk_prover::LbfvPkAggregationCircuit,
                config,
                sample,
                record,
            )
        }
        Case::Named(CircuitName::RlkGeneration) => {
            let config = threshold::rlk_generation::RlkGenerationConfigs::new(
                m.preset,
                &m.threshold,
                m.committee,
            )?;
            let sample = e3_zk_samples::threshold::rlk_generation::generate_sample_for_row(
                m.preset,
                m.committee.values(),
                0,
            )?;
            prepared(e3_zk_prover::RlkGenerationCircuit, config, sample, record)
        }
        Case::Named(CircuitName::RlkAggregation) => {
            let config = threshold::rlk_aggregation::RlkAggregationConfigs::new(
                m.preset,
                &m.threshold,
                m.committee,
            )?;
            let sample = e3_zk_samples::threshold::rlk_aggregation::generate_sample_for_row(
                m.preset,
                m.committee.values(),
                0,
                e3_zk_witness::threshold::rlk_aggregation::RlkAggregationComponent::D0,
            )?;
            prepared(e3_zk_prover::RlkAggregationCircuit, config, sample, record)
        }
        Case::Named(CircuitName::ThresholdShareDecryption) => {
            let config = threshold::share_decryption::Configs::new(&m.threshold)?;
            let sample = e3_zk_samples::threshold::share_decryption::generate(
                &m.threshold,
                m.preset,
                m.committee.values(),
            )?;
            prepared(
                e3_zk_prover::ThresholdShareDecryptionCircuit,
                config,
                sample,
                record,
            )
        }
        Case::Named(
            CircuitName::DecryptedSharesAggregation | CircuitName::DecryptedSharesAggregationWide,
        ) => {
            let config =
                threshold::decrypted_shares_aggregation::Configs::new(&m.threshold, m.committee)?
                    .with_preset(m.preset)?;
            let sample = e3_zk_samples::threshold::decrypted_shares_aggregation::generate(
                &config, m.preset,
            )?;
            prepared(
                e3_zk_prover::DecryptedSharesAggregationCircuit,
                config,
                sample,
                record,
            )
        }
        Case::Named(name) => bail!("No independent leaf fixture for {name}"),
    }
}

pub(crate) fn project_ude(
    json: &serde_json::Value,
    compiled: &CompiledCircuit,
) -> Result<InputMap> {
    let mut values = serde_json::Map::new();
    for parameter in &compiled.abi.parameters {
        let value = json.get(&parameter.name).ok_or_else(|| {
            anyhow::anyhow!("Prepared UDE material has no ABI input {}", parameter.name)
        })?;
        values.insert(parameter.name.clone(), value.clone());
    }
    Ok(e3_zk_prover::inputs_json_to_input_map(
        &serde_json::Value::Object(values),
    )?)
}
