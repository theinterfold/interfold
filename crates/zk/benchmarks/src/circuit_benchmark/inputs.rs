// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    records::{Record, SharedPreparation, Stage},
    selection::Case,
};
use anyhow::{bail, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_config::{dkg, threshold, DkgInputType};
use e3_zk_prover::{CompiledCircuit, Provable};
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
    if record.circuit_path != format!("circuits/bin/{}", resolved.dir_path()) {
        bail!("Production adapter resolved a different circuit: {resolved}");
    }
    let start = Instant::now();
    let result = adapter
        .build_inputs(&config, &sample)
        .map_err(anyhow::Error::from);
    record.preparation.finish(start.elapsed(), &result);
    result
}

pub(crate) fn prepare(
    material: &Material,
    case: Case,
    compiled: &CompiledCircuit,
    ude: &mut Option<Ude>,
    shared: &mut Vec<SharedPreparation>,
    record: &mut Record,
) -> Result<InputMap> {
    let m = material;
    match case {
        Case::Config => Ok(InputMap::new()),
        Case::Ct0 | Case::Ct1 => {
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
        Case::Named(CircuitName::SkShareComputation | CircuitName::ESmShareComputation) => {
            let input_type = if case == Case::Named(CircuitName::SkShareComputation) {
                DkgInputType::SecretKey
            } else {
                DkgInputType::SmudgingNoise
            };
            let config = dkg::share_computation::Configs::new(m.preset, &m.threshold, m.committee)?;
            let sample =
                e3_zk_samples::dkg::share_computation::generate(&config, m.preset, input_type)?;
            prepared(
                e3_zk_prover::ShareComputationCircuit,
                config,
                sample,
                record,
            )
        }
        Case::Named(CircuitName::ShareEncryption) => {
            let config = dkg::share_encryption::Configs::new(&m.dkg)?;
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
        Case::Named(CircuitName::DkgShareDecryption) => {
            let config = dkg::share_decryption::Configs::new(&m.threshold, &m.dkg)?;
            let sample = e3_zk_samples::dkg::share_decryption::generate(
                &config,
                m.preset,
                m.committee.values(),
                DkgInputType::SecretKey,
            )?;
            prepared(
                e3_zk_prover::DkgShareDecryptionCircuit,
                config,
                sample,
                record,
            )
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
        Case::Named(CircuitName::DecryptedSharesAggregation) => {
            let config =
                threshold::decrypted_shares_aggregation::Configs::new(&m.threshold, m.committee)?;
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
