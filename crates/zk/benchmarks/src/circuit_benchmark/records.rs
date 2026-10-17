// SPDX-License-Identifier: LGPL-3.0-only

use super::{selection::Case, Options};
use anyhow::Result;
use e3_committee::CiphernodesCommitteeSize;
use e3_zk_prover::CircuitVariant;
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Stage {
    pub time_seconds: Option<f64>,
    pub success: Option<bool>,
    pub metric: String,
}
impl Stage {
    pub fn unmeasured(metric: &'static str) -> Self {
        Self {
            time_seconds: None,
            success: None,
            metric: metric.into(),
        }
    }
    pub fn finish<T>(&mut self, duration: Duration, result: &Result<T>) {
        self.time_seconds = Some(duration.as_secs_f64());
        self.success = Some(result.is_ok());
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ArtifactIdentity {
    #[serde(default)]
    pub source_stamp: serde_json::Value,
    pub compiled_path: String,
    pub compiled_sha256: String,
    pub vk_sha256: Option<String>,
    pub artifact_noir_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Record {
    pub schema_version: u32,
    pub circuit_name: String,
    pub circuit_path: String,
    pub mode: String,
    pub oracle_type: String,
    pub variant: String,
    pub timestamp: String,
    pub metric_kind: String,
    pub artifact: Option<ArtifactIdentity>,
    pub preparation: Stage,
    pub compilation: Stage,
    pub shared_preparation_id: Option<String>,
    pub execution: Stage,
    pub vk_generation: Stage,
    pub proof_generation: Stage,
    pub verification: Stage,
    pub gates: Gates,
    pub circuit_size_bytes: Option<u64>,
    pub witness_size_bytes: Option<u64>,
    pub vk_size_bytes: Option<u64>,
    pub proof_size_bytes: Option<u64>,
    pub public_inputs_size_bytes: Option<u64>,
    pub proof_hex: Option<String>,
    pub public_inputs_hex: Option<String>,
    pub calldata_gas_proof: Option<u64>,
    pub calldata_gas_public_inputs: Option<u64>,
    pub calldata_gas_total: Option<u64>,
    pub error: Option<String>,
}
#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct Gates {
    pub total_gates: Option<u64>,
    pub acir_opcodes: Option<u64>,
    pub error: Option<String>,
}

impl Record {
    pub fn new(case: Case, mode: &str, variant: CircuitVariant) -> Self {
        Self {
            schema_version: 2,
            circuit_name: case.name(),
            circuit_path: format!("circuits/bin/{}", case.path()),
            mode: mode.into(),
            oracle_type: "default".into(),
            variant: variant.as_str().into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            metric_kind: if matches!(case, Case::Named(_)) {
                "production_bb_adapter_wall"
            } else {
                "external_bb_prove_wall"
            }
            .into(),
            artifact: None,
            preparation: Stage::unmeasured("production_input_preparation_wall"),
            compilation: Stage::unmeasured("external_nargo_compile_wall"),
            shared_preparation_id: None,
            execution: Stage::unmeasured("production_noir_execution_wall"),
            vk_generation: Stage::unmeasured("external_bb_write_vk_wall"),
            proof_generation: Stage::unmeasured(if matches!(case, Case::Named(_)) {
                "production_bb_adapter_wall"
            } else {
                "external_bb_prove_wall"
            }),
            verification: Stage::unmeasured(if matches!(case, Case::Named(_)) {
                "production_bb_adapter_wall"
            } else {
                "external_bb_verify_wall"
            }),
            gates: Gates::default(),
            circuit_size_bytes: None,
            witness_size_bytes: None,
            vk_size_bytes: None,
            proof_size_bytes: None,
            public_inputs_size_bytes: None,
            proof_hex: None,
            public_inputs_hex: None,
            calldata_gas_proof: None,
            calldata_gas_public_inputs: None,
            calldata_gas_total: None,
            error: None,
        }
    }
    pub fn proof_bytes(&mut self, proof: &[u8], public: &[u8]) {
        self.proof_size_bytes = Some(proof.len() as u64);
        self.public_inputs_size_bytes = Some(public.len() as u64);
        self.proof_hex = Some(format!("0x{}", hex::encode(proof)));
        self.public_inputs_hex = Some(format!("0x{}", hex::encode(public)));
        self.calldata_gas_proof = Some(calldata_gas(proof));
        self.calldata_gas_public_inputs = Some(calldata_gas(public));
        self.calldata_gas_total = Some(calldata_gas(proof) + calldata_gas(public));
    }
}
pub(crate) fn calldata_gas(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .map(|value| if *value == 0 { 4 } else { 16 })
        .sum()
}

#[derive(Serialize)]
pub(crate) struct SharedPreparation {
    pub id: &'static str,
    pub preparation: Stage,
}

#[derive(Serialize)]
pub(crate) struct RunMetadata {
    pub schema_version: u32,
    pub benchmark_mode: String,
    pub bfv_preset_subdir: String,
    pub committee: String,
    pub committee_size_n: usize,
    pub committee_threshold_t: usize,
    pub committee_size_h: usize,
    pub variant: String,
    pub artifact_stamp: serde_json::Value,
    pub git_commit: String,
    pub git_branch: String,
    pub git_dirty: bool,
    pub timestamp: String,
    pub bb_version: String,
    pub bb_binary: String,
    pub rust_noir_version: String,
    pub rust_build_profile: &'static str,
    pub runner_sha256: String,
    pub os: String,
    pub arch: String,
    pub logical_cpus: Option<usize>,
    pub proof_aggregation: bool,
    pub multithread_jobs: usize,
    pub verbose: bool,
    pub compilation: Stage,
    pub shared_preparations: Vec<SharedPreparation>,
}
impl RunMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: &Path,
        mode: &str,
        preset: &str,
        committee: CiphernodesCommitteeSize,
        variant: CircuitVariant,
        stamp: serde_json::Value,
        bb_binary: &Path,
        bb: &str,
        noir: &str,
        compilation: Stage,
        options: &Options,
    ) -> Result<Self> {
        let git = |args: &[&str]| {
            super::run(
                std::process::Command::new("git")
                    .args(args)
                    .current_dir(root),
            )
            .map(|value| value.trim().to_string())
        };
        let values = committee.values();
        Ok(Self {
            schema_version: 2,
            benchmark_mode: mode.into(),
            bfv_preset_subdir: preset.into(),
            committee: committee.to_string(),
            committee_size_n: values.n,
            committee_threshold_t: values.threshold,
            committee_size_h: values.h,
            variant: variant.as_str().into(),
            artifact_stamp: stamp,
            git_commit: git(&["rev-parse", "HEAD"])?,
            git_branch: git(&["rev-parse", "--abbrev-ref", "HEAD"])?,
            git_dirty: !git(&["status", "--porcelain"])?.is_empty(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            bb_version: bb.trim().into(),
            bb_binary: bb_binary.display().to_string(),
            rust_noir_version: noir.into(),
            rust_build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "optimized"
            },
            runner_sha256: super::artifacts::digest(&std::env::current_exe()?)?,
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            logical_cpus: std::thread::available_parallelism().ok().map(usize::from),
            proof_aggregation: matches!(options.command.as_str(), "protocol" | "gas")
                || (!options.leaf_only && !options.witness_only),
            multithread_jobs: options.multithread_jobs,
            verbose: options.verbose,
            compilation,
            shared_preparations: Vec::new(),
        })
    }
}
