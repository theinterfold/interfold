// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{bail, Result};
use e3_events::CircuitName;
use e3_zk_prover::CircuitVariant;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Case {
    Named(CircuitName),
    Config,
    Ct0,
    Ct1,
}

impl Case {
    pub fn parse(path: &str) -> Result<Self> {
        match path {
            "config" => Ok(Self::Config),
            "threshold/user_data_encryption_ct0" => Ok(Self::Ct0),
            "threshold/user_data_encryption_ct1" => Ok(Self::Ct1),
            _ => [
                CircuitName::PkBfv,
                CircuitName::SkShareComputation,
                CircuitName::ESmShareComputation,
                CircuitName::ShareEncryption,
                CircuitName::DkgShareDecryption,
                CircuitName::PkGeneration,
                CircuitName::PkAggregation,
                CircuitName::ThresholdShareDecryption,
                CircuitName::DecryptedSharesAggregation,
            ]
            .into_iter()
            .find(|name| name.dir_path() == path)
            .map(Self::Named)
            .ok_or_else(|| anyhow::anyhow!("Unsupported leaf circuit: {path}")),
        }
    }
    pub fn path(self) -> String {
        match self {
            Self::Named(name) => name.dir_path(),
            Self::Config => "config".into(),
            Self::Ct0 => "threshold/user_data_encryption_ct0".into(),
            Self::Ct1 => "threshold/user_data_encryption_ct1".into(),
        }
    }
    pub fn name(self) -> String {
        self.path().rsplit('/').next().unwrap().to_string()
    }
}

pub(crate) fn variant(name: &str) -> Result<CircuitVariant> {
    match name {
        "recursive" => Ok(CircuitVariant::Recursive),
        "default" => Ok(CircuitVariant::Default),
        "evm" => Ok(CircuitVariant::Evm),
        _ => bail!("Variant must be recursive, default, or evm"),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Entry {
    Path(String),
    Restricted { name: String, modes: Vec<String> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub circuits: Vec<Entry>,
    pub oracles: Vec<String>,
    pub mode: String,
    pub bin_dir: String,
    pub output_dir: String,
    pub metrics_to_track: Vec<String>,
}

impl Config {
    pub fn select(&self, mode: &str, filters: &[String]) -> Result<Vec<Case>> {
        if self.oracles != ["default"] {
            bail!("The legacy oracle selector has no effect; use --variant with the default oracle entry");
        }
        if self.bin_dir != "../bin" {
            bail!("Custom Noir source directories are not supported; use --artifacts for validated compiled artifacts");
        }
        if self.output_dir.is_empty() {
            bail!("Benchmark output prefix must not be empty");
        }
        for metric in &self.metrics_to_track {
            if ![
                "compilation_time",
                "execution_time",
                "gate_count",
                "vk_generation_time",
                "proof_generation_time",
                "verification_time",
                "circuit_size",
                "witness_size",
                "vk_size",
                "proof_size",
            ]
            .contains(&metric.as_str())
            {
                bail!("Unsupported benchmark metric: {metric}");
            }
        }
        let mut selected = Vec::new();
        for entry in &self.circuits {
            let (path, modes) = match entry {
                Entry::Path(path) => (path, None),
                Entry::Restricted { name, modes } => (name, Some(modes)),
            };
            if !filters.is_empty() && !filters.contains(path) {
                continue;
            }
            if modes.is_some_and(|modes| !modes.iter().any(|value| value == mode)) {
                continue;
            }
            let case = Case::parse(path)?;
            if selected.contains(&case) {
                bail!("Duplicate benchmark case: {path}");
            }
            selected.push(case);
        }
        for path in filters {
            if !selected.iter().any(|case| case.path() == *path) {
                bail!("Circuit is not selected for {mode}: {path}");
            }
        }
        if selected.is_empty() {
            bail!("No benchmark cases selected");
        }
        Ok(selected)
    }
}
