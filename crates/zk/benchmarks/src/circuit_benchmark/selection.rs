// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{bail, Result};
use e3_zk_config::{CircuitName, CircuitVariant};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Case {
    Named(CircuitName),
    Config,
    /// `threshold/user_data_encryption`: both encryption legs in one circuit.
    Ude,
}

impl Case {
    pub fn parse(path: &str) -> Result<Self> {
        match path {
            "config" => Ok(Self::Config),
            "threshold/user_data_encryption" => Ok(Self::Ude),
            _ => [
                CircuitName::PkBfv,
                CircuitName::SkShareComputation,
                CircuitName::SkShareComputationChain,
                CircuitName::SkShareComputationChainLast,
                CircuitName::ESmShareComputation,
                CircuitName::ESmShareComputationChain,
                CircuitName::ESmShareComputationChainLast,
                CircuitName::SkShareComputationChunk,
                CircuitName::ESmShareComputationChunk,
                CircuitName::ShareEncryption,
                CircuitName::DkgShareDecryption,
                CircuitName::DkgShareDecryptionLimb0,
                CircuitName::DkgShareDecryptionLimb1,
                CircuitName::DkgShareDecryptionLimb2,
                CircuitName::PkGeneration,
                CircuitName::PkAggregation,
                CircuitName::LbfvPkGeneration,
                CircuitName::LbfvPkAggregation,
                CircuitName::RlkGeneration,
                CircuitName::RlkAggregation,
                CircuitName::ThresholdShareDecryption,
                CircuitName::DecryptedSharesAggregation,
                CircuitName::DecryptedSharesAggregationWide,
            ]
            .into_iter()
            .find(|name| name.package_path() == path)
            .map(Self::Named)
            .ok_or_else(|| anyhow::anyhow!("Unsupported leaf circuit: {path}")),
        }
    }
    /// The circuit's package under `circuits/bin`, which is also its name in the benchmark config.
    pub fn path(self) -> String {
        match self {
            Self::Named(name) => name.package_path(),
            Self::Config => "config".into(),
            Self::Ude => "threshold/user_data_encryption".into(),
        }
    }
    /// Where the circuit's artifacts sit below a variant directory: the l-BFV circuits are
    /// published flat, like every other circuit.
    pub fn artifact_path(self) -> String {
        match self {
            Self::Named(name) => name.dir_path(),
            other => other.path(),
        }
    }
    pub fn name(self) -> String {
        self.path().rsplit('/').next().unwrap().to_string()
    }
    /// The variant this case runs in. The C2 chunk and C4 limb circuits are only built, proven and
    /// verified non-ZK (`default`), whichever variant the run requests.
    pub fn variant(self, requested: CircuitVariant) -> CircuitVariant {
        match self {
            Self::Named(
                CircuitName::SkShareComputationChain
                | CircuitName::SkShareComputationChainLast
                | CircuitName::ESmShareComputationChain
                | CircuitName::ESmShareComputationChainLast
                | CircuitName::DkgShareDecryptionLimb0
                | CircuitName::DkgShareDecryptionLimb1
                | CircuitName::DkgShareDecryptionLimb2,
            ) => CircuitVariant::Default,
            _ => requested,
        }
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
    Restricted {
        name: String,
        #[serde(default)]
        modes: Vec<String>,
        #[serde(default)]
        presets: Vec<String>,
    },
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
    pub fn select_for_preset(
        &self,
        mode: &str,
        preset: &str,
        filters: &[String],
    ) -> Result<Vec<Case>> {
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
            let (path, modes, presets) = match entry {
                Entry::Path(path) => (path, &[][..], &[][..]),
                Entry::Restricted {
                    name,
                    modes,
                    presets,
                } => (name, modes.as_slice(), presets.as_slice()),
            };
            if !filters.is_empty() && !filters.contains(path) {
                continue;
            }
            if (!modes.is_empty() && !modes.iter().any(|value| value == mode))
                || (!presets.is_empty() && !presets.iter().any(|value| value == preset))
            {
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
