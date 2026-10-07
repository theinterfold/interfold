// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! OpenVM program execution configuration.
//!
//! Extracted from [`AppConfig`] — these types configure external program
//! execution, not the ciphernode itself.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Which OpenVM worker proves.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OpenVmBackend {
    /// The CUDA worker when one is configured and can open a GPU, otherwise the CPU worker.
    #[default]
    Auto,
    Cpu,
    /// The CUDA worker. The service refuses to start when it cannot open a GPU.
    Cuda,
}

impl OpenVmBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
        }
    }
}

/// The OpenVM proving service. Every path is absolute and local to the deployment.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenVmConfig {
    /// The CPU build of `interfold-openvm-prover`.
    #[serde(default)]
    pub prover_bin: Option<PathBuf>,
    /// The CUDA build of `interfold-openvm-prover`.
    #[serde(default)]
    pub prover_bin_cuda: Option<PathBuf>,
    #[serde(default)]
    pub backend: OpenVmBackend,
    /// The directory `cargo openvm setup` wrote the Halo2 key, parameters and verifier to.
    /// Defaults to `~/.openvm`.
    #[serde(default)]
    pub setup_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramConfig {
    openvm: Option<OpenVmConfig>,
    dev: Option<bool>,
    /// The removed RISC Zero and Boundless settings. A config that still has them loads, so that a
    /// ciphernode sharing the file keeps starting after the upgrade; `interfold program` refuses
    /// them (see [`ProgramConfig::ensure_supported`]).
    #[serde(default, rename = "risc0", skip_serializing)]
    legacy_risc0: Option<figment::value::Value>,
}

impl ProgramConfig {
    pub fn openvm(&self) -> Option<&OpenVmConfig> {
        self.openvm.as_ref()
    }

    pub fn dev(&self) -> bool {
        self.dev.unwrap_or(false)
    }

    /// Refuse the removed `program.risc0` section, which no program backend reads any more.
    pub fn ensure_supported(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.legacy_risc0.is_none(),
            "program.risc0 is no longer supported: OpenVM replaced RISC Zero and Boundless. \
             Remove program.risc0 and configure program.openvm, or set program.dev for unproved \
             local runs"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenVmBackend, ProgramConfig};
    use std::path::PathBuf;

    #[test]
    fn deserializes_openvm_worker_configuration() {
        let config: ProgramConfig = serde_yaml::from_str(
            r#"
openvm:
  prover_bin: "/deployment/bin/interfold-openvm-prover"
  prover_bin_cuda: "/deployment/bin/interfold-openvm-prover-cuda"
  backend: cuda
"#,
        )
        .expect("program config must deserialize");

        let openvm = config.openvm().expect("OpenVM config must be present");
        assert_eq!(
            openvm.prover_bin,
            Some(PathBuf::from("/deployment/bin/interfold-openvm-prover"))
        );
        assert_eq!(openvm.backend, OpenVmBackend::Cuda);
        assert!(!config.dev());
    }

    /// Without a backend, a GPU is used when there is one.
    #[test]
    fn the_backend_defaults_to_auto() {
        let config: ProgramConfig =
            serde_yaml::from_str("openvm:\n  prover_bin: /deployment/bin/worker\n").unwrap();
        assert_eq!(config.openvm().unwrap().backend, OpenVmBackend::Auto);
        assert!(serde_yaml::from_str::<ProgramConfig>("openvm:\n  backend: gpu\n").is_err());
    }

    #[test]
    fn rejects_unknown_backend_configuration() {
        assert!(serde_yaml::from_str::<ProgramConfig>("unknown_backend: {}").is_err());
    }

    /// A config written for the RISC Zero backend still loads, so a ciphernode that shares the file
    /// keeps starting, but no program command accepts it.
    #[test]
    fn loads_the_removed_risc0_section_and_refuses_it_for_programs() {
        let config: ProgramConfig = serde_yaml::from_str(
            r#"
risc0:
  risc0_dev_mode: 0
  boundless:
    rpc_url: "https://base.example"
"#,
        )
        .expect("a config with the removed section must still load");
        assert!(config.ensure_supported().is_err());
        assert!(ProgramConfig::default().ensure_supported().is_ok());
    }

    #[test]
    fn development_execution_requires_explicit_selection() {
        assert!(!ProgramConfig::default().dev());
        let config: ProgramConfig = serde_yaml::from_str("dev: true").unwrap();
        assert!(config.dev());
    }
}
