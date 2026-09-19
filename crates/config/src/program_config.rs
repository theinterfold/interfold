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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenVmConfig {
    pub repository: std::path::PathBuf,
    pub prover_bin: std::path::PathBuf,
    pub prover_config: std::path::PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramConfig {
    openvm: Option<OpenVmConfig>,
    dev: Option<bool>,
}

impl ProgramConfig {
    pub fn openvm(&self) -> Option<&OpenVmConfig> {
        self.openvm.as_ref()
    }

    pub fn dev(&self) -> bool {
        self.dev.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::ProgramConfig;

    #[test]
    fn deserializes_openvm_worker_configuration() {
        let config: ProgramConfig = serde_yaml::from_str(
            r#"
openvm:
  repository: "/deployment/source"
  prover_bin: "/deployment/bin/interfold-openvm-prover"
  prover_config: "/deployment/prover.json"
"#,
        )
        .expect("program config must deserialize");

        let openvm = config.openvm().expect("OpenVM config must be present");
        assert_eq!(
            openvm.prover_bin,
            std::path::PathBuf::from("/deployment/bin/interfold-openvm-prover")
        );
        assert!(!config.dev());
    }

    #[test]
    fn rejects_unknown_backend_configuration() {
        assert!(serde_yaml::from_str::<ProgramConfig>("unknown_backend: {}").is_err());
    }

    #[test]
    fn development_execution_requires_explicit_selection() {
        assert!(!ProgramConfig::default().dev());
        let config: ProgramConfig = serde_yaml::from_str("dev: true").unwrap();
        assert!(config.dev());
    }
}
