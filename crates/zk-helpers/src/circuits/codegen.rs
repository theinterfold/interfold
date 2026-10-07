// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit artifact types and I/O.
//!
//! [`CircuitCodegen`] is implemented by circuits that can produce [`Artifacts`]
//! (Prover.toml and configs.nr). Use [`write_artifacts`] to write them to disk.

use crate::errors::CircuitsErrors;
use std::path::Path;

/// Prover TOML file content (circuit inputs).
pub type CodegenToml = String;
/// Noir configs file content (global constants for the prover).
pub type CodegenConfigs = String;

/// Generated files for a circuit: Prover TOML and Noir configs.
#[derive(Debug, Clone)]
pub struct Artifacts {
    /// Prover.toml content (circuit inputs).
    pub toml: CodegenToml,
    /// configs.nr content (constants for the Noir prover).
    pub configs: CodegenConfigs,
}

/// Trait for circuits that can generate Prover.toml and configs.nr from circuit-specific data.
pub trait CircuitCodegen: crate::registry::Circuit {
    /// Circuit-specific BFV threshold parameters preset.
    type Preset;
    /// Circuit-specific codegen data (e.g. preset + public key).
    type Data;
    /// Error type for codegen failures.
    type Error;

    /// Produces [`Artifacts`] for this circuit from the given input.
    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error>;
}

/// Writes the Prover TOML string to `path/Prover.toml`, or `./Prover.toml` if `path` is `None`.
pub fn write_toml(toml: &CodegenToml, path: Option<&Path>) -> Result<(), CircuitsErrors> {
    let toml_path = path.unwrap_or_else(|| Path::new("."));
    let toml_path = toml_path.join("Prover.toml");
    Ok(std::fs::write(toml_path, toml)?)
}

/// Writes the Noir configs string to `path/configs.nr`, or `./configs.nr` if `path` is `None`.
pub fn write_configs(configs: &CodegenConfigs, path: Option<&Path>) -> Result<(), CircuitsErrors> {
    let configs_path = path.unwrap_or_else(|| Path::new("."));
    let configs_path = configs_path.join("configs.nr");
    Ok(std::fs::write(configs_path, configs)?)
}

/// Writes Prover.toml (if `toml` is `Some`) and always configs.nr into the given directory
/// (or current directory if `path` is `None`).
pub fn write_artifacts(
    toml: Option<&CodegenToml>,
    configs: &CodegenConfigs,
    path: Option<&Path>,
) -> Result<(), CircuitsErrors> {
    if let Some(t) = toml {
        write_toml(t, path)?;
    }
    write_configs(configs, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn write_artifacts_creates_both_files() {
        let toml_content = "[section]\nkey = \"value\"\n";
        let configs_content = "pub global N: u32 = 1024;\n";
        let temp = TempDir::new().unwrap();
        write_artifacts(
            Some(&toml_content.to_string()),
            &configs_content.to_string(),
            Some(temp.path()),
        )
        .unwrap();
        let toml_path = temp.path().join("Prover.toml");
        let configs_path = temp.path().join("configs.nr");
        assert!(toml_path.exists());
        assert!(configs_path.exists());
        assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), toml_content);
        assert_eq!(
            std::fs::read_to_string(&configs_path).unwrap(),
            configs_content
        );
    }
}
