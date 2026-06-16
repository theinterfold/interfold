// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the public-key BFV circuit: Prover.toml and configs.nr.

use crate::circuits::dkg::pk::circuit::PkCircuit;
use crate::circuits::dkg::pk::circuit::PkCircuitData;
use crate::circuits::dkg::pk::computation::{Bits, Inputs, PkComputationOutput};
use crate::Artifacts;
use crate::Circuit;
use crate::CircuitCodegen;
use crate::CircuitComputation;
use crate::CircuitsErrors;
use crate::CodegenConfigs;
use crate::CodegenToml;
use crate::Computation;

use e3_fhe_params::BfvPreset;

/// Implementation of [`CircuitCodegen`] for [`PkCircuit`].
impl CircuitCodegen for PkCircuit {
    type Preset = BfvPreset;
    type Data = PkCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let PkComputationOutput { inputs, bits, .. } = PkCircuit::compute(preset, data)?;

        let toml = generate_toml(inputs)?;
        let configs = generate_configs(preset, &bits);

        Ok(Artifacts { toml, configs })
    }
}

/// Builds the Prover TOML string from the pk input (pk0is, pk1is).
pub fn generate_toml(inputs: Inputs) -> Result<CodegenToml, CircuitsErrors> {
    let json = inputs.to_json().map_err(CircuitsErrors::SerdeJson)?;

    Ok(toml::to_string(&json)?)
}

/// Builds the configs.nr string (N, L, bit parameters) for the Noir prover.
pub fn generate_configs(preset: BfvPreset, bits: &Bits) -> CodegenConfigs {
    format!(
        r#"pub global N: u32 = {};
pub global L: u32 = {};

/************************************
-------------------------------------
pk (CIRCUIT 0 - DKG BFV PUBLIC KEY)
-------------------------------------
************************************/

// pk - bit parameters
pub global {}_BIT_PK: u32 = {};
"#,
        preset.dkg_counterpart().unwrap().metadata().degree,
        preset.dkg_counterpart().unwrap().metadata().num_moduli,
        <PkCircuit as Circuit>::PREFIX,
        bits.pk_bit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::write_artifacts;
    use crate::dkg::pk::PkCircuitData;
    use crate::utils::compute_modulus_bit;

    use e3_fhe_params::{build_pair_for_preset, BfvPreset};
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let (_, dkg_params) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        let sample = PkCircuitData::generate_sample(BfvPreset::InsecureThreshold512).unwrap();

        let artifacts = PkCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let parsed: toml::Value = artifacts.toml.parse().unwrap();
        let pk0is = parsed
            .get("pk0is")
            .and_then(|value| value.as_array())
            .unwrap();
        let pk1is = parsed
            .get("pk1is")
            .and_then(|value| value.as_array())
            .unwrap();
        assert!(!pk0is.is_empty());
        assert!(!pk1is.is_empty());

        let temp_dir = TempDir::new().unwrap();
        write_artifacts(
            Some(&artifacts.toml),
            &artifacts.configs,
            Some(temp_dir.path()),
        )
        .unwrap();

        let output_path = temp_dir.path().join("Prover.toml");
        assert!(output_path.exists());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("pk0is"));
        assert!(content.contains("pk1is"));

        assert!(artifacts.toml.contains("[[pk0is]]"));
        assert!(artifacts.toml.contains("[[pk1is]]"));

        let configs_path = temp_dir.path().join("configs.nr");
        assert!(configs_path.exists());

        let configs_content = std::fs::read_to_string(&configs_path).unwrap();
        let pk_bit = compute_modulus_bit(&dkg_params);

        assert!(configs_content.contains(
            format!(
                "N: u32 = {}",
                BfvPreset::InsecureThreshold512
                    .dkg_counterpart()
                    .unwrap()
                    .metadata()
                    .degree,
            )
            .as_str()
        ));
        assert!(configs_content.contains(
            format!(
                "L: u32 = {}",
                BfvPreset::InsecureThreshold512
                    .dkg_counterpart()
                    .unwrap()
                    .metadata()
                    .num_moduli,
            )
            .as_str()
        ));
        assert!(configs_content.contains(
            format!(
                "{}_BIT_PK: u32 = {}",
                <PkCircuit as Circuit>::PREFIX,
                pk_bit
            )
            .as_str()
        ));
    }
}
