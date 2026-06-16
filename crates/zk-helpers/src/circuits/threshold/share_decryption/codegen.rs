// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the threshold share decryption circuit: Prover.toml and configs.nr.

use crate::circuits::computation::Computation;
use crate::threshold::share_decryption::computation::Inputs;
use crate::threshold::share_decryption::{
    Configs, ShareDecryptionCircuit, ShareDecryptionCircuitData,
};
use crate::utils::join_display;
use crate::Circuit;
use crate::CircuitCodegen;
use crate::CircuitsErrors;
use crate::{Artifacts, CodegenConfigs, CodegenToml};

use e3_fhe_params::BfvPreset;

/// Implementation of [`CircuitCodegen`] for [`ShareDecryptionCircuit`].
impl CircuitCodegen for ShareDecryptionCircuit {
    type Preset = BfvPreset;
    type Data = ShareDecryptionCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let inputs = Inputs::compute(preset, data)?;
        let configs = Configs::compute(preset, &())?;

        let toml = generate_toml(inputs)?;
        let configs = generate_configs(preset, &configs);

        Ok(Artifacts { toml, configs })
    }
}

pub fn generate_toml(inputs: Inputs) -> Result<CodegenToml, CircuitsErrors> {
    let json = inputs.to_json().map_err(CircuitsErrors::SerdeJson)?;

    Ok(toml::to_string(&json)?)
}

pub fn generate_configs(_preset: BfvPreset, configs: &Configs) -> CodegenConfigs {
    let prefix = <ShareDecryptionCircuit as Circuit>::PREFIX;

    let qis_str = join_display(&configs.moduli, ", ");
    let r1_bounds_str = join_display(&configs.bounds.r1_bounds, ", ");
    let r2_bounds_str = join_display(&configs.bounds.r2_bounds, ", ");

    format!(
        r#"use crate::core::threshold::share_decryption::Configs as ShareDecryptionConfigs;

// Global configs for Share Decryption circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
share_decryption (CIRCUIT 6 - THRESHOLD BFV SHARE DECRYPTION)
-------------------------------------
************************************/

pub global {}_BIT_CT: u32 = {};
pub global {}_BIT_SK: u32 = {};
pub global {}_BIT_E_SM: u32 = {};
pub global {}_BIT_R1: u32 = {};
pub global {}_BIT_R2: u32 = {};
pub global {}_BIT_D: u32 = {};
pub global {}_BIT_D_NATIVE: u32 = {};

pub global {}_R1_BOUNDS: [Field; L] = [{}];
pub global {}_R2_BOUNDS: [Field; L] = [{}];

pub global {}_CONFIGS: ShareDecryptionConfigs<L> = ShareDecryptionConfigs::new(
    QIS,
    {}_R1_BOUNDS,
    {}_R2_BOUNDS,
);
"#,
        configs.n,
        configs.l,
        qis_str,
        prefix,
        configs.bits.ct_bit,
        prefix,
        configs.bits.sk_bit,
        prefix,
        configs.bits.e_sm_bit,
        prefix,
        configs.bits.r1_bit,
        prefix,
        configs.bits.r2_bit,
        prefix,
        configs.bits.d_bit,
        prefix,
        configs.bits.d_native_bit,
        prefix,
        r1_bounds_str,
        prefix,
        r2_bounds_str,
        prefix,
        prefix,
        prefix,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::computation::Computation;
    use crate::codegen::write_artifacts;
    use crate::threshold::share_decryption::computation::{Bits, Bounds};
    use crate::threshold::share_decryption::ShareDecryptionCircuitData;
    use crate::CiphernodesCommitteeSize;

    use e3_fhe_params::BfvPreset;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let committee = CiphernodesCommitteeSize::Small.values();

        let sample =
            ShareDecryptionCircuitData::generate_sample(BfvPreset::InsecureThreshold512, committee)
                .unwrap();
        let artifacts = ShareDecryptionCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let parsed: toml::Value = artifacts.toml.parse().unwrap();
        let ct0 = parsed
            .get("ct0")
            .and_then(|value| value.as_array())
            .unwrap();
        let ct1 = parsed
            .get("ct1")
            .and_then(|value| value.as_array())
            .unwrap();
        assert!(!ct0.is_empty());
        assert!(!ct1.is_empty());

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
        assert!(content.contains("ct0"));
        assert!(content.contains("ct1"));

        assert!(artifacts.toml.contains("[[ct0]]"));
        assert!(artifacts.toml.contains("[[ct1]]"));

        let configs_path = temp_dir.path().join("configs.nr");
        assert!(configs_path.exists());

        let configs_content = std::fs::read_to_string(&configs_path).unwrap();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &()).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();

        assert!(configs_content.contains(
            format!(
                "N: u32 = {}",
                BfvPreset::InsecureThreshold512.metadata().degree
            )
            .as_str()
        ));
        assert!(configs_content.contains(
            format!(
                "L: u32 = {}",
                BfvPreset::InsecureThreshold512.metadata().num_moduli
            )
            .as_str()
        ));
        assert!(configs_content.contains(
            format!(
                "{}_BIT_CT: u32 = {}",
                <ShareDecryptionCircuit as Circuit>::PREFIX,
                bits.ct_bit
            )
            .as_str()
        ));
    }
}
