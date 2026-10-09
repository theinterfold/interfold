// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the public-key BFV circuit: Prover.toml and configs.nr.

use crate::circuits::computation::Computation;
use crate::encoding::join_display;
use crate::threshold::user_data_encryption::circuit::UserDataEncryptionCircuit;
use crate::threshold::user_data_encryption::computation::{Configs, Inputs};
use crate::threshold::user_data_encryption::UserDataEncryptionCircuitData;
use crate::Circuit;
use crate::CircuitCodegen;
use crate::CircuitsErrors;
use crate::{Artifacts, CodegenConfigs, CodegenToml};

use e3_fhe_params::BfvPreset;

/// Implementation of [`CircuitCodegen`] for [`UserDataEncryptionCircuit`].
impl CircuitCodegen for UserDataEncryptionCircuit {
    type Preset = BfvPreset;
    type Data = UserDataEncryptionCircuitData;
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

pub fn generate_configs(_: BfvPreset, configs: &Configs) -> CodegenConfigs {
    let prefix = <UserDataEncryptionCircuit as Circuit>::PREFIX;

    let qis_str = join_display(&configs.moduli, ", ");
    let k0is_str = join_display(&configs.k0is, ", ");
    let pk_bounds_str = join_display(&configs.bounds.pk_bounds, ", ");
    let ct0_r_bounds_str = join_display(&configs.bounds.ct0_r_bounds, ", ");
    let ct1_r_bounds_str = join_display(&configs.bounds.ct1_r_bounds, ", ");

    format!(
        r#"use crate::core::threshold::user_data_encryption_ct0::Configs as UserDataEncryptionCt0Configs;
use crate::core::threshold::user_data_encryption_ct1::Configs as UserDataEncryptionCt1Configs;

// Global configs for User Data Encryption circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
user_data_encryption (USED FOR DATA ENCRYPTION)
-------------------------------------
************************************/

pub global {}_BIT_PK: u32 = {};
pub global {}_BIT_CT: u32 = {};
pub global {}_BIT_U: u32 = {};
pub global {}_BIT_E0: u32 = {};
pub global {}_BIT_E1: u32 = {};
pub global {}_BIT_K: u32 = {};
pub global {}_CT0_BIT_R: u32 = {};
pub global {}_CT1_BIT_R: u32 = {};

pub global {}_K0IS: [Field; L] = [{}];
pub global {}_PK_BOUNDS: [Field; L] = [{}];
pub global {}_E0_BOUND: Field = {};
pub global {}_E1_BOUND: Field = {};
pub global {}_U_BOUND: Field = {};
pub global {}_K1_LOW_BOUND: Field = {};
pub global {}_K1_UP_BOUND: Field = {};
pub global {}_CT0_R_BOUNDS: [Field; L] = [{}];
pub global {}_CT1_R_BOUNDS: [Field; L] = [{}];

/************************************
-------------------------------------
user_data_encryption_ct0 (CIRCUIT A - CT0 ENCRYPTION)
-------------------------------------
************************************/

pub global {}_CT0_CONFIGS: UserDataEncryptionCt0Configs<N, L> = UserDataEncryptionCt0Configs::new(
    QIS,
    {}_K0IS,
    {}_E0_BOUND,
    {}_U_BOUND,
    {}_CT0_R_BOUNDS,
    {}_K1_LOW_BOUND,
    {}_K1_UP_BOUND,
);

/************************************
-------------------------------------
user_data_encryption_ct1 (CIRCUIT B - CT1 ENCRYPTION)
-------------------------------------
************************************/

pub global {}_CT1_CONFIGS: UserDataEncryptionCt1Configs<N, L> = UserDataEncryptionCt1Configs::new(
    QIS,
    {}_E1_BOUND,
    {}_U_BOUND,
    {}_CT1_R_BOUNDS,
);
"#,
        configs.n, // N
        configs.l, // L
        qis_str,   // QIS array
        prefix,
        configs.bits.pk_bit, // BIT_PK
        prefix,
        configs.bits.ct_bit, // BIT_CT
        prefix,
        configs.bits.u_bit, // BIT_U
        prefix,
        configs.bits.e0_bit, // BIT_E0
        prefix,
        configs.bits.e1_bit, // BIT_E1
        prefix,
        configs.bits.k_bit, // BIT_K
        prefix,
        configs.bits.ct0_r_bit, // CT0_BIT_R
        prefix,
        configs.bits.ct1_r_bit, // CT1_BIT_R
        prefix,
        k0is_str, // K0IS array
        prefix,
        pk_bounds_str, // PK_BOUNDS array
        prefix,
        configs.bounds.e0_bound, // E0_BOUND
        prefix,
        configs.bounds.e1_bound, // E1_BOUND
        prefix,
        configs.bounds.u_bound, // U_BOUND
        prefix,
        configs.bounds.k1_low_bound, // K1_LOW_BOUND
        prefix,
        configs.bounds.k1_up_bound, // K1_UP_BOUND
        prefix,
        ct0_r_bounds_str, // CT0_R_BOUNDS array
        prefix,
        ct1_r_bounds_str, // CT1_R_BOUNDS array
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
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
    use crate::threshold::user_data_encryption::circuit::UserDataEncryptionCircuitData;
    use crate::threshold::user_data_encryption::computation::{Bits, Bounds};

    use e3_fhe_params::BfvPreset;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let sample =
            UserDataEncryptionCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();
        let artifacts = UserDataEncryptionCircuit
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
                "{}_BIT_PK: u32 = {}",
                <UserDataEncryptionCircuit as Circuit>::PREFIX,
                bits.pk_bit
            )
            .as_str()
        ));
    }
}
