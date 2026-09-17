// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Raw witness and configuration generation for the user-data encryption proof tree.

use crate::circuits::computation::Computation;
use crate::threshold::user_data_encryption::circuit::UserDataEncryptionCircuit;
use crate::threshold::user_data_encryption::computation::{Configs, Inputs};
use crate::threshold::user_data_encryption::UserDataEncryptionCircuitData;
use crate::utils::join_display;
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

    format!(
        r#"use crate::core::threshold::user_data_encryption_ct0::Configs as UserDataEncryptionCt0Configs;
use crate::core::threshold::user_data_encryption_ct1::Configs as UserDataEncryptionCt1Configs;
use crate::core::threshold::user_data_encryption_chunk::Ct0ChunkConfigs as UserDataEncryptionCt0ChunkConfigs;
use crate::core::threshold::user_data_encryption_chunk::Ct1ChunkConfigs as UserDataEncryptionCt1ChunkConfigs;

// Global configs for User Data Encryption circuit
pub global N: u32 = {n};
pub global L: u32 = {l};
pub global QIS: [Field; L] = [{qis}];

/************************************
-------------------------------------
user_data_encryption (USED FOR DATA ENCRYPTION)
-------------------------------------
************************************/

pub global {prefix}_BIT_PK: u32 = {bit_pk};
pub global {prefix}_BIT_CT: u32 = {bit_ct};
pub global {prefix}_BIT_U: u32 = {bit_u};
pub global {prefix}_BIT_E0: u32 = {bit_e0};
pub global {prefix}_BIT_E1: u32 = {bit_e1};
pub global {prefix}_BIT_K: u32 = {bit_k};
pub global {prefix}_BIT_R1: u32 = {bit_r1};
pub global {prefix}_BIT_R2: u32 = {bit_r2};
pub global {prefix}_BIT_P1: u32 = {bit_p1};
pub global {prefix}_BIT_P2: u32 = {bit_p2};
pub global {prefix}_BIT_E0_QUOTIENT: u32 = {bit_e0_quotient};

pub global {prefix}_K0IS: [Field; L] = [{k0is}];
pub global {prefix}_PK_BOUNDS: [Field; L] = [{pk_bounds}];
pub global {prefix}_E0_BOUND: Field = {e0_bound};
pub global {prefix}_E1_BOUND: Field = {e1_bound};
pub global {prefix}_U_BOUND: Field = {u_bound};
pub global {prefix}_K1_LOW_BOUND: Field = {k1_low_bound};
pub global {prefix}_K1_UP_BOUND: Field = {k1_up_bound};
pub global {prefix}_R1_LOW_BOUNDS: [Field; L] = [{r1_low_bounds}];
pub global {prefix}_R1_UP_BOUNDS: [Field; L] = [{r1_up_bounds}];
pub global {prefix}_R2_BOUNDS: [Field; L] = [{r2_bounds}];
pub global {prefix}_P1_BOUNDS: [Field; L] = [{p1_bounds}];
pub global {prefix}_P2_BOUNDS: [Field; L] = [{p2_bounds}];
pub global {prefix}_E0_QUOTIENT_BOUNDS: [Field; L] = [{e0_quotient_bounds}];

/************************************
-------------------------------------
user_data_encryption_ct0 (CIRCUIT A - CT0 ENCRYPTION)
-------------------------------------
************************************/

pub global {prefix}_CT0_CONFIGS: UserDataEncryptionCt0Configs<N, L> = UserDataEncryptionCt0Configs::new(
    QIS,
    {prefix}_K0IS,
    {prefix}_E0_BOUND,
    {prefix}_U_BOUND,
    {prefix}_R1_LOW_BOUNDS,
    {prefix}_R1_UP_BOUNDS,
    {prefix}_R2_BOUNDS,
    {prefix}_K1_LOW_BOUND,
    {prefix}_K1_UP_BOUND,
    {prefix}_E0_QUOTIENT_BOUNDS,
);

/************************************
-------------------------------------
user_data_encryption_ct1 (CIRCUIT B - CT1 ENCRYPTION)
-------------------------------------
************************************/

pub global {prefix}_CT1_CONFIGS: UserDataEncryptionCt1Configs<N, L> = UserDataEncryptionCt1Configs::new(
    QIS,
    {prefix}_E1_BOUND,
    {prefix}_U_BOUND,
    {prefix}_P1_BOUNDS,
    {prefix}_P2_BOUNDS,
);

pub global {prefix}_N_CHUNKS: u32 = 2;
pub global {prefix}_CT0_CHUNK_CONFIGS: UserDataEncryptionCt0ChunkConfigs<L> = UserDataEncryptionCt0ChunkConfigs::new(
    QIS,
    {prefix}_U_BOUND,
    {prefix}_E0_BOUND,
    {prefix}_K1_LOW_BOUND,
    {prefix}_K1_UP_BOUND,
    {prefix}_R1_LOW_BOUNDS,
    {prefix}_R1_UP_BOUNDS,
    {prefix}_R2_BOUNDS,
    {prefix}_E0_QUOTIENT_BOUNDS,
);
pub global {prefix}_CT1_CHUNK_CONFIGS: UserDataEncryptionCt1ChunkConfigs<L> = UserDataEncryptionCt1ChunkConfigs::new(
    {prefix}_U_BOUND,
    {prefix}_E1_BOUND,
    {prefix}_P1_BOUNDS,
    {prefix}_P2_BOUNDS,
);
"#,
        n = configs.n,
        l = configs.l,
        qis = join_display(&configs.moduli, ", "),
        prefix = prefix,
        bit_pk = configs.bits.pk_bit,
        bit_ct = configs.bits.ct_bit,
        bit_u = configs.bits.u_bit,
        bit_e0 = configs.bits.e0_bit,
        bit_e1 = configs.bits.e1_bit,
        bit_k = configs.bits.k_bit,
        bit_r1 = configs.bits.r1_bit,
        bit_r2 = configs.bits.r2_bit,
        bit_p1 = configs.bits.p1_bit,
        bit_p2 = configs.bits.p2_bit,
        bit_e0_quotient = configs.bits.e0_quotient_bit,
        k0is = join_display(&configs.k0is, ", "),
        pk_bounds = join_display(&configs.bounds.pk_bounds, ", "),
        e0_bound = configs.bounds.e0_bound,
        e1_bound = configs.bounds.e1_bound,
        u_bound = configs.bounds.u_bound,
        k1_low_bound = configs.bounds.k1_low_bound,
        k1_up_bound = configs.bounds.k1_up_bound,
        r1_low_bounds = join_display(&configs.bounds.r1_low_bounds, ", "),
        r1_up_bounds = join_display(&configs.bounds.r1_up_bounds, ", "),
        r2_bounds = join_display(&configs.bounds.r2_bounds, ", "),
        p1_bounds = join_display(&configs.bounds.p1_bounds, ", "),
        p2_bounds = join_display(&configs.bounds.p2_bounds, ", "),
        e0_quotient_bounds = join_display(&configs.bounds.e0_quotient_bounds, ", "),
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
