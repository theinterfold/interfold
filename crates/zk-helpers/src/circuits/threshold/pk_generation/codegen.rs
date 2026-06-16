// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the public-key BFV circuit: Prover.toml and configs.nr.

use e3_fhe_params::BfvPreset;

use crate::circuits::computation::Computation;
use crate::threshold::pk_generation::circuit::PkGenerationCircuit;
use crate::threshold::pk_generation::computation::{Configs, Inputs};
use crate::threshold::pk_generation::utils::crp_matrix_constant_string;
use crate::threshold::pk_generation::PkGenerationCircuitData;
use crate::utils::join_display;
use crate::CircuitCodegen;
use crate::CircuitsErrors;
use crate::{Artifacts, CodegenToml};
use crate::{Circuit, CodegenConfigs};
use num_bigint::BigUint;

/// Implementation of [`CircuitCodegen`] for [`PkGenerationCircuit`].
impl CircuitCodegen for PkGenerationCircuit {
    type Preset = BfvPreset;
    type Data = PkGenerationCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let inputs = Inputs::compute(preset, data)?;
        let configs = Configs::compute(preset, &data.committee)?;

        let toml = generate_toml(inputs)?;
        let configs = generate_configs(preset, &configs)?;

        Ok(Artifacts { toml, configs })
    }
}

pub fn generate_toml(inputs: Inputs) -> Result<CodegenToml, CircuitsErrors> {
    let json = inputs.to_json().map_err(CircuitsErrors::SerdeJson)?;

    Ok(toml::to_string(&json)?)
}

pub fn generate_configs(
    preset: BfvPreset,
    configs: &Configs,
) -> Result<CodegenConfigs, CircuitsErrors> {
    let prefix = <PkGenerationCircuit as Circuit>::PREFIX;

    let qis_str = join_display(&configs.moduli, ", ");

    let r1_bounds_str = join_display(&configs.bounds.r1_bounds, ", ");
    let r2_bounds_str = join_display(&configs.bounds.r2_bounds, ", ");

    let (threshold_params, _) = preset
        .build_pair()
        .map_err(|e| CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e)))?;

    let crp_matrix_str = crp_matrix_constant_string(&threshold_params)?;

    // B_enc ≈ sqrt(3 * error1_variance)
    let b_enc = (BigUint::from(3u32) * threshold_params.get_error1_variance()).sqrt();

    Ok(format!(
        r#"use crate::core::threshold::pk_generation::Configs as PkGenerationConfigs;
use crate::math::polynomial::Polynomial;

// Global configs for Threshold Public Key Generation circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

{}

/************************************
-------------------------------------
pk_generation (CIRCUIT 1 - PUBLIC KEY THRESHOLD BFV)
-------------------------------------
************************************/

pub global {}_BIT_EEK: u32 = {};
pub global {}_BIT_SK: u32 = {};
pub global {}_BIT_E_SM: u32 = {};
pub global {}_BIT_R1: u32 = {};
pub global {}_BIT_R2: u32 = {};
pub global {}_BIT_PK: u32 = {};

pub global {}_EEK_BOUND: Field = {};
pub global {}_SK_BOUND: Field = {};
pub global {}_E_SM_BOUND: Field = {};
pub global {}_R1_BOUNDS: [Field; L] = [{}];
pub global {}_R2_BOUNDS: [Field; L] = [{}];

pub global {}_B_ENC: Field = {};

pub global {}_CONFIGS: PkGenerationConfigs<N, L> = PkGenerationConfigs::new(
    QIS,
    {}_EEK_BOUND,
    {}_SK_BOUND,
    {}_E_SM_BOUND,
    {}_R1_BOUNDS,
    {}_R2_BOUNDS,
);
"#,
        configs.n,
        configs.l,
        qis_str,
        crp_matrix_str,
        prefix,
        configs.bits.eek_bit,
        prefix,
        configs.bits.sk_bit,
        prefix,
        configs.bits.e_sm_bit,
        prefix,
        configs.bits.r1_bit,
        prefix,
        configs.bits.r2_bit,
        prefix,
        configs.bits.pk_bit,
        prefix,
        configs.bounds.eek_bound,
        prefix,
        configs.bounds.sk_bound,
        prefix,
        configs.bounds.e_sm_bound,
        prefix,
        r1_bounds_str,
        prefix,
        r2_bounds_str,
        prefix,
        b_enc,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::codegen::write_artifacts;
    use crate::threshold::pk_generation::computation::{Bits, Bounds};
    use crate::threshold::pk_generation::PkGenerationCircuitData;
    use e3_fhe_params::BfvPreset;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample =
            PkGenerationCircuitData::generate_sample(BfvPreset::InsecureThreshold512, committee)
                .unwrap();
        let artifacts = PkGenerationCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let parsed: toml::Value = artifacts.toml.parse().unwrap();
        let pk0is = parsed
            .get("pk0is")
            .and_then(|value| value.as_array())
            .unwrap();
        assert!(!pk0is.is_empty());
        assert!(parsed.get("pk1is").is_none());

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

        assert!(artifacts.toml.contains("[[pk0is]]"));

        let configs_path = temp_dir.path().join("configs.nr");
        assert!(configs_path.exists());

        let configs_content = std::fs::read_to_string(&configs_path).unwrap();
        use crate::ciphernodes_committee::CiphernodesCommitteeSize;
        let committee = CiphernodesCommitteeSize::Micro.values();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &committee).unwrap();
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
                <PkGenerationCircuit as Circuit>::PREFIX,
                bits.pk_bit
            )
            .as_str()
        ));
    }
}
