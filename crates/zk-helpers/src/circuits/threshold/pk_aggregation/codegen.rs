// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the public-key BFV circuit: Prover.toml and configs.nr.

use e3_fhe_params::BfvPreset;

use crate::circuits::computation::Computation;
use crate::threshold::pk_aggregation::circuit::PkAggregationCircuit;
use crate::threshold::pk_aggregation::computation::{Configs, Inputs};
use crate::threshold::pk_aggregation::PkAggregationCircuitData;
use crate::utils::join_display;
use crate::CircuitCodegen;
use crate::CircuitsErrors;
use crate::{Artifacts, CodegenToml};
use crate::{Circuit, CodegenConfigs};

/// Implementation of [`CircuitCodegen`] for [`PkAggregationCircuit`].
impl CircuitCodegen for PkAggregationCircuit {
    type Preset = BfvPreset;
    type Data = PkAggregationCircuitData;
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
    let prefix = <PkAggregationCircuit as Circuit>::PREFIX;

    let qis_str = join_display(&configs.moduli, ", ");

    format!(
        r#"use crate::core::threshold::pk_aggregation::Configs as PkAggregationConfigs;

// Global configs
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
pk_aggregation (CIRCUIT 5)
-------------------------------------
************************************/

pub global {}_BIT_PK: u32 = {};

pub global {}_CONFIGS: PkAggregationConfigs<L> = PkAggregationConfigs::new(QIS);
"#,
        configs.n,           // N
        configs.l,           // L
        qis_str,             // QIS array
        prefix,              // BIT_PK
        configs.bits.pk_bit, // BIT_PK
        prefix,              // CONFIGS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::CiphernodesCommitteeSize;

    #[test]
    fn test_toml_generation_and_structure() {
        let preset = BfvPreset::InsecureThreshold512;
        let committee = CiphernodesCommitteeSize::Small.values();
        let prefix: &str = <PkAggregationCircuit as Circuit>::PREFIX;

        let sample = PkAggregationCircuitData::generate_sample(preset, committee).unwrap();
        let inputs = Inputs::compute(preset, &sample).unwrap();
        let configs = Configs::compute(preset, &()).unwrap();

        let qis_str = join_display(&configs.moduli, ", ");

        let parsed: serde_json::Value = inputs.to_json().unwrap();
        let pk0 = parsed
            .get("pk0")
            .and_then(|value| value.as_array())
            .unwrap();
        let pk0_agg = parsed
            .get("pk0_agg")
            .and_then(|value| value.as_array())
            .unwrap();
        assert!(!pk0.is_empty());
        assert!(!pk0_agg.is_empty());

        let codegen_toml = generate_toml(inputs).unwrap();
        let codegen_configs = generate_configs(preset, &configs);

        assert!(codegen_toml.contains("pk0"));
        assert!(codegen_toml.contains("[[pk0_agg]]"));

        assert!(codegen_configs.contains(format!("N: u32 = {}", configs.n).as_str()));
        assert!(codegen_configs.contains(format!("L: u32 = {}", configs.l).as_str()));
        assert!(codegen_configs
            .contains(format!("{}_BIT_PK: u32 = {}", prefix, configs.bits.pk_bit).as_str()));
        assert!(codegen_configs.contains(
            format!(
                "{}_CONFIGS: PkAggregationConfigs<L> = PkAggregationConfigs::new(QIS);",
                prefix
            )
            .as_str()
        ));
        assert!(codegen_configs.contains(format!("QIS: [Field; L] = [{}];", qis_str).as_str()));
    }
}
