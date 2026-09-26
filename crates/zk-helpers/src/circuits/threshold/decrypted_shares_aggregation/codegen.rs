// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the Decrypted Shares Aggregation circuit: Prover.toml and configs.nr.

use e3_fhe_params::BfvPreset;

use crate::circuits::computation::Computation;
use crate::threshold::decrypted_shares_aggregation::circuit::DecryptedSharesAggregationCircuit;
use crate::threshold::decrypted_shares_aggregation::computation::{Configs, Inputs};
use crate::threshold::decrypted_shares_aggregation::DecryptedSharesAggregationCircuitData;
use crate::Circuit;
use crate::CircuitCodegen;
use crate::CircuitsErrors;
use crate::{Artifacts, CodegenConfigs, CodegenToml};

/// Implementation of [`CircuitCodegen`] for [`DecryptedSharesAggregationCircuit`].
impl CircuitCodegen for DecryptedSharesAggregationCircuit {
    type Preset = BfvPreset;
    type Data = DecryptedSharesAggregationCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let inputs = Inputs::compute(preset, data)?;
        let configs = Configs::compute(preset, &())?;

        let toml = generate_toml(inputs)?;
        let configs_str = generate_configs(preset, &configs);

        Ok(Artifacts {
            toml,
            configs: configs_str,
        })
    }
}

pub fn generate_toml(inputs: Inputs) -> Result<CodegenToml, CircuitsErrors> {
    let json = inputs.to_json().map_err(CircuitsErrors::SerdeJson)?;

    Ok(toml::to_string(&json)?)
}

/// Generates the decrypted_shares_aggregation config fragment for threshold.nr.
/// Emits L, QIS, PLAINTEXT_MODULUS, Q_INVERSE_MOD_T so the circuit uses the same
/// crypto params as the input (avoids "Cannot satisfy constraint" from config mismatch).
pub fn generate_configs(_preset: BfvPreset, configs: &Configs) -> CodegenConfigs {
    let prefix = <DecryptedSharesAggregationCircuit as Circuit>::PREFIX;
    let qis_str = configs
        .moduli
        .iter()
        .map(|q| q.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"use crate::core::threshold::decrypted_shares_aggregation::Configs as DecryptedSharesAggregationConfigs;

pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];
pub global PLAINTEXT_MODULUS: Field = {};
pub global Q_MOD_T: Field = {};
pub global Q_MOD_T_CENTERED: Field = {};
pub global Q_INVERSE_MOD_T: Field = {};
        
/************************************
-------------------------------------
decrypted_shares_aggregation (CIRCUIT 7)
-------------------------------------
************************************/

pub global {}_BIT_NOISE: u32 = {};
pub global {}_BIT_D_NATIVE: u32 = {};

pub global {}_CONFIGS: DecryptedSharesAggregationConfigs<L> =
    DecryptedSharesAggregationConfigs::new(QIS, PLAINTEXT_MODULUS, Q_INVERSE_MOD_T);
"#,
        configs.l,
        qis_str,
        configs.plaintext_modulus,
        configs.q_mod_t,
        configs.q_mod_t_centered,
        configs.q_inverse_mod_t,
        prefix,
        configs.bits.noise_bit,
        prefix,
        configs.bits.d_native_bit,
        prefix,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CiphernodesCommitteeSize;

    #[test]
    fn test_configs_generation() {
        let preset = BfvPreset::InsecureThreshold;
        let configs = Configs::compute(preset, &()).unwrap();
        let prefix: &str = <DecryptedSharesAggregationCircuit as Circuit>::PREFIX;

        let codegen_configs = generate_configs(preset, &configs);

        assert!(codegen_configs.contains("decrypted_shares_aggregation"));
        assert!(codegen_configs.contains(&format!(
            "{}_BIT_NOISE: u32 = {}",
            prefix, configs.bits.noise_bit
        )));
        assert!(codegen_configs.contains(&format!(
            "{}_BIT_D_NATIVE: u32 = {}",
            prefix, configs.bits.d_native_bit
        )));
        assert!(codegen_configs.contains(&format!("{}_CONFIGS:", prefix)));
        assert!(codegen_configs.contains(
            "DecryptedSharesAggregationConfigs::new(QIS, PLAINTEXT_MODULUS, Q_INVERSE_MOD_T)"
        ));
    }

    #[test]
    fn test_codegen_with_sample() {
        let preset = BfvPreset::InsecureThreshold;
        let committee = CiphernodesCommitteeSize::Small.values();
        let input =
            DecryptedSharesAggregationCircuitData::generate_sample(preset, committee).unwrap();
        let circuit = DecryptedSharesAggregationCircuit;

        let artifacts = circuit.codegen(preset, &input).unwrap();

        assert!(!artifacts.toml.is_empty());
        assert!(artifacts
            .configs
            .contains("DECRYPTED_SHARES_AGGREGATION_BIT_NOISE"));
        assert!(artifacts
            .configs
            .contains("DECRYPTED_SHARES_AGGREGATION_BIT_D_NATIVE"));
        assert!(artifacts
            .configs
            .contains("DECRYPTED_SHARES_AGGREGATION_CONFIGS"));
    }
}
