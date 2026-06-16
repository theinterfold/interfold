// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the share-computation BFV circuit: Prover.toml and configs.nr.

use crate::circuits::computation::CircuitComputation;
use crate::circuits::computation::Computation;
use crate::circuits::dkg::share_computation::{
    utils::parity_matrix_constant_string, Bits, Inputs, ShareComputationCircuit,
    ShareComputationCircuitData, ShareComputationOutput,
};
use crate::circuits::{Artifacts, CircuitCodegen, CircuitsErrors, CodegenToml};
use crate::codegen::CodegenConfigs;
use crate::registry::Circuit;
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;

/// Implementation of [`CircuitCodegen`] for [`ShareComputationCircuit`].
impl CircuitCodegen for ShareComputationCircuit {
    type Preset = BfvPreset;
    type Data = ShareComputationCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let ShareComputationOutput { inputs, bits, .. } =
            ShareComputationCircuit::compute(preset, data)?;

        let toml = generate_toml(&inputs)?;
        let configs = generate_configs(
            preset,
            &bits,
            data.n_parties as usize,
            data.threshold as usize,
        )?;

        Ok(Artifacts { toml, configs })
    }
}

pub fn generate_toml(witness: &Inputs) -> Result<CodegenToml, CircuitsErrors> {
    let json = witness.to_json().map_err(CircuitsErrors::SerdeJson)?;

    Ok(toml::to_string(&json)?)
}

/// Builds the configs.nr string (N, L, parity matrix, bit parameters, configs) for the Noir prover.
///
/// `n_parties` and `threshold` are used to build the parity matrix (Reed–Solomon generator null space)
/// and must match the committee size used for the input/sample.
pub fn generate_configs(
    preset: BfvPreset,
    bits: &Bits,
    n_parties: usize,
    threshold: usize,
) -> Result<CodegenConfigs, CircuitsErrors> {
    let (threshold_params, _) =
        build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
    let config_name = preset.metadata().security.as_config_str();
    let parity_matrix_str = parity_matrix_constant_string(&threshold_params, n_parties, threshold)?;
    let prefix = <ShareComputationCircuit as Circuit>::PREFIX;
    let configs = format!(
        r#"
pub use crate::configs::{}::threshold::{{L as L_THRESHOLD, QIS as QIS_THRESHOLD}};

pub global N: u32 = {};

{}
/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

// share_computation_sk - bit parameters
pub global {}_BIT_SHARE: u32 = {};
pub global {}_SK_BIT_SECRET: u32 = {};

// share_computation_sk - configs
pub global {}_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

// share_computation_e_sm - bit parameters
pub global {}_E_SM_BIT_SECRET: u32 = {};

// verify_shares - configs
pub global {}_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);
"#,
        config_name,
        preset.metadata().degree,
        parity_matrix_str,
        prefix,
        bits.bit_share,
        prefix,
        bits.bit_sk_secret,
        prefix,
        prefix,
        bits.bit_e_sm_secret,
        prefix,
    );

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphernodes_committee::CiphernodesCommitteeSize;
    use crate::circuits::computation::Computation;
    use crate::circuits::dkg::share_computation::{Bits, Bounds};
    use crate::codegen::write_artifacts;
    use crate::computation::DkgInputType;
    use crate::Circuit;
    use e3_fhe_params::BfvPreset;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();

        let artifacts = ShareComputationCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let parsed: toml::Value = artifacts.toml.parse().unwrap();
        let sk_secret = parsed.get("sk_secret").unwrap();
        assert!(sk_secret
            .get("coefficients")
            .and_then(|c| c.as_array())
            .is_some());
        let y = parsed.get("y").and_then(|v| v.as_array()).unwrap();
        assert!(!y.is_empty());
        assert!(parsed.get("expected_secret_commitment").is_some());

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
        assert!(content.contains("sk_secret"));
        assert!(content.contains("expected_secret_commitment"));
        assert!(content.contains("y"));

        let configs_path = temp_dir.path().join("configs.nr");
        assert!(configs_path.exists());

        let configs_content = std::fs::read_to_string(&configs_path).unwrap();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();
        let prefix = <ShareComputationCircuit as Circuit>::PREFIX;

        assert!(configs_content.contains(
            format!(
                "N: u32 = {}",
                BfvPreset::InsecureThreshold512.metadata().degree
            )
            .as_str()
        ));
        assert!(configs_content
            .contains(format!("{}_BIT_SHARE: u32 = {}", prefix, bits.bit_share).as_str()));
        assert!(configs_content
            .contains(format!("{}_SK_BIT_SECRET: u32 = {}", prefix, bits.bit_sk_secret).as_str()));
        assert!(configs_content.contains(
            format!("{}_E_SM_BIT_SECRET: u32 = {}", prefix, bits.bit_e_sm_secret).as_str()
        ));
    }
}
