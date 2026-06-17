// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the share-encryption BFV circuit: Prover.toml and configs.nr.

use crate::circuits::computation::CircuitComputation;
use crate::circuits::dkg::share_encryption::Configs;
use crate::circuits::dkg::share_encryption::Inputs;
use crate::circuits::dkg::share_encryption::ShareEncryptionCircuit;
use crate::circuits::dkg::share_encryption::ShareEncryptionCircuitData;
use crate::circuits::dkg::share_encryption::ShareEncryptionOutput;
use crate::circuits::{Artifacts, CircuitCodegen, CircuitsErrors, CodegenToml};
use crate::codegen::CodegenConfigs;
use crate::computation::Computation;
use crate::registry::Circuit;
use crate::utils::join_display;
use e3_fhe_params::BfvPreset;

/// Implementation of [`CircuitCodegen`] for [`ShareEncryptionCircuit`].
impl CircuitCodegen for ShareEncryptionCircuit {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let ShareEncryptionOutput { inputs, .. } = ShareEncryptionCircuit::compute(preset, data)?;

        let toml = generate_toml(&inputs)?;
        let configs = Configs::compute(preset, data)?;
        let configs_str = generate_configs(preset, &configs);

        Ok(Artifacts {
            toml,
            configs: configs_str,
        })
    }
}

/// Serializes the input to TOML string for the Noir prover (Prover.toml).
pub fn generate_toml(inputs: &Inputs) -> Result<CodegenToml, CircuitsErrors> {
    let json = inputs.to_json().map_err(CircuitsErrors::SerdeJson)?;

    Ok(toml::to_string(&json)?)
}

/// Builds the configs.nr string (N, L, bit parameters, bounds, and ShareEncryptionConfigs) for the Noir prover.
pub fn generate_configs(preset: BfvPreset, configs: &Configs) -> CodegenConfigs {
    let prefix = <ShareEncryptionCircuit as Circuit>::PREFIX;

    let qis_str = join_display(&configs.moduli, ", ");
    let k0is_str = join_display(&configs.k0is, ", ");
    let pk_bounds_str = join_display(&configs.bounds.pk_bounds, ", ");
    let r1_low_bounds_str = join_display(&configs.bounds.r1_low_bounds, ", ");
    let r1_up_bounds_str = join_display(&configs.bounds.r1_up_bounds, ", ");
    let r2_bounds_str = join_display(&configs.bounds.r2_bounds, ", ");
    let p1_bounds_str = join_display(&configs.bounds.p1_bounds, ", ");
    let p2_bounds_str = join_display(&configs.bounds.p2_bounds, ", ");

    format!(
        r#"use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];
pub global PLAINTEXT_MODULUS: Field = {};
pub global Q_MOD_T: Field = {};
pub global Q_MOD_T_CENTERED: Field = {};

/************************************
-------------------------------------
share_encryption_sk (CIRCUIT 3a)
share_encryption_e_sm (CIRCUIT 3b)
-------------------------------------
************************************/

pub global {}_BIT_PK: u32 = {};
pub global {}_BIT_CT: u32 = {};
pub global {}_BIT_U: u32 = {};
pub global {}_BIT_E0: u32 = {};
pub global {}_BIT_E1: u32 = {};
pub global {}_BIT_MSG: u32 = {};
pub global {}_BIT_R1: u32 = {};
pub global {}_BIT_R2: u32 = {};
pub global {}_BIT_P1: u32 = {};
pub global {}_BIT_P2: u32 = {};

pub global {}_K0IS: [Field; L] = [{}];
pub global {}_PK_BOUNDS: [Field; L] = [{}];
pub global {}_E0_BOUND: Field = {};
pub global {}_E1_BOUND: Field = {};
pub global {}_U_BOUND: Field = {};
pub global {}_R1_LOW_BOUNDS: [Field; L] = [{}];
pub global {}_R1_UP_BOUNDS: [Field; L] = [{}];
pub global {}_R2_BOUNDS: [Field; L] = [{}];
pub global {}_P1_BOUNDS: [Field; L] = [{}];
pub global {}_P2_BOUNDS: [Field; L] = [{}];
pub global {}_MSG_BOUND: Field = {};

pub global {}_CONFIGS: ShareEncryptionConfigs<L> = ShareEncryptionConfigs::new(
    PLAINTEXT_MODULUS,
    Q_MOD_T,
    QIS,
    {}_K0IS,
    {}_PK_BOUNDS,
    {}_E0_BOUND,
    {}_E1_BOUND,
    {}_U_BOUND,
    {}_R1_LOW_BOUNDS,
    {}_R1_UP_BOUNDS,
    {}_R2_BOUNDS,
    {}_P1_BOUNDS,
    {}_P2_BOUNDS,
    {}_MSG_BOUND,
);
"#,
        preset.dkg_counterpart().unwrap().metadata().degree,
        preset.dkg_counterpart().unwrap().metadata().num_moduli,
        qis_str,
        configs.t,
        configs.q_mod_t,
        configs.q_mod_t_centered,
        prefix,
        configs.bits.pk_bit,
        prefix,
        configs.bits.ct_bit,
        prefix,
        configs.bits.u_bit,
        prefix,
        configs.bits.e0_bit,
        prefix,
        configs.bits.e1_bit,
        prefix,
        configs.bits.msg_bit,
        prefix,
        configs.bits.r1_bit,
        prefix,
        configs.bits.r2_bit,
        prefix,
        configs.bits.p1_bit,
        prefix,
        configs.bits.p2_bit,
        prefix,
        k0is_str,
        prefix,
        pk_bounds_str,
        prefix,
        configs.bounds.e0_bound,
        prefix,
        configs.bounds.e1_bound,
        prefix,
        configs.bounds.u_bound,
        prefix,
        r1_low_bounds_str,
        prefix,
        r1_up_bounds_str,
        prefix,
        r2_bounds_str,
        prefix,
        p1_bounds_str,
        prefix,
        p2_bounds_str,
        prefix,
        configs.bounds.msg_bound,
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
        prefix,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::circuits::dkg::share_encryption::{Bounds, ShareEncryptionCircuitData};
    use crate::computation::Computation;
    use crate::computation::DkgInputType;
    use crate::{CiphernodesCommitteeSize, Circuit};
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_toml_generation_and_structure() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold512.search_defaults().unwrap();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee.clone(),
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();
        let artifacts = ShareEncryptionCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let parsed: toml::Value = artifacts.toml.parse().unwrap();
        assert!(parsed.get("message").is_some());
        assert!(parsed.get("pk0is").is_some());
        assert!(parsed.get("expected_pk_commitment").is_some());
        assert!(parsed.get("expected_message_commitment").is_some());
    }

    #[test]
    fn test_configs_generation_contains_expected() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sd = BfvPreset::InsecureThreshold512.search_defaults().unwrap();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee.clone(),
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();

        let artifacts = ShareEncryptionCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let bits = crate::circuits::dkg::share_encryption::Bits::compute(
            BfvPreset::InsecureThreshold512,
            &bounds,
        )
        .unwrap();
        let prefix = <ShareEncryptionCircuit as Circuit>::PREFIX;

        assert!(artifacts.configs.contains("ShareEncryptionConfigs"));
        assert!(artifacts
            .configs
            .contains(format!("{}_BIT_PK: u32 = {}", prefix, bits.pk_bit).as_str()));
        assert!(artifacts
            .configs
            .contains(format!("{}_BIT_MSG: u32 = {}", prefix, bits.msg_bit).as_str()));
        assert!(artifacts.configs.contains("SHARE_ENCRYPTION_CONFIGS"));
    }
}
