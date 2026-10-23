// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::{CircuitMetadata, ConfigError};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
pub mod parity;
use parity::parity_matrix_constant_string;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "share-computation",
    prefix: "SHARE_COMPUTATION",
    parameter: ParameterType::THRESHOLD,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    pub committee: CiphernodesCommitteeSize,
    preset: BfvPreset,
    pub bits: Bits,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub bit_sk_secret: u32,
    pub bit_e_sm_secret: u32,
    pub bit_share: u32,
}
impl Configs {
    pub fn new(
        preset: BfvPreset,
        threshold_params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        crate::parameters::require_threshold_preset(preset, threshold_params)?;
        let bits = Bits::new(threshold_params);

        Ok(Configs {
            params: threshold_params.clone(),
            committee,
            preset,

            bits,
        })
    }
}
impl Bits {
    fn new(threshold_params: &Arc<BfvParameters>) -> Self {
        let bit_share = compute_native_crt_coeff_bit(threshold_params.moduli());

        Bits {
            bit_sk_secret: calculate_bit_width(&BigUint::from(SecretKey::sk_bound() as u128)),
            // The e_sm secret is held as centered CRT residues, so it shares the modulus width
            // with C1's committed limbs. C1 range-checks the smudging bound on its lifted
            // witness; that bound exceeds every q_i and is not the width of what is hashed here.
            bit_e_sm_secret: compute_modulus_bit(threshold_params),
            bit_share,
        }
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let preset = self.preset;
        let committee = self.committee;
        let threshold_params = &self.params;
        let config_name = preset.metadata().security.as_config_str();
        let bits = &configs.bits;
        let committee = committee.values();
        let parity_matrix_str =
            parity_matrix_constant_string(threshold_params, committee.n, committee.threshold)?;
        let prefix = METADATA.prefix;
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
            configs.params.degree(),
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
}

impl Configs {
    pub fn for_preset(
        preset: BfvPreset,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        let (threshold_params, _) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(preset, &threshold_params, committee)
    }
}
