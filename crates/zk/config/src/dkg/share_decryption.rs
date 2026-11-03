// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::{CircuitMetadata, ConfigError};
use e3_fhe_params::utils::{compute_modulus_bit, compute_msg_bit};
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::BfvParameters;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "share-decryption",
    prefix: "SHARE_DECRYPTION",
    parameter: ParameterType::DKG,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub preset: BfvPreset,
    pub params: Arc<BfvParameters>,
    pub threshold_params: Arc<BfvParameters>,
    pub bits: Bits,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    /// Per-share message coefficients in `[0, t)`; matches C2 share encryption
    /// (`compute_msg_bit` on DKG params).
    pub msg_bit: u32,
    /// CRT aggregate polynomials (same ring semantics as C6 `sk` / `e_sm`);
    /// matches [`e3_fhe_params::utils::compute_modulus_bit`] on threshold params.
    pub agg_bit: u32,
}
impl Configs {
    pub fn new(
        threshold_params: &Arc<BfvParameters>,
        dkg_params: &Arc<BfvParameters>,
    ) -> Result<Self, ConfigError> {
        let threshold =
            crate::parameters::matching_preset(threshold_params, ParameterType::THRESHOLD)?;
        let dkg = crate::parameters::matching_preset(dkg_params, ParameterType::DKG)?;
        if threshold.dkg_counterpart() != Some(dkg) {
            return Err(ConfigError::Other(
                "DKG and threshold parameters belong to different presets".into(),
            ));
        }

        let bits = Bits::new(threshold_params, dkg_params);

        Ok(Configs {
            preset: threshold,
            params: dkg_params.clone(),
            threshold_params: threshold_params.clone(),

            bits,
        })
    }
}
impl Bits {
    fn new(threshold_params: &Arc<BfvParameters>, dkg_params: &Arc<BfvParameters>) -> Self {
        Bits {
            msg_bit: compute_msg_bit(&dkg_params),
            agg_bit: compute_modulus_bit(&threshold_params),
        }
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let prefix = METADATA.prefix;

        Ok(format!(
            r#"pub global N: u32 = {};
pub global L: u32 = {};

/************************************
-------------------------------------
share_decryption_sk (CIRCUIT 4a - BFV DECRYPTION SK)
share_decryption_e_sm (CIRCUIT 4b - BFV DECRYPTION E_SM)
-------------------------------------
************************************/

pub global {}_BIT_MSG: u32 = {};
pub global {}_BIT_AGG: u32 = {};
"#,
            configs.params.degree(),
            configs.params.moduli().len(),
            prefix,
            configs.bits.msg_bit,
            prefix,
            configs.bits.agg_bit,
        ))
    }
}

impl Configs {
    pub fn with_preset(mut self, preset: BfvPreset) -> Result<Self, ConfigError> {
        crate::parameters::require_threshold_preset(preset, &self.threshold_params)?;
        self.preset = preset;
        Ok(self)
    }

    pub fn for_preset(preset: BfvPreset) -> Result<Self, ConfigError> {
        let (threshold_params, dkg_params) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(&threshold_params, &dkg_params)?
            .with_preset(preset.threshold_counterpart().unwrap_or(preset))
    }
}
