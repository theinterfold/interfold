// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::{CircuitMetadata, ConfigError};
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::BfvParameters;
use std::sync::Arc;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "pk",
    prefix: "PK",
    parameter: ParameterType::DKG,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    pub pk_bit: u32,
}
impl Configs {
    pub fn new(dkg_params: &Arc<BfvParameters>) -> Result<Self, ConfigError> {
        crate::parameters::matching_preset(dkg_params, ParameterType::DKG)?;

        Ok(Configs {
            params: dkg_params.clone(),
            pk_bit: compute_modulus_bit(dkg_params),
        })
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        Ok(format!(
            r#"pub global N: u32 = {};
pub global L: u32 = {};

/************************************
-------------------------------------
pk (CIRCUIT 0 - DKG BFV PUBLIC KEY)
-------------------------------------
************************************/

// pk - bit parameters
pub global {}_BIT_PK: u32 = {};
"#,
            configs.params.degree(),
            configs.params.moduli().len(),
            METADATA.prefix,
            configs.pk_bit,
        ))
    }
}

impl Configs {
    pub fn for_preset(preset: BfvPreset) -> Result<Self, ConfigError> {
        let (_, dkg_params) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(&dkg_params)
    }
}
