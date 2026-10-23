// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::field::join_display;
use crate::{CircuitMetadata, ConfigError};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::BfvParameters;
use std::sync::Arc;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "pk-aggregation",
    prefix: "PK_AGGREGATION",
    parameter: ParameterType::THRESHOLD,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    pub committee: CiphernodesCommitteeSize,
    pub pk_bit: u32,
}
impl Configs {
    pub fn new(
        threshold_params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        crate::parameters::matching_preset(threshold_params, ParameterType::THRESHOLD)?;

        Ok(Configs {
            params: threshold_params.clone(),
            committee,
            pk_bit: compute_modulus_bit(threshold_params),
        })
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let prefix = METADATA.prefix;

        let qis_str = join_display(&configs.params.moduli(), ", ");

        Ok(format!(
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
            configs.params.degree(),       // N
            configs.params.moduli().len(), // L
            qis_str,                       // QIS array
            prefix,                        // BIT_PK
            configs.pk_bit,                // BIT_PK
            prefix,                        // CONFIGS
        ))
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
        Self::new(&threshold_params, committee)
    }
}
