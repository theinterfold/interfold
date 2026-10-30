// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static l-BFV row configuration and Noir declarations.

use crate::ConfigError;
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{utils::compute_modulus_bit, BfvPreset};
use fhe::bfv::BfvParameters;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RlkAggregationConfigs {
    pub params: Arc<BfvParameters>,
    pub preset: BfvPreset,
    pub committee: CiphernodesCommitteeSize,
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: RlkAggregationBits,
}
#[derive(Debug, Clone)]
pub struct RlkAggregationBits {
    pub d_bit: u32,
}
impl RlkAggregationConfigs {
    pub fn new(
        preset: BfvPreset,
        params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        crate::parameters::require_threshold_preset(preset, params)?;
        if e3_fhe_params::lbfv_crs_seed(preset).is_none() {
            return Err(ConfigError::Other(format!(
                "l-BFV is not enabled for {preset:?}"
            )));
        }
        let _pk = crate::threshold::pk_generation::Configs::new(preset, params, committee)?;
        let bits = RlkAggregationBits {
            d_bit: compute_modulus_bit(params),
        };
        Ok(Self {
            params: params.clone(),
            preset,
            committee,
            n: params.degree(),
            l: params.moduli().len(),
            moduli: params.moduli().to_vec(),
            bits,
        })
    }
    pub fn for_preset(
        preset: BfvPreset,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        let (params, _) = preset
            .build_pair()
            .map_err(|error| ConfigError::Other(error.to_string()))?;
        Self::new(preset, &params, committee)
    }
    pub fn render(&self) -> Result<String, ConfigError> {
        Ok(generate_configs(self))
    }
}
pub fn generate_configs(configs: &RlkAggregationConfigs) -> String {
    let prefix = "RLK_AGGREGATION";
    let moduli = crate::field::join_display(&configs.moduli, ", ");
    format!(
        r#"use crate::core::threshold::rlk_aggregation::Configs as RlkAggregationConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

pub global {}_BIT_D: u32 = {};
pub global {}_CONFIGS: RlkAggregationConfigs<L> = RlkAggregationConfigs::new(QIS);
"#,
        configs.n, configs.l, moduli, prefix, configs.bits.d_bit, prefix,
    )
}
