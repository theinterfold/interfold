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
pub struct LbfvPkAggregationConfigs {
    pub params: Arc<BfvParameters>,
    pub preset: BfvPreset,
    pub committee: CiphernodesCommitteeSize,
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: LbfvPkAggregationBits,
}
#[derive(Debug, Clone)]
pub struct LbfvPkAggregationBits {
    pub pk_bit: u32,
}
impl LbfvPkAggregationConfigs {
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
        let bits = LbfvPkAggregationBits {
            pk_bit: compute_modulus_bit(params),
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
pub fn generate_configs(configs: &LbfvPkAggregationConfigs) -> String {
    let moduli = crate::field::join_display(&configs.moduli, ", ");
    format!(
        r#"use crate::core::threshold::pk_aggregation::Configs as PkAggregationConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

pub global PK_AGGREGATION_BIT_PK: u32 = {};
pub global PK_AGGREGATION_CONFIGS: PkAggregationConfigs<L> = PkAggregationConfigs::new(QIS);
"#,
        configs.n, configs.l, moduli, configs.bits.pk_bit,
    )
}
