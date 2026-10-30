// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static l-BFV row configuration and Noir declarations.

use crate::ConfigError;
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{
    utils::{calculate_bit_width, compute_modulus_bit},
    BfvPreset,
};
use fhe::bfv::BfvParameters;
use num_bigint::BigUint;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RlkGenerationConfigs {
    pub params: Arc<BfvParameters>,
    pub preset: BfvPreset,
    pub committee: CiphernodesCommitteeSize,
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: RlkGenerationBits,
    pub bounds: RlkGenerationBounds,
}
#[derive(Debug, Clone)]
pub struct RlkGenerationBits {
    pub r_bit: u32,
    pub sk_bit: u32,
    pub e0_bit: u32,
    pub e2_bit: u32,
    pub rd0_bit: u32,
    pub rd2_bit: u32,
    pub d_bit: u32,
}
#[derive(Debug, Clone)]
pub struct RlkGenerationBounds {
    pub r_bound: BigUint,
    pub sk_bound: BigUint,
    pub e0_bound: BigUint,
    pub e2_bound: BigUint,
    pub rd0_bounds: Vec<BigUint>,
    pub rd2_bounds: Vec<BigUint>,
}
impl RlkGenerationConfigs {
    pub fn new(
        preset: BfvPreset,
        params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        crate::parameters::require_threshold_preset(preset, params)?;
        if e3_fhe_params::lbfv_crs_seed(preset).is_none()
            || e3_fhe_params::lbfv_urs_seed(preset).is_none()
        {
            return Err(ConfigError::Other(format!(
                "l-BFV is not enabled for {preset:?}"
            )));
        }
        let pk = crate::threshold::pk_generation::Configs::new(preset, params, committee)?;
        let n = BigUint::from(params.degree());
        let sk_bound = pk.bounds.sk_bound;
        let r_bound = sk_bound.clone();
        let error_bound = pk.bounds.eek_bound;
        // The circuit checks, over the integers and per CRT limb,
        //   d0 = -(d1 * sk mod X^N + 1) + e0 + delta * r  + q_i * rd0
        //   d2 =  (a  * r  mod X^N + 1) + e2 + delta * sk + q_i * rd2
        // with delta in {0, 1}. With qb = (q_i - 1) / 2 and m = max(sk_bound, r_bound):
        // |d| <= qb, |d1|, |a| <= qb (stored centered), so each negacyclic product is at most
        // N * qb * m, |e| <= error_bound and |delta * r|, |delta * sk| <= m. Dividing by q_i bounds
        // `rd`; the `+ 2` keeps one qb of margin, as C1's `r` bound does. Both identities share
        // the same term bounds, so one bound serves `rd0` and `rd2`.
        let m = std::cmp::max(&sk_bound, &r_bound).clone();
        let rd_bounds = params
            .moduli()
            .iter()
            .map(|modulus| {
                let modulus = BigUint::from(*modulus);
                let centered_bound = (&modulus - 1u32) / 2u32;
                ((&n * &m + 2u32) * &centered_bound + &error_bound + &m) / &modulus
            })
            .collect::<Vec<_>>();

        let bounds = RlkGenerationBounds {
            r_bound,
            sk_bound,
            e0_bound: error_bound.clone(),
            e2_bound: error_bound,
            rd0_bounds: rd_bounds.clone(),
            rd2_bounds: rd_bounds,
        };
        let max_bit =
            |values: &[BigUint]| values.iter().map(calculate_bit_width).max().unwrap_or(0);

        let bits = RlkGenerationBits {
            r_bit: calculate_bit_width(&bounds.r_bound),
            sk_bit: calculate_bit_width(&bounds.sk_bound),
            e0_bit: calculate_bit_width(&bounds.e0_bound),
            e2_bit: calculate_bit_width(&bounds.e2_bound),
            rd0_bit: max_bit(&bounds.rd0_bounds),
            rd2_bit: max_bit(&bounds.rd2_bounds),
            d_bit: compute_modulus_bit(&params),
        };
        Ok(Self {
            params: params.clone(),
            preset,
            committee,
            n: params.degree(),
            l: params.moduli().len(),
            moduli: params.moduli().to_vec(),
            bits,
            bounds,
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
pub fn generate_configs(configs: &RlkGenerationConfigs) -> String {
    let prefix = "RLK_GENERATION";
    let moduli = crate::field::join_display(&configs.moduli, ", ");
    let rd0 = crate::field::join_display(&configs.bounds.rd0_bounds, ", ");
    let rd2 = crate::field::join_display(&configs.bounds.rd2_bounds, ", ");

    format!(
        r#"use crate::core::threshold::rlk_generation::Configs as RlkGenerationConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

pub global {prefix}_BIT_R: u32 = {};
pub global {prefix}_BIT_SK: u32 = {};
pub global {prefix}_BIT_E0: u32 = {};
pub global {prefix}_BIT_E2: u32 = {};
pub global {prefix}_BIT_RD0: u32 = {};
pub global {prefix}_BIT_RD2: u32 = {};
pub global {prefix}_BIT_D: u32 = {};

pub global {prefix}_R_BOUND: Field = {};
pub global {prefix}_SK_BOUND: Field = {};
pub global {prefix}_E0_BOUND: Field = {};
pub global {prefix}_E2_BOUND: Field = {};
pub global {prefix}_RD0_BOUNDS: [Field; L] = [{}];
pub global {prefix}_RD2_BOUNDS: [Field; L] = [{}];

pub global {prefix}_CONFIGS: RlkGenerationConfigs<N, L> = RlkGenerationConfigs::new(
    QIS,
    {prefix}_R_BOUND,
    {prefix}_SK_BOUND,
    {prefix}_E0_BOUND,
    {prefix}_E2_BOUND,
    {prefix}_RD0_BOUNDS,
    {prefix}_RD2_BOUNDS,
);
"#,
        configs.n,
        configs.l,
        moduli,
        configs.bits.r_bit,
        configs.bits.sk_bit,
        configs.bits.e0_bit,
        configs.bits.e2_bit,
        configs.bits.rd0_bit,
        configs.bits.rd2_bit,
        configs.bits.d_bit,
        configs.bounds.r_bound,
        configs.bounds.sk_bound,
        configs.bounds.e0_bound,
        configs.bounds.e2_bound,
        rd0,
        rd2,
        prefix = prefix,
    )
}
