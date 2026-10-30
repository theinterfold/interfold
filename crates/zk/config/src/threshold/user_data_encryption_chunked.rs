// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunked user-encryption bounds and static Noir declarations.
use crate::ConfigError;
use e3_fhe_params::{
    utils::{calculate_bit_width, compute_k0is},
    BfvPreset, ParameterType,
};
use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{Signed, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub k0is: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
}
impl Configs {
    pub fn new(threshold_params: &Arc<BfvParameters>) -> Result<Self, ConfigError> {
        crate::parameters::matching_preset(threshold_params, ParameterType::THRESHOLD)?;
        let moduli = threshold_params.moduli().to_vec();
        let k0is = compute_k0is(threshold_params.moduli(), threshold_params.plaintext())?;

        let bounds = Bounds::new(threshold_params, &k0is)?;
        let bits = Bits::new(threshold_params, &bounds)?;

        Ok(Configs {
            params: threshold_params.clone(),
            n: threshold_params.degree(),
            l: moduli.len(),
            k0is,
            moduli,
            bits,
            bounds,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub pk_bit: u32,
    pub ct_bit: u32,
    pub u_bit: u32,
    pub e0_bit: u32,
    pub e1_bit: u32,
    pub k_bit: u32,
    pub r1_bit: u32,
    pub p1_bit: u32,
}
impl Bits {
    fn new(_threshold_params: &Arc<BfvParameters>, data: &Bounds) -> Result<Self, ConfigError> {
        let max_pk_bound = data.pk_bounds.iter().max().unwrap();

        let pk_bit = calculate_bit_width(max_pk_bound);
        // We can safely assume that the ct bound is the same as the pk bound.
        let ct_bit = calculate_bit_width(max_pk_bound);
        let u_bit = calculate_bit_width(&data.u_bound);
        let e0_bit = calculate_bit_width(&data.e0_bound);
        let e1_bit = calculate_bit_width(&data.e1_bound);

        // For k1, use the maximum of low and up bounds
        let k1_low_bit = calculate_bit_width(&data.k1_low_bound);
        let k1_up_bit = calculate_bit_width(&data.k1_up_bound);
        let k_bit = k1_low_bit.max(k1_up_bit);

        // For r1, use the maximum of all low and up bounds
        let mut r1_bit = 0;
        for bound in data.r1_low_bounds.iter().chain(data.r1_up_bounds.iter()) {
            r1_bit = r1_bit.max(calculate_bit_width(bound));
        }

        // For p1, use the maximum of all bounds
        let mut p1_bit = 0;
        for bound in &data.p1_bounds {
            p1_bit = p1_bit.max(calculate_bit_width(bound));
        }

        Ok(Bits {
            pk_bit,
            ct_bit,
            u_bit,
            e0_bit,
            e1_bit,
            k_bit,
            r1_bit,
            p1_bit,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub pk_bounds: Vec<BigUint>,
    pub u_bound: BigUint,
    pub e0_bound: BigUint,
    pub e1_bound: BigUint,
    pub k1_low_bound: BigUint,
    pub k1_up_bound: BigUint,
    pub r1_low_bounds: Vec<BigUint>,
    pub r1_up_bounds: Vec<BigUint>,
    pub p1_bounds: Vec<BigUint>,
}
impl Bounds {
    fn new(threshold_params: &Arc<BfvParameters>, k0is: &[u64]) -> Result<Self, ConfigError> {
        let n = BigInt::from(threshold_params.degree());
        let ctx = threshold_params.context_at_level(0)?;

        let t = BigInt::from(threshold_params.plaintext());

        let error_bound =
            e3_fhe_params::utils::error_sampler_bound(threshold_params.get_error1_variance())
                .to_bigint()
                .ok_or_else(|| {
                    ConfigError::Other("Failed to convert error bound to BigInt".into())
                })?;

        let u_bound = SecretKey::sk_bound() as u128; // u_bound is the same as sk_bound

        // e0 = e1 in fhe.rs; e1 = e2 in fhe.rs.
        let e0_bound = error_bound.to_u128().unwrap();
        let e1_bound = (threshold_params.variance() * 2) as u64;

        // Plaintext coefficients are encoded in [0, t), not centered around zero.
        let ptxt_low_bound = BigInt::from(0);
        let ptxt_up_bound = t.clone() - BigInt::from(1);

        let k1_low_bound: BigInt = BigInt::from(-1) * ptxt_low_bound.clone();
        let k1_up_bound: BigInt = ptxt_up_bound.clone();

        // Calculate bounds for each CRT basis
        let _moduli: Vec<u64> = ctx.moduli_operators().iter().map(|q| **q).collect();

        let mut pk_bounds: Vec<BigInt> = Vec::new();
        let mut r1_low_bounds: Vec<BigInt> = Vec::new();
        let mut r1_up_bounds: Vec<BigInt> = Vec::new();
        let mut p1_bounds: Vec<BigInt> = Vec::new();

        let e0_bound_bigint = BigInt::from(e0_bound);

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(**qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            let k0qi = BigInt::from(k0is[i]);

            // PK bounds: centered magnitude (qi-1)/2; matches pk_aggregation / C1 commitment
            pk_bounds.push(qi_bound.clone());

            // R1 bounds. The identity reads the committed, lifted `e0`, not a residue at `q_i`
            // (IF-006), so `r1` also absorbs `e0`'s multiple of `q_i`: the bound takes the whole
            // `e0_bound`, as main's ct0 `r` bound does.
            let r1_residual_bound = (&n * u_bound + BigInt::from(2)) * &qi_bound + &e0_bound_bigint;
            let r1_low_numerator = &ptxt_up_bound * k0qi.abs() + &r1_residual_bound;
            let r1_low_magnitude = (&r1_low_numerator + &qi_bigint - BigInt::from(1)) / &qi_bigint;
            let r1_up = (&r1_residual_bound + &qi_bigint - BigInt::from(1)) / &qi_bigint;

            r1_low_bounds.push(r1_low_magnitude);
            r1_up_bounds.push(r1_up);

            // P1 bound. The folded product has the same per-coefficient bound as the unreduced one.
            let p1_bound: BigInt =
                ((&n * u_bound + BigInt::from(2)) * &qi_bound + e1_bound) / &qi_bigint;
            p1_bounds.push(p1_bound.clone());
        }

        Ok(Bounds {
            pk_bounds: pk_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            u_bound: BigUint::from(u_bound as u64),
            e0_bound: BigUint::from(e0_bound),
            e1_bound: BigUint::from(e1_bound),
            k1_low_bound: BigUint::from(k1_low_bound.to_u128().unwrap()),
            k1_up_bound: BigUint::from(k1_up_bound.to_u128().unwrap()),
            r1_low_bounds: r1_low_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r1_up_bounds: r1_up_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            p1_bounds: p1_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
        })
    }
}
use crate::field::join_display;
fn generate_configs(configs: &Configs) -> String {
    let prefix = "USER_DATA_ENCRYPTION_CHUNKED";

    format!(
        r#"use crate::core::threshold::user_data_encryption_chunk::Ct0ChunkConfigs as UserDataEncryptionCt0ChunkConfigs;
use crate::core::threshold::user_data_encryption_chunk::Ct1ChunkConfigs as UserDataEncryptionCt1ChunkConfigs;

// Global configs for User Data Encryption circuit
pub global N: u32 = {n};
pub global L: u32 = {l};
pub global QIS: [Field; L] = [{qis}];

/************************************
-------------------------------------
user_data_encryption (USED FOR DATA ENCRYPTION)
-------------------------------------
************************************/

pub global {prefix}_BIT_PK: u32 = {bit_pk};
pub global {prefix}_BIT_CT: u32 = {bit_ct};
pub global {prefix}_BIT_U: u32 = {bit_u};
pub global {prefix}_BIT_E0: u32 = {bit_e0};
pub global {prefix}_BIT_E1: u32 = {bit_e1};
pub global {prefix}_BIT_K: u32 = {bit_k};
pub global {prefix}_BIT_R1: u32 = {bit_r1};
pub global {prefix}_BIT_P1: u32 = {bit_p1};

pub global {prefix}_K0IS: [Field; L] = [{k0is}];
pub global {prefix}_PK_BOUNDS: [Field; L] = [{pk_bounds}];
pub global {prefix}_E0_BOUND: Field = {e0_bound};
pub global {prefix}_E1_BOUND: Field = {e1_bound};
pub global {prefix}_U_BOUND: Field = {u_bound};
pub global {prefix}_K1_LOW_BOUND: Field = {k1_low_bound};
pub global {prefix}_K1_UP_BOUND: Field = {k1_up_bound};
pub global {prefix}_R1_LOW_BOUNDS: [Field; L] = [{r1_low_bounds}];
pub global {prefix}_R1_UP_BOUNDS: [Field; L] = [{r1_up_bounds}];
pub global {prefix}_P1_BOUNDS: [Field; L] = [{p1_bounds}];

pub global {prefix}_CT0_CHUNK_CONFIGS: UserDataEncryptionCt0ChunkConfigs<L> = UserDataEncryptionCt0ChunkConfigs::new(
    QIS,
    {prefix}_U_BOUND,
    {prefix}_E0_BOUND,
    {prefix}_K1_LOW_BOUND,
    {prefix}_K1_UP_BOUND,
    {prefix}_R1_LOW_BOUNDS,
    {prefix}_R1_UP_BOUNDS,
);
pub global {prefix}_CT1_CHUNK_CONFIGS: UserDataEncryptionCt1ChunkConfigs<L> = UserDataEncryptionCt1ChunkConfigs::new(
    {prefix}_U_BOUND,
    {prefix}_E1_BOUND,
    {prefix}_P1_BOUNDS,
);
"#,
        n = configs.n,
        l = configs.l,
        qis = join_display(&configs.moduli, ", "),
        prefix = prefix,
        bit_pk = configs.bits.pk_bit,
        bit_ct = configs.bits.ct_bit,
        bit_u = configs.bits.u_bit,
        bit_e0 = configs.bits.e0_bit,
        bit_e1 = configs.bits.e1_bit,
        bit_k = configs.bits.k_bit,
        bit_r1 = configs.bits.r1_bit,
        bit_p1 = configs.bits.p1_bit,
        k0is = join_display(&configs.k0is, ", "),
        pk_bounds = join_display(&configs.bounds.pk_bounds, ", "),
        e0_bound = configs.bounds.e0_bound,
        e1_bound = configs.bounds.e1_bound,
        u_bound = configs.bounds.u_bound,
        k1_low_bound = configs.bounds.k1_low_bound,
        k1_up_bound = configs.bounds.k1_up_bound,
        r1_low_bounds = join_display(&configs.bounds.r1_low_bounds, ", "),
        r1_up_bounds = join_display(&configs.bounds.r1_up_bounds, ", "),
        p1_bounds = join_display(&configs.bounds.p1_bounds, ", "),
    )
}
impl Configs {
    pub fn for_preset(preset: BfvPreset) -> Result<Self, ConfigError> {
        let (params, _) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(&params)
    }
    pub fn render(&self) -> Result<String, ConfigError> {
        Ok(generate_configs(self))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_declarations_keep_their_namespace_and_parameter_owner() {
        let (params, _) = BfvPreset::InsecureThresholdLbfv.build_pair().unwrap();
        let config = Configs::new(&params).unwrap();
        assert!(Arc::ptr_eq(&params, &config.params));
        let noir = config.render().unwrap();
        assert!(noir.contains("USER_DATA_ENCRYPTION_CHUNKED_CT0_CHUNK_CONFIGS"));
        assert!(noir.contains("USER_DATA_ENCRYPTION_CHUNKED_CT1_CHUNK_CONFIGS"));
        assert!(!noir.contains("USER_DATA_ENCRYPTION_CT0_CHUNK_CONFIGS"));
    }
}
