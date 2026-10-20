// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::field::join_display;
use crate::{CircuitMetadata, ConfigError};
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "user-data-encryption",
    prefix: "USER_DATA_ENCRYPTION",
    parameter: ParameterType::THRESHOLD,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    pub k0is: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub pk_bit: u32,
    pub ct_bit: u32,
    pub u_bit: u32,
    pub e0_bit: u32,
    pub e1_bit: u32,
    pub k_bit: u32,
    /// Width of ct0's reduction quotient `r`.
    pub ct0_r_bit: u32,
    /// Width of ct1's reduction quotient `r`.
    pub ct1_r_bit: u32,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub pk_bounds: Vec<BigUint>,
    pub u_bound: BigUint,
    pub e0_bound: BigUint,
    pub e1_bound: BigUint,
    pub k1_low_bound: BigUint,
    pub k1_up_bound: BigUint,
    /// Bounds on ct0's reduction quotient `r`, per CRT basis.
    pub ct0_r_bounds: Vec<BigUint>,
    /// Bounds on ct1's reduction quotient `r`, per CRT basis.
    pub ct1_r_bounds: Vec<BigUint>,
}
impl Configs {
    pub fn new(threshold_params: &Arc<BfvParameters>) -> Result<Self, ConfigError> {
        crate::parameters::matching_preset(threshold_params, ParameterType::THRESHOLD)?;

        let k0is = compute_k0is(threshold_params.moduli(), threshold_params.plaintext())?;

        let bounds = Bounds::new(threshold_params, &k0is)?;
        let bits = Bits::new(&bounds);

        Ok(Configs {
            params: threshold_params.clone(),

            k0is,

            bits,
            bounds,
        })
    }
}
impl Bounds {
    fn new(threshold_params: &Arc<BfvParameters>, k0is: &[u64]) -> Result<Self, ConfigError> {
        let n = BigUint::from(threshold_params.degree());
        let ctx = threshold_params.context_at_level(0)?;

        let t = BigUint::from(threshold_params.plaintext());

        // CBD bound
        let cbd_bound = (threshold_params.variance() * 2) as u64;
        // Uniform bound
        let uniform_bound = (threshold_params.get_error1_variance() * 3u32).sqrt();

        let u_bound = BigUint::from(SecretKey::sk_bound() as u128);

        // e0 = e1 in the fhe.rs
        let e0_bound = if threshold_params.get_error1_variance() <= &BigUint::from(16u32) {
            threshold_params.get_error1_variance() * 2u32
        } else {
            uniform_bound
        };
        let e1_bound = BigUint::from(cbd_bound); // e1 = e2 in the fhe.rs

        let k1_low_bound = BigUint::from(0u32);
        let k1_up_bound = &t - 1u32;

        // Calculate bounds for each CRT basis
        let mut pk_bounds = Vec::with_capacity(ctx.moduli().len());
        let mut ct0_r_bounds = Vec::with_capacity(ctx.moduli().len());
        let mut ct1_r_bounds = Vec::with_capacity(ctx.moduli().len());

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_big = BigUint::from(**qi);
            let qi_bound = (&qi_big - 1u32) / 2u32;

            let k0qi = BigUint::from(k0is[i]);

            // PK bounds: centered magnitude (qi-1)/2; matches pk_aggregation / C1 commitment
            pk_bounds.push(qi_bound.clone());

            // `r` is the quotient of the mod-q reduction in the identity the circuit checks:
            //   ct = pk * u + e + k0 * k1 + q * r   (mod X^N + 1, over the integers)
            // so bounding each term on the right and dividing by q bounds `r`:
            //   |pk * u| <= n * (q-1)/2 (negacyclic convolution of n terms, |u| <= u_bound),
            //   |ct| <= (q-1)/2, |k0 * k1| <= |k0| * k1_bound, |e| <= e_bound.
            // The bound holds for `|r|`, so one bound covers the two-sided range check.
            //
            // ct0 takes the *lifted* `e0_bound`, not its residue at q_i: the reduced identity reads
            // the lifted `e0` directly now that the CRT split and `e0is` are gone.
            // `k1` lies in `[0, t - 1]`, so `k1_up_bound` is its largest magnitude.
            let ct0_r_bound =
                (&k1_up_bound * &k0qi + (&n * &u_bound + 2u32) * &qi_bound + &e0_bound) / &qi_big;
            ct0_r_bounds.push(ct0_r_bound);

            // ct1 has no `k0 * k1` term, so only the product, ciphertext and `e1` contribute.
            let ct1_r_bound = ((&n * &u_bound + 2u32) * &qi_bound + &e1_bound) / &qi_big;
            ct1_r_bounds.push(ct1_r_bound);
        }

        Ok(Bounds {
            pk_bounds,
            u_bound,
            e0_bound,
            e1_bound,
            k1_low_bound,
            k1_up_bound,
            ct0_r_bounds,
            ct1_r_bounds,
        })
    }
}
impl Bits {
    fn new(data: &Bounds) -> Self {
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

        // Each `r` is two-sided, so take the widest bound across the CRT bases.
        let ct0_r_bit = data
            .ct0_r_bounds
            .iter()
            .max()
            .map(calculate_bit_width)
            .unwrap_or(0);
        let ct1_r_bit = data
            .ct1_r_bounds
            .iter()
            .max()
            .map(calculate_bit_width)
            .unwrap_or(0);

        Bits {
            pk_bit,
            ct_bit,
            u_bit,
            e0_bit,
            e1_bit,
            k_bit,
            ct0_r_bit,
            ct1_r_bit,
        }
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let prefix = METADATA.prefix;

        let qis_str = join_display(&configs.params.moduli(), ", ");
        let k0is_str = join_display(&configs.k0is, ", ");
        let pk_bounds_str = join_display(&configs.bounds.pk_bounds, ", ");
        let ct0_r_bounds_str = join_display(&configs.bounds.ct0_r_bounds, ", ");
        let ct1_r_bounds_str = join_display(&configs.bounds.ct1_r_bounds, ", ");

        Ok(format!(
            r#"use crate::core::threshold::user_data_encryption_ct0::Configs as UserDataEncryptionCt0Configs;
use crate::core::threshold::user_data_encryption_ct1::Configs as UserDataEncryptionCt1Configs;

// Global configs for User Data Encryption circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
user_data_encryption (USED FOR DATA ENCRYPTION)
-------------------------------------
************************************/

pub global {}_BIT_PK: u32 = {};
pub global {}_BIT_CT: u32 = {};
pub global {}_BIT_U: u32 = {};
pub global {}_BIT_E0: u32 = {};
pub global {}_BIT_E1: u32 = {};
pub global {}_BIT_K: u32 = {};
pub global {}_CT0_BIT_R: u32 = {};
pub global {}_CT1_BIT_R: u32 = {};

pub global {}_K0IS: [Field; L] = [{}];
pub global {}_PK_BOUNDS: [Field; L] = [{}];
pub global {}_E0_BOUND: Field = {};
pub global {}_E1_BOUND: Field = {};
pub global {}_U_BOUND: Field = {};
pub global {}_K1_LOW_BOUND: Field = {};
pub global {}_K1_UP_BOUND: Field = {};
pub global {}_CT0_R_BOUNDS: [Field; L] = [{}];
pub global {}_CT1_R_BOUNDS: [Field; L] = [{}];

/************************************
-------------------------------------
user_data_encryption: ct0 leg
-------------------------------------
************************************/

pub global {}_CT0_CONFIGS: UserDataEncryptionCt0Configs<N, L> = UserDataEncryptionCt0Configs::new(
    QIS,
    {}_K0IS,
    {}_E0_BOUND,
    {}_U_BOUND,
    {}_CT0_R_BOUNDS,
    {}_K1_LOW_BOUND,
    {}_K1_UP_BOUND,
);

/************************************
-------------------------------------
user_data_encryption: ct1 leg
-------------------------------------
************************************/

pub global {}_CT1_CONFIGS: UserDataEncryptionCt1Configs<N, L> = UserDataEncryptionCt1Configs::new(
    QIS,
    {}_E1_BOUND,
    {}_U_BOUND,
    {}_CT1_R_BOUNDS,
);
"#,
            configs.params.degree(),       // N
            configs.params.moduli().len(), // L
            qis_str,                       // QIS array
            prefix,
            configs.bits.pk_bit, // BIT_PK
            prefix,
            configs.bits.ct_bit, // BIT_CT
            prefix,
            configs.bits.u_bit, // BIT_U
            prefix,
            configs.bits.e0_bit, // BIT_E0
            prefix,
            configs.bits.e1_bit, // BIT_E1
            prefix,
            configs.bits.k_bit, // BIT_K
            prefix,
            configs.bits.ct0_r_bit, // CT0_BIT_R
            prefix,
            configs.bits.ct1_r_bit, // CT1_BIT_R
            prefix,
            k0is_str, // K0IS array
            prefix,
            pk_bounds_str, // PK_BOUNDS array
            prefix,
            configs.bounds.e0_bound, // E0_BOUND
            prefix,
            configs.bounds.e1_bound, // E1_BOUND
            prefix,
            configs.bounds.u_bound, // U_BOUND
            prefix,
            configs.bounds.k1_low_bound, // K1_LOW_BOUND
            prefix,
            configs.bounds.k1_up_bound, // K1_UP_BOUND
            prefix,
            ct0_r_bounds_str, // CT0_R_BOUNDS array
            prefix,
            ct1_r_bounds_str, // CT1_R_BOUNDS array
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
        ))
    }
}

impl Configs {
    pub fn for_preset(preset: BfvPreset) -> Result<Self, ConfigError> {
        let (threshold_params, _) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(&threshold_params)
    }
}
