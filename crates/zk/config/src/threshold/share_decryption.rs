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
use fhe::bfv::BfvParameters;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "threshold-share-decryption",
    prefix: "THRESHOLD_SHARE_DECRYPTION",
    parameter: ParameterType::THRESHOLD,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    /// Must match the message width of the selected C6/C7 artifacts.
    pub max_msg_non_zero_coeffs: usize,
    pub bits: Bits,
    pub bounds: Bounds,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub ct_bit: u32,
    pub sk_bit: u32,
    pub e_sm_bit: u32,
    pub r_bit: u32,
    /// Centered `d` coefficient bound (payload flatten / Fiat–Shamir).
    pub d_bit: u32,
    /// Native \([0, q)\) limb width for `d_native_trunc` / C7 share commitments.
    pub d_native_bit: u32,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub r_bounds: Vec<BigUint>,
}
impl Configs {
    pub fn new(threshold_params: &Arc<BfvParameters>) -> Result<Self, ConfigError> {
        crate::parameters::matching_preset(threshold_params, ParameterType::THRESHOLD)?;

        let bounds = Bounds::new(threshold_params)?;
        let bits = Bits::new(threshold_params, &bounds);

        Ok(Configs {
            params: threshold_params.clone(),
            max_msg_non_zero_coeffs: crate::MAX_MSG_NON_ZERO_COEFFS,

            bits,
            bounds,
        })
    }
}
impl Bounds {
    fn new(threshold_params: &Arc<BfvParameters>) -> Result<Self, ConfigError> {
        let n = BigUint::from(threshold_params.degree());
        // Get cyclotomic degree and context at provided level
        let ctx = threshold_params.context_at_level(0)?;

        // Calculate bounds for each CRT basis
        let mut r_bounds = Vec::with_capacity(ctx.moduli().len());

        for qi in ctx.moduli_operators() {
            let qi_big = BigUint::from(**qi);
            let qi_bound = (&qi_big - 1u32) / 2u32;

            // `r` is the mod-q quotient of the identity reduced modulo X^N + 1:
            //   d = ct0 + (ct1 * sk mod X^N + 1) + e_sm + q * r
            // so bounding the other terms and dividing by q bounds `r`. The negacyclic product of n
            // terms contributes n * ((q-1)/2)^2 and each of `d`, `ct0`, `e_sm` contributes (q-1)/2.
            // The 4 rather than 3 keeps the margin the unreduced `r1` bound carried, which also
            // means the reduced quotient is no wider -- the width stays 69 (43 insecure).
            r_bounds.push((&qi_bound * &qi_bound * &n + 4u32 * &qi_bound) / &qi_big);
        }

        Ok(Bounds { r_bounds })
    }
}
impl Bits {
    fn new(threshold_params: &Arc<BfvParameters>, data: &Bounds) -> Self {
        // One width covers every limb's `r`, so take the widest bound.
        let r_bit = data
            .r_bounds
            .iter()
            .max()
            .map(calculate_bit_width)
            .unwrap_or(0);
        let d_native_bit = compute_native_crt_coeff_bit(threshold_params.moduli());

        // `ct`, `sk`, `e_sm` and `d` are centered residues, so they share the modulus width. This
        // used to piggyback on the `r2` bound, which was `(max(q) - 1) / 2` for exactly that reason;
        // with `r2` gone the width comes from the moduli directly.
        let modulus_bit = e3_fhe_params::utils::compute_modulus_bit(&threshold_params);

        Bits {
            ct_bit: modulus_bit,
            sk_bit: modulus_bit,
            e_sm_bit: modulus_bit,
            r_bit,
            d_bit: modulus_bit,
            d_native_bit,
        }
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let prefix = METADATA.prefix;

        let qis_str = join_display(&configs.params.moduli(), ", ");
        let r_bounds_str = join_display(&configs.bounds.r_bounds, ", ");

        Ok(format!(
            r#"use crate::core::threshold::share_decryption::Configs as ShareDecryptionConfigs;

// Global configs for Share Decryption circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
share_decryption (CIRCUIT 6 - THRESHOLD BFV SHARE DECRYPTION)
-------------------------------------
************************************/

pub global {}_BIT_CT: u32 = {};
pub global {}_BIT_SK: u32 = {};
pub global {}_BIT_E_SM: u32 = {};
pub global {}_BIT_R: u32 = {};
pub global {}_BIT_D: u32 = {};
pub global {}_BIT_D_NATIVE: u32 = {};

pub global {}_R_BOUNDS: [Field; L] = [{}];

pub global {}_CONFIGS: ShareDecryptionConfigs<L> = ShareDecryptionConfigs::new(
    QIS,
    {}_R_BOUNDS,
);
"#,
            configs.params.degree(),
            configs.params.moduli().len(),
            qis_str,
            prefix,
            configs.bits.ct_bit,
            prefix,
            configs.bits.sk_bit,
            prefix,
            configs.bits.e_sm_bit,
            prefix,
            configs.bits.r_bit,
            prefix,
            configs.bits.d_bit,
            prefix,
            configs.bits.d_native_bit,
            prefix,
            r_bounds_str,
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
